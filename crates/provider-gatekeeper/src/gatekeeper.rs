use windows_sys::Win32::Security::Authentication::Identity::{
    SECPKG_ATTR_LIFESPAN, SECPKG_ATTR_NAMES, SECPKG_ATTR_PROTO_INFO, SECPKG_ATTR_SIZES,
    SECURITY_NATIVE_DREP, SecPkgContext_Lifespan, SecPkgContext_NamesA, SecPkgContext_NamesW,
    SecPkgContext_ProtoInfoA, SecPkgContext_ProtoInfoW, SecPkgContext_Sizes,
};

use crate::base_provider::{
    BaseProvider, Handle, SEC_E_OK, SecPkgInfoA, SecPkgInfoW, SecurityProvider, SecurityStatus,
    SessionManager,
};
use crate::gatekeeper_session_manager::GateKeeperSessionManager;

/// Equivalent to CGateKeeperProvider C++ class.
pub struct GateKeeperProvider {
    pub base: BaseProvider,
}

impl Default for GateKeeperProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl GateKeeperProvider {
    pub fn new() -> Self {
        Self {
            base: BaseProvider::new(),
        }
    }
}

impl SecurityProvider for GateKeeperProvider {
    fn base(&self) -> &BaseProvider {
        &self.base
    }

    fn initialize(&mut self) -> bool {
        self.base.init_package_info(
            52,
            64,
            "GateKeeper",
            "GateKeeper Security Package",
            w!("GateKeeper"),
            w!("GateKeeper Security Package"),
        );
        BaseProvider::initialize(self)
    }

    fn create_session_manager(&self) -> Option<Box<dyn SessionManager>> {
        Some(Box::new(GateKeeperSessionManager::new()))
    }

    fn accept_security_context(
        &self,
        ph_credential: &Handle,
        ph_context: &mut Handle,
        p_input: usize,
        _f_context_req: u32,
        target_data_rep: u32,
        ph_new_context: &mut Handle,
        p_output: usize,
        _pf_context_attr: &mut u32,
        pts_expiry: usize,
    ) -> SecurityStatus {
        use crate::base_provider::{
            SEC_E_INVALID_HANDLE, SEC_E_INVALID_TOKEN, SEC_E_OK, SEC_E_UNKNOWN_CREDENTIALS,
            SEC_E_UNSUPPORTED_FUNCTION, SEC_I_CONTINUE_NEEDED, SECBUFFER_PKG_PARAMS,
            SECBUFFER_TOKEN, find_sec_buffer,
        };
        use hmac::{Hmac, KeyInit, Mac};
        use md5::Md5;
        use std::ptr;

        if !self.base.is_valid_credential_handle(ph_credential) {
            return SEC_E_UNKNOWN_CREDENTIALS;
        }

        if target_data_rep != SECURITY_NATIVE_DREP {
            return SEC_E_UNSUPPORTED_FUNCTION;
        }

        unsafe {
            let pts = pts_expiry as *mut u64;
            if !pts.is_null() {
                *pts = 0x0FFFFFFF_7FFFFFFF;
            }
        }

        let is_initial = ph_context.lower == 0 && ph_context.upper == 0;

        if is_initial {
            let input_token_res = unsafe { find_sec_buffer(p_input, SECBUFFER_TOKEN, 0) };
            let output_token_res = unsafe { find_sec_buffer(p_output, SECBUFFER_TOKEN, 0) };
            if input_token_res.is_none() || output_token_res.is_none() {
                return SEC_E_INVALID_TOKEN;
            }
            let input_token = input_token_res.unwrap();
            let output_token = output_token_res.unwrap();

            let pb0_res = unsafe { find_sec_buffer(p_input, SECBUFFER_PKG_PARAMS, 0) };
            let pb1_res = unsafe { find_sec_buffer(p_input, SECBUFFER_PKG_PARAMS, 1) };
            if pb0_res.is_none() || pb1_res.is_none() {
                return SEC_E_INVALID_TOKEN;
            }
            let pb0 = pb0_res.unwrap();
            let pb1 = pb1_res.unwrap();

            // Validate Input Token (Step 1)
            let version;
            unsafe {
                let p_in = (*input_token).pvBuffer as *const u32;
                let cb_in = (*input_token).cbBuffer;
                if cb_in != 16 {
                    return SEC_E_INVALID_TOKEN;
                }
                let mut magic = [0u8; 8];
                ptr::copy_nonoverlapping(p_in as *const u8, magic.as_mut_ptr(), 8);
                if &magic[0..5] != b"GKSSP" {
                    return SEC_E_INVALID_TOKEN;
                }
                version = *p_in.add(2);
                let step = *p_in.add(3);
                if step != 1 {
                    return SEC_E_INVALID_TOKEN;
                }
            }

            let mut sm_lock = self.base.session_manager.lock();
            if let Some(ref mut sm) = *sm_lock
                && let Some(handle) = sm.create_context()
                && let Some(gk_sm) = sm.as_any().downcast_ref::<GateKeeperSessionManager>()
                && let Some(session_arc) = gk_sm.get_session(&handle)
            {
                let mut session = session_arc.lock();

                unsafe {
                    // Extract Hostname
                    let p_host = (*pb0).pvBuffer as *const u8;
                    let cb_host = (*pb0).cbBuffer;
                    let copy_len = std::cmp::min(cb_host as usize, 15);
                    ptr::copy_nonoverlapping(p_host, session.hostname.as_mut_ptr(), copy_len);
                    session.hostname[copy_len] = 0;
                    session.hostname_len = copy_len as u32;

                    // Extract Flags
                    let p_flags = (*pb1).pvBuffer as *const u8;
                    let cb_flags = (*pb1).cbBuffer;
                    if cb_flags > 0 {
                        session.version_flag = *p_flags;
                    }

                    let is_valid_version = if session.version_flag == 0 {
                        (3..=4).contains(&version)
                    } else {
                        (1..=4).contains(&version)
                    };

                    if !is_valid_version {
                        return SEC_E_INVALID_TOKEN;
                    }

                    // Server Nonce (Hardcoded for demo predictability)
                    session.server_nonce = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];

                    // Generate Output Token (Step 2 Challenge)
                    let p_out = (*output_token).pvBuffer as *mut u32;
                    ptr::write_bytes(p_out, 0, 6);
                    ptr::copy_nonoverlapping(b"GKSSP\0\0\0".as_ptr(), p_out as *mut u8, 8);
                    *p_out.add(2) = version; // Echo version
                    *p_out.add(3) = 2; // Step 2
                    ptr::copy_nonoverlapping(
                        session.server_nonce.as_ptr(),
                        p_out.add(4) as *mut u8,
                        8,
                    );
                    (*output_token).cbBuffer = 24;
                }

                session.flags |= 2;
                *ph_new_context = handle;
                return SEC_I_CONTINUE_NEEDED;
            }
            SEC_E_INVALID_TOKEN
        } else {
            // Processing Step 3 token from Client
            let input_token_res = unsafe { find_sec_buffer(p_input, SECBUFFER_TOKEN, 0) };
            if input_token_res.is_none() {
                return SEC_E_INVALID_TOKEN;
            }
            let input_token = input_token_res.unwrap();

            let mut sm_lock = self.base.session_manager.lock();
            if let Some(ref mut sm) = *sm_lock
                && let Some(gk_sm) = sm.as_any().downcast_ref::<GateKeeperSessionManager>()
                && let Some(session_arc) = gk_sm.get_session(ph_context)
            {
                let mut session = session_arc.lock();

                let is_match;
                unsafe {
                    let p_in = (*input_token).pvBuffer as *const u32;
                    let cb_in = (*input_token).cbBuffer;

                    let mut magic = [0u8; 8];
                    ptr::copy_nonoverlapping(p_in as *const u8, magic.as_mut_ptr(), 8);
                    if &magic[0..5] != b"GKSSP" {
                        return SEC_E_INVALID_TOKEN;
                    }
                    let version = *p_in.add(2);
                    let step = *p_in.add(3);

                    let is_valid_version = if session.version_flag == 0 {
                        (3..=4).contains(&version)
                    } else {
                        (1..=4).contains(&version)
                    };

                    if !is_valid_version || step != 3 {
                        return SEC_E_INVALID_TOKEN;
                    }

                    if (version >= 2 && cb_in != 48) || (version == 1 && cb_in != 32) {
                        return SEC_E_INVALID_TOKEN;
                    }

                    if version >= 2 {
                        let p_guid = p_in.add(8) as *const u8;
                        ptr::copy_nonoverlapping(
                            p_guid,
                            &mut session.gatekeeper_id as *mut _ as *mut u8,
                            16,
                        );
                    }

                    // Verify HMAC — the client's HMAC is at token offset 16 (after header)
                    let p_hmac = p_in.add(4) as *const u8;

                    // Build the same data the server used: nonce + hostname (for v3+)
                    // or nonce only (for v1/v2)
                    let mut data = Vec::new();
                    data.extend_from_slice(&session.server_nonce);
                    if version >= 3 {
                        data.extend_from_slice(&session.hostname[..session.hostname_len as usize]);
                    }

                    type HmacMd5 = Hmac<Md5>;
                    let mut mac = HmacMd5::new_from_slice(&session.hmac_key).unwrap();
                    mac.update(&data);
                    let result = mac.finalize().into_bytes();

                    is_match = (0..16).all(|i| result[i] == *p_hmac.add(i));
                }

                if !is_match {
                    return SEC_E_INVALID_TOKEN;
                }

                if let Some(out_token) = unsafe { find_sec_buffer(p_output, SECBUFFER_TOKEN, 0) } {
                    unsafe {
                        (*out_token).cbBuffer = 0;
                    }
                }

                session.flags |= 8; // Handshake complete
                return SEC_E_OK;
            }
            SEC_E_INVALID_HANDLE
        }
    }

    fn initialize_security_context_a(
        &self,
        ph_credential: &Handle,
        ph_context: &Handle,
        psz_target_name: &str,
        _f_context_req: u32,
        _reserved1: u32,
        target_data_rep: u32,
        p_input: usize,
        _reserved2: u32,
        ph_new_context: &mut Handle,
        p_output: usize,
        _pf_context_attr: &mut u32,
        pts_expiry: usize,
    ) -> SecurityStatus {
        use crate::base_provider::{
            SEC_E_INVALID_HANDLE, SEC_E_INVALID_TOKEN, SEC_E_NOT_SUPPORTED, SEC_E_TARGET_UNKNOWN,
            SEC_E_UNKNOWN_CREDENTIALS, SEC_I_CONTINUE_NEEDED, SECBUFFER_PKG_PARAMS,
            SECBUFFER_TOKEN, find_sec_buffer,
        };
        use hmac::{Hmac, KeyInit, Mac};
        use md5::Md5;
        use std::ptr;

        if !self.base.is_valid_credential_handle(ph_credential) {
            return SEC_E_UNKNOWN_CREDENTIALS;
        }

        if !psz_target_name.is_empty() {
            return SEC_E_TARGET_UNKNOWN;
        }

        if target_data_rep != SECURITY_NATIVE_DREP {
            return SEC_E_NOT_SUPPORTED;
        }

        unsafe {
            let pts = pts_expiry as *mut u64;
            if !pts.is_null() {
                // IDA: *(_DWORD *)ptsExpiry = 0x7FFFFFFF; *((_DWORD *)ptsExpiry + 1) = 0xFFFFFFF;
                *pts = 0x0FFFFFFF_7FFFFFFF;
            }
        }

        let output_token_res = unsafe { find_sec_buffer(p_output, SECBUFFER_TOKEN, 0) };
        if output_token_res.is_none() {
            return SEC_E_INVALID_TOKEN;
        }
        let output_token = output_token_res.unwrap();

        if ph_context.lower == 0 && ph_context.upper == 0 {
            // --- Step 1 ---
            let pkg_buffer0 = unsafe { find_sec_buffer(p_input, SECBUFFER_PKG_PARAMS, 0) };
            let pkg_buffer1 = unsafe { find_sec_buffer(p_input, SECBUFFER_PKG_PARAMS, 1) };

            if let (Some(pb0), Some(pb1)) = (pkg_buffer0, pkg_buffer1) {
                let mut sm_lock = self.base.session_manager.lock();
                if let Some(ref mut sm) = *sm_lock
                    && let Some(handle) = sm.create_context()
                    && let Some(gk_sm) = sm.as_any().downcast_ref::<GateKeeperSessionManager>()
                    && let Some(session_arc) = gk_sm.get_session(&handle)
                {
                    let mut session = session_arc.lock();

                    unsafe {
                        // Fill GateKeeperID (GUID)
                        let p_guid = (*pb0).pvBuffer as *const u8;
                        ptr::copy_nonoverlapping(
                            p_guid,
                            &mut session.gatekeeper_id as *mut _ as *mut u8,
                            16,
                        );

                        // Fill Hostname
                        let p_host = (*pb1).pvBuffer as *const u8;
                        let cb_host = (*pb1).cbBuffer;
                        let copy_len = std::cmp::min(cb_host as usize, 15);
                        ptr::copy_nonoverlapping(p_host, session.hostname.as_mut_ptr(), copy_len);
                        session.hostname[copy_len] = 0;
                        session.hostname_len = copy_len as u32;

                        // Init Output Token (Step 1)
                        let p_out = (*output_token).pvBuffer as *mut u32;
                        ptr::write_bytes(p_out, 0, 4); // Clear buffer
                        ptr::copy_nonoverlapping(b"GKSSP\0\0\0".as_ptr(), p_out as *mut u8, 8);
                        *p_out.add(2) = 3; // Version
                        *p_out.add(3) = 1; // Step
                        (*output_token).cbBuffer = 16;
                    }

                    session.flags |= 2; // Step 1 complete
                    *ph_new_context = handle;
                    return SEC_I_CONTINUE_NEEDED;
                }
            }
            SEC_E_INVALID_TOKEN
        } else {
            // --- Step 2 & 3 ---
            let sm_lock = self.base.session_manager.lock();
            if let Some(ref sm) = *sm_lock
                && let Some(gk_sm) = sm.as_any().downcast_ref::<GateKeeperSessionManager>()
                && let Some(session_arc) = gk_sm.get_session(ph_context)
            {
                let mut session = session_arc.lock();

                // 1. Process Input Token (Step 2)
                let input_token_res = unsafe { find_sec_buffer(p_input, SECBUFFER_TOKEN, 0) };
                if input_token_res.is_none() {
                    return SEC_E_INVALID_TOKEN;
                }
                let input_token = input_token_res.unwrap();

                unsafe {
                    let p_in = (*input_token).pvBuffer as *const u32;
                    let cb_in = (*input_token).cbBuffer;

                    if cb_in != 24 || (session.flags & 2) == 0 {
                        return SEC_E_INVALID_TOKEN;
                    }

                    // Verify Header
                    let mut magic = [0u8; 8];
                    ptr::copy_nonoverlapping(p_in as *const u8, magic.as_mut_ptr(), 8);
                    if &magic[0..5] != b"GKSSP" {
                        return SEC_E_INVALID_TOKEN;
                    }

                    let version = *p_in.add(2);
                    let step = *p_in.add(3);

                    let is_valid_version = if session.version_flag == 0 {
                        (3..=4).contains(&version)
                    } else {
                        (1..=4).contains(&version)
                    };

                    if !is_valid_version || step != 2 {
                        return SEC_E_INVALID_TOKEN;
                    }

                    // Save Server Nonce
                    ptr::copy_nonoverlapping(
                        p_in.add(4) as *const u8,
                        session.server_nonce.as_mut_ptr(),
                        8,
                    );
                    session.flags = (session.flags & !2) | 4; // Step 2 complete
                }

                // 2. Generate Output Token (Step 3)
                unsafe {
                    // Data = ServerNonce (8) + Hostname (cbHostname)
                    let mut data = Vec::with_capacity(8 + session.hostname_len as usize);
                    data.extend_from_slice(&session.server_nonce);
                    data.extend_from_slice(&session.hostname[..session.hostname_len as usize]);

                    // HMAC-MD5
                    type HmacMd5 = Hmac<Md5>;
                    let mut mac = HmacMd5::new_from_slice(&session.hmac_key)
                        .map_err(|_| SEC_E_INVALID_TOKEN)
                        .unwrap();
                    mac.update(&data);
                    let result = mac.finalize().into_bytes();
                    ptr::copy_nonoverlapping(result.as_ptr(), session.hmac_result.as_mut_ptr(), 16);

                    // Token layout (48 bytes): "GKSSP\0\0\0" (8) | Version (4) | Step (4) | HMAC (16) | GateKeeperID (16)
                    let p_out = (*output_token).pvBuffer as *mut u32;
                    ptr::write_bytes(p_out, 0, 12);
                    ptr::copy_nonoverlapping(b"GKSSP\0\0\0".as_ptr(), p_out as *mut u8, 8);
                    *p_out.add(2) = 3; // Version
                    *p_out.add(3) = 3; // Step 3
                    ptr::copy_nonoverlapping(
                        session.hmac_result.as_ptr(),
                        p_out.add(4) as *mut u8,
                        16,
                    );
                    ptr::copy_nonoverlapping(
                        &session.gatekeeper_id as *const _ as *const u8,
                        p_out.add(8) as *mut u8,
                        16,
                    );
                    (*output_token).cbBuffer = 48;
                }

                return SEC_E_OK;
            }
            SEC_E_INVALID_HANDLE
        }
    }

    fn query_context_attributes_a(
        &self,
        ph_context: &Handle,
        ul_attribute: u32,
        p_buffer: usize,
    ) -> SecurityStatus {
        use crate::base_provider::{
            SEC_E_INCOMPLETE_CREDENTIALS, SEC_E_INVALID_HANDLE, SEC_E_OK,
            SEC_E_UNSUPPORTED_FUNCTION,
        };
        use crate::gatekeeper_session_manager::GateKeeperSessionManager;

        if p_buffer == 0 {
            return SEC_E_UNSUPPORTED_FUNCTION;
        }

        let sm_lock = self.base.session_manager.lock();
        let session_arc = if let Some(ref sm) = *sm_lock {
            if let Some(gk_sm) = sm.as_any().downcast_ref::<GateKeeperSessionManager>() {
                gk_sm.get_session(ph_context)
            } else {
                None
            }
        } else {
            None
        };

        let s_arc = match session_arc {
            Some(arc) => arc,
            None => return SEC_E_INVALID_HANDLE,
        };

        let session = s_arc.lock();

        unsafe {
            match ul_attribute {
                SECPKG_ATTR_SIZES => {
                    let out = p_buffer as *mut SecPkgContext_Sizes;
                    (*out).cbMaxToken = self.base.max_token_size;
                    (*out).cbMaxSignature = 0;
                    (*out).cbBlockSize = 0;
                    (*out).cbSecurityTrailer = 0;
                    SEC_E_OK
                }
                SECPKG_ATTR_NAMES => {
                    use std::io::Write;

                    // Allocate 33 bytes for the string using Rust's standard allocator
                    let alloc_ptr = Box::into_raw(Box::new([0u8; 33])) as *mut u8;

                    let id = session.gatekeeper_id;

                    let mut buf =
                        std::io::Cursor::new(std::slice::from_raw_parts_mut(alloc_ptr, 33));
                    write!(buf, "{:08X}{:04X}{:04X}", id.data1, id.data2, id.data3).unwrap();
                    for &b in &id.data4 {
                        write!(buf, "{:02X}", b).unwrap();
                    }
                    *alloc_ptr.add(32) = 0;

                    let out = p_buffer as *mut SecPkgContext_NamesA;
                    (*out).sUserName = alloc_ptr as *mut i8;

                    if id.data1 == 0
                        && id.data2 == 0
                        && id.data3 == 0
                        && id.data4.iter().all(|&b| b == 0)
                    {
                        return SEC_E_INCOMPLETE_CREDENTIALS;
                    }
                    SEC_E_OK
                }
                SECPKG_ATTR_LIFESPAN => {
                    let out = p_buffer as *mut SecPkgContext_Lifespan;
                    (*out).tsStart = 0i64;
                    (*out).tsExpiry = i64::MAX;
                    SEC_E_OK
                }
                SECPKG_ATTR_PROTO_INFO => {
                    let out = p_buffer as *mut SecPkgContext_ProtoInfoA;
                    (*out).sProtocolName = std::ptr::null_mut();
                    (*out).majorVersion = session.version_flag as u32;
                    (*out).minorVersion = 0;
                    SEC_E_OK
                }
                _ => SEC_E_UNSUPPORTED_FUNCTION,
            }
        }
    }

    fn query_context_attributes_w(
        &self,
        ph_context: &Handle,
        ul_attribute: u32,
        p_buffer: usize,
    ) -> SecurityStatus {
        use crate::base_provider::{
            SEC_E_INCOMPLETE_CREDENTIALS, SEC_E_INVALID_HANDLE, SEC_E_OK,
            SEC_E_UNSUPPORTED_FUNCTION,
        };
        use crate::gatekeeper_session_manager::GateKeeperSessionManager;

        if p_buffer == 0 {
            return SEC_E_UNSUPPORTED_FUNCTION;
        }

        let sm_lock = self.base.session_manager.lock();
        let session_arc = if let Some(ref sm) = *sm_lock {
            if let Some(gk_sm) = sm.as_any().downcast_ref::<GateKeeperSessionManager>() {
                gk_sm.get_session(ph_context)
            } else {
                None
            }
        } else {
            None
        };

        let s_arc = match session_arc {
            Some(arc) => arc,
            None => return SEC_E_INVALID_HANDLE,
        };

        let session = s_arc.lock();

        unsafe {
            match ul_attribute {
                SECPKG_ATTR_SIZES => {
                    let out = p_buffer as *mut SecPkgContext_Sizes;
                    (*out).cbMaxToken = self.base.max_token_size;
                    (*out).cbMaxSignature = 0;
                    (*out).cbBlockSize = 0;
                    (*out).cbSecurityTrailer = 0;
                    SEC_E_OK
                }
                SECPKG_ATTR_NAMES => {
                    // SECPKG_ATTR_NAMES (Wide)
                    let alloc_ptr = Box::into_raw(Box::new([0u16; 33])) as *mut u16;

                    let id = session.gatekeeper_id;
                    let formatted_str = format!(
                        "{:08X}{:04X}{:04X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}",
                        id.data1,
                        id.data2,
                        id.data3,
                        id.data4[0],
                        id.data4[1],
                        id.data4[2],
                        id.data4[3],
                        id.data4[4],
                        id.data4[5],
                        id.data4[6],
                        id.data4[7]
                    );

                    for (i, c) in formatted_str.encode_utf16().enumerate() {
                        *alloc_ptr.add(i) = c;
                    }
                    *alloc_ptr.add(32) = 0; // Null terminator

                    let out = p_buffer as *mut SecPkgContext_NamesW;
                    (*out).sUserName = alloc_ptr;

                    if id.data1 == 0
                        && id.data2 == 0
                        && id.data3 == 0
                        && id.data4.iter().all(|&b| b == 0)
                    {
                        return SEC_E_INCOMPLETE_CREDENTIALS;
                    }
                    SEC_E_OK
                }
                SECPKG_ATTR_LIFESPAN => {
                    let out = p_buffer as *mut SecPkgContext_Lifespan;
                    (*out).tsStart = 0i64;
                    (*out).tsExpiry = i64::MAX;
                    SEC_E_OK
                }
                SECPKG_ATTR_PROTO_INFO => {
                    let out = p_buffer as *mut SecPkgContext_ProtoInfoW;
                    (*out).sProtocolName = std::ptr::null_mut();
                    (*out).majorVersion = session.version_flag as u32;
                    (*out).minorVersion = 0;
                    SEC_E_OK
                }
                _ => SEC_E_UNSUPPORTED_FUNCTION,
            }
        }
    }

    // Default delegation to base for common methods
    fn shutdown(&self) {
        self.base.shutdown()
    }
    fn enumerate_security_packages_a(
        &self,
        pc: &mut u32,
        pp: &mut Vec<SecPkgInfoA>,
    ) -> SecurityStatus {
        self.base.enumerate_security_packages_a(pc, pp)
    }
    fn enumerate_security_packages_w(
        &self,
        pc: &mut u32,
        pp: &mut Vec<SecPkgInfoW>,
    ) -> SecurityStatus {
        self.base.enumerate_security_packages_w(pc, pp)
    }
    fn acquire_credentials_handle_a(
        &self,
        p1: &str,
        p2: &str,
        p3: u32,
        p4: usize,
        p5: usize,
        p6: usize,
        p7: usize,
        p8: &mut Handle,
        p9: usize,
    ) -> SecurityStatus {
        self.base
            .acquire_credentials_handle_a(p1, p2, p3, p4, p5, p6, p7, p8, p9)
    }
    fn acquire_credentials_handle_w(
        &self,
        p1: &str,
        p2: &str,
        p3: u32,
        p4: usize,
        p5: usize,
        p6: usize,
        p7: usize,
        p8: &mut Handle,
        p9: usize,
    ) -> SecurityStatus {
        self.base
            .acquire_credentials_handle_w(p1, p2, p3, p4, p5, p6, p7, p8, p9)
    }
    fn delete_security_context(&self, h: &Handle) -> SecurityStatus {
        self.base.delete_security_context(h)
    }
    fn free_context_buffer(&self, b: usize) -> SecurityStatus {
        self.base.free_context_buffer(b)
    }
    fn free_credentials_handle(&self, h: &Handle) -> SecurityStatus {
        self.base.free_credentials_handle(h)
    }
    fn query_security_package_info_a(&self, n: &str, p: &mut usize) -> SecurityStatus {
        self.base.query_security_package_info_a(n, p)
    }
    fn query_security_package_info_w(&self, n: &str, p: &mut usize) -> SecurityStatus {
        self.base.query_security_package_info_w(n, p)
    }
}
