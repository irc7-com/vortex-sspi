use windows_sys::Win32::Security::Authentication::Identity::SECURITY_NATIVE_DREP;

use crate::base_provider::{
    BaseProvider, Handle, SEC_E_OK, SecPkgInfoA, SecPkgInfoW, SecurityProvider, SecurityStatus,
    SessionManager,
};
use crate::gatekeeper_session_manager::GateKeeperSessionManager;

/// Equivalent to CGateKeeperProvider C++ class.
pub struct GateKeeperProvider {
    pub base: BaseProvider,
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
        self.base.initialize()
    }

    fn create_session_manager(&self) -> Option<Box<dyn SessionManager>> {
        Some(Box::new(GateKeeperSessionManager::new()))
    }

    fn accept_security_context(
        &self,
        _ph_credential: &Handle,
        _ph_context: &mut Handle,
        _p_input: usize,
        _f_context_req: u32,
        _target_data_rep: u32,
        _ph_new_context: &mut Handle,
        _p_output: usize,
        _pf_context_attr: &mut u32,
        _pts_expiry: usize,
    ) -> SecurityStatus {
        SEC_E_OK
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
                if let Some(ref mut sm) = *sm_lock {
                    if let Some(handle) = sm.create_context() {
                        if let Some(gk_sm) = sm.as_any().downcast_ref::<GateKeeperSessionManager>() {
                            if let Some(session_arc) = gk_sm.get_session(&handle) {
                                let mut session = session_arc.lock();

                                unsafe {
                                    // Fill GateKeeperID (GUID)
                                    let p_guid = (*pb0).pvBuffer as *const u8;
                                    ptr::copy_nonoverlapping(p_guid, session.gatekeeper_id.as_mut_ptr(), 16);

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
                                    ptr::copy_nonoverlapping("GKSSP\0\0\0".as_ptr(), p_out as *mut u8, 8);
                                    *p_out.add(2) = 3; // Version
                                    *p_out.add(3) = 1; // Step
                                    (*output_token).cbBuffer = 16;
                                }

                                session.flags |= 2; // Step 1 complete
                                *ph_new_context = handle;
                                return SEC_I_CONTINUE_NEEDED;
                            }
                        }
                    }
                }
            }
            return SEC_E_INVALID_TOKEN;
        } else {
            // --- Step 2 & 3 ---
            let sm_lock = self.base.session_manager.lock();
            if let Some(ref sm) = *sm_lock {
                if let Some(gk_sm) = sm.as_any().downcast_ref::<GateKeeperSessionManager>() {
                    if let Some(session_arc) = gk_sm.get_session(ph_context) {
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

                            if version < 3 || step != 2 {
                                return SEC_E_INVALID_TOKEN;
                            }

                            // Save Server Nonce
                            ptr::copy_nonoverlapping(p_in.add(4) as *const u8, session.server_nonce.as_mut_ptr(), 8);
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
                            let mut mac = HmacMd5::new_from_slice(&session.hmac_key).map_err(|_| SEC_E_INVALID_TOKEN).unwrap();
                            mac.update(&data);
                            let result = mac.finalize().into_bytes();
                            ptr::copy_nonoverlapping(result.as_ptr(), session.hmac_result.as_mut_ptr(), 16);

                            // Token layout (48 bytes): "GKSSP\0\0\0" (8) | Version (4) | Step (4) | HMAC (16) | GateKeeperID (16)
                            let p_out = (*output_token).pvBuffer as *mut u32;
                            ptr::write_bytes(p_out, 0, 12);
                            ptr::copy_nonoverlapping("GKSSP\0\0\0".as_ptr(), p_out as *mut u8, 8);
                            *p_out.add(2) = 3; // Version
                            *p_out.add(3) = 3; // Step 3
                            ptr::copy_nonoverlapping(session.hmac_result.as_ptr(), p_out.add(4) as *mut u8, 16);
                            ptr::copy_nonoverlapping(session.gatekeeper_id.as_ptr(), p_out.add(8) as *mut u8, 16);
                            (*output_token).cbBuffer = 48;
                        }

                        return SEC_E_OK;
                    }
                }
            }
            return SEC_E_INVALID_HANDLE;
        }
    }

    fn query_context_attributes_a(
        &self,
        _ph_context: &Handle,
        _ul_attribute: u32,
        _p_buffer: usize,
    ) -> SecurityStatus {
        SEC_E_OK
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
    fn initialize_security_context_w(
        &self,
        p1: &Handle,
        p2: &Handle,
        p3: &str,
        p4: u32,
        p5: u32,
        p6: u32,
        p7: usize,
        p8: u32,
        p9: &mut Handle,
        p10: usize,
        p11: &mut u32,
        p12: usize,
    ) -> SecurityStatus {
        self.base
            .initialize_security_context_w(p1, p2, p3, p4, p5, p6, p7, p8, p9, p10, p11, p12)
    }
    fn query_security_package_info_a(&self, n: &str, p: &mut usize) -> SecurityStatus {
        self.base.query_security_package_info_a(n, p)
    }
    fn query_security_package_info_w(&self, n: &str, p: &mut usize) -> SecurityStatus {
        self.base.query_security_package_info_w(n, p)
    }
}
