use crate::base_provider::{
    BaseProvider, Handle, SEC_E_OK, SECBUFFER_TOKEN, SecurityProvider, SecurityStatus,
    SessionManager, find_sec_buffer,
};
use crate::passport_session_managers::PassportSessionManager;
use std::ptr;
use windows_sys::Win32::Security::Authentication::Identity::{
    SECURITY_NATIVE_DREP, SecPkgInfoA, SecPkgInfoW,
};

/// Equivalent to CPassportProvider C++ class.
pub struct PassportProvider {
    pub base: BaseProvider,
}

impl Default for PassportProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl PassportProvider {
    pub fn new() -> Self {
        Self {
            base: BaseProvider::new(),
        }
    }
}

impl SecurityProvider for PassportProvider {
    fn base(&self) -> &BaseProvider {
        &self.base
    }

    fn initialize(&mut self) -> bool {
        self.base.init_package_info(
            52,
            32, // Match IDA: 0x20
            "Passport",
            "Passport Security Package",
            w!("Passport"),
            w!("Passport Security Package"),
        );
        BaseProvider::initialize(self)
    }

    fn shutdown(&self) {}

    fn create_session_manager(&self) -> Option<Box<dyn SessionManager>> {
        Some(Box::new(PassportSessionManager::new()))
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
            SEC_E_INVALID_HANDLE, SEC_E_INVALID_TOKEN, SEC_E_UNKNOWN_CREDENTIALS,
            SEC_E_UNSUPPORTED_FUNCTION, SEC_I_CONTINUE_NEEDED,
        };

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

        let input_token_opt = unsafe { find_sec_buffer(p_input, SECBUFFER_TOKEN, 0) };
        if input_token_opt.is_none() {
            return SEC_E_INVALID_TOKEN;
        }
        let input_token = input_token_opt.unwrap();

        let output_token_opt = unsafe { find_sec_buffer(p_output, SECBUFFER_TOKEN, 0) };
        let is_first_call = ph_context.lower == 0 && ph_context.upper == 0;

        if is_first_call && output_token_opt.is_none() {
            return SEC_E_INVALID_TOKEN;
        }

        let mut sm_lock = self.base.session_manager.lock();
        let session_arc = if !is_first_call {
            if let Some(sm) = sm_lock.as_ref() {
                if let Some(p_sm) = sm.as_any().downcast_ref::<PassportSessionManager>() {
                    p_sm.get_session(ph_context).ok_or(SEC_E_INVALID_HANDLE)
                } else {
                    Err(SEC_E_INVALID_HANDLE)
                }
            } else {
                Err(SEC_E_INVALID_HANDLE)
            }
        } else {
            if let Some(sm) = sm_lock.as_mut() {
                if let Some(handle) = sm.create_context() {
                    if let Some(p_sm) = sm.as_any().downcast_ref::<PassportSessionManager>() {
                        *ph_new_context = handle;
                        Ok(p_sm.get_session(&handle).unwrap())
                    } else {
                        Err(SEC_E_INVALID_HANDLE)
                    }
                } else {
                    Err(SEC_E_INVALID_HANDLE)
                }
            } else {
                Err(SEC_E_INVALID_HANDLE)
            }
        };

        let session_arc = match session_arc {
            Ok(s) => s,
            Err(e) => return e,
        };

        let mut session = session_arc.lock();

        if is_first_call {
            let output_token = output_token_opt.unwrap();
            // Step 1: Fragment management
            unsafe {
                let input_len = (*input_token).cbBuffer as usize;
                let input_ptr = (*input_token).pvBuffer as *const u8;
                let output_cap = (*output_token).cbBuffer as usize;
                let output_ptr = (*output_token).pvBuffer as *mut u8;

                if input_len > 480 || input_len > output_cap {
                    let to_copy = 480.min(output_cap);
                    ptr::copy_nonoverlapping(input_ptr, output_ptr, to_copy);
                    (*output_token).cbBuffer = to_copy as u32;

                    if input_len > to_copy {
                        let remaining = input_len - to_copy;
                        session.buffer = vec![0u8; remaining];
                        if !input_ptr.is_null() {
                            ptr::copy_nonoverlapping(
                                input_ptr.add(to_copy),
                                session.buffer.as_mut_ptr(),
                                remaining,
                            );
                        }
                    }
                    session.is_done = false;
                } else {
                    ptr::copy_nonoverlapping(input_ptr, output_ptr, input_len);
                    (*output_token).cbBuffer = input_len as u32;
                    session.is_done = true;
                }
            }
            if session.is_done {
                unsafe {
                    let input_len = (*input_token).cbBuffer as usize;
                    let input_ptr = (*input_token).pvBuffer as *const u8;
                    let mut buf = vec![0u8; input_len.min(99)];
                    if input_len > 0 && !input_ptr.is_null() {
                        ptr::copy_nonoverlapping(input_ptr, buf.as_mut_ptr(), buf.len());
                    }
                    session.client_info = String::from_utf8_lossy(&buf).into_owned();
                }
                SEC_E_OK
            } else {
                SEC_I_CONTINUE_NEEDED
            }
        } else {
            // Step 2+
            if !session.buffer.is_empty() {
                if output_token_opt.is_none() {
                    return SEC_E_INVALID_TOKEN;
                }
                let output_token = output_token_opt.unwrap();
                // Return saved data
                unsafe {
                    let output_cap = (*output_token).cbBuffer as usize;
                    let output_ptr = (*output_token).pvBuffer as *mut u8;
                    let to_copy = session.buffer.len().min(output_cap);

                    ptr::copy_nonoverlapping(session.buffer.as_ptr(), output_ptr, to_copy);
                    (*output_token).cbBuffer = to_copy as u32;

                    // Remove copied part
                    session.buffer.drain(..to_copy);
                    if session.buffer.is_empty() {
                        session.is_done = true;
                    }
                }
                SEC_I_CONTINUE_NEEDED
            } else {
                // Final step: process input string
                if session.is_done {
                    // During accept_security_context, the input_token contains the passport ticket sent from the client
                    unsafe {
                        let input_len = (*input_token).cbBuffer as usize;
                        let input_ptr = (*input_token).pvBuffer as *const u8;
                        let mut buf = vec![0u8; input_len.min(99)];
                        if input_len > 0 && !input_ptr.is_null() {
                            ptr::copy_nonoverlapping(input_ptr, buf.as_mut_ptr(), buf.len());
                        }
                        session.client_info = String::from_utf8_lossy(&buf).into_owned();
                        if let Some(output_token) = output_token_opt {
                            (*output_token).cbBuffer = 0;
                        }
                    }
                    SEC_E_OK
                } else {
                    use crate::base_provider::SEC_E_LOGON_DENIED;
                    SEC_E_LOGON_DENIED
                }
            }
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
            SEC_E_INVALID_HANDLE, SEC_E_INVALID_TOKEN, SEC_E_TARGET_UNKNOWN,
            SEC_E_UNKNOWN_CREDENTIALS, SEC_E_UNSUPPORTED_FUNCTION, SEC_I_CONTINUE_NEEDED,
        };

        if !self.base.is_valid_credential_handle(ph_credential) {
            return SEC_E_UNKNOWN_CREDENTIALS;
        }
        if !psz_target_name.is_empty() {
            return SEC_E_TARGET_UNKNOWN;
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

        let input_token_opt = unsafe { find_sec_buffer(p_input, SECBUFFER_TOKEN, 0) };
        if input_token_opt.is_none() {
            return SEC_E_INVALID_TOKEN;
        }
        let _input_token = input_token_opt.unwrap();

        let output_token_opt = unsafe { find_sec_buffer(p_output, SECBUFFER_TOKEN, 0) };
        if output_token_opt.is_none() {
            return SEC_E_INVALID_TOKEN;
        }
        let output_token = output_token_opt.unwrap();

        let mut sm_lock = self.base.session_manager.lock();
        let session_arc = if ph_context.lower != 0 || ph_context.upper != 0 {
            if let Some(sm) = sm_lock.as_ref() {
                if let Some(p_sm) = sm.as_any().downcast_ref::<PassportSessionManager>() {
                    p_sm.get_session(ph_context).ok_or(SEC_E_INVALID_HANDLE)
                } else {
                    Err(SEC_E_INVALID_HANDLE)
                }
            } else {
                Err(SEC_E_INVALID_HANDLE)
            }
        } else {
            if let Some(sm) = sm_lock.as_mut() {
                if let Some(handle) = sm.create_context() {
                    if let Some(p_sm) = sm.as_any().downcast_ref::<PassportSessionManager>() {
                        *ph_new_context = handle;
                        Ok(p_sm.get_session(&handle).unwrap())
                    } else {
                        Err(SEC_E_INVALID_HANDLE)
                    }
                } else {
                    Err(SEC_E_INVALID_HANDLE)
                }
            } else {
                Err(SEC_E_INVALID_HANDLE)
            }
        };

        let session_arc = match session_arc {
            Ok(s) => s,
            Err(e) => return e,
        };

        let mut session = session_arc.lock();

        if ph_context.lower == 0 && ph_context.upper == 0 {
            // For initialize_security_context (Client), we just write the passport ticket and mark done
            unsafe {
                let passport_ticket = b"00000016PassportTicket00000017PassportProfile";
                let output_cap = (*output_token).cbBuffer as usize;
                let output_ptr = (*output_token).pvBuffer as *mut u8;

                let to_copy = passport_ticket.len().min(output_cap);
                ptr::copy_nonoverlapping(passport_ticket.as_ptr(), output_ptr, to_copy);
                (*output_token).cbBuffer = to_copy as u32;
                session.is_done = true;
            }
            SEC_I_CONTINUE_NEEDED // The client needs to send this token to the server
        } else if session.is_done {
            use crate::base_provider::SEC_E_OK;
            if let Some(output_token) = output_token_opt {
                unsafe {
                    (*output_token).cbBuffer = 0;
                }
            }
            SEC_E_OK
        } else {
            use crate::base_provider::SEC_E_LOGON_DENIED;
            SEC_E_LOGON_DENIED
        }
    }

    fn query_context_attributes_a(
        &self,
        ph_context: &Handle,
        ul_attribute: u32,
        p_buffer: usize,
    ) -> SecurityStatus {
        use crate::base_provider::{SEC_E_INVALID_HANDLE, SEC_E_NOT_SUPPORTED};
        use windows_sys::Win32::Security::Authentication::Identity::{
            SECPKG_ATTR_LIFESPAN, SECPKG_ATTR_NAMES, SECPKG_ATTR_SIZES, SecPkgContext_Lifespan,
            SecPkgContext_NamesA, SecPkgContext_Sizes,
        };

        let sm_lock = self.base.session_manager.lock();
        let session = if let Some(sm) = sm_lock.as_ref() {
            if let Some(p_sm) = sm.as_any().downcast_ref::<PassportSessionManager>() {
                p_sm.get_session(ph_context)
            } else {
                None
            }
        } else {
            None
        };

        if session.is_none() {
            println!(
                "Passport Query: Invalid handle (session not found for handle {:?}",
                ph_context
            );
            return SEC_E_INVALID_HANDLE;
        }

        let session = session.unwrap();

        match ul_attribute {
            SECPKG_ATTR_NAMES => {
                let info = session.lock();
                if info.client_info.is_empty() {
                    println!("Passport Query: Invalid handle (client_info is empty)");
                    return SEC_E_INVALID_HANDLE;
                }

                // We need to allocate memory for the string that SSPI owns until FreeContextBuffer is called.
                // We'll allocate via a leaked Box representing a null-terminated C string.
                if let Ok(c_str) = std::ffi::CString::new(info.client_info.clone()) {
                    let ptr = c_str.into_raw();
                    unsafe {
                        let names_desc = p_buffer as *mut SecPkgContext_NamesA;
                        (*names_desc).sUserName = ptr as *mut i8;
                    }
                    SEC_E_OK
                } else {
                    println!(
                        "Passport Query: Invalid handle (failed to allocate string for names desc)"
                    );
                    SEC_E_INVALID_HANDLE
                }
            }
            SECPKG_ATTR_LIFESPAN => {
                unsafe {
                    let lifespan = p_buffer as *mut SecPkgContext_Lifespan;
                    (*lifespan).tsStart = 0;
                    (*lifespan).tsExpiry = 0x0FFFFFFF_7FFFFFFF;
                }
                SEC_E_OK
            }
            SECPKG_ATTR_SIZES => {
                unsafe {
                    let sizes = p_buffer as *mut SecPkgContext_Sizes;
                    (*sizes).cbMaxToken = 32;
                    (*sizes).cbMaxSignature = 0;
                    (*sizes).cbBlockSize = 0;
                    (*sizes).cbSecurityTrailer = 0;
                }
                SEC_E_OK
            }
            _ => SEC_E_NOT_SUPPORTED,
        }
    }

    fn query_context_attributes_w(
        &self,
        ph_context: &Handle,
        ul_attribute: u32,
        p_buffer: usize,
    ) -> SecurityStatus {
        use crate::base_provider::{SEC_E_INVALID_HANDLE, SEC_E_NOT_SUPPORTED};
        use windows_sys::Win32::Security::Authentication::Identity::{
            SECPKG_ATTR_LIFESPAN, SECPKG_ATTR_NAMES, SECPKG_ATTR_SIZES, SecPkgContext_Lifespan,
            SecPkgContext_NamesW, SecPkgContext_Sizes,
        };

        let sm_lock = self.base.session_manager.lock();
        let session = if let Some(sm) = sm_lock.as_ref() {
            if let Some(p_sm) = sm.as_any().downcast_ref::<PassportSessionManager>() {
                p_sm.get_session(ph_context)
            } else {
                None
            }
        } else {
            None
        };

        if session.is_none() {
            return SEC_E_INVALID_HANDLE;
        }

        let session = session.unwrap();

        match ul_attribute {
            SECPKG_ATTR_NAMES => {
                let info = session.lock();
                if info.client_info.is_empty() {
                    return SEC_E_INVALID_HANDLE;
                }

                // Convert to UTF-16 wide string
                let mut wide: Vec<u16> = info.client_info.encode_utf16().collect();
                wide.push(0); // null terminator

                let boxed_slice = wide.into_boxed_slice();
                let ptr = Box::into_raw(boxed_slice) as *mut u16;
                unsafe {
                    let names_desc = p_buffer as *mut SecPkgContext_NamesW;
                    (*names_desc).sUserName = ptr;
                }
                SEC_E_OK
            }
            SECPKG_ATTR_LIFESPAN => {
                unsafe {
                    let lifespan = p_buffer as *mut SecPkgContext_Lifespan;
                    (*lifespan).tsStart = 0;
                    (*lifespan).tsExpiry = 0x0FFFFFFF_7FFFFFFF;
                }
                SEC_E_OK
            }
            SECPKG_ATTR_SIZES => {
                unsafe {
                    let sizes = p_buffer as *mut SecPkgContext_Sizes;
                    (*sizes).cbMaxToken = 32;
                    (*sizes).cbMaxSignature = 0;
                    (*sizes).cbBlockSize = 0;
                    (*sizes).cbSecurityTrailer = 0;
                }
                SEC_E_OK
            }
            _ => SEC_E_NOT_SUPPORTED,
        }
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
        // If the caller allocated a pointer via SECPKG_ATTR_NAMES, we need to free it here
        if b != 0 {
            unsafe {
                // FreeContextBuffer accepts both ASCII and Wide strings, we determine how to free based
                // on if it's the A or W version of SECPKG_ATTR_NAMES. Since both A and W point to heap memory
                // allocated via Rust, we can simply reconstruct and drop a Box slice. It's unsafe to know if
                // it's an ASCII or WIDE string, but SSPI applications usually always use Wide or always ASCII.
                // We'll try dropping it as an array to prevent memory leaks from happening.
                // Ideally SSPI tracks this natively via `LsaFreeReturnBuffer`, but we are mimicking it here.
                let _ = Box::from_raw(b as *mut u8);
            }
        }
        SEC_E_OK
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
