use crate::base_provider::{
    BaseProvider, Handle, SEC_E_OK, SECBUFFER_TOKEN, SecBuffer, SecBufferDesc, SecPkgInfoA,
    SecPkgInfoW, SecurityProvider, SecurityStatus, SessionManager, find_sec_buffer,
};
use crate::ntlm::NtlmProvider;
use crate::passport::PassportProvider;
use crate::passport_session_managers::NtlmPassportSessionManager;
use std::ptr;
use std::sync::Arc;
use windows_sys::Win32::Security::Authentication::Identity::SECURITY_NATIVE_DREP;

/// Equivalent to CNTLMPassportProvider C++ class.
pub struct NtlmPassportProvider {
    pub base: BaseProvider,
    pub passport: Arc<PassportProvider>,
    pub ntlm: Arc<NtlmProvider>,
    pub passport_creds: Handle,
}

impl Default for NtlmPassportProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl NtlmPassportProvider {
    pub fn new() -> Self {
        Self {
            base: BaseProvider::new(),
            passport: Arc::new(PassportProvider::new()),
            ntlm: Arc::new(NtlmProvider::new()),
            passport_creds: Handle::default(),
        }
    }
}

impl SecurityProvider for NtlmPassportProvider {
    fn base(&self) -> &BaseProvider {
        &self.base
    }

    fn initialize(&mut self) -> bool {
        self.base.init_package_info(
            52,
            1024,
            "NTLMPassport",
            "NTLMPassport Security Package",
            w!("NTLMPassport"),
            w!("NTLMPassport Security Package"),
        );
        BaseProvider::initialize(self)
    }

    fn shutdown(&self) {}
    fn create_session_manager(&self) -> Option<Box<dyn SessionManager>> {
        Some(Box::new(NtlmPassportSessionManager::new()))
    }

    fn accept_security_context(
        &self,
        _: &Handle,
        _: &mut Handle,
        _: usize,
        _: u32,
        _: u32,
        _: &mut Handle,
        _: usize,
        _: &mut u32,
        _: usize,
    ) -> SecurityStatus {
        SEC_E_OK
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

    fn delete_security_context(&self, h: &Handle) -> SecurityStatus {
        let sm_lock = self.base.session_manager.lock();
        if let Some(sm) = sm_lock.as_ref()
            && let Some(ntlm_p_sm) = sm.as_any().downcast_ref::<NtlmPassportSessionManager>()
                && let Some(session_arc) = ntlm_p_sm.get_session(h) {
                    let session = session_arc.lock();
                    if session.sub_contexts[0].lower != 0 || session.sub_contexts[0].upper != 0 {
                        self.ntlm.delete_security_context(&session.sub_contexts[0]);
                    }
                    if session.sub_contexts[1].lower != 0 || session.sub_contexts[1].upper != 0 {
                        self.passport
                            .delete_security_context(&session.sub_contexts[1]);
                    }
                }
        self.passport.delete_security_context(h)
    }

    fn free_credentials_handle(&self, h: &Handle) -> SecurityStatus {
        self.base.free_credentials_handle(h)
    }

    fn impersonate_security_context(&self, h: &Handle) -> SecurityStatus {
        self.ntlm.impersonate_security_context(h)
    }

    fn initialize_security_context_a(
        &self,
        ph_credential: &Handle,
        ph_context: &Handle,
        psz_target_name: &str,
        f_context_req: u32,
        _reserved1: u32,
        target_data_rep: u32,
        p_input: usize,
        _reserved2: u32,
        ph_new_context: &mut Handle,
        p_output: usize,
        pf_context_attr: &mut u32,
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

        let mut sm_lock = self.base.session_manager.lock();
        let session_arc = if ph_context.lower != 0 || ph_context.upper != 0 {
            if let Some(sm) = sm_lock.as_ref() {
                if let Some(ntlm_p_sm) = sm.as_any().downcast_ref::<NtlmPassportSessionManager>() {
                    ntlm_p_sm
                        .get_session(ph_context)
                        .ok_or(SEC_E_INVALID_HANDLE)
                } else {
                    Err(SEC_E_INVALID_HANDLE)
                }
            } else {
                Err(SEC_E_INVALID_HANDLE)
            }
        } else {
            if unsafe { find_sec_buffer(p_output, SECBUFFER_TOKEN, 0) }.is_none() {
                return SEC_E_INVALID_TOKEN;
            }
            if let Some(sm) = sm_lock.as_mut() {
                if let Some(handle) = sm.create_context() {
                    if let Some(ntlm_p_sm) =
                        sm.as_any().downcast_ref::<NtlmPassportSessionManager>()
                    {
                        *ph_new_context = handle;
                        Ok(ntlm_p_sm.get_session(&handle).unwrap())
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
        let state = session.state;

        match state {
            160 => {
                // InitializeSecurityContextA Step 1
                if let Some(input_token) = unsafe { find_sec_buffer(p_input, SECBUFFER_TOKEN, 0) } {
                    unsafe {
                        let cb = (*input_token).cbBuffer as usize;
                        let pv = (*input_token).pvBuffer as *const u8;
                        session.saved_token.clear();
                        if !pv.is_null() && cb > 0 {
                            let mut buf = vec![0u8; cb];
                            ptr::copy_nonoverlapping(pv, buf.as_mut_ptr(), cb);
                            session.saved_token = buf;
                        }
                    }
                }

                let context_handle = session.sub_contexts[0];
                let res = self.ntlm.initialize_security_context_a(
                    ph_credential,
                    &context_handle,
                    psz_target_name,
                    f_context_req,
                    0,
                    SECURITY_NATIVE_DREP,
                    0, // No input token for Step 1
                    0,
                    &mut session.sub_contexts[0],
                    p_output,
                    pf_context_attr,
                    pts_expiry,
                );

                if res < 0 {
                    return res;
                }
                session.state = 161;
                SEC_I_CONTINUE_NEEDED
            }
            161 => {
                let input_token = unsafe { find_sec_buffer(p_input, SECBUFFER_TOKEN, 0) }
                    .ok_or(SEC_E_INVALID_TOKEN);
                let input_token = match input_token {
                    Ok(t) => t,
                    Err(e) => return e,
                };

                // Check if server responded with "OK"
                let is_ok = unsafe {
                    let cb = (*input_token).cbBuffer;
                    let pv = (*input_token).pvBuffer as *const u8;
                    cb == 2 && !pv.is_null() && *pv == b'O' && *pv.add(1) == b'K'
                };

                if is_ok {
                    // Switch to Passport
                    let mut p_params = [SecBuffer {
                        cbBuffer: session.saved_token.len() as u32,
                        BufferType: SECBUFFER_TOKEN,
                        pvBuffer: session.saved_token.as_mut_ptr() as *mut _,
                    }];
                    let p_desc = SecBufferDesc {
                        ulVersion: 0,
                        cBuffers: 1,
                        pBuffers: p_params.as_mut_ptr(),
                    };

                    let res = self.passport.initialize_security_context_a(
                        &self.passport_creds,
                        &Handle::default(),
                        "",
                        f_context_req,
                        0,
                        SECURITY_NATIVE_DREP,
                        &p_desc as *const _ as usize,
                        0,
                        &mut session.sub_contexts[1],
                        p_output,
                        pf_context_attr,
                        pts_expiry,
                    );

                    if res < 0 {
                        return res;
                    }
                    session.state = 163;
                    res
                } else {
                    // Continue NTLM
                    let context_handle = session.sub_contexts[0];
                    self.ntlm.initialize_security_context_a(
                        ph_credential,
                        &context_handle,
                        psz_target_name,
                        f_context_req,
                        0,
                        SECURITY_NATIVE_DREP,
                        p_input,
                        0,
                        &mut session.sub_contexts[0],
                        p_output,
                        pf_context_attr,
                        pts_expiry,
                    )
                }
            }
            163 => {
                // Continue Passport
                let context_handle = session.sub_contexts[1];
                self.passport.initialize_security_context_a(
                    &self.passport_creds,
                    &context_handle,
                    "",
                    f_context_req,
                    0,
                    SECURITY_NATIVE_DREP,
                    p_input,
                    0,
                    &mut session.sub_contexts[1],
                    p_output,
                    pf_context_attr,
                    pts_expiry,
                )
            }
            _ => pts_expiry as i32,
        }
    }

    fn make_signature(&self, h: &Handle, a: u32, b: usize, c: u32) -> SecurityStatus {
        self.ntlm.make_signature(h, a, b, c)
    }
    fn revert_security_context(&self, h: &Handle) -> SecurityStatus {
        self.ntlm.revert_security_context(h)
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
    fn free_context_buffer(&self, b: usize) -> SecurityStatus {
        self.base.free_context_buffer(b)
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
    fn query_context_attributes_w(&self, h: &Handle, a: u32, b: usize) -> SecurityStatus {
        self.base.query_context_attributes_w(h, a, b)
    }
    fn query_security_package_info_a(&self, n: &str, p: &mut usize) -> SecurityStatus {
        self.base.query_security_package_info_a(n, p)
    }
    fn query_security_package_info_w(&self, n: &str, p: &mut usize) -> SecurityStatus {
        self.base.query_security_package_info_w(n, p)
    }
}
