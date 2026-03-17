use crate::base_provider::{
    BaseProvider, Handle, SEC_E_OK, SECBUFFER_PKG_PARAMS, SECBUFFER_TOKEN, SecBuffer,
    SecBufferDesc, SecPkgInfoA, SecPkgInfoW, SecurityProvider, SecurityStatus, SessionManager,
    find_sec_buffer,
};
use crate::gatekeeper::GateKeeperProvider;
use crate::passport::PassportProvider;
use crate::passport_session_managers::GateKeeperPassportSessionManager;
use std::ptr;
use std::sync::Arc;
use windows_sys::Win32::Security::Authentication::Identity::SECURITY_NATIVE_DREP;

/// Equivalent to CGateKeeperPassport C++ class.
pub struct GateKeeperPassportProvider {
    pub base: BaseProvider,
    pub passport: Arc<PassportProvider>,
    pub gatekeeper: Arc<GateKeeperProvider>,
    pub passport_creds: Handle,
    pub gatekeeper_creds: Handle,
}

impl Default for GateKeeperPassportProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl GateKeeperPassportProvider {
    pub fn new() -> Self {
        Self {
            base: BaseProvider::new(),
            passport: Arc::new(PassportProvider::new()),
            gatekeeper: Arc::new(GateKeeperProvider::new()),
            passport_creds: Handle::default(),
            gatekeeper_creds: Handle::default(),
        }
    }
}

impl SecurityProvider for GateKeeperPassportProvider {
    fn base(&self) -> &BaseProvider {
        &self.base
    }

    fn initialize(&mut self) -> bool {
        self.base.init_package_info(
            0x34,
            0x400,
            "GateKeeperPassport",
            "GateKeeperPassport Security Package",
            w!("GateKeeperPassport"),
            w!("GateKeeperPassport Security Package"),
        );

        // Match sub_3723D36D: Initialize sub-providers and acquire their credentials
        let mut passport = PassportProvider::new();
        if !passport.initialize() {
            return false;
        }
        passport.acquire_credentials_handle_a(
            "",
            "Passport",
            1,
            0,
            0,
            0,
            0,
            &mut self.passport_creds,
            0,
        );
        self.passport = Arc::new(passport);

        let mut gatekeeper = GateKeeperProvider::new();
        if !gatekeeper.initialize() {
            return false;
        }
        gatekeeper.acquire_credentials_handle_a(
            "",
            "GateKeeper",
            1,
            0,
            0,
            0,
            0,
            &mut self.gatekeeper_creds,
            0,
        );
        self.gatekeeper = Arc::new(gatekeeper);

        BaseProvider::initialize(self)
    }

    fn shutdown(&self) {
        self.gatekeeper.shutdown();
        self.passport.shutdown();
        self.base.shutdown();
    }

    fn create_session_manager(&self) -> Option<Box<dyn SessionManager>> {
        Some(Box::new(GateKeeperPassportSessionManager::new()))
    }

    fn acquire_credentials_handle_a(
        &self,
        _psz_principal: &str,
        psz_package: &str,
        f_credential_use: u32,
        pv_logon_id: usize,
        p_auth_data: usize,
        p_get_key_fn: usize,
        pv_get_key_arg: usize,
        ph_credential: &mut Handle,
        pts_expiry: usize,
    ) -> SecurityStatus {
        if psz_package != "GateKeeperPassport" {
            return crate::base_provider::SEC_E_SECPKG_NOT_FOUND;
        }

        let mut gk_cred = Box::new(Handle::default());
        let res = self.gatekeeper.acquire_credentials_handle_a(
            "", // original code passes NULL
            "GateKeeper",
            f_credential_use,
            pv_logon_id,
            p_auth_data,
            p_get_key_fn,
            pv_get_key_arg,
            &mut gk_cred,
            pts_expiry,
        );

        if res != crate::base_provider::SEC_E_OK {
            return res;
        }

        if f_credential_use == 0 || f_credential_use > 2 {
            return crate::base_provider::SEC_E_NOT_SUPPORTED;
        }

        ph_credential.upper = 0;
        ph_credential.lower = Box::into_raw(gk_cred) as usize;

        unsafe {
            let pts = pts_expiry as *mut u64;
            if !pts.is_null() {
                *pts = 0x0FFFFFFF_7FFFFFFF;
            }
        }

        crate::base_provider::SEC_E_OK
    }

    fn free_credentials_handle(&self, h: &Handle) -> SecurityStatus {
        if h.lower == 0 && h.upper == 0 {
            return crate::base_provider::SEC_E_INVALID_HANDLE;
        }

        let gk_cred_ptr = h.lower as *mut Handle;
        let res = self
            .gatekeeper
            .free_credentials_handle(unsafe { &*gk_cred_ptr });

        unsafe {
            let _ = Box::from_raw(gk_cred_ptr);
        }
        res
    }

    fn impersonate_security_context(&self, h: &Handle) -> SecurityStatus {
        let sm_lock = self.base.session_manager.lock();
        if let Some(sm) = sm_lock.as_ref()
            && let Some(gk_p_sm) = sm
                .as_any()
                .downcast_ref::<GateKeeperPassportSessionManager>()
            && let Some(session_arc) = gk_p_sm.get_session(h)
        {
            let session = session_arc.lock();
            return self
                .gatekeeper
                .impersonate_security_context(&session.sub_contexts[0]);
        }
        crate::base_provider::SEC_E_INVALID_HANDLE
    }

    fn revert_security_context(&self, h: &Handle) -> SecurityStatus {
        let sm_lock = self.base.session_manager.lock();
        if let Some(sm) = sm_lock.as_ref()
            && let Some(gk_p_sm) = sm
                .as_any()
                .downcast_ref::<GateKeeperPassportSessionManager>()
            && let Some(session_arc) = gk_p_sm.get_session(h)
        {
            let session = session_arc.lock();
            return self
                .gatekeeper
                .revert_security_context(&session.sub_contexts[0]);
        }
        crate::base_provider::SEC_E_INVALID_HANDLE
    }

    fn query_context_attributes_a(
        &self,
        h: &Handle,
        ul_attribute: u32,
        p_buffer: usize,
    ) -> SecurityStatus {
        let sm_lock = self.base.session_manager.lock();
        let session_arc = if let Some(sm) = sm_lock.as_ref() {
            if let Some(gk_p_sm) = sm
                .as_any()
                .downcast_ref::<GateKeeperPassportSessionManager>()
            {
                gk_p_sm.get_session(h)
            } else {
                None
            }
        } else {
            None
        };

        let session_arc = match session_arc {
            Some(arc) => arc,
            None => return crate::base_provider::SEC_E_INVALID_HANDLE,
        };

        let session = session_arc.lock();

        if ul_attribute == 0 {
            // Fallback to GateKeeper
            self.gatekeeper.query_context_attributes_a(
                &session.sub_contexts[0],
                ul_attribute,
                p_buffer,
            )
        } else if ul_attribute == 1 {
            // SECPKG_ATTR_NAMES
            self.passport
                .query_context_attributes_a(&session.sub_contexts[1], 1, p_buffer)
        } else if ul_attribute == 2 {
            // SECPKG_ATTR_LIFESPAN
            unsafe {
                let out = p_buffer as *mut u32;
                *out = 0;
                *out.add(1) = 0;
                *out.add(2) = 0x7FFFFFFF;
                *out.add(3) = 0x0FFFFFFF;
            }
            crate::base_provider::SEC_E_OK
        } else {
            crate::base_provider::SEC_E_UNSUPPORTED_FUNCTION
        }
    }

    fn query_context_attributes_w(
        &self,
        h: &Handle,
        ul_attribute: u32,
        p_buffer: usize,
    ) -> SecurityStatus {
        let sm_lock = self.base.session_manager.lock();
        let session_arc = if let Some(sm) = sm_lock.as_ref() {
            if let Some(gk_p_sm) = sm
                .as_any()
                .downcast_ref::<GateKeeperPassportSessionManager>()
            {
                gk_p_sm.get_session(h)
            } else {
                None
            }
        } else {
            None
        };

        let session_arc = match session_arc {
            Some(arc) => arc,
            None => return crate::base_provider::SEC_E_INVALID_HANDLE,
        };

        let session = session_arc.lock();

        if ul_attribute == 0 {
            // Fallback to GateKeeper
            self.gatekeeper.query_context_attributes_w(
                &session.sub_contexts[0],
                ul_attribute,
                p_buffer,
            )
        } else if ul_attribute == 1 {
            // SECPKG_ATTR_NAMES
            self.passport
                .query_context_attributes_w(&session.sub_contexts[1], 1, p_buffer)
        } else if ul_attribute == 2 {
            // SECPKG_ATTR_LIFESPAN
            unsafe {
                let out = p_buffer as *mut u32;
                *out = 0;
                *out.add(1) = 0;
                *out.add(2) = 0x7FFFFFFF;
                *out.add(3) = 0x0FFFFFFF;
            }
            crate::base_provider::SEC_E_OK
        } else {
            crate::base_provider::SEC_E_UNSUPPORTED_FUNCTION
        }
    }

    fn accept_security_context(
        &self,
        ph_credential: &Handle,
        ph_context: &mut Handle,
        p_input: usize,
        f_context_req: u32,
        target_data_rep: u32,
        ph_new_context: &mut Handle,
        p_output: usize,
        pf_context_attr: &mut u32,
        pts_expiry: usize,
    ) -> SecurityStatus {
        use crate::base_provider::{
            SEC_E_INVALID_HANDLE, SEC_E_INVALID_TOKEN, SEC_E_NOT_SUPPORTED,
            SEC_E_UNKNOWN_CREDENTIALS, SEC_I_CONTINUE_NEEDED,
        };

        if ph_credential.lower == 0 {
            return SEC_E_UNKNOWN_CREDENTIALS;
        }
        if target_data_rep != SECURITY_NATIVE_DREP {
            return SEC_E_NOT_SUPPORTED;
        }

        unsafe {
            let pts = pts_expiry as *mut u64;
            if !pts.is_null() {
                *pts = 0x0FFFFFFF_7FFFFFFF;
            }
        }

        let output_token_res = unsafe { find_sec_buffer(p_output, SECBUFFER_TOKEN, 0) };
        if output_token_res.is_none() {
            return SEC_E_INVALID_TOKEN;
        }
        let output_token = output_token_res.unwrap();
        let _max_length = unsafe { (*output_token).cbBuffer }; // unused but kept for parity

        let mut sm_lock = self.base.session_manager.lock();

        let session_arc = if ph_context.lower != 0 || ph_context.upper != 0 {
            if let Some(sm) = sm_lock.as_ref() {
                if let Some(gk_p_sm) = sm
                    .as_any()
                    .downcast_ref::<GateKeeperPassportSessionManager>()
                {
                    gk_p_sm.get_session(ph_context).ok_or(SEC_E_INVALID_HANDLE)
                } else {
                    Err(SEC_E_INVALID_HANDLE)
                }
            } else {
                Err(SEC_E_INVALID_HANDLE)
            }
        } else {
            if let Some(sm) = sm_lock.as_mut() {
                if let Some(handle) = sm.create_context() {
                    if let Some(gk_p_sm) = sm
                        .as_any()
                        .downcast_ref::<GateKeeperPassportSessionManager>()
                    {
                        *ph_new_context = handle;
                        Ok(gk_p_sm.get_session(&handle).unwrap())
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
        let gk_cred = unsafe { &*(ph_credential.lower as *const Handle) };

        match state {
            160 => {
                let context_handle = session.sub_contexts[0];
                let res = self.gatekeeper.accept_security_context(
                    gk_cred,
                    &mut context_handle.clone(),
                    p_input,
                    f_context_req,
                    target_data_rep,
                    &mut session.sub_contexts[0],
                    p_output,
                    pf_context_attr,
                    pts_expiry,
                );
                if res >= 0 {
                    session.state = 161;
                }
                res
            }
            161 => {
                let mut context_handle = session.sub_contexts[0];
                let res = self.gatekeeper.accept_security_context(
                    gk_cred,
                    &mut context_handle,
                    p_input,
                    f_context_req,
                    target_data_rep,
                    &mut session.sub_contexts[0],
                    p_output,
                    pf_context_attr,
                    pts_expiry,
                );
                if res == SEC_E_OK {
                    session.state = 162;
                    unsafe {
                        let out_ptr = (*output_token).pvBuffer as *mut u8;
                        std::ptr::copy_nonoverlapping(b"OK".as_ptr(), out_ptr, 2);
                        (*output_token).cbBuffer = 2;
                    }
                    SEC_I_CONTINUE_NEEDED // 0x90312 == 590610
                } else {
                    res
                }
            }
            162 => {
                // The client read our OK and sent the Passport Ticket.
                // We pass it to the Passport provider.
                let context_handle = session.sub_contexts[1];
                let res = self.passport.accept_security_context(
                    &self.passport_creds,
                    &mut context_handle.clone(),
                    p_input,
                    f_context_req,
                    target_data_rep,
                    &mut session.sub_contexts[1],
                    p_output, // Passport won't write an output token here
                    pf_context_attr,
                    pts_expiry,
                );
                if res == crate::base_provider::SEC_I_CONTINUE_NEEDED {
                    session.state = 163;
                }
                res
            }
            163 => {
                let mut context_handle = session.sub_contexts[1];
                self.passport.accept_security_context(
                    &self.passport_creds,
                    &mut context_handle,
                    p_input,
                    f_context_req,
                    target_data_rep,
                    &mut session.sub_contexts[1],
                    p_output,
                    pf_context_attr,
                    pts_expiry,
                )
            }
            _ => p_output as i32, // Odd fallback from IDA
        }
    }

    fn delete_security_context(&self, h: &Handle) -> SecurityStatus {
        let mut sm_lock = self.base.session_manager.lock();
        if let Some(sm) = sm_lock.as_mut() {
            if let Some(gk_p_sm) = sm
                .as_any()
                .downcast_ref::<GateKeeperPassportSessionManager>()
                && let Some(session_arc) = gk_p_sm.get_session(h)
            {
                let session = session_arc.lock();
                if session.state != 160 {
                    let _ = self
                        .gatekeeper
                        .delete_security_context(&session.sub_contexts[0]);
                }
                if session.state == 163 || session.state == 164 {
                    let _ = self
                        .passport
                        .delete_security_context(&session.sub_contexts[1]);
                }
            }
            sm.delete_context(h);
            return crate::base_provider::SEC_E_OK;
        }
        crate::base_provider::SEC_E_INVALID_HANDLE
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
            SEC_E_INVALID_HANDLE, SEC_E_INVALID_TOKEN, SEC_E_TARGET_UNKNOWN,
            SEC_E_UNKNOWN_CREDENTIALS, SEC_E_UNSUPPORTED_FUNCTION, SEC_I_CONTINUE_NEEDED,
        };

        if ph_credential.lower == 0 {
            return SEC_E_UNKNOWN_CREDENTIALS;
        }
        if !psz_target_name.is_empty() {
            return SEC_E_TARGET_UNKNOWN;
        }
        // IDA: TargetDataRep must be 16 (0x10)
        if target_data_rep != SECURITY_NATIVE_DREP {
            return SEC_E_UNSUPPORTED_FUNCTION;
        }

        unsafe {
            let pts = pts_expiry as *mut u64;
            if !pts.is_null() {
                *pts = 0x0FFFFFFF_7FFFFFFF;
            }
        }

        if unsafe { find_sec_buffer(p_output, SECBUFFER_TOKEN, 0) }.is_none() {
            return SEC_E_INVALID_TOKEN;
        }

        let input_token_opt = unsafe { find_sec_buffer(p_input, SECBUFFER_TOKEN, 0) };
        if input_token_opt.is_none() {
            return SEC_E_INVALID_TOKEN;
        }
        let input_token = input_token_opt.unwrap();

        let mut sm_lock = self.base.session_manager.lock();
        let session_arc = if ph_context.lower != 0 || ph_context.upper != 0 {
            if let Some(sm) = sm_lock.as_ref() {
                if let Some(gk_p_sm) = sm
                    .as_any()
                    .downcast_ref::<GateKeeperPassportSessionManager>()
                {
                    gk_p_sm.get_session(ph_context).ok_or(SEC_E_INVALID_HANDLE)
                } else {
                    Err(SEC_E_INVALID_HANDLE)
                }
            } else {
                Err(SEC_E_INVALID_HANDLE)
            }
        } else {
            if let Some(sm) = sm_lock.as_mut() {
                if let Some(handle) = sm.create_context() {
                    if let Some(gk_p_sm) = sm
                        .as_any()
                        .downcast_ref::<GateKeeperPassportSessionManager>()
                    {
                        *ph_new_context = handle;
                        Ok(gk_p_sm.get_session(&handle).unwrap())
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
                // InitializeSecurityContextA Step 1: Save User TOKEN and call GateKeeper
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

                // Match IDA: Expect exactly ONE PKG_PARAMS in Step 1
                let pkg_buffer_opt = unsafe { find_sec_buffer(p_input, SECBUFFER_PKG_PARAMS, 0) };
                if let Some(user_pkg) = pkg_buffer_opt {
                    // Forward to GateKeeper with: 16 bytes of zeros + User's PKG_PARAMS
                    let mut zeros = [0u8; 16];
                    let mut gk_params = [
                        SecBuffer {
                            cbBuffer: 16,
                            BufferType: SECBUFFER_PKG_PARAMS,
                            pvBuffer: zeros.as_mut_ptr() as *mut _,
                        },
                        SecBuffer {
                            cbBuffer: unsafe { (*user_pkg).cbBuffer },
                            BufferType: SECBUFFER_PKG_PARAMS,
                            pvBuffer: unsafe { (*user_pkg).pvBuffer },
                        },
                    ];
                    let gk_desc = SecBufferDesc {
                        ulVersion: 0,
                        cBuffers: 2,
                        pBuffers: gk_params.as_mut_ptr(),
                    };

                    let res = self.gatekeeper.initialize_security_context_a(
                        &self.gatekeeper_creds,
                        &Handle::default(),
                        "",
                        f_context_req,
                        0,
                        SECURITY_NATIVE_DREP,
                        &gk_desc as *const _ as usize,
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
                } else {
                    SEC_E_INVALID_TOKEN
                }
            }
            161 => {
                // Step 2: Check for "OK" to switch to Passport
                let is_ok = unsafe {
                    let cb = (*input_token).cbBuffer;
                    let pv = (*input_token).pvBuffer as *const u8;
                    cb == 2 && !pv.is_null() && *pv == b'O' && *pv.add(1) == b'K'
                };

                if is_ok {
                    // Switch to Passport using the SAVED token from Step 1
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
                    // Continue GateKeeper
                    let context_handle = session.sub_contexts[0];
                    self.gatekeeper.initialize_security_context_a(
                        &self.gatekeeper_creds,
                        &context_handle,
                        "",
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
                // Step 3: Continue Passport
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
    fn free_context_buffer(&self, b: usize) -> SecurityStatus {
        self.base.free_context_buffer(b)
    }

    fn query_security_package_info_a(&self, n: &str, p: &mut usize) -> SecurityStatus {
        self.base.query_security_package_info_a(n, p)
    }
    fn query_security_package_info_w(&self, n: &str, p: &mut usize) -> SecurityStatus {
        self.base.query_security_package_info_w(n, p)
    }
}
