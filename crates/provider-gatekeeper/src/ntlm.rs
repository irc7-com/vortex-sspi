use crate::base_provider::{
    BaseProvider, Handle, SEC_E_OK, SEC_E_UNSUPPORTED_FUNCTION, SecPkgInfoA, SecPkgInfoW,
    SecurityProvider, SecurityStatus, SessionManager,
};
use std::ffi::CString;
use std::os::windows::ffi::OsStrExt;
use std::ffi::OsStr;
use windows_sys::Win32::Security::Authentication::Identity::{
    SecPkgInfoA as WinSecPkgInfoA, SecPkgInfoW as WinSecPkgInfoW, SecurityFunctionTableA,
    SecurityFunctionTableW,
};

/// Helper to convert Rust string to null-terminated UTF-16
fn to_wide(s: &str) -> Vec<u16> {
    OsStr::new(s).encode_wide().chain(std::iter::once(0)).collect()
}

/// Equivalent to CNTLMProvider C++ class.
pub struct NtlmProvider {
    pub base: BaseProvider,
    /// Handle to loaded secur32.dll / security.dll (HMODULE)
    pub security_dll: *mut std::ffi::c_void,
    /// Pointer to SecurityFunctionTableA
    pub security_interface_a: *const SecurityFunctionTableA,
    /// Pointer to SecurityFunctionTableW
    pub security_interface_w: *const SecurityFunctionTableW,
}

// SecurityFunctionTable is opaque pointer data; safe to send across threads
// when properly synchronized (which it is via the provider lock).
unsafe impl Send for NtlmProvider {}
unsafe impl Sync for NtlmProvider {}

impl Default for NtlmProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl NtlmProvider {
    pub fn new() -> Self {
        Self {
            base: BaseProvider::new(),
            security_dll: std::ptr::null_mut(),
            security_interface_a: std::ptr::null(),
            security_interface_w: std::ptr::null(),
        }
    }
}

impl SecurityProvider for NtlmProvider {
    fn base(&self) -> &BaseProvider {
        &self.base
    }

    /// CNTLMProvider::Initialize — loads secur32.dll or security.dll depending
    /// on the OS platform, then resolves InitSecurityInterfaceA and InitSecurityInterfaceW.
    fn initialize(&mut self) -> bool {
        use std::mem::size_of;
        use windows_sys::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryA};
        use windows_sys::Win32::System::SystemInformation::{GetVersionExA, OSVERSIONINFOA};

        unsafe extern "system" {
            fn FreeLibrary(hlibmodule: *mut std::ffi::c_void) -> i32;
        }

        let mut version_info: OSVERSIONINFOA = unsafe { std::mem::zeroed() };
        version_info.dwOSVersionInfoSize = size_of::<OSVERSIONINFOA>() as u32;

        unsafe {
            if GetVersionExA(&mut version_info) == 0 {
                return false;
            }

            // VER_PLATFORM_WIN32_WINDOWS (Win9x) = 1 → secur32.dll
            // VER_PLATFORM_WIN32_NT (NT-based)   = 2 → security.dll
            let dll_name = if version_info.dwPlatformId != 1 {
                b"security.dll\0".as_ptr()
            } else {
                b"secur32.dll\0".as_ptr()
            };

            let h_module = LoadLibraryA(dll_name);
            self.security_dll = h_module;

            if h_module.is_null() {
                return false;
            }

            let init_sec_fn_a = GetProcAddress(h_module, b"InitSecurityInterfaceA\0".as_ptr());
            let init_sec_fn_w = GetProcAddress(h_module, b"InitSecurityInterfaceW\0".as_ptr());

            if let (Some(init_a), Some(init_w)) = (init_sec_fn_a, init_sec_fn_w) {
                let init_sec_interface_a: extern "system" fn() -> *const SecurityFunctionTableA =
                    std::mem::transmute(init_a);
                let init_sec_interface_w: extern "system" fn() -> *const SecurityFunctionTableW =
                    std::mem::transmute(init_w);

                let p_table_a = init_sec_interface_a();
                let p_table_w = init_sec_interface_w();
                
                self.security_interface_a = p_table_a;
                self.security_interface_w = p_table_w;

                if p_table_a.is_null() || p_table_w.is_null() {
                    FreeLibrary(h_module);
                    return false;
                }

                true
            } else {
                FreeLibrary(h_module);
                false
            }
        }
    }

    /// CNTLMProvider::Shutdown — frees the loaded security DLL.
    fn shutdown(&self) {
        unsafe extern "system" {
            fn FreeLibrary(hlibmodule: *mut std::ffi::c_void) -> i32;
        }

        if !self.security_dll.is_null() {
            unsafe {
                FreeLibrary(self.security_dll);
            }
        }
    }

    // Delegate to base for CreateSessionManager
    fn create_session_manager(&self) -> Option<Box<dyn SessionManager>> {
        self.base.create_session_manager()
    }

    /// CNTLMProvider::EnumerateSecurityPackagesA — delegates to the system SSPI.
    fn enumerate_security_packages_a(
        &self,
        pc_packages: &mut u32,
        pp_pkg_info: &mut Vec<SecPkgInfoA>,
    ) -> SecurityStatus {
        if self.security_interface_a.is_null() {
            return SEC_E_UNSUPPORTED_FUNCTION;
        }
        unsafe {
            let table = &*self.security_interface_a;
            if let Some(func) = table.EnumerateSecurityPackagesA {
                let mut raw_count: u32 = 0;
                let mut raw_pkg_info: *mut WinSecPkgInfoA = std::ptr::null_mut();
                let status = func(&mut raw_count, &mut raw_pkg_info);
                if status == SEC_E_OK {
                    *pc_packages = raw_count;
                    let slice = std::slice::from_raw_parts(raw_pkg_info, raw_count as usize);
                    *pp_pkg_info = slice.to_vec();
                }
                status
            } else {
                SEC_E_UNSUPPORTED_FUNCTION
            }
        }
    }

    fn enumerate_security_packages_w(
        &self,
        pc_packages: &mut u32,
        pp_pkg_info: &mut Vec<SecPkgInfoW>,
    ) -> SecurityStatus {
        if self.security_interface_w.is_null() {
            return SEC_E_UNSUPPORTED_FUNCTION;
        }
        unsafe {
            let table = &*self.security_interface_w;
            if let Some(func) = table.EnumerateSecurityPackagesW {
                let mut raw_count: u32 = 0;
                let mut raw_pkg_info: *mut WinSecPkgInfoW = std::ptr::null_mut();
                let status = func(&mut raw_count, &mut raw_pkg_info);
                if status == SEC_E_OK {
                    *pc_packages = raw_count;
                    let slice = std::slice::from_raw_parts(raw_pkg_info, raw_count as usize);
                    *pp_pkg_info = slice.to_vec();
                }
                status
            } else {
                SEC_E_UNSUPPORTED_FUNCTION
            }
        }
    }

    /// CNTLMProvider::AcceptSecurityContext — delegates to the system SSPI.
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
        if self.security_interface_a.is_null() {
            return SEC_E_UNSUPPORTED_FUNCTION;
        }
        unsafe {
            let table = &*self.security_interface_a;
            if let Some(func) = table.AcceptSecurityContext {
                func(
                    ph_credential as *const Handle as *mut _,
                    // SSPI requires NULL phContext on the first call (new context)
                    if ph_context.lower == 0 && ph_context.upper == 0 {
                        std::ptr::null_mut()
                    } else {
                        ph_context as *mut Handle as *mut _
                    },
                    p_input as *mut _,
                    f_context_req,
                    target_data_rep,
                    ph_new_context as *mut Handle as *mut _,
                    p_output as *mut _,
                    pf_context_attr,
                    pts_expiry as *mut _,
                )
            } else {
                SEC_E_UNSUPPORTED_FUNCTION
            }
        }
    }

    /// CNTLMProvider::AcquireCredentialsHandleA — delegates to the system SSPI.
    fn acquire_credentials_handle_a(
        &self,
        psz_principal: &str,
        psz_package: &str,
        f_credential_use: u32,
        pv_logon_id: usize,
        p_auth_data: usize,
        p_get_key_fn: usize,
        pv_get_key_arg: usize,
        ph_credential: &mut Handle,
        pts_expiry: usize,
    ) -> SecurityStatus {
        if self.security_interface_a.is_null() {
            return SEC_E_UNSUPPORTED_FUNCTION;
        }
        // SSPI treats NULL pszPrincipal as "current user" — an empty string pointer is different.
        let c_principal = if psz_principal.is_empty() { None } else { CString::new(psz_principal).ok() };
        let c_package = CString::new(psz_package).unwrap_or_default();
        unsafe {
            let table = &*self.security_interface_a;
            if let Some(func) = table.AcquireCredentialsHandleA {
                func(
                    c_principal.as_ref().map_or(std::ptr::null_mut(), |s| s.as_ptr() as *mut _),
                    c_package.as_ptr() as *mut _,
                    f_credential_use,
                    pv_logon_id as *mut _,
                    p_auth_data as *mut _,
                    std::mem::transmute(p_get_key_fn),
                    pv_get_key_arg as *mut _,
                    ph_credential as *mut Handle as *mut _,
                    pts_expiry as *mut _,
                )
            } else {
                SEC_E_UNSUPPORTED_FUNCTION
            }
        }
    }

    fn acquire_credentials_handle_w(
        &self,
        psz_principal: &str,
        psz_package: &str,
        f_credential_use: u32,
        pv_logon_id: usize,
        p_auth_data: usize,
        p_get_key_fn: usize,
        pv_get_key_arg: usize,
        ph_credential: &mut Handle,
        pts_expiry: usize,
    ) -> SecurityStatus {
        if self.security_interface_w.is_null() {
            return SEC_E_UNSUPPORTED_FUNCTION;
        }
        let w_principal = if psz_principal.is_empty() { None } else { Some(to_wide(psz_principal)) };
        let w_package = to_wide(psz_package);
        unsafe {
            let table = &*self.security_interface_w;
            if let Some(func) = table.AcquireCredentialsHandleW {
                func(
                    w_principal.as_ref().map_or(std::ptr::null_mut(), |s| s.as_ptr() as *mut _),
                    w_package.as_ptr() as *mut _,
                    f_credential_use,
                    pv_logon_id as *mut _,
                    p_auth_data as *mut _,
                    std::mem::transmute(p_get_key_fn),
                    pv_get_key_arg as *mut _,
                    ph_credential as *mut Handle as *mut _,
                    pts_expiry as *mut _,
                )
            } else {
                SEC_E_UNSUPPORTED_FUNCTION
            }
        }
    }

    /// CNTLMProvider::ApplyControlToken — delegates to the system SSPI.
    fn apply_control_token(&self, ph_context: &Handle, p_input: usize) -> SecurityStatus {
        if self.security_interface_a.is_null() {
            return SEC_E_UNSUPPORTED_FUNCTION;
        }
        unsafe {
            let table = &*self.security_interface_a;
            if let Some(func) = table.ApplyControlToken {
                func(ph_context as *const Handle as *mut _, p_input as *mut _)
            } else {
                SEC_E_UNSUPPORTED_FUNCTION
            }
        }
    }

    /// CNTLMProvider::CompleteAuthToken — delegates to the system SSPI.
    fn complete_auth_token(&self, ph_context: &Handle, p_token: usize) -> SecurityStatus {
        if self.security_interface_a.is_null() {
            return SEC_E_UNSUPPORTED_FUNCTION;
        }
        unsafe {
            let table = &*self.security_interface_a;
            if let Some(func) = table.CompleteAuthToken {
                func(ph_context as *const Handle as *mut _, p_token as *mut _)
            } else {
                SEC_E_UNSUPPORTED_FUNCTION
            }
        }
    }

    /// CNTLMProvider::DeleteSecurityContext — delegates to the system SSPI.
    fn delete_security_context(&self, ph_context: &Handle) -> SecurityStatus {
        if self.security_interface_a.is_null() {
            return SEC_E_UNSUPPORTED_FUNCTION;
        }
        unsafe {
            let table = &*self.security_interface_a;
            if let Some(func) = table.DeleteSecurityContext {
                func(ph_context as *const Handle as *mut _)
            } else {
                SEC_E_UNSUPPORTED_FUNCTION
            }
        }
    }

    /// CNTLMProvider::FreeContextBuffer — delegates to the system SSPI.
    fn free_context_buffer(&self, pv_context_buffer: usize) -> SecurityStatus {
        if self.security_interface_a.is_null() {
            return SEC_E_UNSUPPORTED_FUNCTION;
        }
        unsafe {
            let table = &*self.security_interface_a;
            if let Some(func) = table.FreeContextBuffer {
                func(pv_context_buffer as *mut _)
            } else {
                SEC_E_UNSUPPORTED_FUNCTION
            }
        }
    }

    /// CNTLMProvider::FreeCredentialHandle — delegates to the system SSPI.
    fn free_credentials_handle(&self, ph_credential: &Handle) -> SecurityStatus {
        if self.security_interface_a.is_null() {
            return SEC_E_UNSUPPORTED_FUNCTION;
        }
        unsafe {
            let table = &*self.security_interface_a;
            if let Some(func) = table.FreeCredentialsHandle {
                func(ph_credential as *const Handle as *mut _)
            } else {
                SEC_E_UNSUPPORTED_FUNCTION
            }
        }
    }

    /// CNTLMProvider::ImpersonateSecurityContext — delegates to the system SSPI.
    fn impersonate_security_context(&self, ph_context: &Handle) -> SecurityStatus {
        if self.security_interface_a.is_null() {
            return SEC_E_UNSUPPORTED_FUNCTION;
        }
        unsafe {
            let table = &*self.security_interface_a;
            if let Some(func) = table.ImpersonateSecurityContext {
                func(ph_context as *const Handle as *mut _)
            } else {
                SEC_E_UNSUPPORTED_FUNCTION
            }
        }
    }

    /// CNTLMProvider::InitializeSecurityContextA — delegates to the system SSPI.
    fn initialize_security_context_a(
        &self,
        ph_credential: &Handle,
        ph_context: &Handle,
        psz_target_name: &str,
        f_context_req: u32,
        reserved1: u32,
        target_data_rep: u32,
        p_input: usize,
        reserved2: u32,
        ph_new_context: &mut Handle,
        p_output: usize,
        pf_context_attr: &mut u32,
        pts_expiry: usize,
    ) -> SecurityStatus {
        if self.security_interface_a.is_null() {
            return SEC_E_UNSUPPORTED_FUNCTION;
        }
        // SSPI treats NULL pszTargetName as local auth.
        let c_target = if psz_target_name.is_empty() { None } else { CString::new(psz_target_name).ok() };
        unsafe {
            let table = &*self.security_interface_a;
            if let Some(func) = table.InitializeSecurityContextA {
                func(
                    ph_credential as *const Handle as *mut _,
                    // SSPI requires NULL phContext on the first call (new context)
                    if ph_context.lower == 0 && ph_context.upper == 0 {
                        std::ptr::null_mut()
                    } else {
                        ph_context as *const Handle as *mut _
                    },
                    c_target.as_ref().map_or(std::ptr::null_mut(), |s| s.as_ptr() as *mut _),
                    f_context_req,
                    reserved1,
                    target_data_rep,
                    p_input as *mut _,
                    reserved2,
                    ph_new_context as *mut Handle as *mut _,
                    p_output as *mut _,
                    pf_context_attr,
                    pts_expiry as *mut _,
                )
            } else {
                SEC_E_UNSUPPORTED_FUNCTION
            }
        }
    }

    fn initialize_security_context_w(
        &self,
        ph_credential: &Handle,
        ph_context: &Handle,
        psz_target_name: &str,
        f_context_req: u32,
        reserved1: u32,
        target_data_rep: u32,
        p_input: usize,
        reserved2: u32,
        ph_new_context: &mut Handle,
        p_output: usize,
        pf_context_attr: &mut u32,
        pts_expiry: usize,
    ) -> SecurityStatus {
        if self.security_interface_w.is_null() {
            return SEC_E_UNSUPPORTED_FUNCTION;
        }
        let w_target = if psz_target_name.is_empty() { None } else { Some(to_wide(psz_target_name)) };
        unsafe {
            let table = &*self.security_interface_w;
            if let Some(func) = table.InitializeSecurityContextW {
                func(
                    ph_credential as *const Handle as *mut _,
                    // SSPI requires NULL phContext on the first call
                    if ph_context.lower == 0 && ph_context.upper == 0 {
                        std::ptr::null_mut()
                    } else {
                        ph_context as *const Handle as *mut _
                    },
                    w_target.as_ref().map_or(std::ptr::null_mut(), |s| s.as_ptr() as *mut _),
                    f_context_req,
                    reserved1,
                    target_data_rep,
                    p_input as *mut _,
                    reserved2,
                    ph_new_context as *mut Handle as *mut _,
                    p_output as *mut _,
                    pf_context_attr,
                    pts_expiry as *mut _,
                )
            } else {
                SEC_E_UNSUPPORTED_FUNCTION
            }
        }
    }

    /// CNTLMProvider::MakeSignature — delegates to the system SSPI.
    fn make_signature(
        &self,
        ph_context: &Handle,
        f_qop: u32,
        p_message: usize,
        message_seq_num: u32,
    ) -> SecurityStatus {
        if self.security_interface_a.is_null() {
            return SEC_E_UNSUPPORTED_FUNCTION;
        }
        unsafe {
            let table = &*self.security_interface_a;
            if let Some(func) = table.MakeSignature {
                func(
                    ph_context as *const Handle as *mut _,
                    f_qop,
                    p_message as *mut _,
                    message_seq_num,
                )
            } else {
                SEC_E_UNSUPPORTED_FUNCTION
            }
        }
    }

    /// CNTLMProvider::QueryContextAttributesA — delegates to the system SSPI.
    fn query_context_attributes_a(
        &self,
        ph_context: &Handle,
        ul_attribute: u32,
        p_buffer: usize,
    ) -> SecurityStatus {
        if self.security_interface_a.is_null() {
            return SEC_E_UNSUPPORTED_FUNCTION;
        }
        unsafe {
            let table = &*self.security_interface_a;
            if let Some(func) = table.QueryContextAttributesA {
                func(
                    ph_context as *const Handle as *mut _,
                    ul_attribute,
                    p_buffer as *mut _,
                )
            } else {
                SEC_E_UNSUPPORTED_FUNCTION
            }
        }
    }

    fn query_context_attributes_w(
        &self,
        ph_context: &Handle,
        ul_attribute: u32,
        p_buffer: usize,
    ) -> SecurityStatus {
        if self.security_interface_w.is_null() {
            return SEC_E_UNSUPPORTED_FUNCTION;
        }
        unsafe {
            let table = &*self.security_interface_w;
            if let Some(func) = table.QueryContextAttributesW {
                func(
                    ph_context as *const Handle as *mut _,
                    ul_attribute,
                    p_buffer as *mut _,
                )
            } else {
                SEC_E_UNSUPPORTED_FUNCTION
            }
        }
    }

    /// CNTLMProvider::QuerySecurityPackageInfoA — delegates to the system SSPI.
    fn query_security_package_info_a(
        &self,
        psz_package_name: &str,
        pp_pkg_info: &mut usize,
    ) -> SecurityStatus {
        if self.security_interface_a.is_null() {
            return SEC_E_UNSUPPORTED_FUNCTION;
        }
        let c_package = CString::new(psz_package_name).unwrap_or_default();
        unsafe {
            let table = &*self.security_interface_a;
            if let Some(func) = table.QuerySecurityPackageInfoA {
                func(
                    c_package.as_ptr() as *mut _,
                    pp_pkg_info as *mut usize as *mut *mut _,
                )
            } else {
                SEC_E_UNSUPPORTED_FUNCTION
            }
        }
    }

    fn query_security_package_info_w(
        &self,
        psz_package_name: &str,
        pp_pkg_info: &mut usize,
    ) -> SecurityStatus {
        if self.security_interface_w.is_null() {
            return SEC_E_UNSUPPORTED_FUNCTION;
        }
        let w_package = to_wide(psz_package_name);
        unsafe {
            let table = &*self.security_interface_w;
            if let Some(func) = table.QuerySecurityPackageInfoW {
                func(
                    w_package.as_ptr() as *mut _,
                    pp_pkg_info as *mut usize as *mut *mut _,
                )
            } else {
                SEC_E_UNSUPPORTED_FUNCTION
            }
        }
    }

    /// CNTLMProvider::RevertSecurityContext — delegates to the system SSPI.
    fn revert_security_context(&self, ph_context: &Handle) -> SecurityStatus {
        if self.security_interface_a.is_null() {
            return SEC_E_UNSUPPORTED_FUNCTION;
        }
        unsafe {
            let table = &*self.security_interface_a;
            if let Some(func) = table.RevertSecurityContext {
                func(ph_context as *const Handle as *mut _)
            } else {
                SEC_E_UNSUPPORTED_FUNCTION
            }
        }
    }

    /// CNTLMProvider::VerifySignature — delegates to the system SSPI.
    fn verify_signature(
        &self,
        ph_context: &Handle,
        p_message: usize,
        message_seq_num: u32,
        pf_qop: &mut u32,
    ) -> SecurityStatus {
        if self.security_interface_a.is_null() {
            return SEC_E_UNSUPPORTED_FUNCTION;
        }
        unsafe {
            let table = &*self.security_interface_a;
            if let Some(func) = table.VerifySignature {
                func(
                    ph_context as *const Handle as *mut _,
                    p_message as *mut _,
                    message_seq_num,
                    pf_qop,
                )
            } else {
                SEC_E_UNSUPPORTED_FUNCTION
            }
        }
    }
}
