use crate::base_provider::{
    BaseProvider, Handle, SEC_E_OK, SecPkgInfoA, SecurityProvider, SecurityStatus, SessionManager,
};

/// Equivalent to CNTLMProvider C++ class.
pub struct NtlmProvider {
    pub base: BaseProvider,
    /// Handle to loaded secur32.dll / security.dll
    pub security_dll: usize,
    /// Pointer to PSecurityFunctionTableA
    pub security_interface: usize,
}

impl Default for NtlmProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl NtlmProvider {
    pub fn new() -> Self {
        Self {
            base: BaseProvider::new(),
            security_dll: 0,
            security_interface: 0,
        }
    }
}

impl SecurityProvider for NtlmProvider {
    fn base(&self) -> &BaseProvider {
        &self.base
    }

    fn initialize(&mut self) -> bool {
        true
    }

    fn shutdown(&self) {}

    // Delegate to base for CreateSessionManager
    fn create_session_manager(&self) -> Option<Box<dyn SessionManager>> {
        self.base.create_session_manager()
    }

    fn enumerate_security_packages_a(
        &self,
        _pc_packages: &mut u32,
        _pp_pkg_info: &mut Vec<SecPkgInfoA>,
    ) -> SecurityStatus {
        SEC_E_OK
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
        _: &str,
        _: &str,
        _: u32,
        _: usize,
        _: usize,
        _: usize,
        _: usize,
        _: &mut Handle,
        _: usize,
    ) -> SecurityStatus {
        SEC_E_OK
    }
    fn apply_control_token(&self, _: &Handle, _: usize) -> SecurityStatus {
        SEC_E_OK
    }
    fn complete_auth_token(&self, _: &Handle, _: usize) -> SecurityStatus {
        SEC_E_OK
    }
    fn delete_security_context(&self, _: &Handle) -> SecurityStatus {
        SEC_E_OK
    }
    fn free_context_buffer(&self, _: usize) -> SecurityStatus {
        SEC_E_OK
    }
    fn free_credentials_handle(&self, _: &Handle) -> SecurityStatus {
        SEC_E_OK
    }
    fn impersonate_security_context(&self, _: &Handle) -> SecurityStatus {
        SEC_E_OK
    }
    fn initialize_security_context_a(
        &self,
        _: &Handle,
        _: &Handle,
        _: &str,
        _: u32,
        _: u32,
        _: u32,
        _: usize,
        _: u32,
        _: &mut Handle,
        _: usize,
        _: &mut u32,
        _: usize,
    ) -> SecurityStatus {
        SEC_E_OK
    }
    fn make_signature(&self, _: &Handle, _: u32, _: usize, _: u32) -> SecurityStatus {
        SEC_E_OK
    }
    fn query_context_attributes_a(&self, _: &Handle, _: u32, _: usize) -> SecurityStatus {
        SEC_E_OK
    }
    fn query_security_package_info_a(&self, _: &str, _: &mut usize) -> SecurityStatus {
        SEC_E_OK
    }
    fn revert_security_context(&self, _: &Handle) -> SecurityStatus {
        SEC_E_OK
    }
    fn verify_signature(&self, _: &Handle, _: usize, _: u32, _: &mut u32) -> SecurityStatus {
        SEC_E_OK
    }
}
