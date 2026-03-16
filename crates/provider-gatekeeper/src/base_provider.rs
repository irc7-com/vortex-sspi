use parking_lot::Mutex;
use std::ffi::CString;
use std::sync::Arc;
pub use windows_sys::Win32::{
    Foundation::{
        SEC_E_INSUFFICIENT_MEMORY, SEC_E_INVALID_HANDLE, SEC_E_INVALID_TOKEN, SEC_E_NOT_SUPPORTED,
        SEC_E_OK, SEC_E_TARGET_UNKNOWN, SEC_E_UNKNOWN_CREDENTIALS, SEC_E_UNSUPPORTED_FUNCTION,
        SEC_I_CONTINUE_NEEDED,
    },
    Security::Authentication::Identity::{
        SECBUFFER_PKG_PARAMS, SECBUFFER_TOKEN, SecBuffer, SecBufferDesc, SecPkgInfoA, SecPkgInfoW,
    },
};

pub type SecurityStatus = i32;

/// Utility to find a SecBuffer of a specific type in a SecBufferDesc.
/// Ported from sub_3723B953 (FindSecBuffer) in IDA.
pub unsafe fn find_sec_buffer(
    p_desc: usize,
    buffer_type: u32,
    index: u32,
) -> Option<*mut SecBuffer> {
    if p_desc == 0 {
        return None;
    }
    unsafe {
        let desc = &*(p_desc as *const SecBufferDesc);
        let mut current_index = 0;
        for i in 0..desc.cBuffers {
            let buffer = &*desc.pBuffers.add(i as usize);
            if buffer.BufferType == buffer_type {
                if current_index == index {
                    return Some(desc.pBuffers.add(i as usize));
                }
                current_index += 1;
            }
        }
    }
    None
}

/// Equivalent to Windows CredHandle / CtxtHandle
#[derive(Debug, Default, Clone, Copy, Eq, Hash, PartialEq)]
#[repr(C)]
pub struct Handle {
    pub lower: usize,
    pub upper: usize,
}

/// The VTable interface for all security providers.
pub use crate::session_manager::SessionManager;

pub trait SecurityProvider: Send + Sync {
    fn base(&self) -> &BaseProvider;
    fn initialize(&mut self) -> bool {
        false
    }
    fn shutdown(&self) {}
    fn create_session_manager(&self) -> Option<Box<dyn SessionManager>> {
        None
    }

    fn enumerate_security_packages_a(
        &self,
        _pc_packages: &mut u32,
        _pp_pkg_info: &mut Vec<SecPkgInfoA>,
    ) -> SecurityStatus {
        SEC_E_UNSUPPORTED_FUNCTION
    }

    fn enumerate_security_packages_w(
        &self,
        _pc_packages: &mut u32,
        _pp_pkg_info: &mut Vec<SecPkgInfoW>,
    ) -> SecurityStatus {
        SEC_E_UNSUPPORTED_FUNCTION
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
        SEC_E_UNSUPPORTED_FUNCTION
    }

    fn acquire_credentials_handle_a(
        &self,
        _psz_principal: &str,
        _psz_package: &str,
        _f_credential_use: u32,
        _pv_logon_id: usize,
        _p_auth_data: usize,
        _p_get_key_fn: usize,
        _pv_get_key_arg: usize,
        _ph_credential: &mut Handle,
        _pts_expiry: usize,
    ) -> SecurityStatus {
        SEC_E_UNSUPPORTED_FUNCTION
    }

    fn acquire_credentials_handle_w(
        &self,
        _psz_principal: &str,
        _psz_package: &str,
        _f_credential_use: u32,
        _pv_logon_id: usize,
        _p_auth_data: usize,
        _p_get_key_fn: usize,
        _pv_get_key_arg: usize,
        _ph_credential: &mut Handle,
        _pts_expiry: usize,
    ) -> SecurityStatus {
        SEC_E_UNSUPPORTED_FUNCTION
    }

    fn apply_control_token(&self, _ph_context: &Handle, _p_input: usize) -> SecurityStatus {
        SEC_E_UNSUPPORTED_FUNCTION
    }

    fn complete_auth_token(&self, _ph_context: &Handle, _p_token: usize) -> SecurityStatus {
        SEC_E_UNSUPPORTED_FUNCTION
    }

    fn delete_security_context(&self, _ph_context: &Handle) -> SecurityStatus {
        SEC_E_UNSUPPORTED_FUNCTION
    }

    fn free_context_buffer(&self, _pv_context_buffer: usize) -> SecurityStatus {
        SEC_E_UNSUPPORTED_FUNCTION
    }

    fn free_credentials_handle(&self, _ph_credential: &Handle) -> SecurityStatus {
        SEC_E_UNSUPPORTED_FUNCTION
    }

    fn impersonate_security_context(&self, _ph_context: &Handle) -> SecurityStatus {
        SEC_E_UNSUPPORTED_FUNCTION
    }

    fn initialize_security_context_a(
        &self,
        _ph_credential: &Handle,
        _ph_context: &Handle,
        _psz_target_name: &str,
        _f_context_req: u32,
        _reserved1: u32,
        _target_data_rep: u32,
        _p_input: usize,
        _reserved2: u32,
        _ph_new_context: &mut Handle,
        _p_output: usize,
        _pf_context_attr: &mut u32,
        _pts_expiry: usize,
    ) -> SecurityStatus {
        SEC_E_UNSUPPORTED_FUNCTION
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
        if !psz_target_name.is_empty() {
            SEC_E_TARGET_UNKNOWN
        } else {
            self.initialize_security_context_a(
                ph_credential,
                ph_context,
                "",
                f_context_req,
                reserved1,
                target_data_rep,
                p_input,
                reserved2,
                ph_new_context,
                p_output,
                pf_context_attr,
                pts_expiry,
            )
        }
    }

    fn make_signature(
        &self,
        _ph_context: &Handle,
        _f_qop: u32,
        _p_message: usize,
        _message_seq_num: u32,
    ) -> SecurityStatus {
        SEC_E_UNSUPPORTED_FUNCTION
    }

    fn query_context_attributes_a(
        &self,
        _ph_context: &Handle,
        _ul_attribute: u32,
        _p_buffer: usize,
    ) -> SecurityStatus {
        SEC_E_UNSUPPORTED_FUNCTION
    }

    fn query_context_attributes_w(
        &self,
        _ph_context: &Handle,
        _ul_attribute: u32,
        _p_buffer: usize,
    ) -> SecurityStatus {
        SEC_E_UNSUPPORTED_FUNCTION
    }

    fn query_security_package_info_a(
        &self,
        _psz_package_name: &str,
        _pp_pkg_info: &mut usize,
    ) -> SecurityStatus {
        SEC_E_UNSUPPORTED_FUNCTION
    }

    fn query_security_package_info_w(
        &self,
        _psz_package_name: &str,
        _pp_pkg_info: &mut usize,
    ) -> SecurityStatus {
        SEC_E_UNSUPPORTED_FUNCTION
    }

    fn revert_security_context(&self, _ph_context: &Handle) -> SecurityStatus {
        SEC_E_UNSUPPORTED_FUNCTION
    }

    fn verify_signature(
        &self,
        _ph_context: &Handle,
        _p_message: usize,
        _message_seq_num: u32,
        _pf_qop: &mut u32,
    ) -> SecurityStatus {
        SEC_E_UNSUPPORTED_FUNCTION
    }
}

/// Equivalent to CSecurityProvider C++ class.
pub struct BaseProvider {
    pub session_manager: Mutex<Option<Box<dyn SessionManager>>>, // offset 0x04
    pub lock: Arc<Mutex<()>>,                                    // offset 0x08 (24 bytes)
    pub provider_creds: Handle,                                  // offset 0x20 (8 bytes)
    pub capabilities: u32,                                       // offset 0x28
    pub pkg_info_ascii: SecPkgInfoA,                             // offset 0x2C (20 bytes)
    pub pkg_info_unicode: SecPkgInfoW,                           // offset 0x40 (20 bytes)
    // String storage — keeps CString/UTF-16 data alive for the raw pointers in SecPkgInfoA/W
    _name_a: CString,
    _comment_a: CString,
    _name_w: Vec<u16>,
    _comment_w: Vec<u16>,
    pub max_token_size: u32, // offset 0x64
}

// SecPkgInfoA/W contain raw pointers but our storage keeps them valid
unsafe impl Send for BaseProvider {}
unsafe impl Sync for BaseProvider {}

impl BaseProvider {
    pub fn new() -> Self {
        let empty_a = CString::new("").unwrap();
        let empty_w: Vec<u16> = vec![0];
        Self {
            session_manager: Mutex::new(None),
            lock: Arc::new(Mutex::new(())),
            provider_creds: Handle::default(),
            capabilities: 0,
            pkg_info_ascii: SecPkgInfoA {
                fCapabilities: 0,
                wVersion: 1,
                wRPCID: 0,
                cbMaxToken: 0,
                Name: empty_a.as_ptr() as *mut i8,
                Comment: empty_a.as_ptr() as *mut i8,
            },
            pkg_info_unicode: SecPkgInfoW {
                fCapabilities: 0,
                wVersion: 1,
                wRPCID: 0,
                cbMaxToken: 0,
                Name: empty_w.as_ptr() as *mut u16,
                Comment: empty_w.as_ptr() as *mut u16,
            },
            max_token_size: 0,
            _name_a: empty_a,
            _comment_a: CString::new("").unwrap(),
            _name_w: empty_w,
            _comment_w: vec![0],
        }
    }

    pub fn init_package_info(
        &mut self,
        capabilities: u32,
        max_token_size: u32,
        name_a: &str,
        comment_a: &str,
        name_w: Vec<u16>,
        comment_w: Vec<u16>,
    ) {
        self.capabilities = capabilities;
        self.max_token_size = max_token_size;

        // Allocate ASCII strings
        self._name_a = CString::new(name_a).unwrap();
        self._comment_a = CString::new(comment_a).unwrap();

        self.pkg_info_ascii = SecPkgInfoA {
            fCapabilities: capabilities,
            wVersion: 1,
            wRPCID: 0,
            cbMaxToken: max_token_size,
            Name: self._name_a.as_ptr() as *mut i8,
            Comment: self._comment_a.as_ptr() as *mut i8,
        };

        // Take ownership of the caller-encoded wide strings
        self._name_w = name_w;
        self._comment_w = comment_w;

        self.pkg_info_unicode = SecPkgInfoW {
            fCapabilities: capabilities,
            wVersion: 1,
            wRPCID: 0,
            cbMaxToken: max_token_size,
            Name: self._name_w.as_ptr() as *mut u16,
            Comment: self._comment_w.as_ptr() as *mut u16,
        };
    }

    pub fn initialize(provider: &mut dyn SecurityProvider) -> bool {
        let mut session_manager = provider.create_session_manager();
        let base = provider.base();
        if let Some(ref mut sm) = session_manager {
            if !sm.init() {
                sm.shutdown();
                *base.session_manager.lock() = None;
                return false;
            }
            *base.session_manager.lock() = session_manager;
        } else {
            *base.session_manager.lock() = None;
            return false;
        }
        true
    }
}

/// Implementation of the base class methods as seen in IDA.
impl SecurityProvider for BaseProvider {
    fn base(&self) -> &BaseProvider {
        self
    }
    /// CSecurityProvider::Initialize — calls CreateSessionManager via vtable,
    /// initializes it via SessionManager::init(), stores or clears on failure.
    fn initialize(&mut self) -> bool {
        BaseProvider::initialize(self)
    }
    fn shutdown(&self) {}
    fn create_session_manager(&self) -> Option<Box<dyn SessionManager>> {
        None
    }

    fn enumerate_security_packages_a(
        &self,
        pc_packages: &mut u32,
        pp_pkg_info: &mut Vec<SecPkgInfoA>,
    ) -> SecurityStatus {
        *pc_packages = 1;
        *pp_pkg_info = vec![self.pkg_info_ascii];
        SEC_E_OK
    }

    fn enumerate_security_packages_w(
        &self,
        pc_packages: &mut u32,
        pp_pkg_info: &mut Vec<SecPkgInfoW>,
    ) -> SecurityStatus {
        *pc_packages = 1;
        *pp_pkg_info = vec![self.pkg_info_unicode];
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

    fn acquire_credentials_handle_w(
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

    fn delete_security_context(&self, h: &Handle) -> SecurityStatus {
        let mut sm_lock = self.session_manager.lock();
        if let Some(sm) = sm_lock.as_mut() {
            sm.delete_context(h);
        }
        SEC_E_OK
    }

    fn free_context_buffer(&self, _: usize) -> SecurityStatus {
        SEC_E_OK
    }

    fn free_credentials_handle(&self, _: &Handle) -> SecurityStatus {
        SEC_E_OK
    }

    fn query_security_package_info_a(&self, _: &str, _: &mut usize) -> SecurityStatus {
        SEC_E_OK
    }

    fn query_security_package_info_w(&self, _: &str, _: &mut usize) -> SecurityStatus {
        SEC_E_OK
    }
}

impl BaseProvider {
    pub fn is_valid_credential_handle(&self, handle: &Handle) -> bool {
        handle.lower == self.provider_creds.lower && handle.upper == self.provider_creds.upper
    }
}
