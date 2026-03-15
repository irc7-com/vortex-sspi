//! # NTLM Server Authentication Provider
//!
//! FFI wrapper around the `sspi` crate's NTLM server-side authentication flow.
//! Exposes an opaque `NtlmProvider` to C#/.NET consumers through `extern "C"` functions.
//!
//! ## Authentication Flow
//!
//! 1. `ntlm_server_create()` — allocate provider
//! 2. `ntlm_server_parse_token()` with Type 1 → returns Type 2 challenge (`SEC_I_CONTINUE_NEEDED`)
//! 3. `ntlm_server_parse_token()` with Type 3 → parses message using SSPI (`SEC_E_OK`)
//! 4. `ntlm_server_get_identity()` — retrieve username/domain via SSPI
//! 5. `ntlm_server_verify()` — inject NT hash via `custom_set_auth_identity` and complete auth
//! 6. `ntlm_server_destroy()` — free provider

use md4::{Digest, Md4};
use sspi::{
    AuthIdentity, AuthIdentityBuffers, BufferType, CredentialUse, DataRepresentation, Ntlm,
    NtlmHash, SecurityBuffer, ServerRequestFlags, Sspi, SspiEx, SspiImpl,
};
use std::{ptr, slice};
use windows_sys::Win32::Foundation::{
    SEC_E_INTERNAL_ERROR, SEC_E_INVALID_HANDLE, SEC_E_INVALID_TOKEN, SEC_E_LOGON_DENIED, SEC_E_OK,
    SEC_I_CONTINUE_NEEDED,
};

// ─── Internal types ─────────────────────────────────────────────────────────

/// Opaque NTLM server authentication provider.
///
/// Manages the sspi `Ntlm` state machine and internal buffers.
/// Created via `ntlm_server_create`, destroyed via `ntlm_server_destroy`.
pub struct NtlmProvider {
    /// The sspi NTLM context.
    ntlm: Ntlm,
    /// Credentials handle generated during phase 1.
    credentials_handle: <Ntlm as SspiImpl>::CredentialsHandle,
    /// Internal output buffer for `accept_security_context` responses.
    output_buffer: Vec<SecurityBuffer>,
    /// UTF-16 strings caching `user`, `domain`, `workstation` for FFI pointers.
    /// Since the pointers must remain valid, we store the vectors here.
    identity_utf16: Option<(Vec<u16>, Vec<u16>, Vec<u16>)>,
}

impl NtlmProvider {
    /// Creates a new `NtlmProvider` with a fresh NTLM context.
    fn new() -> Self {
        Self {
            ntlm: Ntlm::new(),
            credentials_handle: None,
            output_buffer: vec![SecurityBuffer::new(Vec::new(), BufferType::Token)],
            identity_utf16: None,
        }
    }

    /// Processes an incoming NTLM token through `accept_security_context`.
    ///
    /// The `sspi::Ntlm` context automatically parses Type 1 and Type 3 messages.
    fn parse_token(&mut self, input: &[u8]) -> Result<i32, i32> {
        // Prepare input/output buffers for accept_security_context.
        let mut input_buffer = vec![SecurityBuffer::new(input.to_vec(), BufferType::Token)];
        self.output_buffer[0].buffer.clear();

        // If credentials handle is not yet acquired, acquire it without credentials
        if self.credentials_handle.is_none() {
            let acq_result = self
                .ntlm
                .acquire_credentials_handle()
                .with_credential_use(CredentialUse::Inbound)
                .execute(&mut self.ntlm)
                .map_err(|_| SEC_E_INTERNAL_ERROR)?;
            self.credentials_handle = acq_result.credentials_handle;
        }

        let builder = self
            .ntlm
            .accept_security_context()
            .with_credentials_handle(&mut self.credentials_handle)
            .with_context_requirements(ServerRequestFlags::ALLOCATE_MEMORY)
            .with_target_data_representation(DataRepresentation::Native)
            .with_input(&mut input_buffer)
            .with_output(&mut self.output_buffer);

        let result = self
            .ntlm
            .accept_security_context_impl(builder)
            .map_err(|_| SEC_E_INTERNAL_ERROR)?
            .resolve_to_result()
            .map_err(|_| SEC_E_INTERNAL_ERROR)?;

        match result.status {
            sspi::SecurityStatus::ContinueNeeded => Ok(SEC_I_CONTINUE_NEEDED),
            sspi::SecurityStatus::CompleteNeeded | sspi::SecurityStatus::Ok => {
                // Populate the identity cache from SSPI directly
                self.cache_identity_from_sspi()?;
                Ok(SEC_E_OK)
            }
            _ => Err(SEC_E_LOGON_DENIED),
        }
    }

    /// Queries the `ContextNames` from SSPI and caches it as UTF-16 vectors.
    fn cache_identity_from_sspi(&mut self) -> Result<(), i32> {
        let context_names = self
            .ntlm
            .query_context_names()
            .map_err(|_| SEC_E_INTERNAL_ERROR)?;

        let username = context_names
            .username
            .account_name()
            .encode_utf16()
            .collect();
        let domain = context_names
            .username
            .domain_name()
            .unwrap_or("")
            .encode_utf16()
            .collect();

        // sspi's NTLM implementation ignores workstation during Type 3, so we set it empty.
        let workstation = Vec::new();

        self.identity_utf16 = Some((username, domain, workstation));
        Ok(())
    }

    /// Performs cryptographic verification using the provided NT hash.
    ///
    /// Constructs an `AuthIdentityBuffers` with the injected NT hash and uses
    /// `SspiEx::custom_set_auth_identity` to inject it into the context before
    /// calling `complete_auth_token`.
    fn verify(&mut self, nt_hash: &[u8; 16]) -> i32 {
        let (username, domain) = match &self.identity_utf16 {
            Some((u, d, _)) => {
                let u_str = String::from_utf16(u).unwrap_or_default();
                let d_str = String::from_utf16(d).unwrap_or_default();
                (u_str, d_str)
            }
            None => return SEC_E_INVALID_HANDLE,
        };

        // Construct AuthIdentity with the provided NT hash
        let ntlm_hash = NtlmHash::from_bytes(*nt_hash);
        let buffers = AuthIdentityBuffers::from_utf8_with_hash(&username, &domain, &ntlm_hash);
        let auth_identity = match AuthIdentity::try_from(buffers) {
            Ok(aid) => aid,
            Err(_) => return SEC_E_INTERNAL_ERROR,
        };

        // Inject the credentials into the underlying SSPI context
        if self.ntlm.custom_set_auth_identity(auth_identity).is_err() {
            return SEC_E_INTERNAL_ERROR;
        }

        // Complete the authentication process which performs actual cryptographic verification
        match self.ntlm.complete_auth_token(&mut []) {
            Ok(sspi::SecurityStatus::Ok) => SEC_E_OK,
            _ => SEC_E_LOGON_DENIED,
        }
    }
}

// ─── FFI types ──────────────────────────────────────────────────────────────

/// C-compatible struct containing UTF-16 pointers to the extracted NTLM identity.
///
/// All pointers are owned by the `NtlmProvider` and remain valid until `ntlm_server_destroy`
/// is called. The C# consumer should copy the data if it needs to outlive the provider.
#[repr(C)]
pub struct NtlmIdentity {
    pub username: *const u16,
    pub username_len: u32,
    pub domain: *const u16,
    pub domain_len: u32,
    pub workstation: *const u16,
    pub workstation_len: u32,
}

// ─── FFI functions ──────────────────────────────────────────────────────────

/// Creates a new NTLM server authentication provider.
///
/// Returns an opaque handle to the provider. The caller must eventually call
/// `ntlm_server_destroy` to free the allocated memory.
#[unsafe(no_mangle)]
pub extern "C" fn ntlm_server_create() -> *mut NtlmProvider {
    Box::into_raw(Box::new(NtlmProvider::new()))
}

/// Processes an incoming NTLM token (Type 1 or Type 3) using SSPI.
///
/// # Parameters
/// - `handle`: Opaque provider handle from `ntlm_server_create`.
/// - `input_ptr`: Pointer to the incoming NTLM token bytes.
/// - `input_len`: Length of the incoming token in bytes.
/// - `out_ptr_ptr`: Receives a pointer to the output token data (Type 2 challenge).
///   The caller must NOT free this memory — it is owned by the provider.
/// - `out_len_ptr`: Receives the length of the output token in bytes.
///
/// # Returns
/// - `SEC_I_CONTINUE_NEEDED` (0x00090312): Type 1 processed, Type 2 challenge written.
/// - `SEC_E_OK` (0): Type 3 processed, identity ready for retrieval.
/// - `SEC_E_LOGON_DENIED`: Token rejected by SSPI.
///
/// # Safety
/// Requires `handle` to point to a valid `NtlmProvider` allocated by `ntlm_server_create`.
/// `input_ptr` must point to a valid byte slice of size `input_len`.
/// `out_ptr_ptr` and `out_len_ptr` must safely point to memory where pointers/lengths can be unmarshaled.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ntlm_server_parse_token(
    handle: *mut NtlmProvider,
    input_ptr: *const u8,
    input_len: u32,
    out_ptr_ptr: *mut *const u8,
    out_len_ptr: *mut u32,
) -> i32 {
    if handle.is_null() {
        return SEC_E_INVALID_HANDLE;
    }
    let provider = unsafe { &mut *handle };

    // Valid inputs only: empty tokens are mapped to SEC_E_INVALID_TOKEN by parse_token
    let input = if input_len > 0 && !input_ptr.is_null() {
        unsafe { std::slice::from_raw_parts(input_ptr, input_len as usize) }
    } else {
        return SEC_E_INVALID_TOKEN;
    };

    let status = match provider.parse_token(input) {
        Ok(s) => s,
        Err(e) => return e,
    };

    if !out_ptr_ptr.is_null() && !out_len_ptr.is_null() {
        let out_buf = &provider.output_buffer[0].buffer;
        unsafe {
            *out_ptr_ptr = out_buf.as_ptr();
            *out_len_ptr = out_buf.len() as u32;
        }
    }

    status
}

/// Retrieves the identity extracted from `query_context_names` after a Type 3 message.
///
/// Must be called after `ntlm_server_parse_token` has successfully processed a Type 3 message.
///
/// # Safety
/// Requires `handle` to point to a valid `NtlmProvider`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ntlm_server_get_identity(handle: *mut NtlmProvider) -> NtlmIdentity {
    if handle.is_null() {
        return NtlmIdentity {
            username: std::ptr::null(),
            username_len: 0,
            domain: std::ptr::null(),
            domain_len: 0,
            workstation: std::ptr::null(),
            workstation_len: 0,
        };
    }

    let provider = unsafe { &*handle };

    match &provider.identity_utf16 {
        Some((u, d, w)) => NtlmIdentity {
            username: u.as_ptr(),
            username_len: u.len() as u32,
            domain: d.as_ptr(),
            domain_len: d.len() as u32,
            workstation: w.as_ptr(),
            workstation_len: w.len() as u32,
        },
        None => NtlmIdentity {
            username: std::ptr::null(),
            username_len: 0,
            domain: std::ptr::null(),
            domain_len: 0,
            workstation: std::ptr::null(),
            workstation_len: 0,
        },
    }
}

/// Verifies the NTLM authentication using a provided 16-byte NT hash.
///
/// Uses `SspiEx::custom_set_auth_identity` to inject the NT hash into the SSPI context,
/// and validates the cryptographic exchange via `complete_auth_token`.
///
/// # Parameters
/// - `handle`: Opaque provider handle.
/// - `hash_ptr`: Pointer to a 16-byte NT hash (MD4 of the user's password).
///
/// # Safety
/// Requires `handle` to point to a valid `NtlmProvider`.
/// `hash_ptr` must be a valid, non-null pointer to at least 16 bytes of data.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ntlm_server_verify(handle: *mut NtlmProvider, hash_ptr: *const u8) -> i32 {
    if handle.is_null() || hash_ptr.is_null() {
        return SEC_E_INVALID_HANDLE;
    }

    let provider = unsafe { &mut *handle };
    let hash_slice = unsafe { std::slice::from_raw_parts(hash_ptr, 16) };

    let mut hash = [0u8; 16];
    hash.copy_from_slice(hash_slice);

    provider.verify(&hash)
}

/// Destroys the NTLM provider and frees all associated memory.
///
/// # Safety
/// Requires `handle` to be a valid pointer returned by `ntlm_server_create`.
/// If `handle` is null, the function does nothing.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ntlm_server_destroy(handle: *mut NtlmProvider) {
    if !handle.is_null() {
        unsafe {
            let _ = Box::from_raw(handle);
        }
    }
}

/// # Safety
/// - `out_hash` must be a valid pointer to at least 16 bytes.
/// - `password_utf16` must be a valid pointer to a null-terminated UTF-16 string.
///   Returns 0 on success, nonzero on error.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ntlm_hash_password(out_hash: *mut u8, password_utf16: *const u16) -> i32 {
    if out_hash.is_null() || password_utf16.is_null() {
        return SEC_E_INVALID_HANDLE;
    }

    // Find the length of the null-terminated UTF-16 string
    let mut len = 0;
    while unsafe { *password_utf16.add(len) } != 0 {
        len += 1;
    }

    // NTLM hash = MD4(UTF-16LE(PASSWORD))
    let password_slice = unsafe { slice::from_raw_parts(password_utf16, len) };
    let mut md4 = Md4::new();
    for &c in password_slice {
        md4.update(&c.to_le_bytes());
    }
    let hash = md4.finalize();

    // Write the hash to the output buffer
    unsafe { ptr::copy_nonoverlapping(hash.as_ptr(), out_hash, 16) };

    SEC_E_OK
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ntlm_hash_password() {
        let password: Vec<u16> = "password".encode_utf16().chain(std::iter::once(0)).collect();
        let mut hash = [0u8; 16];
        let res = unsafe { ntlm_hash_password(hash.as_mut_ptr(), password.as_ptr()) };
        assert_eq!(res, SEC_E_OK);

        let expected: [u8; 16] = [
            0x88, 0x46, 0xF7, 0xEA, 0xEE, 0x8F, 0xB1, 0x17, 0xAD, 0x06, 0xBD, 0xD8, 0x30, 0xB7, 0x58, 0x6C,
        ];
        assert_eq!(hash, expected);
    }
}
