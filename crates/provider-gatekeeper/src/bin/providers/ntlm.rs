use provider_gatekeeper::base_provider::{
    SEC_E_OK, SEC_I_CONTINUE_NEEDED, SECBUFFER_TOKEN, SecBuffer, SecBufferDesc,
};
use provider_gatekeeper::{Handle, NtlmProvider, SecurityProvider};
use windows_sys::Win32::Security::Authentication::Identity::SECURITY_NATIVE_DREP;

use crate::utils::{enumerate_and_print_packages, hexdump, query_and_print_context_attributes};

/// This binary demonstrates the SSPI handshake process for the NTLM provider.
/// It simulates a full client/server NTLM authentication flow by using
/// InitializeSecurityContext (client) and AcceptSecurityContext (server)
/// in a loop until SEC_E_OK or an error is returned.
pub fn main() {
    let mut ntlm = NtlmProvider::new();
    if !ntlm.initialize() {
        eprintln!("Failed to initialize NTLM provider.");
        return;
    }

    println!("╔══════════════════════════════════════════╗");
    println!("║       NTLM Provider Handshake Demo       ║");
    println!("╚══════════════════════════════════════════╝");

    // --- Package Enumeration Phase ---
    enumerate_and_print_packages(&ntlm);

    // --- Acquire Credentials ---
    println!("\n=== Acquiring Credentials ===");
    let mut client_cred = Handle::default();
    let mut server_cred = Handle::default();
    let mut ts_expiry: i64 = 0;

    let result = ntlm.acquire_credentials_handle_a(
        "",     // pszPrincipal (NULL = current user)
        "NTLM", // pszPackage
        2,      // SECPKG_CRED_OUTBOUND (client initiator)
        0,      // pvLogonId
        0,      // pAuthData
        0,      // pGetKeyFn
        0,      // pvGetKeyArgument
        &mut client_cred,
        &mut ts_expiry as *mut i64 as usize,
    );

    if result != SEC_E_OK {
        eprintln!("AcquireCredentialsHandleA failed: {:#x}", result);
        return;
    }
    println!(
        "  Client credentials acquired: {:#x}:{:#x}",
        client_cred.lower, client_cred.upper
    );

    // Get a separate credential handle for the server side
    let result = ntlm.acquire_credentials_handle_a(
        "",     // pszPrincipal
        "NTLM", // pszPackage
        1,      // SECPKG_CRED_INBOUND (server acceptor)
        0,      // pvLogonId
        0,      // pAuthData
        0,      // pGetKeyFn
        0,      // pvGetKeyArgument
        &mut server_cred,
        &mut ts_expiry as *mut i64 as usize,
    );

    if result != SEC_E_OK {
        eprintln!("AcquireCredentialsHandleA (server) failed: {:#x}", result);
        return;
    }
    println!(
        "  Server credentials acquired: {:#x}:{:#x}",
        server_cred.lower, server_cred.upper
    );

    // --- ISC / ASC Loop ---
    // NTLM handshake works as follows:
    //   1. Client ISC (no input)       → Type 1 (Negotiate) message
    //   2. Server ASC (Type 1 input)   → Type 2 (Challenge) message
    //   3. Client ISC (Type 2 input)   → Type 3 (Authenticate) message
    //   4. Server ASC (Type 3 input)   → SEC_E_OK (authentication complete)

    let max_token_size: usize = 4096;
    let mut isc_out_token = vec![0u8; max_token_size];
    let mut asc_out_token = vec![0u8; max_token_size];

    let mut client_ctx_new = Handle::default();
    let mut server_ctx_new = Handle::default();
    let mut pf_context_attr: u32 = 0;

    let mut round = 0u32;
    #[allow(unused_assignments)]
    let mut isc_status: i32 = SEC_I_CONTINUE_NEEDED;
    let mut asc_status: i32 = SEC_I_CONTINUE_NEEDED;

    // Track the server's last output length for the next ISC input
    let mut last_server_output_len: u32 = 0;
    let mut first_isc = true;
    let mut first_asc = true;

    loop {
        round += 1;

        // ===== Client: InitializeSecurityContext =====
        println!(
            "\n=== ISC Round {} (Client → Type {}) ===",
            round,
            if round == 1 { 1 } else { 3 }
        );

        // Prepare input from server's last output (if any)
        let mut isc_in_buffers = [SecBuffer {
            cbBuffer: last_server_output_len,
            BufferType: SECBUFFER_TOKEN,
            pvBuffer: asc_out_token.as_mut_ptr() as *mut _,
        }];
        let isc_input_desc = SecBufferDesc {
            ulVersion: 0,
            cBuffers: 1,
            pBuffers: isc_in_buffers.as_mut_ptr(),
        };

        let isc_input = if first_isc {
            0usize // No input on first call
        } else {
            &isc_input_desc as *const _ as usize
        };

        // Prepare output buffer
        isc_out_token.fill(0);
        let mut isc_out_buffers = [SecBuffer {
            cbBuffer: max_token_size as u32,
            BufferType: SECBUFFER_TOKEN,
            pvBuffer: isc_out_token.as_mut_ptr() as *mut _,
        }];
        let mut isc_output_desc = SecBufferDesc {
            ulVersion: 0,
            cBuffers: 1,
            pBuffers: isc_out_buffers.as_mut_ptr(),
        };

        let ctx_for_isc = if first_isc {
            Handle::default()
        } else {
            client_ctx_new
        };

        isc_status = ntlm.initialize_security_context_a(
            &client_cred,
            &ctx_for_isc,
            "",
            0,
            0,
            SECURITY_NATIVE_DREP,
            isc_input,
            0,
            &mut client_ctx_new,
            &mut isc_output_desc as *mut _ as usize,
            &mut pf_context_attr,
            &mut ts_expiry as *mut i64 as usize,
        );

        first_isc = false;
        let isc_output_len = isc_out_buffers[0].cbBuffer;

        println!("  ISC returned: {:#x}", isc_status);
        if isc_output_len > 0 {
            println!("  Client output token ({} bytes):", isc_output_len);
            hexdump(&isc_out_token[..isc_output_len as usize]);
        }

        if isc_status != SEC_E_OK && isc_status != SEC_I_CONTINUE_NEEDED {
            eprintln!("  ISC failed with error: {:#x}", isc_status);
            break;
        }

        // If both sides are done, we're finished
        if isc_status == SEC_E_OK && asc_status == SEC_E_OK {
            println!("\n✓ Both client and server report SEC_E_OK. Handshake complete!");
            break;
        }

        // ===== Server: AcceptSecurityContext =====
        println!(
            "\n=== ASC Round {} (Server → Type {}) ===",
            round,
            round * 2
        );

        let mut asc_in_buffers = [SecBuffer {
            cbBuffer: isc_output_len,
            BufferType: SECBUFFER_TOKEN,
            pvBuffer: isc_out_token.as_mut_ptr() as *mut _,
        }];
        let asc_input_desc = SecBufferDesc {
            ulVersion: 0,
            cBuffers: 1,
            pBuffers: asc_in_buffers.as_mut_ptr(),
        };

        asc_out_token.fill(0);
        let mut asc_out_buffers = [SecBuffer {
            cbBuffer: max_token_size as u32,
            BufferType: SECBUFFER_TOKEN,
            pvBuffer: asc_out_token.as_mut_ptr() as *mut _,
        }];
        let mut asc_output_desc = SecBufferDesc {
            ulVersion: 0,
            cBuffers: 1,
            pBuffers: asc_out_buffers.as_mut_ptr(),
        };

        let mut ctx_for_asc = if first_asc {
            Handle::default()
        } else {
            server_ctx_new
        };

        asc_status = ntlm.accept_security_context(
            &server_cred,
            &mut ctx_for_asc,
            &asc_input_desc as *const _ as usize,
            0,
            SECURITY_NATIVE_DREP,
            &mut server_ctx_new,
            &mut asc_output_desc as *mut _ as usize,
            &mut pf_context_attr,
            &mut ts_expiry as *mut i64 as usize,
        );

        first_asc = false;
        last_server_output_len = asc_out_buffers[0].cbBuffer;

        println!("  ASC returned: {:#x}", asc_status);
        if last_server_output_len > 0 {
            println!("  Server output token ({} bytes):", last_server_output_len);
            hexdump(&asc_out_token[..last_server_output_len as usize]);
        }

        if asc_status != SEC_E_OK && asc_status != SEC_I_CONTINUE_NEEDED {
            eprintln!("  ASC failed with error: {:#x}", asc_status);
            break;
        }

        if asc_status == SEC_E_OK && last_server_output_len == 0 {
            println!("\n✓ Server returned SEC_E_OK with no output. Handshake complete!");
            break;
        }

        if asc_status == SEC_E_OK && isc_status == SEC_E_OK {
            println!("\n✓ Both client and server report SEC_E_OK. Handshake complete!");
            break;
        }

        // Safety: prevent infinite loops
        if round > 10 {
            eprintln!("Too many rounds — something is wrong.");
            break;
        }
    }

    // --- Query Context Attributes ---
    if isc_status == SEC_E_OK || asc_status == SEC_E_OK {
        println!("\n=== Querying Client Context Attributes ===");
        query_and_print_context_attributes(&ntlm, &client_ctx_new);

        println!("\n=== Querying Server Context Attributes ===");
        query_and_print_context_attributes(&ntlm, &server_ctx_new);
    }

    // --- Cleanup ---
    ntlm.delete_security_context(&client_ctx_new);
    ntlm.delete_security_context(&server_ctx_new);
    ntlm.free_credentials_handle(&client_cred);
    ntlm.free_credentials_handle(&server_cred);
    ntlm.shutdown();

    println!("\nNTLM handshake demo complete.");
}
