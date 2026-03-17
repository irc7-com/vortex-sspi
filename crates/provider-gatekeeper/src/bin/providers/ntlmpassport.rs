use provider_gatekeeper::base_provider::{
    SEC_E_OK, SEC_I_CONTINUE_NEEDED, SECBUFFER_TOKEN, SecBuffer, SecBufferDesc,
};
use provider_gatekeeper::{Handle, NtlmPassportProvider, SecurityProvider};
use windows_sys::Win32::Security::Authentication::Identity::SECURITY_NATIVE_DREP;

use crate::utils::{enumerate_and_print_packages, hexdump, query_and_print_context_attributes};

/// This binary demonstrates the SSPI handshake process for the NTLMPassport hybrid provider.
/// It simulates a full client/server authentication flow, handling the NTLM phases
/// and automatically transitioning to the Passport phase.
pub fn main() {
    let mut ntlmpass = NtlmPassportProvider::new();
    if !ntlmpass.initialize() {
        eprintln!("Failed to initialize NTLMPassport provider.");
        return;
    }

    println!("╔══════════════════════════════════════════╗");
    println!("║   NTLMPassport Provider Handshake Demo   ║");
    println!("╚══════════════════════════════════════════╝");

    // --- Package Enumeration Phase ---
    enumerate_and_print_packages(&ntlmpass);

    // --- Acquire Credentials ---
    println!("\n=== Acquiring Credentials ===");
    let mut client_cred = Handle::default();
    let mut server_cred = Handle::default();
    let mut ts_expiry: i64 = 0;

    let result = ntlmpass.acquire_credentials_handle_a(
        "",             // pszPrincipal (NULL = current user)
        "NTLMPassport", // pszPackage
        2,              // SECPKG_CRED_OUTBOUND (client initiator)
        0,              // pvLogonId
        0,              // pAuthData
        0,              // pGetKeyFn
        0,              // pvGetKeyArgument
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

    let result = ntlmpass.acquire_credentials_handle_a(
        "",             // pszPrincipal
        "NTLMPassport", // pszPackage
        1,              // SECPKG_CRED_INBOUND (server acceptor)
        0,              // pvLogonId
        0,              // pAuthData
        0,              // pGetKeyFn
        0,              // pvGetKeyArgument
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
    let max_token_size: usize = 4096;
    let mut isc_out_token = vec![0u8; max_token_size];
    let mut asc_out_token = vec![0u8; max_token_size];

    let mut client_ctx_new = Handle::default();
    let mut server_ctx_new = Handle::default();
    let mut pf_context_attr: u32 = 0;

    let mut round = 0u32;
    #[allow(unused_assignments)]
    let mut isc_status: i32 = SEC_I_CONTINUE_NEEDED;

    // The hybrid provider needs the PassportTicket and Profile on round 1 of ISC
    let passportticket_and_passportprofile =
        b"00000016PassportTicket00000017PassportProfile".to_vec();

    let mut last_server_output_len: u32 = 0;
    let mut first_isc = true;
    let mut first_asc = true;

    loop {
        round += 1;

        // ===== Client: InitializeSecurityContext =====
        println!("\n=== ISC Round {} (Client) ===", round);

        let mut isc_in_buffers = [SecBuffer {
            cbBuffer: if first_isc {
                passportticket_and_passportprofile.len() as u32
            } else {
                last_server_output_len
            },
            BufferType: SECBUFFER_TOKEN,
            pvBuffer: if first_isc {
                passportticket_and_passportprofile.as_ptr() as *mut _
            } else {
                asc_out_token.as_mut_ptr() as *mut _
            },
        }];
        let isc_input_desc = SecBufferDesc {
            ulVersion: 0,
            cBuffers: 1,
            pBuffers: isc_in_buffers.as_mut_ptr(),
        };

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
            client_ctx_new.clone()
        };

        isc_status = ntlmpass.initialize_security_context_a(
            &client_cred,
            &ctx_for_isc,
            "",
            0,
            0,
            SECURITY_NATIVE_DREP,
            &isc_input_desc as *const _ as usize, // Input token is always provided (passport payload on round 1)
            0,
            &mut client_ctx_new,
            &mut isc_output_desc as *mut _ as usize,
            &mut pf_context_attr,
            &mut ts_expiry as *mut i64 as usize,
        );

        println!("  ISC returned: {:#x}", isc_status);

        let isc_cb = isc_out_buffers[0].cbBuffer as usize;
        if isc_cb > 0 {
            if isc_status != SEC_E_OK {
                println!("  Client output token ({} bytes):", isc_cb);
                hexdump(&isc_out_token[..isc_cb]);
            }
        } else {
            println!("  Client output token (0 bytes)");
        }

        if isc_status != SEC_I_CONTINUE_NEEDED && isc_status != SEC_E_OK {
            println!("  ISC failed with error: {:#x}", isc_status);
            break;
        }

        // Exit if we're fully done (both sides SEC_E_OK)
        // Note: ISC returns OK before ASC, so we usually need to let ASC run with ISC's final token

        let client_output_len = isc_out_buffers[0].cbBuffer;

        // ===== Server: AcceptSecurityContext =====
        println!("\n=== ASC Round {} (Server) ===", round);

        let mut asc_in_buffers = [SecBuffer {
            cbBuffer: client_output_len,
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
            server_ctx_new.clone()
        };

        let mut next_server_ctx = Handle::default();

        let asc_res = ntlmpass.accept_security_context(
            &server_cred,
            &mut ctx_for_asc,
            &asc_input_desc as *const _ as usize,
            0,
            SECURITY_NATIVE_DREP,
            &mut next_server_ctx,
            &mut asc_output_desc as *mut _ as usize,
            &mut pf_context_attr,
            &mut ts_expiry as *mut i64 as usize,
        );

        if first_asc {
            server_ctx_new = next_server_ctx;
        } else if next_server_ctx.lower != 0 || next_server_ctx.upper != 0 {
            server_ctx_new = next_server_ctx;
        }

        println!("  ASC returned: {:#x}", asc_res);

        let asc_cb = asc_out_buffers[0].cbBuffer as usize;
        if asc_cb > 0 {
            if asc_res != SEC_E_OK {
                println!("  Server output token ({} bytes):", asc_cb);
                hexdump(&asc_out_token[..asc_cb]);
            }
        } else {
            println!("  Server output token (0 bytes)");
        }

        if asc_res != SEC_I_CONTINUE_NEEDED && asc_res != SEC_E_OK {
            println!("  ASC failed with error: {:#x}", asc_res);
            break;
        }

        if asc_res == SEC_E_OK && asc_cb == 0 {
            println!("\n✓ Server returned SEC_E_OK with no output. Handshake complete!");
            break;
        }

        last_server_output_len = asc_out_buffers[0].cbBuffer;

        first_isc = false;
        first_asc = false;

        if isc_status == SEC_E_OK && asc_res == SEC_E_OK {
            println!("\n✓ Both client and server report SEC_E_OK. Handshake complete!");
            break;
        }
    }

    // --- Query Context Attributes ---
    println!("\n=== Querying Client Context Attributes ===");
    query_and_print_context_attributes(&ntlmpass, &client_ctx_new);

    println!("\n=== Querying Server Context Attributes ===");
    query_and_print_context_attributes(&ntlmpass, &server_ctx_new);

    // Free resources
    ntlmpass.free_credentials_handle(&client_cred);
    ntlmpass.free_credentials_handle(&server_cred);
    ntlmpass.delete_security_context(&client_ctx_new);
    ntlmpass.delete_security_context(&server_ctx_new);

    println!("\nNTLMPassport handshake demo complete.");
}
