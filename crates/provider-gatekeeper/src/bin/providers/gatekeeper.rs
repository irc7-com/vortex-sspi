use provider_gatekeeper::base_provider::{
    SEC_E_OK, SEC_I_CONTINUE_NEEDED, SECBUFFER_PKG_PARAMS, SECBUFFER_TOKEN, SecBuffer,
    SecBufferDesc,
};
use provider_gatekeeper::{GateKeeperProvider, Handle, SecurityProvider};
use windows_sys::Win32::Security::Authentication::Identity::SECURITY_NATIVE_DREP;

use crate::utils::{
    enumerate_and_print_packages, print_round_results,
    query_and_print_context_attributes,
};

/// This binary demonstrates the SSPI handshake process for the GateKeeper provider.
/// It simulates a client-side authentication flow, including package enumeration
/// and a multi-round InitializeSecurityContext handshake.
pub fn main() {
    let mut gk = GateKeeperProvider::new();
    if !gk.initialize() {
        eprintln!("Failed to initialize GateKeeper provider.");
        return;
    }

    // --- Package Enumeration Phase ---
    // Enumerating packages allows us to discover capabilities and buffer requirements.
    enumerate_and_print_packages(&gk);

    // --- Security Context Handshake (Round 1) ---
    // In the first round, the client provides its identity information (GUID and Hostname)
    // to the SSPI package to generate the initial Step 1 token.
    println!("\n=== Starting Security Context Handshake (Round 1) ===");

    let ph_credential = Handle::default();
    let ph_context = Handle::default();
    let mut ph_new_context = Handle::default();
    let mut pf_context_attr = 0;
    let mut ts_expiry: i64 = 0;

    // GateKeeper requires a 16-byte GUID and a hostname as input parameters.
    let mut guid = [0u8; 16];
    guid.copy_from_slice(&[
        0xE0, 0x04, 0x25, 0x3F, 0x89, 0x4F, 0xD3, 0x11, 0x9A, 0x0C, 0x03, 0x05, 0xE8, 0x2C, 0x33,
        0x01,
    ]);
    let hostname = "TESTHOST\0";

    let mut in_buffers = [
        SecBuffer {
            cbBuffer: 16,
            BufferType: SECBUFFER_PKG_PARAMS,
            pvBuffer: guid.as_mut_ptr() as *mut _,
        },
        SecBuffer {
            cbBuffer: hostname.len() as u32,
            BufferType: SECBUFFER_PKG_PARAMS,
            pvBuffer: hostname.as_ptr() as *mut _,
        },
    ];
    let input_desc = SecBufferDesc {
        ulVersion: 0,
        cBuffers: 2,
        pBuffers: in_buffers.as_mut_ptr(),
    };

    // Prepare output buffer for the generated Step 1 token.
    let max_token_size = 64; // Based on GateKeeper package info
    let mut out_token = vec![0u8; max_token_size as usize];
    let mut out_buffers = [SecBuffer {
        cbBuffer: max_token_size,
        BufferType: SECBUFFER_TOKEN,
        pvBuffer: out_token.as_mut_ptr() as *mut _,
    }];
    let mut output_desc = SecBufferDesc {
        ulVersion: 0,
        cBuffers: 1,
        pBuffers: out_buffers.as_mut_ptr(),
    };

    let result = gk.initialize_security_context_a(
        &ph_credential,
        &ph_context,
        "",
        0,
        0,
        SECURITY_NATIVE_DREP,
        &input_desc as *const _ as usize,
        0,
        &mut ph_new_context,
        &mut output_desc as *mut _ as usize,
        &mut pf_context_attr,
        &mut ts_expiry as *mut i64 as usize,
    );

    if result != SEC_I_CONTINUE_NEEDED {
        println!("InitializeSecurityContextA (Round 1) failed: {:#x}", result);
        return;
    }

    print_round_results(1, &out_buffers[0], &out_token);

    // --- Security Context Handshake (Round 2) ---
    // We simulate a response from the server which contains a challenge (Step 2).
    // The client processes this challenge to generate the final Step 3 token.
    println!("\n=== Processing Server Challenge (Round 2) ===");

    let server_reply: [u8; 24] = [
        0x47, 0x4B, 0x53, 0x53, 0x50, 0x00, 0x00, 0x00, // Header ("GKSSP\0\0\0")
        0x03, 0x00, 0x00, 0x00, // Version 3
        0x02, 0x00, 0x00, 0x00, // Step 2 (Server Challenge)
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, // Server Nonce
    ];

    let mut in_buffers_round2 = [SecBuffer {
        cbBuffer: server_reply.len() as u32,
        BufferType: SECBUFFER_TOKEN,
        pvBuffer: server_reply.as_ptr() as *mut _,
    }];
    let input_desc_round2 = SecBufferDesc {
        ulVersion: 0,
        cBuffers: 1,
        pBuffers: in_buffers_round2.as_mut_ptr(),
    };

    // Prepare output buffer for the generated Step 3 token.
    let mut out_buffers_round2 = [SecBuffer {
        cbBuffer: max_token_size,
        BufferType: SECBUFFER_TOKEN,
        pvBuffer: out_token.as_mut_ptr() as *mut _,
    }];
    let mut output_desc_round2 = SecBufferDesc {
        ulVersion: 0,
        cBuffers: 1,
        pBuffers: out_buffers_round2.as_mut_ptr(),
    };

    // Note: We use the context handle from the first round call.
    let h_context_round1 = ph_new_context;
    let result_round2 = gk.initialize_security_context_a(
        &ph_credential,
        &h_context_round1,
        "",
        0,
        0,
        SECURITY_NATIVE_DREP,
        &input_desc_round2 as *const _ as usize,
        0,
        &mut ph_new_context,
        &mut output_desc_round2 as *mut _ as usize,
        &mut pf_context_attr,
        &mut ts_expiry as *mut i64 as usize,
    );

    if result_round2 != SEC_E_OK {
        println!(
            "InitializeSecurityContextA (Round 2) failed: {:#x}",
            result_round2
        );
        return;
    }

    print_round_results(2, &out_buffers_round2[0], &out_token);
    println!("\nSecurity context successfully established.");

    query_and_print_context_attributes(&gk, &h_context_round1);
}
