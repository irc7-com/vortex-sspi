use provider_gatekeeper::base_provider::{
    SEC_E_OK, SEC_I_CONTINUE_NEEDED, SECBUFFER_PKG_PARAMS, SECBUFFER_TOKEN, SecBuffer,
    SecBufferDesc,
};
use provider_gatekeeper::{
    GateKeeperPassportProvider, Handle, SecPkgInfoA, SecPkgInfoW, SecurityProvider,
};
use std::ffi::CStr;
use windows_sys::Win32::Security::Authentication::Identity::SECURITY_NATIVE_DREP;

use crate::utils::{print_round_results, wstr_from_ptr};

/// This binary demonstrates the SSPI handshake process for the GateKeeper provider.
/// It simulates a client-side authentication flow, including package enumeration
/// and a multi-round InitializeSecurityContext handshake.
pub fn main() {
    let mut gk = GateKeeperPassportProvider::new();
    if !gk.initialize() {
        eprintln!("Failed to initialize GateKeeper provider.");
        return;
    }

    // --- Package Enumeration Phase ---
    // Enumerating packages allows us to discover capabilities and buffer requirements.
    enumerate_and_print_packages(&mut gk);

    // --- Security Context Handshake (Round 1) ---
    // In the first round, the client provides its identity information (GUID and Hostname)
    // to the SSPI package to generate the initial Step 1 token.
    println!("\n=== Starting Security Context Handshake (Round 1) ===");

    let ph_credential = Handle::default();
    let ph_context = Handle::default();
    let mut ph_new_context = Handle::default();
    let mut pf_context_attr = 0;
    let mut ts_expiry: i64 = 0;

    let hostname = "dir.irc7.com";
    let passportticket_and_passportprofile =
        b"00000016PassportTicket00000017PassportProfile".to_vec();
    let mut in_buffers = [
        SecBuffer {
            cbBuffer: passportticket_and_passportprofile.len() as u32,
            BufferType: SECBUFFER_TOKEN,
            pvBuffer: passportticket_and_passportprofile.as_ptr() as *mut _,
        },
        SecBuffer {
            cbBuffer: hostname.len() as u32,
            BufferType: SECBUFFER_PKG_PARAMS,
            pvBuffer: hostname.as_ptr() as *mut _,
        },
    ];
    let input_desc = SecBufferDesc {
        ulVersion: 0,
        cBuffers: in_buffers.len() as u32,
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

    // --- Security Context Handshake (Round 3) ---
    // Simulating the server switching to Passport by sending "OK".
    println!("\n=== Receiving 'OK' Challenge (Round 3) - Switching to Passport ===");

    let ok_reply = b"OK";
    let mut in_buffers_round3 = [SecBuffer {
        cbBuffer: 2,
        BufferType: SECBUFFER_TOKEN,
        pvBuffer: ok_reply.as_ptr() as *mut _,
    }];
    let input_desc_round3 = SecBufferDesc {
        ulVersion: 0,
        cBuffers: 1,
        pBuffers: in_buffers_round3.as_mut_ptr(),
    };

    // Prepare output buffer for Passport token.
    let mut out_token_passport = vec![0u8; 1024];
    let mut out_buffers_round3 = [SecBuffer {
        cbBuffer: 1024,
        BufferType: SECBUFFER_TOKEN,
        pvBuffer: out_token_passport.as_mut_ptr() as *mut _,
    }];
    let mut output_desc_round3 = SecBufferDesc {
        ulVersion: 0,
        cBuffers: 1,
        pBuffers: out_buffers_round3.as_mut_ptr(),
    };

    let result_round3 = gk.initialize_security_context_a(
        &ph_credential,
        &h_context_round1,
        "",
        0,
        0,
        SECURITY_NATIVE_DREP,
        &input_desc_round3 as *const _ as usize,
        0,
        &mut ph_new_context,
        &mut output_desc_round3 as *mut _ as usize,
        &mut pf_context_attr,
        &mut ts_expiry as *mut i64 as usize,
    );

    if result_round3 != SEC_I_CONTINUE_NEEDED {
        println!(
            "InitializeSecurityContextA (Round 3) failed: {:#x}",
            result_round3
        );
        return;
    }

    print_round_results(3, &out_buffers_round3[0], &out_token_passport);
    println!("\nSuccessfully transitioned to Passport.");
}

/// Helper to print SSPI package information.
fn enumerate_and_print_packages(gk: &mut GateKeeperPassportProvider) {
    let mut pc_packages = 0;
    let mut pp_pkg_info_a: Vec<SecPkgInfoA> = Vec::new();
    if gk.enumerate_security_packages_a(&mut pc_packages, &mut pp_pkg_info_a) == SEC_E_OK {
        println!("Enumerated {} package(s) (ANSI):", pc_packages);
        for pkg in &pp_pkg_info_a {
            unsafe {
                let name = CStr::from_ptr(pkg.Name as *const i8).to_string_lossy();
                let comment = CStr::from_ptr(pkg.Comment as *const i8).to_string_lossy();
                println!("  - [{}] {}", name, comment);
                println!(
                    "    Capabilities: {:#x}, MaxToken: {}",
                    pkg.fCapabilities, pkg.cbMaxToken
                );
            }
        }
    }

    let mut pc_packages_w = 0;
    let mut pp_pkg_info_w: Vec<SecPkgInfoW> = Vec::new();
    if gk.enumerate_security_packages_w(&mut pc_packages_w, &mut pp_pkg_info_w) == SEC_E_OK {
        println!("\nEnumerated {} package(s) (Wide):", pc_packages_w);
        for pkg in &pp_pkg_info_w {
            unsafe {
                let name = wstr_from_ptr(pkg.Name as *const u16);
                let comment = wstr_from_ptr(pkg.Comment as *const u16);
                println!("  - [{}] {}", name, comment);
                println!(
                    "    Capabilities: {:#x}, MaxToken: {}",
                    pkg.fCapabilities, pkg.cbMaxToken
                );
            }
        }
    }
}
