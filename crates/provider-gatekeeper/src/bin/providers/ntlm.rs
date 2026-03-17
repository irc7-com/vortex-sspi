use provider_gatekeeper::base_provider::{SECBUFFER_TOKEN, SecBuffer, SecBufferDesc};
use provider_gatekeeper::{NtlmProvider, SecurityProvider};

use crate::utils::{AscInput, HandshakeConfig, IscInput, run_handshake};

// ─── NTLM Handshake Overview ────────────────────────────────────────────────
//
// The NTLM authentication protocol is a challenge-response mechanism:
//
//   Round 1 ISC → Type 1 (Negotiate) message:
//     Client sends capabilities and domain/workstation info.
//     ISC input: NULL (no server token yet).
//
//   Round 1 ASC → Type 2 (Challenge) message:
//     Server responds with a challenge nonce and its own capabilities.
//
//   Round 2 ISC → Type 3 (Authenticate) message:
//     Client computes response(s) to the server's challenge using
//     the user's password hash(es).
//
//   Round 2 ASC → SEC_E_OK:
//     Server verifies the client's response. Handshake complete.
//
// NTLM uses simple buffer layouts — just SECBUFFER_TOKEN, no PKG_PARAMS.

/// Build InitializeSecurityContext input buffers for NTLM.
///
/// # Round 1 — Negotiate
///
/// No input is provided (returns `None` → NULL pInput). NTLM's first ISC call
/// generates a Type 1 Negotiate message without any server input.
///
/// # Round 2+ — Authenticate
///
/// ```text
/// SecBufferDesc {
///     cBuffers: 1,
///     pBuffers: [
///         SecBuffer { BufferType: SECBUFFER_TOKEN, cbBuffer: server_len, pvBuffer: server_token },
///     ]
/// }
/// ```
///
/// The single TOKEN buffer carries the server's Type 2 Challenge message.
fn build_isc_input(round: u32, server_token: &mut [u8], server_token_len: u32) -> Option<IscInput> {
    if round == 1 {
        // Round 1: NTLM's initial ISC takes no input — the client generates
        // the Type 1 Negotiate message from scratch.
        None
    } else {
        // Round 2+: pass the server's Type 2 Challenge as input
        let buffers = vec![SecBuffer {
            cbBuffer: server_token_len,
            BufferType: SECBUFFER_TOKEN,
            pvBuffer: server_token.as_mut_ptr() as *mut _,
        }];
        Some(IscInput {
            desc: SecBufferDesc {
                ulVersion: 0,
                cBuffers: 1,
                pBuffers: std::ptr::null_mut(), // fixed up by run_handshake
            },
            buffers,
        })
    }
}

/// Build AcceptSecurityContext input buffers for NTLM.
///
/// Every ASC round receives a single TOKEN buffer containing the client's output:
///
/// ```text
/// SecBufferDesc {
///     cBuffers: 1,
///     pBuffers: [
///         SecBuffer { BufferType: SECBUFFER_TOKEN, cbBuffer: client_len, pvBuffer: client_token },
///     ]
/// }
/// ```
///
/// - Round 1: receives the Type 1 Negotiate message → produces Type 2 Challenge.
/// - Round 2: receives the Type 3 Authenticate message → produces SEC_E_OK.
fn build_asc_input(
    _round: u32,
    client_token: &mut [u8],
    client_token_len: u32,
) -> Option<AscInput> {
    let buffers = vec![SecBuffer {
        cbBuffer: client_token_len,
        BufferType: SECBUFFER_TOKEN,
        pvBuffer: client_token.as_mut_ptr() as *mut _,
    }];
    Some(AscInput {
        desc: SecBufferDesc {
            ulVersion: 0,
            cBuffers: 1,
            pBuffers: std::ptr::null_mut(),
        },
        buffers,
    })
}

/// NTLM handshake demo entry point.
///
/// Initializes the NTLM provider (which loads secur32.dll / security.dll and
/// resolves the system SSPI function tables) and runs the standardized
/// handshake loop. NTLM uses simple TOKEN-only buffers with no PKG_PARAMS.
pub fn main() {
    let mut ntlm = NtlmProvider::new();
    if !ntlm.initialize() {
        eprintln!("Failed to initialize NTLM provider.");
        return;
    }

    run_handshake(
        &ntlm,
        &HandshakeConfig {
            package_name: "NTLM",
            display_name: "NTLM Provider",
            max_token_size: 4096,
            build_isc_input,
            build_asc_input,
        },
    );
}
