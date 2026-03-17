use provider_gatekeeper::base_provider::{SECBUFFER_TOKEN, SecBuffer, SecBufferDesc};
use provider_gatekeeper::{NtlmPassportProvider, SecurityProvider};

use crate::utils::{AscInput, HandshakeConfig, IscInput, run_handshake};

// ─── NTLMPassport Handshake Overview ────────────────────────────────────────
//
// NTLMPassport is a hybrid provider that combines NTLM and Passport
// authentication. The buffer layout is simpler than GateKeeperPassport:
//
//   1. The client's first ISC call receives the Passport ticket and profile
//      payload in a single SECBUFFER_TOKEN. Unlike GateKeeperPassport,
//      there are no SECBUFFER_PKG_PARAMS buffers (no GUID or hostname).
//
//   2. On subsequent ISC rounds, the TOKEN buffer carries the server's
//      previous ASC output (standard NTLM Type 2/3 message flow).
//
//   3. ASC always receives a single TOKEN buffer with the client's output.
//
//   4. The hybrid provider internally handles the transition between
//      NTLM authentication phases and Passport ticket validation.
//
// Key difference from pure NTLM: ISC always receives input (even on round 1)
// because the Passport payload is passed in the TOKEN buffer.

/// Passport ticket and profile payload — sent in the TOKEN buffer on
/// the first ISC call. Same format as GateKeeperPassport:
///   "00000016" + "PassportTicket" + "00000017" + "PassportProfile"
static PASSPORT_PAYLOAD: &[u8] = b"00000016PassportTicket00000017PassportProfile";

/// Build InitializeSecurityContext input buffers for NTLMPassport.
///
/// # Round 1 — Passport payload
///
/// ```text
/// SecBufferDesc {
///     cBuffers: 1,
///     pBuffers: [
///         SecBuffer { BufferType: SECBUFFER_TOKEN, cbBuffer: payload_len, pvBuffer: passport_payload },
///     ]
/// }
/// ```
///
/// Unlike pure NTLM (which passes NULL input on round 1), the hybrid provider
/// receives the Passport ticket+profile in the TOKEN buffer.
///
/// # Subsequent Rounds — Server challenge/response
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
/// The TOKEN buffer carries the server's previous ASC output (NTLM Type 2, etc.).
fn build_isc_input(round: u32, server_token: &mut [u8], server_token_len: u32) -> Option<IscInput> {
    if round == 1 {
        // Round 1: Passport payload in TOKEN (not NULL like pure NTLM)
        let buffers = vec![SecBuffer {
            cbBuffer: PASSPORT_PAYLOAD.len() as u32,
            BufferType: SECBUFFER_TOKEN,
            pvBuffer: PASSPORT_PAYLOAD.as_ptr() as *mut _,
        }];
        Some(IscInput {
            desc: SecBufferDesc {
                ulVersion: 0,
                cBuffers: 1,
                pBuffers: std::ptr::null_mut(), // fixed up by run_handshake
            },
            buffers,
        })
    } else {
        // Subsequent rounds: server's previous output
        let buffers = vec![SecBuffer {
            cbBuffer: server_token_len,
            BufferType: SECBUFFER_TOKEN,
            pvBuffer: server_token.as_mut_ptr() as *mut _,
        }];
        Some(IscInput {
            desc: SecBufferDesc {
                ulVersion: 0,
                cBuffers: 1,
                pBuffers: std::ptr::null_mut(),
            },
            buffers,
        })
    }
}

/// Build AcceptSecurityContext input buffers for NTLMPassport.
///
/// Every ASC round receives a single TOKEN buffer with the client's output:
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
/// The server processes the client's token (which contains NTLM Type 1/3
/// messages depending on the round) and produces a response.
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

/// NTLMPassport handshake demo entry point.
///
/// Initializes the hybrid NTLMPassport provider and runs the standardized
/// handshake loop. This provider uses simple TOKEN-only buffers (no PKG_PARAMS)
/// but provides the Passport payload on round 1 instead of NULL.
pub fn main() {
    let mut ntlmpass = NtlmPassportProvider::new();
    if !ntlmpass.initialize() {
        eprintln!("Failed to initialize NTLMPassport provider.");
        return;
    }

    run_handshake(
        &ntlmpass,
        &HandshakeConfig {
            package_name: "NTLMPassport",
            display_name: "NTLMPassport Provider",
            max_token_size: 4096,
            build_isc_input,
            build_asc_input,
        },
    );
}
