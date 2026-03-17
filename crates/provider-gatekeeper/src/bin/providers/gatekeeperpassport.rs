use provider_gatekeeper::base_provider::{
    SECBUFFER_PKG_PARAMS, SECBUFFER_TOKEN, SecBuffer, SecBufferDesc,
};
use provider_gatekeeper::{GateKeeperPassportProvider, SecurityProvider};

use crate::utils::{AscInput, HandshakeConfig, IscInput, run_handshake};

// ─── GateKeeperPassport Handshake Overview ──────────────────────────────────
//
// GateKeeperPassport is a hybrid provider that combines GateKeeper and Passport
// authentication. The handshake has several phases:
//
//   1. The client's first ISC call receives the Passport ticket and profile
//      (encoded as "00000016PassportTicket00000017PassportProfile") in the
//      TOKEN buffer, along with two SECBUFFER_PKG_PARAMS buffers carrying
//      the GateKeeper protocol GUID and the target hostname.
//
//   2. On subsequent ISC rounds, only the TOKEN buffer (with the server's
//      previous output) is needed.
//
//   3. On the first ASC call, the server receives the hostname and a 1-byte
//      legacy version flag as PKG_PARAMS (different from ISC which uses GUID +
//      hostname). Subsequent ASC calls only receive the TOKEN.
//
//   4. The hybrid provider internally delegates to GateKeeper for the initial
//      handshake phases and transitions to Passport when needed.

/// Hostname for the GateKeeperPassport handshake (null-terminated).
static GKP_HOSTNAME: &[u8] = b"dir.irc7.com\0";

/// Legacy version flag for ASC — controls whether GateKeeper v1/v2 are allowed.
/// Set to 0 to only allow the current protocol version.
/// Note: This is only used by AcceptSecurityContext, not InitializeSecurityContext.
static GK_ALLOW_LEGACY: [u8; 1] = [0];

/// Passport ticket and profile payload — sent in the TOKEN buffer on the
/// first ISC call. The format uses length-prefixed fields:
///   "00000016" + "PassportTicket" + "00000017" + "PassportProfile"
///
/// The provider parses this to extract the ticket and profile values which
/// are used during the Passport authentication phase.
static PASSPORT_PAYLOAD: &[u8] = b"00000016PassportTicket00000017PassportProfile";

/// Build InitializeSecurityContext input buffers for GateKeeperPassport.
///
/// Note: Unlike the pure GateKeeper provider, GateKeeperPassport ISC only
/// expects ONE PKG_PARAMS from the caller — the hostname. The provider
/// internally constructs the GUID (as zeros) and prepends it before delegating
/// to the GateKeeper ISC. Passing the GUID as a separate PKG_PARAMS here would
/// cause the provider to treat it as the hostname, leading to HMAC mismatches.
///
/// # Round 1 — Hybrid handshake initiation
///
/// ```text
/// SecBufferDesc {
///     cBuffers: 2,
///     pBuffers: [
///         SecBuffer { BufferType: SECBUFFER_TOKEN,      cbBuffer: payload_len,  pvBuffer: passport_payload },
///         SecBuffer { BufferType: SECBUFFER_PKG_PARAMS, cbBuffer: hostname_len, pvBuffer: hostname         },
///     ]
/// }
/// ```
///
/// - TOKEN carries the Passport ticket+profile payload (not a server token).
/// - PKG_PARAMS[0] is the target hostname (the provider adds GUID internally).
///
/// # Subsequent Rounds
///
/// ```text
/// SecBufferDesc {
///     cBuffers: 1,
///     pBuffers: [
///         SecBuffer { BufferType: SECBUFFER_TOKEN, cbBuffer: server_len, pvBuffer: server_token },
///     ]
/// }
/// ```
fn build_isc_input(round: u32, server_token: &mut [u8], server_token_len: u32) -> Option<IscInput> {
    if round == 1 {
        // Round 1: Passport payload + hostname (provider adds GUID internally)
        let buffers = vec![
            SecBuffer {
                cbBuffer: PASSPORT_PAYLOAD.len() as u32,
                BufferType: SECBUFFER_TOKEN,
                pvBuffer: PASSPORT_PAYLOAD.as_ptr() as *mut _,
            },
            SecBuffer {
                cbBuffer: GKP_HOSTNAME.len() as u32,
                BufferType: SECBUFFER_PKG_PARAMS,
                pvBuffer: GKP_HOSTNAME.as_ptr() as *mut _,
            },
        ];
        Some(IscInput {
            desc: SecBufferDesc {
                ulVersion: 0,
                cBuffers: 2,
                pBuffers: std::ptr::null_mut(), // fixed up by run_handshake
            },
            buffers,
        })
    } else {
        // Subsequent rounds: server's previous output as TOKEN
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

/// Build AcceptSecurityContext input buffers for GateKeeperPassport.
///
/// Note: ASC uses *different* PKG_PARAMS than ISC. While ISC passes a GUID +
/// hostname, ASC passes a hostname + a 1-byte legacy version flag.
///
/// # Round 1 — Server receives client's initial hybrid token + params
///
/// ```text
/// SecBufferDesc {
///     cBuffers: 3,
///     pBuffers: [
///         SecBuffer { BufferType: SECBUFFER_TOKEN,      cbBuffer: client_len,   pvBuffer: client_token },
///         SecBuffer { BufferType: SECBUFFER_PKG_PARAMS, cbBuffer: hostname_len,  pvBuffer: hostname     },
///         SecBuffer { BufferType: SECBUFFER_PKG_PARAMS, cbBuffer: 1,             pvBuffer: allow_legacy },
///     ]
/// }
/// ```
///
/// - TOKEN carries the client's ISC output.
/// - PKG_PARAMS[0] carries the hostname (passed to SetServerHostname).
/// - PKG_PARAMS[1] carries a 1-byte boolean flag: allow legacy GateKeeper v1/v2.
///
/// # Subsequent Rounds
///
/// ```text
/// SecBufferDesc {
///     cBuffers: 1,
///     pBuffers: [
///         SecBuffer { BufferType: SECBUFFER_TOKEN, cbBuffer: client_len, pvBuffer: client_token },
///     ]
/// }
/// ```
fn build_asc_input(round: u32, client_token: &mut [u8], client_token_len: u32) -> Option<AscInput> {
    if round == 1 {
        let buffers = vec![
            SecBuffer {
                cbBuffer: client_token_len,
                BufferType: SECBUFFER_TOKEN,
                pvBuffer: client_token.as_mut_ptr() as *mut _,
            },
            SecBuffer {
                cbBuffer: GKP_HOSTNAME.len() as u32,
                BufferType: SECBUFFER_PKG_PARAMS,
                pvBuffer: GKP_HOSTNAME.as_ptr() as *mut _,
            },
            SecBuffer {
                cbBuffer: GK_ALLOW_LEGACY.len() as u32,
                BufferType: SECBUFFER_PKG_PARAMS,
                pvBuffer: GK_ALLOW_LEGACY.as_ptr() as *mut _,
            },
        ];
        Some(AscInput {
            desc: SecBufferDesc {
                ulVersion: 0,
                cBuffers: 3,
                pBuffers: std::ptr::null_mut(),
            },
            buffers,
        })
    } else {
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
}

/// GateKeeperPassport handshake demo entry point.
///
/// Initializes the hybrid GateKeeperPassport provider and runs the standardized
/// handshake loop. This provider combines GateKeeper (GUID + hostname in PKG_PARAMS)
/// with Passport (ticket + profile in the initial TOKEN buffer).
pub fn main() {
    let mut gkpass = GateKeeperPassportProvider::new();
    if !gkpass.initialize() {
        eprintln!("Failed to initialize GateKeeperPassport provider.");
        return;
    }

    run_handshake(
        &gkpass,
        &HandshakeConfig {
            package_name: "GateKeeperPassport",
            display_name: "GateKeeperPassport Provider",
            max_token_size: 4096,
            build_isc_input,
            build_asc_input,
        },
    );
}
