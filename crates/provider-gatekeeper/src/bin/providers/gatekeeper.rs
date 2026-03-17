use provider_gatekeeper::base_provider::{
    SECBUFFER_PKG_PARAMS, SECBUFFER_TOKEN, SecBuffer, SecBufferDesc,
};
use provider_gatekeeper::{GateKeeperProvider, SecurityProvider};

use crate::utils::{AscInput, HandshakeConfig, IscInput, run_handshake};

// ─── GateKeeper-specific constants ──────────────────────────────────────────
//
// The GateKeeper provider requires two SECBUFFER_PKG_PARAMS buffers on the
// first ISC and ASC calls:
//
//   1. A 16-byte GUID identifying the GateKeeper protocol:
//      {3F2504E0-4F89-11D3-9A0C-0305E82C3301}
//
//   2. A null-terminated hostname string (the server being authenticated to).
//
// These are passed alongside the SECBUFFER_TOKEN buffer. On subsequent rounds,
// only the TOKEN buffer is needed (carrying the previous side's output).

/// GateKeeper protocol GUID — identifies this as a GateKeeper authentication exchange.
/// This is the binary representation of {3F2504E0-4F89-11D3-9A0C-0305E82C3301}.
static GK_GUID: [u8; 16] = [
    0xE0, 0x04, 0x25, 0x3F, 0x89, 0x4F, 0xD3, 0x11, 0x9A, 0x0C, 0x03, 0x05, 0xE8, 0x2C, 0x33, 0x01,
];

/// Hostname to authenticate against (null-terminated for C interop).
static GK_HOSTNAME: &[u8] = b"TESTHOST\0";

/// Legacy version flag for ASC — controls whether GateKeeper v1/v2 are allowed.
/// Set to 0 to only allow the current protocol version.
/// Note: This is only used by AcceptSecurityContext, not InitializeSecurityContext.
static GK_ALLOW_LEGACY: [u8; 1] = [0];

/// Build InitializeSecurityContext input buffers for GateKeeper.
///
/// # Round 1 — Initial handshake setup
///
/// The ISC input descriptor contains 3 buffers:
///
/// ```text
/// SecBufferDesc {
///     cBuffers: 3,
///     pBuffers: [
///         SecBuffer { BufferType: SECBUFFER_TOKEN,      cbBuffer: 0,          pvBuffer: (empty)   },
///         SecBuffer { BufferType: SECBUFFER_PKG_PARAMS,  cbBuffer: 16,         pvBuffer: GK_GUID   },
///         SecBuffer { BufferType: SECBUFFER_PKG_PARAMS,  cbBuffer: hostname_len, pvBuffer: hostname },
///     ]
/// }
/// ```
///
/// - The TOKEN buffer is empty on round 1 (no server output yet).
/// - PKG_PARAMS[0] carries the GateKeeper protocol GUID.
/// - PKG_PARAMS[1] carries the target hostname.
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
///
/// Only the TOKEN buffer is needed, containing the server's previous ASC output.
fn build_isc_input(round: u32, server_token: &mut [u8], server_token_len: u32) -> Option<IscInput> {
    if round == 1 {
        // Round 1: TOKEN (empty) + GUID + hostname
        let buffers = vec![
            SecBuffer {
                cbBuffer: 0,
                BufferType: SECBUFFER_TOKEN,
                pvBuffer: std::ptr::null_mut(),
            },
            SecBuffer {
                cbBuffer: GK_GUID.len() as u32,
                BufferType: SECBUFFER_PKG_PARAMS,
                pvBuffer: GK_GUID.as_ptr() as *mut _,
            },
            SecBuffer {
                cbBuffer: GK_HOSTNAME.len() as u32,
                BufferType: SECBUFFER_PKG_PARAMS,
                pvBuffer: GK_HOSTNAME.as_ptr() as *mut _,
            },
        ];
        Some(IscInput {
            desc: SecBufferDesc {
                ulVersion: 0,
                cBuffers: 3,
                pBuffers: std::ptr::null_mut(), // fixed up by run_handshake
            },
            buffers,
        })
    } else {
        // Subsequent rounds: just the server's output token
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

/// Build AcceptSecurityContext input buffers for GateKeeper.
///
/// Note: ASC uses *different* PKG_PARAMS than ISC. While ISC passes a GUID +
/// hostname, ASC passes a hostname + a 1-byte legacy version flag.
///
/// # Round 1 — Initial handshake
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
                cbBuffer: GK_HOSTNAME.len() as u32,
                BufferType: SECBUFFER_PKG_PARAMS,
                pvBuffer: GK_HOSTNAME.as_ptr() as *mut _,
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

/// GateKeeper handshake demo entry point.
///
/// Initializes a GateKeeper provider and runs the standardized handshake
/// loop with GateKeeper-specific buffer layouts (GUID + hostname as PKG_PARAMS).
pub fn main() {
    let mut gk = GateKeeperProvider::new();
    if !gk.initialize() {
        eprintln!("Failed to initialize GateKeeper provider.");
        return;
    }

    run_handshake(
        &gk,
        &HandshakeConfig {
            package_name: "GateKeeper",
            display_name: "GateKeeper Provider",
            max_token_size: 1024,
            build_isc_input,
            build_asc_input,
        },
    );
}
