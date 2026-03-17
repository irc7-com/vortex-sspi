use provider_gatekeeper::base_provider::{
    SEC_E_OK, SEC_I_CONTINUE_NEEDED, SECBUFFER_TOKEN, SecBuffer, SecBufferDesc, SecurityStatus,
};
use provider_gatekeeper::{Handle, SecPkgInfoA, SecurityProvider};
use std::ffi::CStr;
use windows_sys::Win32::Security::Authentication::Identity::{
    SECURITY_NATIVE_DREP, SecPkgContext_NamesA, SecPkgContext_NamesW,
};

// ─── Pretty-print helpers ───────────────────────────────────────────────────

/// Read a null-terminated UTF-16 wide string from a raw pointer.
pub unsafe fn wstr_from_ptr(ptr: *const u16) -> String {
    let mut len = 0;
    unsafe {
        while *ptr.add(len) != 0 {
            len += 1;
        }
        let slice = std::slice::from_raw_parts(ptr, len);
        String::from_utf16_lossy(slice)
    }
}

/// Prints a byte buffer in hex editor format (16 bytes per line).
pub fn hexdump(data: &[u8]) {
    for (i, chunk) in data.chunks(16).enumerate() {
        let offset = i * 16;
        print!("{:08x}: ", offset);
        for byte in chunk {
            print!("{:02x} ", byte);
        }
        if chunk.len() < 16 {
            for _ in 0..(16 - chunk.len()) {
                print!("   ");
            }
        }
        print!("  ");
        for byte in chunk {
            if *byte >= 32 && *byte <= 126 {
                print!("{}", *byte as char);
            } else {
                print!(".");
            }
        }
        println!();
    }
}

/// Decode a capabilities bitmask into human-readable flag names.
pub fn format_capabilities(caps: u32) -> String {
    use windows_sys::Win32::Security::Authentication::Identity::*;
    let mut flags = Vec::new();

    if caps & SECPKG_FLAG_INTEGRITY != 0 {
        flags.push("INTEGRITY");
    }
    if caps & SECPKG_FLAG_PRIVACY != 0 {
        flags.push("PRIVACY");
    }
    if caps & SECPKG_FLAG_TOKEN_ONLY != 0 {
        flags.push("TOKEN_ONLY");
    }
    if caps & SECPKG_FLAG_DATAGRAM != 0 {
        flags.push("DATAGRAM");
    }
    if caps & SECPKG_FLAG_CONNECTION != 0 {
        flags.push("CONNECTION");
    }
    if caps & SECPKG_FLAG_MULTI_REQUIRED != 0 {
        flags.push("MULTI_REQUIRED");
    }
    if caps & SECPKG_FLAG_CLIENT_ONLY != 0 {
        flags.push("CLIENT_ONLY");
    }
    if caps & SECPKG_FLAG_EXTENDED_ERROR != 0 {
        flags.push("EXTENDED_ERROR");
    }
    if caps & SECPKG_FLAG_IMPERSONATION != 0 {
        flags.push("IMPERSONATION");
    }
    if caps & SECPKG_FLAG_ACCEPT_WIN32_NAME != 0 {
        flags.push("ACCEPT_WIN32_NAME");
    }
    if caps & SECPKG_FLAG_STREAM != 0 {
        flags.push("STREAM");
    }
    if caps & SECPKG_FLAG_NEGOTIABLE != 0 {
        flags.push("NEGOTIABLE");
    }
    if caps & SECPKG_FLAG_GSS_COMPATIBLE != 0 {
        flags.push("GSS_COMPATIBLE");
    }
    if caps & SECPKG_FLAG_LOGON != 0 {
        flags.push("LOGON");
    }
    if caps & SECPKG_FLAG_ASCII_BUFFERS != 0 {
        flags.push("ASCII_BUFFERS");
    }
    if caps & SECPKG_FLAG_FRAGMENT != 0 {
        flags.push("FRAGMENT");
    }
    if caps & SECPKG_FLAG_MUTUAL_AUTH != 0 {
        flags.push("MUTUAL_AUTH");
    }
    if caps & SECPKG_FLAG_DELEGATION != 0 {
        flags.push("DELEGATION");
    }
    if caps & SECPKG_FLAG_READONLY_WITH_CHECKSUM != 0 {
        flags.push("READONLY_WITH_CHECKSUM");
    }
    if caps & SECPKG_FLAG_RESTRICTED_TOKENS != 0 {
        flags.push("RESTRICTED_TOKENS");
    }
    if caps & SECPKG_FLAG_NEGO_EXTENDER != 0 {
        flags.push("NEGO_EXTENDER");
    }
    if caps & SECPKG_FLAG_NEGOTIABLE2 != 0 {
        flags.push("NEGOTIABLE2");
    }
    if caps & SECPKG_FLAG_APPCONTAINER_CHECKS != 0 {
        flags.push("APPCONTAINER_CHECKS");
    }
    if caps & SECPKG_FLAG_APPCONTAINER_PASSTHROUGH != 0 {
        flags.push("APPCONTAINER_PASSTHROUGH");
    }

    if flags.is_empty() {
        return "None".to_string();
    }

    flags.join(" | ")
}

// ─── Package info (query by name, not enumerate) ────────────────────────────

/// Query and print the security package info for a specific package by name.
///
/// For NTLM-based providers that delegate to the real SSPI, this calls
/// `QuerySecurityPackageInfoA` which returns a pointer to a `SecPkgInfoA` struct
/// allocated by the system. For our own providers (GateKeeper, etc.) that implement
/// a stub, we fall back to reading `provider.base().pkg_info_ascii` directly.
fn query_and_print_package_info(provider: &dyn SecurityProvider, package_name: &str) {
    println!("\n=== Package Info: \"{}\" ===", package_name);

    // Try QuerySecurityPackageInfoA first — this is what SSPI apps normally use
    // to retrieve info about a single package by name (rather than enumerating all).
    let mut pp_pkg_info: usize = 0;
    let status = provider.query_security_package_info_a(package_name, &mut pp_pkg_info);

    if status == SEC_E_OK && pp_pkg_info != 0 {
        // The provider returned a valid pointer to a SecPkgInfoA struct.
        // This is the case for NTLM providers that delegate to the system SSPI.
        unsafe {
            let pkg = &*(pp_pkg_info as *const SecPkgInfoA);
            print_package_info(pkg);
        }
    } else {
        // Our own providers (GateKeeper, GateKeeperPassport, etc.) store package
        // info directly in base().pkg_info_ascii — use that as a fallback.
        let pkg = &provider.base().pkg_info_ascii;
        print_package_info(pkg);
    }
}

/// Pretty-print a `SecPkgInfoA` structure.
fn print_package_info(pkg: &SecPkgInfoA) {
    unsafe {
        let name = if pkg.Name.is_null() {
            "(null)".to_string()
        } else {
            CStr::from_ptr(pkg.Name as *const i8)
                .to_string_lossy()
                .into_owned()
        };
        let comment = if pkg.Comment.is_null() {
            "(null)".to_string()
        } else {
            CStr::from_ptr(pkg.Comment as *const i8)
                .to_string_lossy()
                .into_owned()
        };
        println!("  Name:         {}", name);
        println!("  Comment:      {}", comment);
        println!(
            "  Capabilities: {:#010x} ({})",
            pkg.fCapabilities,
            format_capabilities(pkg.fCapabilities)
        );
        println!("  Version:      {}", pkg.wVersion);
        println!("  RPCID:        {}", pkg.wRPCID);
        println!("  MaxToken:     {} bytes", pkg.cbMaxToken);
    }
}

// ─── Context attribute querying ─────────────────────────────────────────────

/// Query and print SecPkgContext_NamesA/W (SECPKG_ATTR_NAMES = 1) for a context.
fn query_and_print_context_names(provider: &dyn SecurityProvider, label: &str, h_context: &Handle) {
    // ── ANSI variant ──
    println!("\n--- {} Context: SECPKG_ATTR_NAMES (ANSI) ---", label);
    let mut names_a = SecPkgContext_NamesA {
        sUserName: std::ptr::null_mut(),
    };
    let res = provider.query_context_attributes_a(
        h_context,
        1, // SECPKG_ATTR_NAMES
        &mut names_a as *mut _ as usize,
    );
    if res == SEC_E_OK {
        if !names_a.sUserName.is_null() {
            let name = unsafe { CStr::from_ptr(names_a.sUserName).to_string_lossy() };
            println!("  Name: {}", name);
            provider.free_context_buffer(names_a.sUserName as usize);
        } else {
            println!("  (returned SEC_E_OK but sUserName is null)");
        }
    } else {
        println!("  QueryContextAttributesA failed: {:#x}", res);
    }

    // ── Wide variant ──
    println!("--- {} Context: SECPKG_ATTR_NAMES (Wide) ---", label);
    let mut names_w = SecPkgContext_NamesW {
        sUserName: std::ptr::null_mut(),
    };
    let res_w = provider.query_context_attributes_w(
        h_context,
        1, // SECPKG_ATTR_NAMES
        &mut names_w as *mut _ as usize,
    );
    if res_w == SEC_E_OK {
        if !names_w.sUserName.is_null() {
            let name = unsafe { wstr_from_ptr(names_w.sUserName) };
            println!("  Name: {}", name);
            provider.free_context_buffer(names_w.sUserName as usize);
        } else {
            println!("  (returned SEC_E_OK but sUserName is null)");
        }
    } else {
        println!("  QueryContextAttributesW failed: {:#x}", res_w);
    }
}

// ─── ISC / ASC input builder types ──────────────────────────────────────────

/// Holds the input buffers and descriptor for an InitializeSecurityContext call.
/// The struct keeps the buffer array alive for the duration of the call.
pub struct IscInput {
    pub buffers: Vec<SecBuffer>,
    pub desc: SecBufferDesc,
}

/// Holds the input buffers and descriptor for an AcceptSecurityContext call.
pub struct AscInput {
    pub buffers: Vec<SecBuffer>,
    pub desc: SecBufferDesc,
}

// ─── Handshake configuration ────────────────────────────────────────────────

/// Configuration for a provider handshake demo. Each provider supplies its own
/// package name, display name, and functions that build the ISC/ASC input buffers
/// for each round. Everything else (credentials, handshake loop, hexdump,
/// context attribute queries, cleanup) is handled by `run_handshake`.
pub struct HandshakeConfig {
    /// The SSPI package name, e.g. "GateKeeper", "NTLM", "GateKeeperPassport".
    pub package_name: &'static str,

    /// Human-readable name for the banner, e.g. "GateKeeper Provider".
    pub display_name: &'static str,

    /// Maximum token buffer size. GateKeeper uses 1024, NTLM-based use 4096.
    pub max_token_size: usize,

    /// Build the ISC (client) input for a given round.
    ///
    /// Arguments:
    ///   - `round`:            Current round number (1-based).
    ///   - `server_token`:     Mutable ref to the ASC output buffer from the previous round.
    ///   - `server_token_len`: Number of valid bytes in `server_token` from the previous ASC.
    ///
    /// Return `Some(IscInput)` to pass an input descriptor to ISC, or `None` for
    /// a NULL input (used by NTLM on round 1 where no input is needed).
    pub build_isc_input:
        fn(round: u32, server_token: &mut [u8], server_token_len: u32) -> Option<IscInput>,

    /// Build the ASC (server) input for a given round.
    ///
    /// Arguments:
    ///   - `round`:            Current round number (1-based).
    ///   - `client_token`:     Mutable ref to the ISC output buffer from this round.
    ///   - `client_token_len`: Number of valid bytes in `client_token` from ISC.
    ///
    /// Always returns `Some(AscInput)` — the server always receives the client's output.
    pub build_asc_input:
        fn(round: u32, client_token: &mut [u8], client_token_len: u32) -> Option<AscInput>,
}

// ─── Main handshake runner ──────────────────────────────────────────────────

/// Run a standardized SSPI handshake demo for any provider.
///
/// This function implements the full ISC/ASC loop:
///   1. Print a banner
///   2. Query and print package info (by name — not enumerate)
///   3. Acquire client (OUTBOUND) and server (INBOUND) credentials
///   4. Loop: ISC → hexdump → ASC → hexdump, until SEC_E_OK or failure
///   5. On success: query and print SECPKG_ATTR_NAMES for both contexts
///   6. Cleanup: delete contexts, free credentials, shutdown
pub fn run_handshake(provider: &dyn SecurityProvider, config: &HandshakeConfig) {
    // ╔════════════════════════════════════════════════════════════════════════╗
    // ║  Banner                                                              ║
    // ╚════════════════════════════════════════════════════════════════════════╝
    let banner = format!("{} Handshake Demo", config.display_name);
    let width = banner.len() + 4;
    println!("\n╔{}╗", "═".repeat(width));
    println!("║  {}  ║", banner);
    println!("╚{}╝", "═".repeat(width));

    // ╔════════════════════════════════════════════════════════════════════════╗
    // ║  Step 1: Query package info by name                                  ║
    // ║                                                                      ║
    // ║  Instead of enumerating all packages (which on Windows returns the   ║
    // ║  full secur32.dll list), we query the specific package by name.      ║
    // ╚════════════════════════════════════════════════════════════════════════╝
    query_and_print_package_info(provider, config.package_name);

    // ╔════════════════════════════════════════════════════════════════════════╗
    // ║  Step 2: Acquire credentials                                         ║
    // ║                                                                      ║
    // ║  We acquire two separate credential handles:                         ║
    // ║    - Client (SECPKG_CRED_OUTBOUND = 2): the initiator               ║
    // ║    - Server (SECPKG_CRED_INBOUND  = 1): the acceptor                ║
    // ║                                                                      ║
    // ║  AcquireCredentialsHandleA parameters:                               ║
    // ║    pszPrincipal:   "" (NULL = current user)                          ║
    // ║    pszPackage:     package name (e.g. "GateKeeper")                  ║
    // ║    fCredentialUse: OUTBOUND(2) or INBOUND(1)                         ║
    // ║    pvLogonId:      0 (not used)                                      ║
    // ║    pAuthData:      0 (no auth data)                                  ║
    // ║    pGetKeyFn:      0 (no key callback)                               ║
    // ║    pvGetKeyArg:    0 (no key callback arg)                           ║
    // ╚════════════════════════════════════════════════════════════════════════╝
    println!("\n=== Acquiring Credentials ===");
    let mut client_cred = Handle::default();
    let mut server_cred = Handle::default();
    let mut ts_expiry: i64 = 0;

    let result = provider.acquire_credentials_handle_a(
        "",                  // pszPrincipal (NULL = current user)
        config.package_name, // pszPackage
        2,                   // SECPKG_CRED_OUTBOUND (client initiator)
        0,                   // pvLogonId
        0,                   // pAuthData
        0,                   // pGetKeyFn
        0,                   // pvGetKeyArgument
        &mut client_cred,
        &mut ts_expiry as *mut i64 as usize,
    );
    if result != SEC_E_OK {
        eprintln!("AcquireCredentialsHandleA (client) failed: {:#x}", result);
        return;
    }
    println!(
        "  Client credentials acquired: {:#x}:{:#x}",
        client_cred.lower, client_cred.upper
    );

    let result = provider.acquire_credentials_handle_a(
        "",                  // pszPrincipal
        config.package_name, // pszPackage
        1,                   // SECPKG_CRED_INBOUND (server acceptor)
        0,                   // pvLogonId
        0,                   // pAuthData
        0,                   // pGetKeyFn
        0,                   // pvGetKeyArgument
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

    // ╔════════════════════════════════════════════════════════════════════════╗
    // ║  Step 3: ISC / ASC Handshake Loop                                    ║
    // ║                                                                      ║
    // ║  The loop alternates between:                                        ║
    // ║    - InitializeSecurityContextA (ISC) — the client side              ║
    // ║    - AcceptSecurityContext (ASC)       — the server side              ║
    // ║                                                                      ║
    // ║  Each call receives an input SecBufferDesc (built by the config's    ║
    // ║  builder function) and produces an output SecBufferDesc containing   ║
    // ║  a single SECBUFFER_TOKEN. The output token from one side becomes    ║
    // ║  the input to the other side on the next call.                       ║
    // ║                                                                      ║
    // ║  The loop terminates when:                                           ║
    // ║    - ASC returns SEC_E_OK (handshake complete)                       ║
    // ║    - Either side returns an error (!= SEC_E_OK && != CONTINUE)       ║
    // ║    - Safety limit of 10 rounds is exceeded                           ║
    // ║                                                                      ║
    // ║  Every ISC and ASC output token is hexdumped before the handshake    ║
    // ║  completes, so we can inspect the raw protocol messages.             ║
    // ╚════════════════════════════════════════════════════════════════════════╝

    let max_token = config.max_token_size;
    let mut isc_out_token = vec![0u8; max_token];
    let mut asc_out_token = vec![0u8; max_token];

    let mut client_ctx = Handle::default();
    let mut server_ctx = Handle::default();
    let mut pf_context_attr: u32 = 0;

    let mut round = 0u32;
    #[allow(unused_assignments)]
    let mut isc_status: SecurityStatus = SEC_I_CONTINUE_NEEDED;
    let mut asc_status: SecurityStatus = SEC_I_CONTINUE_NEEDED;

    let mut last_server_output_len: u32 = 0;
    let mut first_isc = true;
    let mut first_asc = true;

    loop {
        round += 1;

        // ── ISC (Client → Server) ───────────────────────────────────────
        //
        // InitializeSecurityContextA parameters:
        //   phCredential:   Client credential handle (OUTBOUND)
        //   phContext:       NULL on first call, client context on subsequent
        //   pszTargetName:  "" (NULL — local authentication)
        //   fContextReq:    0 (no special requirements)
        //   Reserved1:      0
        //   TargetDataRep:  SECURITY_NATIVE_DREP
        //   pInput:         Provider-specific input (see build_isc_input)
        //   Reserved2:      0
        //   phNewContext:   Receives the updated client context handle
        //   pOutput:        SecBufferDesc with one SECBUFFER_TOKEN for output
        //   pfContextAttr:  Receives negotiated context attributes
        //   ptsExpiry:      Receives credential expiry time
        println!("\n=== ISC Round {} (Client) ===", round);

        // Build provider-specific ISC input buffers.
        // The builder returns None for a NULL pInput (e.g. NTLM round 1).
        let mut isc_input =
            (config.build_isc_input)(round, &mut asc_out_token, last_server_output_len);
        let isc_input_ptr = match isc_input {
            Some(ref mut input) => {
                // Fix up the descriptor's pBuffers pointer after the Vec is in place
                input.desc.pBuffers = input.buffers.as_mut_ptr();
                &input.desc as *const _ as usize
            }
            None => 0usize, // NULL input — no input token on this call
        };

        // Prepare ISC output: a single SECBUFFER_TOKEN buffer to receive the output token.
        isc_out_token.fill(0);
        let mut isc_out_buffers = [SecBuffer {
            cbBuffer: max_token as u32,
            BufferType: SECBUFFER_TOKEN,
            pvBuffer: isc_out_token.as_mut_ptr() as *mut _,
        }];
        let mut isc_output_desc = SecBufferDesc {
            ulVersion: 0,
            cBuffers: 1,
            pBuffers: isc_out_buffers.as_mut_ptr(),
        };

        // On the first call, pass a zeroed handle (SSPI interprets 0:0 as NULL → new context).
        // On subsequent calls, pass the existing client context handle.
        let ctx_for_isc = if first_isc {
            Handle::default()
        } else {
            client_ctx
        };

        isc_status = provider.initialize_security_context_a(
            &client_cred,
            &ctx_for_isc,
            "",                                      // pszTargetName (NULL = local)
            0,                                       // fContextReq
            0,                                       // Reserved1
            SECURITY_NATIVE_DREP,                    // TargetDataRep
            isc_input_ptr,                           // pInput (provider-specific)
            0,                                       // Reserved2
            &mut client_ctx,                         // phNewContext (out)
            &mut isc_output_desc as *mut _ as usize, // pOutput (out)
            &mut pf_context_attr,                    // pfContextAttr (out)
            &mut ts_expiry as *mut i64 as usize,     // ptsExpiry (out)
        );

        first_isc = false;
        let isc_output_len = isc_out_buffers[0].cbBuffer;

        println!("  ISC returned: {:#x}", isc_status);
        if isc_output_len > 0 {
            // Hexdump every ISC output token so we can inspect the raw messages.
            println!("  Client output token ({} bytes):", isc_output_len);
            hexdump(&isc_out_token[..isc_output_len as usize]);
        } else {
            println!("  Client produced no output token.");
        }

        // Check for ISC failure (anything other than OK or CONTINUE).
        if isc_status != SEC_E_OK && isc_status != SEC_I_CONTINUE_NEEDED {
            eprintln!("  ✗ ISC failed with error: {:#x}", isc_status);
            break;
        }

        // If both sides have already reported SEC_E_OK, we're done.
        if isc_status == SEC_E_OK && asc_status == SEC_E_OK {
            println!("\n✓ Both client and server report SEC_E_OK. Handshake complete!");
            break;
        }

        // ── ASC (Server ← Client) ───────────────────────────────────────
        //
        // AcceptSecurityContext parameters:
        //   phCredential:   Server credential handle (INBOUND)
        //   phContext:       NULL on first call, server context on subsequent
        //   pInput:         SecBufferDesc with the client's output token
        //                   (plus any provider-specific PKG_PARAMS buffers)
        //   fContextReq:    0 (no special requirements)
        //   TargetDataRep:  SECURITY_NATIVE_DREP
        //   phNewContext:   Receives the updated server context handle
        //   pOutput:        SecBufferDesc with one SECBUFFER_TOKEN for output
        //   pfContextAttr:  Receives negotiated context attributes
        //   ptsExpiry:      Receives credential expiry time
        println!("\n=== ASC Round {} (Server) ===", round);

        // Build provider-specific ASC input buffers.
        let mut asc_input = (config.build_asc_input)(round, &mut isc_out_token, isc_output_len);
        let asc_input_ptr = match asc_input {
            Some(ref mut input) => {
                input.desc.pBuffers = input.buffers.as_mut_ptr();
                &input.desc as *const _ as usize
            }
            None => 0usize,
        };

        // Prepare ASC output: a single SECBUFFER_TOKEN buffer for the server's reply.
        asc_out_token.fill(0);
        let mut asc_out_buffers = [SecBuffer {
            cbBuffer: max_token as u32,
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
            server_ctx
        };

        let mut next_server_ctx = Handle::default();

        asc_status = provider.accept_security_context(
            &server_cred,
            &mut ctx_for_asc,
            asc_input_ptr,                           // pInput (provider-specific)
            0,                                       // fContextReq
            SECURITY_NATIVE_DREP,                    // TargetDataRep
            &mut next_server_ctx,                    // phNewContext (out)
            &mut asc_output_desc as *mut _ as usize, // pOutput (out)
            &mut pf_context_attr,                    // pfContextAttr (out)
            &mut ts_expiry as *mut i64 as usize,     // ptsExpiry (out)
        );

        // Update the server context handle. On the first call the provider always
        // returns a brand new handle. On subsequent calls it may return a new one
        // (non-zero) or signal reuse of the existing one (zero handle).
        if first_asc || next_server_ctx.lower != 0 || next_server_ctx.upper != 0 {
            server_ctx = next_server_ctx;
        }

        first_asc = false;
        last_server_output_len = asc_out_buffers[0].cbBuffer;

        println!("  ASC returned: {:#x}", asc_status);
        if last_server_output_len > 0 && asc_status != SEC_E_OK {
            // Hexdump server output tokens while the handshake is still in progress.
            // (Once ASC returns SEC_E_OK, the handshake is done — no need to dump.)
            println!("  Server output token ({} bytes):", last_server_output_len);
            hexdump(&asc_out_token[..last_server_output_len as usize]);
        } else if last_server_output_len > 0 {
            println!(
                "  Server output token ({} bytes) [final, not dumped]",
                last_server_output_len
            );
        } else {
            println!("  Server produced no output token.");
        }

        // Check for ASC failure.
        if asc_status != SEC_E_OK && asc_status != SEC_I_CONTINUE_NEEDED {
            eprintln!("  ✗ ASC failed with error: {:#x}", asc_status);
            break;
        }

        // ASC returned SEC_E_OK — handshake is complete from the server's perspective.
        if asc_status == SEC_E_OK {
            println!("\n✓ Server returned SEC_E_OK. Handshake complete!");
            break;
        }

        // Safety: prevent infinite loops in case of protocol bugs.
        if round > 10 {
            eprintln!("Too many rounds (>{}) — aborting.", 10);
            break;
        }
    }

    // ╔════════════════════════════════════════════════════════════════════════╗
    // ║  Step 4: Query context attributes (SECPKG_ATTR_NAMES)                ║
    // ║                                                                      ║
    // ║  On successful handshake, query the SecPkgContext_NamesA/W structure  ║
    // ║  for both the client and server contexts. This returns the           ║
    // ║  authenticated user name associated with each security context.      ║
    // ╚════════════════════════════════════════════════════════════════════════╝
    if isc_status == SEC_E_OK || asc_status == SEC_E_OK {
        println!("\n=== Querying Context Attributes ===");
        query_and_print_context_names(provider, "Client", &client_ctx);
        query_and_print_context_names(provider, "Server", &server_ctx);
    }

    // ╔════════════════════════════════════════════════════════════════════════╗
    // ║  Step 5: Cleanup                                                     ║
    // ║                                                                      ║
    // ║  Delete security contexts and free credential handles to release     ║
    // ║  any resources held by the provider.                                 ║
    // ╚════════════════════════════════════════════════════════════════════════╝
    provider.delete_security_context(&client_ctx);
    provider.delete_security_context(&server_ctx);
    provider.free_credentials_handle(&client_cred);
    provider.free_credentials_handle(&server_cred);
    provider.shutdown();

    println!("\n{} handshake demo complete.\n", config.display_name);
}
