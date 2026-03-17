use provider_gatekeeper::base_provider::{SecBuffer, SEC_E_OK};
use provider_gatekeeper::{Handle, SecPkgInfoA, SecPkgInfoW, SecurityProvider};
use std::ffi::CStr;
use windows_sys::Win32::Security::Authentication::Identity::{SecPkgContext_NamesA, SecPkgContext_NamesW};

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

/// Helper to format and print the results of a context initialization round.
pub fn print_round_results(round: u32, buffer: &SecBuffer, token: &[u8]) {
    println!("InitializeSecurityContextA (Round {}): Success", round);
    println!("Output Token Size: {} bytes", buffer.cbBuffer);
    println!("Output Token Hex Dump:");
    hexdump(&token[..buffer.cbBuffer as usize]);
}

/// Helper to decode capabilities bitmask into readable string formats.
pub fn format_capabilities(caps: u32) -> String {
    use windows_sys::Win32::Security::Authentication::Identity::*;
    let mut flags = Vec::new();
    
    if caps & SECPKG_FLAG_INTEGRITY != 0 { flags.push("INTEGRITY"); }
    if caps & SECPKG_FLAG_PRIVACY != 0 { flags.push("PRIVACY"); }
    if caps & SECPKG_FLAG_TOKEN_ONLY != 0 { flags.push("TOKEN_ONLY"); }
    if caps & SECPKG_FLAG_DATAGRAM != 0 { flags.push("DATAGRAM"); }
    if caps & SECPKG_FLAG_CONNECTION != 0 { flags.push("CONNECTION"); }
    if caps & SECPKG_FLAG_MULTI_REQUIRED != 0 { flags.push("MULTI_REQUIRED"); }
    if caps & SECPKG_FLAG_CLIENT_ONLY != 0 { flags.push("CLIENT_ONLY"); }
    if caps & SECPKG_FLAG_EXTENDED_ERROR != 0 { flags.push("EXTENDED_ERROR"); }
    if caps & SECPKG_FLAG_IMPERSONATION != 0 { flags.push("IMPERSONATION"); }
    if caps & SECPKG_FLAG_ACCEPT_WIN32_NAME != 0 { flags.push("ACCEPT_WIN32_NAME"); }
    if caps & SECPKG_FLAG_STREAM != 0 { flags.push("STREAM"); }
    if caps & SECPKG_FLAG_NEGOTIABLE != 0 { flags.push("NEGOTIABLE"); }
    if caps & SECPKG_FLAG_GSS_COMPATIBLE != 0 { flags.push("GSS_COMPATIBLE"); }
    if caps & SECPKG_FLAG_LOGON != 0 { flags.push("LOGON"); }
    if caps & SECPKG_FLAG_ASCII_BUFFERS != 0 { flags.push("ASCII_BUFFERS"); }
    if caps & SECPKG_FLAG_FRAGMENT != 0 { flags.push("FRAGMENT"); }
    if caps & SECPKG_FLAG_MUTUAL_AUTH != 0 { flags.push("MUTUAL_AUTH"); }
    if caps & SECPKG_FLAG_DELEGATION != 0 { flags.push("DELEGATION"); }
    if caps & SECPKG_FLAG_READONLY_WITH_CHECKSUM != 0 { flags.push("READONLY_WITH_CHECKSUM"); }
    if caps & SECPKG_FLAG_RESTRICTED_TOKENS != 0 { flags.push("RESTRICTED_TOKENS"); }
    if caps & SECPKG_FLAG_NEGO_EXTENDER != 0 { flags.push("NEGO_EXTENDER"); }
    if caps & SECPKG_FLAG_NEGOTIABLE2 != 0 { flags.push("NEGOTIABLE2"); }
    if caps & SECPKG_FLAG_APPCONTAINER_CHECKS != 0 { flags.push("APPCONTAINER_CHECKS"); }
    if caps & SECPKG_FLAG_APPCONTAINER_PASSTHROUGH != 0 { flags.push("APPCONTAINER_PASSTHROUGH"); }
    
    if flags.is_empty() {
        return "None".to_string();
    }
    
    flags.join(" | ")
}

/// Helper to print SSPI package information.
pub fn enumerate_and_print_packages(gk: &impl SecurityProvider) {
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
                    "    Capabilities: {:#x} ({}), MaxToken: {}",
                    pkg.fCapabilities,
                    format_capabilities(pkg.fCapabilities),
                    pkg.cbMaxToken
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
                    "    Capabilities: {:#x} ({}), MaxToken: {}",
                    pkg.fCapabilities,
                    format_capabilities(pkg.fCapabilities),
                    pkg.cbMaxToken
                );
            }
        }
    }
}

/// Helper to query and print context attributes for both ANSI and Wide versions.
pub fn query_and_print_context_attributes(gk: &impl SecurityProvider, h_context: &Handle) {
    // --- Query Context Attributes (SECPKG_ATTR_NAMES) ---
    println!("\n=== Querying Context Attributes (SECPKG_ATTR_NAMES) ===");
    let mut names_ctx = SecPkgContext_NamesA {
        sUserName: std::ptr::null_mut(),
    };
    let res = gk.query_context_attributes_a(
        h_context,
        1, // SECPKG_ATTR_NAMES
        &mut names_ctx as *mut _ as usize,
    );
    if res == SEC_E_OK {
        if !names_ctx.sUserName.is_null() {
            let name_str = unsafe { CStr::from_ptr(names_ctx.sUserName).to_string_lossy() };
            println!("  Context Name: {}", name_str);
            gk.free_context_buffer(names_ctx.sUserName as usize);
            println!("  Context buffer successfully freed.\n");
        } else {
            println!("  QueryContextAttributes successful (SEC_E_OK) but returned null pointer.\n");
        }
    } else {
        println!("  Failed to query SECPKG_ATTR_NAMES. Status: {:#x}\n", res);
    }

    // --- Query Context Attributes (SECPKG_ATTR_NAMES) (WIDE) ---
    println!("=== Querying Context Attributes (SECPKG_ATTR_NAMES (WIDE)) ===");
    let mut names_ctx_w = SecPkgContext_NamesW {
        sUserName: std::ptr::null_mut(),
    };
    let res_w = gk.query_context_attributes_w(
        h_context,
        1, // SECPKG_ATTR_NAMES
        &mut names_ctx_w as *mut _ as usize,
    );
    if res_w == SEC_E_OK {
        if !names_ctx_w.sUserName.is_null() {
            let name_str = unsafe { wstr_from_ptr(names_ctx_w.sUserName) };
            println!("  Context Name: {}", name_str);
            gk.free_context_buffer(names_ctx_w.sUserName as usize);
            println!("  Context buffer successfully freed.\n");
        } else {
            println!("  QueryContextAttributes successful (SEC_E_OK) but returned null pointer.\n");
        }
    } else {
        println!("  Failed to query SECPKG_ATTR_NAMES (WIDE). Status: {:#x}\n", res_w);
    }
}
