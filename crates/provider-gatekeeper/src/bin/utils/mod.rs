use provider_gatekeeper::base_provider::SecBuffer;

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
