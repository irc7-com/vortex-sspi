#[repr(C)]
pub struct SspiResult {
    pub status: i32,
    pub out_ptr: *mut u8,
    pub out_len: u32,
}

/// # Safety
/// Caller must ensure that `input_ptr` is valid for `input_len` bytes and points to properly initialized memory.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn process_token(input_ptr: *const u8, input_len: u32) -> SspiResult {
    // 1. Read input from C#
    let input = unsafe { std::slice::from_raw_parts(input_ptr, input_len as usize) };

    // 2. Mock Logic: Just append a prefix to the input
    let mut response_data = b"MOCK_RESPONSE: ".to_vec();
    response_data.extend_from_slice(input);

    // 3. Prepare the buffer for C#
    // We must use Box to move the memory to the heap so it survives the function return
    let len = response_data.len() as u32;
    let ptr = response_data.as_mut_ptr();
    std::mem::forget(response_data); // Tell Rust not to deallocate this yet!

    SspiResult {
        status: 0, // SEC_E_OK
        out_ptr: ptr,
        out_len: len,
    }
}

/// # Safety
/// Caller must ensure that `ptr` and `len` match a previously allocated buffer from this library.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn free_buffer(ptr: *mut u8, len: u32) {
    if !ptr.is_null() {
        // Re-construct the Vec so it goes out of scope and drops the memory
        unsafe {
            let _ = Vec::from_raw_parts(ptr, len as usize, len as usize);
        }
    }
}
