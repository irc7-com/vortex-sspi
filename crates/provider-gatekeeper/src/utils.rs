/// Produces a null-terminated UTF-16 Vec<u16> from a string literal.
/// Equivalent to the `w!` macro in the `windows` crate.
#[macro_export]
macro_rules! w {
    ($s:literal) => {
        $s.encode_utf16()
            .chain(::std::iter::once(0u16))
            .collect::<Vec<u16>>()
    };
}

/// Produces a null-terminated UTF-8 CString from a string literal.
/// Equivalent to the `s!` macro in the `windows` crate.
#[macro_export]
macro_rules! s {
    ($s:literal) => {
        ::std::ffi::CString::new($s).unwrap()
    };
}
