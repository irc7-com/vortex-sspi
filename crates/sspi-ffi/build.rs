fn main() {
    // Only rerun this script if the lib.rs file changes
    println!("cargo:rerun-if-changed=src/lib.rs");

    csbindgen::Builder::new()
        .input_extern_file("src/lib.rs")
        .csharp_class_name("NativeMethods")
        .csharp_namespace("Vortex.Sspi")
        .csharp_dll_name("vortex_sspi") 
        .generate_csharp_file("../../dotnet/Vortex.Sspi/NativeMethods.g.cs")
        .expect("Failed to generate C# bindings");
}