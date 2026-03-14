use sspi::{CredentialUse, Ntlm, Sspi};

fn main() {
    let mut ntlm = Ntlm::new();
    let _acq_result = ntlm
        .acquire_credentials_handle()
        .with_credential_use(CredentialUse::Inbound)
        .execute(&mut ntlm)
        .unwrap();

    println!("Context initialized.");

    // Test Type 1
    // (We can't easily generate a real Type 1 without client, but we can compile this code)
    println!("Compiled successfully.");
}
