mod providers;
mod utils;
use providers::gatekeeper as gk;
use providers::gatekeeperpassport as gkp;
#[cfg(target_os = "windows")]
use providers::ntlm;
#[cfg(target_os = "windows")]
use providers::ntlmpassport;
fn main() {
    gk::main();
    gkp::main();
    #[cfg(target_os = "windows")]
    ntlm::main();
    #[cfg(target_os = "windows")]
    ntlmpassport::main();
}
