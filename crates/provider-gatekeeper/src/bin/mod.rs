mod providers;
mod utils;
use providers::gatekeeper as gk;
use providers::gatekeeperpassport as gkp;
use providers::ntlm;
use providers::ntlmpassport;
fn main() {
    gk::main();
    gkp::main();
    ntlm::main();
    ntlmpassport::main();
}
