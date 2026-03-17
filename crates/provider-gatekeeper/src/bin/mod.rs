mod providers;
mod utils;
use providers::gatekeeper as gk;
use providers::gatekeeperpassport as gkp;
use providers::ntlm;

fn main() {
    gk::main();
    gkp::main();
    ntlm::main();
}
