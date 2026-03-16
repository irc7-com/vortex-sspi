mod providers;
mod utils;
use providers::gatekeeper as gk;
use providers::gatekeeperpassport as gkp;

fn main() {
    gk::main();
    gkp::main();
}
