use provider_gatekeeper::{GateKeeperProvider, SecPkgInfoA, SecPkgInfoW, SecurityProvider};
use std::ffi::CStr;
mod utils;

use utils::wstr_from_ptr;

fn main() {
    let mut gk = GateKeeperProvider::new();
    gk.initialize();

    let mut pc_packages = 0;
    let mut pp_pkg_info: Vec<SecPkgInfoA> = Vec::new();
    gk.enumerate_security_packages_a(&mut pc_packages, &mut pp_pkg_info);

    println!("{} package(s) available:", pc_packages);
    for pkg in &pp_pkg_info {
        unsafe {
            let name = CStr::from_ptr(pkg.Name as *const i8).to_str().unwrap();
            let comment = CStr::from_ptr(pkg.Comment as *const i8).to_str().unwrap();
            println!("  Package: {} - {}", name, comment);
        }
    }

    // Now, we do the same with the wide string...
    let mut pc_packages = 0;
    let mut pp_pkg_info: Vec<SecPkgInfoW> = Vec::new();
    gk.enumerate_security_packages_w(&mut pc_packages, &mut pp_pkg_info);
    println!("{} package(s) available:", pc_packages);
    for pkg in &pp_pkg_info {
        unsafe {
            let name = wstr_from_ptr(pkg.Name as *const u16);
            let comment = wstr_from_ptr(pkg.Comment as *const u16);
            println!("  Package: {} - {}", name, comment);
        }
    }
}
