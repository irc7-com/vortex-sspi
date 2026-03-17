#![allow(
    clippy::too_many_arguments,
    clippy::missing_safety_doc,
    clippy::manual_c_str_literals
)]

#[macro_use]
pub mod utils;
pub mod base_provider;
pub mod gatekeeper;
pub mod gatekeeper_passport;
pub mod gatekeeper_session_manager;
#[cfg(target_os = "windows")]
pub mod ntlm;
#[cfg(target_os = "windows")]
pub mod ntlm_passport;
pub mod passport;
pub mod passport_session_managers;
pub mod session_manager;

pub use base_provider::{BaseProvider, Handle, SecPkgInfoA, SecPkgInfoW, SecurityProvider};
pub use gatekeeper::GateKeeperProvider;
pub use gatekeeper_passport::GateKeeperPassportProvider;
#[cfg(target_os = "windows")]
pub use ntlm::NtlmProvider;
#[cfg(target_os = "windows")]
pub use ntlm_passport::NtlmPassportProvider;
pub use passport::PassportProvider;
pub use session_manager::SessionManager;
