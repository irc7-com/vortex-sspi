use crate::base_provider::Handle;
use std::any::Any;

/// Equivalent to the CSessionManager vtable interface.
/// Matches the vtable dispatch in CSessionManager_Init / CSecurityProvider_Initialize.
pub trait SessionManager: Send + Sync + Any {
    /// CSessionManager::Init — initialize the session manager.
    /// Returns true on success, false on failure (triggers Shutdown).
    fn init(&mut self) -> bool;
    /// CSessionManager::Shutdown — called with arg=1 on init failure.
    fn shutdown(&mut self);

    /// Create a new session context. Matches slot 1 in CSessionManager_Vtable.
    fn create_context(&mut self) -> Option<Handle>;
    /// Find a session context by handle.
    fn find_session(&self, handle: &Handle) -> bool;
    /// Delete a session context by handle.
    fn delete_context(&mut self, handle: &Handle);

    /// Helper for downcasting.
    fn as_any(&self) -> &dyn Any;
    fn as_any_mut(&mut self) -> &mut dyn Any;
}
