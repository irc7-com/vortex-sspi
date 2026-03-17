use crate::base_provider::Handle;
use crate::session_manager::SessionManager;
use parking_lot::{Mutex, ReentrantMutex};
use std::any::Any;
use std::collections::HashMap;
use std::sync::Arc;
use windows_sys::core::GUID;

/// Equivalent to CGateKeeperSession C++ class.
/// Size: 120 bytes (0x78)
pub struct GateKeeperSession {
    /// Offset 0x04: hContext (Handle)
    pub handle: Handle,
    /// Offset 0x0C: dwFlags
    pub flags: u32,
    /// Offset 0x14: ServerNonce (8 bytes)
    pub server_nonce: [u8; 8],
    /// Offset 0x2B: HMAC result (16 bytes)
    pub hmac_result: [u8; 16],
    /// Offset 0x3C: GateKeeperID (GUID/16 bytes)
    pub gatekeeper_id: GUID,
    /// Offset 0x4C: szHostname (16 bytes, ANSI, max 15 chars)
    pub hostname: [u8; 16],
    /// Offset 0x5C: cbHostname (Actual length)
    pub hostname_len: u32,
    /// Offset 0x60: HMAC key (16 bytes)
    pub hmac_key: [u8; 16],
    /// Offset 0x70: bVersionFlag
    pub version_flag: u8,
}

impl GateKeeperSession {
    pub fn new(id: [u8; 8], index: u32) -> Self {
        Self {
            handle: Handle {
                lower: (id[0] as usize)
                    | ((id[1] as usize) << 8)
                    | ((id[2] as usize) << 16)
                    | ((id[3] as usize) << 24), // Placeholder
                upper: index as usize,
            },
            flags: 0,
            server_nonce: [0; 8],
            hmac_result: [0; 16],
            gatekeeper_id: GUID {
                data1: 0,
                data2: 0,
                data3: 0,
                data4: [0; 8],
            },
            hostname: [0; 16],
            hostname_len: 0,
            hmac_key: [
                0x53, 0x52, 0x46, 0x4D, 0x4B, 0x53, 0x4A, 0x41, 0x4E, 0x44, 0x52, 0x45, 0x53, 0x4B,
                0x4B, 0x43, // Translates to the ASCII string "SRFMKSJANDRESKKC"
            ],
            version_flag: 0,
        }
    }
}

/// Equivalent to CGateKeeperSessionManager C++ class.
pub struct GateKeeperSessionManager {
    /// Offset 0x04: CriticalSection (24 bytes)
    pub lock: ReentrantMutex<()>,
    /// Offset 0x1C: dword_1C
    pub field_1c: u32,
    /// Offset 0x20: dword_20
    pub field_20: u32,
    /// Offset 0x24: dword_24
    pub field_24: u32,
    /// Offset 0x28: dword_28 (ref count or sequence?)
    pub field_28: u32,

    /// Internal storage for sessions (mirrors the pool of 8 slots in C++)
    pub sessions: HashMap<u32, Arc<Mutex<GateKeeperSession>>>,
}

impl Default for GateKeeperSessionManager {
    fn default() -> Self {
        Self::new()
    }
}

impl GateKeeperSessionManager {
    pub fn new() -> Self {
        Self {
            lock: ReentrantMutex::new(()),
            field_1c: 0,
            field_20: 0,
            field_24: 0,
            field_28: 0,
            sessions: HashMap::new(),
        }
    }

    pub fn get_session(&self, handle: &Handle) -> Option<Arc<Mutex<GateKeeperSession>>> {
        let _lock = self.lock.lock();
        self.sessions.get(&(handle.upper as u32)).cloned()
    }
}

impl SessionManager for GateKeeperSessionManager {
    fn init(&mut self) -> bool {
        true
    }

    fn shutdown(&mut self) {
        self.sessions.clear();
    }

    fn create_context(&mut self) -> Option<Handle> {
        let _lock = self.lock.lock();
        if self.sessions.len() >= 8 {
            return None;
        }

        let index = (0..8).find(|i| !self.sessions.contains_key(i))?;
        let session = Arc::new(Mutex::new(GateKeeperSession::new(
            [0xAA, 0xBB, 0xCC, 0xDD, 0x11, 0x22, 0x33, 0x44],
            index,
        )));
        let handle = session.lock().handle;
        self.sessions.insert(index, session);
        Some(handle)
    }

    fn find_session(&self, handle: &Handle) -> bool {
        let _lock = self.lock.lock();
        self.sessions.contains_key(&(handle.upper as u32))
    }

    fn delete_context(&mut self, handle: &Handle) {
        let _lock = self.lock.lock();
        self.sessions.remove(&(handle.upper as u32));
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }
}
