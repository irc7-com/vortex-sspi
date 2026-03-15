use crate::base_provider::Handle;
use crate::session_manager::SessionManager;
use parking_lot::{Mutex, ReentrantMutex};
use std::any::Any;
use std::collections::HashMap;
use std::sync::Arc;

/// Equivalent to CGateKeeperPassportSession C++ struct.
pub struct GateKeeperPassportSession {
    pub handle: Handle,
    /// Arrays of 2 Handles at offset 16 and 24
    pub sub_contexts: [Handle; 2],
    /// Offset 32: State
    pub state: u32,
    /// Offset 36: Saved token buffer
    pub saved_token: Vec<u8>,
}

impl GateKeeperPassportSession {
    pub fn new(handle: Handle) -> Self {
        Self {
            handle,
            sub_contexts: [Handle::default(), Handle::default()],
            state: 160, // Initial state
            saved_token: Vec::new(),
        }
    }
}

/// Equivalent to CPassportSession C++ struct.
pub struct PassportSession {
    pub handle: Handle,
    /// Offset 1280: Buffer for saved token data
    pub buffer: Vec<u8>,
    /// Offset 2316: Client info string (max 100)
    pub client_info: String,
    /// Offset 2424: Flag (0 = has more data, 1 = no more data)
    pub is_done: bool,
}

impl PassportSession {
    pub fn new(handle: Handle) -> Self {
        Self {
            handle,
            buffer: Vec::new(),
            client_info: String::new(),
            is_done: false,
        }
    }
}

/// Equivalent to CPassportSessionManager C++ class.
pub struct PassportSessionManager {
    pub inner: Mutex<PassportSessionManagerInner>,
}

pub struct PassportSessionManagerInner {
    pub sessions: HashMap<Handle, Arc<Mutex<PassportSession>>>,
    pub next_handle: u32,
}

impl PassportSessionManager {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(PassportSessionManagerInner {
                sessions: HashMap::new(),
                next_handle: 1,
            }),
        }
    }

    pub fn get_session(&self, handle: &Handle) -> Option<Arc<Mutex<PassportSession>>> {
        self.inner.lock().sessions.get(handle).cloned()
    }
}

impl SessionManager for PassportSessionManager {
    fn init(&mut self) -> bool {
        true
    }
    fn shutdown(&mut self) {}

    fn create_context(&mut self) -> Option<Handle> {
        let mut inner = self.inner.lock();
        if inner.sessions.len() >= 8 {
            return None;
        }

        let handle = Handle {
            lower: 0x13572468, // Placeholder base
            upper: inner.next_handle as usize,
        };
        inner.next_handle += 1;

        let session = Arc::new(Mutex::new(PassportSession::new(handle)));
        inner.sessions.insert(handle, session);

        Some(handle)
    }

    fn find_session(&self, handle: &Handle) -> bool {
        self.inner.lock().sessions.contains_key(handle)
    }

    fn delete_context(&mut self, handle: &Handle) {
        self.inner.lock().sessions.remove(handle);
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }
}

/// Equivalent to CNTLMPassportSession C++ struct.
pub struct NtlmPassportSession {
    pub handle: Handle,
    pub sub_contexts: [Handle; 2],
    pub state: u32,
    pub saved_token: Vec<u8>,
}

impl NtlmPassportSession {
    pub fn new(handle: Handle) -> Self {
        Self {
            handle,
            sub_contexts: [Handle::default(), Handle::default()],
            state: 160,
            saved_token: Vec::new(),
        }
    }
}

/// Equivalent to CNTLMPassportSessionManager C++ class.
pub struct NtlmPassportSessionManager {
    pub inner: Mutex<NtlmPassportSessionManagerInner>,
}

pub struct NtlmPassportSessionManagerInner {
    pub sessions: HashMap<Handle, Arc<Mutex<NtlmPassportSession>>>,
    pub next_handle: u32,
}

impl NtlmPassportSessionManager {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(NtlmPassportSessionManagerInner {
                sessions: HashMap::new(),
                next_handle: 1,
            }),
        }
    }

    pub fn get_session(&self, handle: &Handle) -> Option<Arc<Mutex<NtlmPassportSession>>> {
        self.inner.lock().sessions.get(handle).cloned()
    }
}

impl SessionManager for NtlmPassportSessionManager {
    fn init(&mut self) -> bool {
        true
    }
    fn shutdown(&mut self) {}

    fn create_context(&mut self) -> Option<Handle> {
        let mut inner = self.inner.lock();
        if inner.sessions.len() >= 8 {
            return None;
        }

        let handle = Handle {
            lower: 0x87654321, // Placeholder base
            upper: inner.next_handle as usize,
        };
        inner.next_handle += 1;

        let session = Arc::new(Mutex::new(NtlmPassportSession::new(handle)));
        inner.sessions.insert(handle, session);

        Some(handle)
    }

    fn find_session(&self, handle: &Handle) -> bool {
        self.inner.lock().sessions.contains_key(handle)
    }

    fn delete_context(&mut self, handle: &Handle) {
        self.inner.lock().sessions.remove(handle);
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }
}

/// Equivalent to CGateKeeperPassportSessionManager C++ class.
pub struct GateKeeperPassportSessionManager {
    pub inner: Mutex<GateKeeperPassportSessionManagerInner>,
}

pub struct GateKeeperPassportSessionManagerInner {
    pub sessions: HashMap<Handle, Arc<Mutex<GateKeeperPassportSession>>>,
    pub next_handle: u32,
}

impl GateKeeperPassportSessionManager {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(GateKeeperPassportSessionManagerInner {
                sessions: HashMap::new(),
                next_handle: 1,
            }),
        }
    }

    pub fn get_session(&self, handle: &Handle) -> Option<Arc<Mutex<GateKeeperPassportSession>>> {
        self.inner.lock().sessions.get(handle).cloned()
    }
}

impl SessionManager for GateKeeperPassportSessionManager {
    fn init(&mut self) -> bool {
        true
    }
    fn shutdown(&mut self) {}

    fn create_context(&mut self) -> Option<Handle> {
        let mut inner = self.inner.lock();
        if inner.sessions.len() >= 8 {
            return None;
        }

        let handle = Handle {
            lower: 0x12345678, // Placeholder base
            upper: inner.next_handle as usize,
        };
        inner.next_handle += 1;

        let session = Arc::new(Mutex::new(GateKeeperPassportSession::new(handle)));
        inner.sessions.insert(handle, session);

        Some(handle)
    }

    fn find_session(&self, handle: &Handle) -> bool {
        self.inner.lock().sessions.contains_key(handle)
    }

    fn delete_context(&mut self, handle: &Handle) {
        self.inner.lock().sessions.remove(handle);
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }
}
