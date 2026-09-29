//! Bounded stdout/stderr capture.
//!
//! A supervisor must keep reading a child's pipes — otherwise a workload that
//! writes more than the pipe buffer blocks forever — but it must also never let
//! a chatty workload exhaust its own memory. So reads continue while bytes past
//! the cap are discarded and the result is flagged as truncated.

use std::io::Read;
use std::thread::JoinHandle;

/// Per-stream cap. Past this, bytes are drained and dropped.
pub const MAX_CAPTURE_BYTES: usize = 8 * 1024 * 1024;

pub struct Captured {
    pub bytes: Vec<u8>,
    pub truncated: bool,
}

impl Captured {
    fn empty() -> Self {
        Self {
            bytes: Vec::new(),
            truncated: false,
        }
    }
}

/// Drain `pipe` on its own thread.
pub fn spawn_reader(mut pipe: impl Read + Send + 'static) -> JoinHandle<Captured> {
    std::thread::spawn(move || {
        let mut chunk = [0u8; 16 * 1024];
        let mut bytes = Vec::new();
        let mut truncated = false;
        loop {
            match pipe.read(&mut chunk) {
                Ok(0) | Err(_) => break,
                Ok(read) => {
                    let room = MAX_CAPTURE_BYTES.saturating_sub(bytes.len());
                    if room == 0 {
                        truncated = true;
                        continue;
                    }
                    let keep = room.min(read);
                    bytes.extend_from_slice(&chunk[..keep]);
                    truncated |= keep < read;
                }
            }
        }
        Captured { bytes, truncated }
    })
}

/// Join both reader threads, tolerating a panicked reader rather than failing
/// the whole `exec` because output could not be collected.
pub fn collect(
    stdout: Option<JoinHandle<Captured>>,
    stderr: Option<JoinHandle<Captured>>,
) -> (Vec<u8>, Vec<u8>, bool) {
    let out = stdout
        .and_then(|handle| handle.join().ok())
        .unwrap_or_else(Captured::empty);
    let err = stderr
        .and_then(|handle| handle.join().ok())
        .unwrap_or_else(Captured::empty);
    (out.bytes, err.bytes, out.truncated || err.truncated)
}
