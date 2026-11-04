//! WebExtensions native messaging framing: 4-byte native-endian length + JSON.

use std::io::{Read, Write};
use std::sync::Mutex;

use serde_json::Value;
use tokio::sync::mpsc;
use tracing::{debug, warn};

/// Firefox allows up to 4 GB browser -> host; we cap far lower.
const MAX_INCOMING: usize = 64 * 1024 * 1024;
/// Firefox rejects host -> browser messages above 1 MB.
const MAX_OUTGOING: usize = 1024 * 1024;

/// Reads framed JSON messages from stdin on a blocking thread.
pub fn spawn_stdin_reader() -> mpsc::Receiver<Value> {
    let (tx, rx) = mpsc::channel(32);
    std::thread::Builder::new()
        .name("stdin-reader".into())
        .spawn(move || {
            let stdin = std::io::stdin();
            let mut stdin = stdin.lock();
            loop {
                let mut len = [0u8; 4];
                if stdin.read_exact(&mut len).is_err() {
                    break;
                }
                let len = u32::from_ne_bytes(len) as usize;
                if len > MAX_INCOMING {
                    warn!(len, "incoming message too large; closing");
                    break;
                }
                let mut buf = vec![0u8; len];
                if stdin.read_exact(&mut buf).is_err() {
                    break;
                }
                match serde_json::from_slice::<Value>(&buf) {
                    Ok(v) => {
                        if tx.blocking_send(v).is_err() {
                            break;
                        }
                    }
                    Err(e) => warn!(%e, "ignoring malformed message"),
                }
            }
            debug!("stdin reader finished");
        })
        .expect("failed to spawn stdin reader thread");
    rx
}

/// Serialises framed JSON messages to stdout; safe to share between tasks.
pub struct Writer {
    stdout: Mutex<std::io::Stdout>,
}

impl Writer {
    pub fn new() -> Self {
        Self { stdout: Mutex::new(std::io::stdout()) }
    }

    pub fn send(&self, msg: &Value) {
        let bytes = match serde_json::to_vec(msg) {
            Ok(b) => b,
            Err(e) => {
                warn!(%e, "could not serialise outgoing message");
                return;
            }
        };
        if bytes.len() > MAX_OUTGOING {
            warn!(len = bytes.len(), "outgoing message exceeds the 1 MB limit; dropped");
            return;
        }
        let mut out = self.stdout.lock().unwrap_or_else(|p| p.into_inner());
        let len = (bytes.len() as u32).to_ne_bytes();
        let result = out
            .write_all(&len)
            .and_then(|_| out.write_all(&bytes))
            .and_then(|_| out.flush());
        if let Err(e) = result {
            warn!(%e, "could not write to stdout");
        }
    }
}
