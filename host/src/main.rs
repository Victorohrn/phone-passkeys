//! Native messaging host for the Phone Passkeys extension.
//!
//! Speaks the WebExtensions native messaging protocol on stdin/stdout
//! (4-byte native-endian length prefix + JSON) and runs WebAuthn hybrid
//! ("use your phone") ceremonies with libwebauthn:
//!
//! browser -> host:
//!   {"type":"ping"}
//!   {"type":"start","id":"…","cmd":"get"|"create","origin":"https://…",
//!    "topOrigin":"https://…"?, "options":{…WebAuthn JSON options…}}
//!   {"type":"cancel","id":"…"}
//!
//! host -> browser:
//!   {"type":"pong","version":"…","bluetooth":true|false}
//!   {"type":"qr","id":"…","fido":"FIDO:/…","svg":"<svg…>"}
//!   {"type":"state","id":"…","state":"waiting"|"connecting"|"connected"|"restarting","detail":"…"?}
//!   {"type":"result","id":"…","credential":{…WebAuthn JSON credential…}}
//!   {"type":"error","id":"…","name":"<DOMException name>","message":"…"}
//!
//! One request runs at a time; the host exits when stdin closes.

mod ceremony;
mod messaging;
mod qr;
mod suffix_list;

use std::sync::Arc;
use std::time::Duration;

use libwebauthn::ops::webauthn::psl::PublicSuffixList;
use serde_json::{json, Value};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};
use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter, Layer};

use messaging::Writer;

struct Active {
    id: String,
    cancel: CancellationToken,
    handle: tokio::task::JoinHandle<()>,
}

#[tokio::main]
async fn main() {
    init_logging();
    info!(version = env!("CARGO_PKG_VERSION"), pid = std::process::id(), "phone-passkeys-host starting");

    let writer = Arc::new(Writer::new());
    let psl: Arc<dyn PublicSuffixList> = Arc::from(suffix_list::load());
    let mut incoming = messaging::spawn_stdin_reader();
    let (done_tx, mut done_rx) = mpsc::channel::<String>(4);
    let mut active: Option<Active> = None;

    loop {
        tokio::select! {
            msg = incoming.recv() => match msg {
                None => {
                    info!("stdin closed, shutting down");
                    break;
                }
                Some(v) => handle_message(v, &writer, &psl, &done_tx, &mut active).await,
            },
            Some(finished) = done_rx.recv() => {
                if active.as_ref().map(|a| a.id == finished).unwrap_or(false) {
                    active = None;
                }
            }
        }
    }

    if let Some(a) = active.take() {
        a.cancel.cancel();
        // Let the ceremony tell the phone the session ended before we exit.
        let _ = tokio::time::timeout(Duration::from_secs(3), a.handle).await;
    }
}

async fn handle_message(
    v: Value,
    writer: &Arc<Writer>,
    psl: &Arc<dyn PublicSuffixList>,
    done_tx: &mpsc::Sender<String>,
    active: &mut Option<Active>,
) {
    let kind = v.get("type").and_then(Value::as_str).unwrap_or("");
    match kind {
        "ping" => {
            let bluetooth = libwebauthn::transport::hybrid::is_available().await;
            writer.send(&json!({
                "type": "pong",
                "version": env!("CARGO_PKG_VERSION"),
                "bluetooth": bluetooth,
            }));
        }
        "start" => {
            let id = v.get("id").and_then(Value::as_str).unwrap_or("").to_string();
            if active.as_ref().map(|a| !a.handle.is_finished()).unwrap_or(false) {
                writer.send(&json!({
                    "type": "error", "id": id, "name": "NotAllowedError",
                    "message": "Another passkey request is already in progress.",
                }));
                return;
            }
            match serde_json::from_value::<ceremony::StartRequest>(v) {
                Ok(req) => {
                    let cancel = CancellationToken::new();
                    let task_id = id.clone();
                    let (psl, writer, done_tx, token) =
                        (psl.clone(), writer.clone(), done_tx.clone(), cancel.clone());
                    let handle = tokio::spawn(async move {
                        ceremony::run(req, psl, writer, token).await;
                        let _ = done_tx.send(task_id).await;
                    });
                    *active = Some(Active { id, cancel, handle });
                }
                Err(e) => writer.send(&json!({
                    "type": "error", "id": id, "name": "EncodingError",
                    "message": format!("invalid request: {e}"),
                })),
            }
        }
        "cancel" => {
            let id = v.get("id").and_then(Value::as_str).unwrap_or("");
            if let Some(a) = active.as_ref() {
                if id.is_empty() || a.id == id {
                    a.cancel.cancel();
                }
            }
        }
        other => warn!(%other, "ignoring unknown message type"),
    }
}

/// Logs go to stderr (the browser shows it in the Browser Console) at the level
/// in `PHONE_PASSKEYS_LOG`, default `info`. Browsers start the host without a
/// controllable environment, so a debug log file can be switched on by creating
/// `~/.config/phone-passkeys/debug`; it is appended to
/// `~/.cache/phone-passkeys/host.log`.
fn init_logging() {
    let stderr_filter =
        EnvFilter::try_from_env("PHONE_PASSKEYS_LOG").unwrap_or_else(|_| EnvFilter::new("info"));
    let stderr_layer = fmt::layer().with_writer(std::io::stderr).with_filter(stderr_filter);
    let file_layer = debug_log_file().map(|file| {
        fmt::layer()
            .with_writer(std::sync::Mutex::new(file))
            .with_ansi(false)
            .with_filter(EnvFilter::new(
                "debug,libwebauthn::proto=trace,libwebauthn::ops::webauthn::large_blob=trace,pxp::protocol=trace,hyper=info,hyper_util=info,h2=info,rustls=info,reqwest=info,tungstenite=info,tokio_tungstenite=info,zbus=info,tracing=info",
            ))
    });
    tracing_subscriber::registry().with(stderr_layer).with(file_layer).init();
}

fn debug_log_file() -> Option<std::fs::File> {
    use std::path::PathBuf;
    let home = PathBuf::from(std::env::var_os("HOME")?);
    let config_dir = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| home.join(".config"));
    if !config_dir.join("phone-passkeys").join("debug").exists() {
        return None;
    }
    let cache_dir = std::env::var_os("XDG_CACHE_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| home.join(".cache"))
        .join("phone-passkeys");
    std::fs::create_dir_all(&cache_dir).ok()?;
    std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(cache_dir.join("host.log"))
        .ok()
}
