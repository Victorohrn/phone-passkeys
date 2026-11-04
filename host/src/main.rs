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
use tracing_subscriber::EnvFilter;

use messaging::Writer;

struct Active {
    id: String,
    cancel: CancellationToken,
    handle: tokio::task::JoinHandle<()>,
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_env("PHONE_PASSKEYS_LOG").unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_writer(std::io::stderr)
        .init();
    info!(version = env!("CARGO_PKG_VERSION"), "phone-passkeys-host starting");

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
