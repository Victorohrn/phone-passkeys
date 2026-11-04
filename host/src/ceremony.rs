//! Runs one WebAuthn hybrid ceremony: QR code -> BLE proximity check ->
//! tunnel to the phone -> CTAP2 makeCredential / getAssertion.

use std::sync::Arc;
use std::time::Duration;

use libwebauthn::ops::webauthn::psl::PublicSuffixList;
use libwebauthn::ops::webauthn::related_origins::{
    MaxRegistrableLabels, RelatedOrigins, ReqwestRelatedOriginsSource,
};
use libwebauthn::ops::webauthn::{
    GetAssertionPrepareError, GetAssertionRequest, MakeCredentialPrepareError,
    MakeCredentialRequest, Origin, OriginValidation, RequestOrigin, RequestSettings,
    WebAuthnIDLResponse,
};
use libwebauthn::proto::CtapError;
use libwebauthn::transport::hybrid::channel::{HybridUxUpdate, PxpUpdate};
use libwebauthn::transport::hybrid::error::PxpError;
use libwebauthn::transport::hybrid::qr_code_device::{
    PxpQrCodeDevice, PxpTransports, QrCodeOperationHint,
};
use libwebauthn::transport::{Channel, ChannelSettings, Device};
use libwebauthn::webauthn::error::{PlatformError, WebAuthnError};
use libwebauthn::webauthn::WebAuthn;
use libwebauthn::UvUpdate;
use serde::Deserialize;
use serde_json::{json, Value};
use tokio::sync::broadcast;
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use crate::messaging::Writer;

#[derive(Debug, Deserialize)]
pub struct StartRequest {
    pub id: String,
    pub cmd: String,
    pub origin: String,
    #[serde(default, rename = "topOrigin")]
    pub top_origin: Option<String>,
    pub options: Value,
}

/// Relying parties often ask for 60 s, but a person needs longer than that to
/// unlock a phone, open the camera and scan. Browsers clamp too.
const MIN_TIMEOUT: Duration = Duration::from_secs(120);
const MAX_TIMEOUT: Duration = Duration::from_secs(10 * 60);
/// How many fresh QR codes to issue after transport-level failures.
const MAX_ATTEMPTS: u32 = 5;

/// A failure reported to the page as a DOMException.
#[derive(Debug)]
pub struct Failure {
    pub name: &'static str,
    pub message: String,
}

impl Failure {
    fn new(name: &'static str, message: impl Into<String>) -> Self {
        Self { name, message: message.into() }
    }
}

enum Outcome {
    /// Report to the page and stop.
    Fatal(Failure),
    /// Transport-level trouble: issue a new QR code and try again.
    Retry(String),
}

enum Prepared {
    Create(MakeCredentialRequest),
    Get(GetAssertionRequest),
}

impl Prepared {
    fn timeout(&self) -> Duration {
        match self {
            Prepared::Create(r) => r.timeout,
            Prepared::Get(r) => r.timeout,
        }
    }

    fn hint(&self) -> QrCodeOperationHint {
        match self {
            Prepared::Create(_) => QrCodeOperationHint::MakeCredential,
            Prepared::Get(_) => QrCodeOperationHint::GetAssertionRequest,
        }
    }

    fn rp_id(&self) -> &str {
        match self {
            Prepared::Create(r) => r.relying_party.id.as_str(),
            Prepared::Get(r) => r.relying_party_id.as_str(),
        }
    }
}

pub async fn run(
    req: StartRequest,
    psl: Arc<dyn PublicSuffixList>,
    writer: Arc<Writer>,
    cancel: CancellationToken,
) {
    let id = req.id.clone();
    match run_inner(req, psl, &writer, &cancel).await {
        Ok(credential) => {
            info!("ceremony completed");
            writer.send(&json!({ "type": "result", "id": id, "credential": credential }));
        }
        Err(failure) => {
            warn!(name = failure.name, message = %failure.message, "ceremony failed");
            writer.send(&json!({
                "type": "error", "id": id, "name": failure.name, "message": failure.message,
            }));
        }
    }
}

async fn run_inner(
    req: StartRequest,
    psl: Arc<dyn PublicSuffixList>,
    writer: &Arc<Writer>,
    cancel: &CancellationToken,
) -> Result<Value, Failure> {
    if !libwebauthn::transport::hybrid::is_available().await {
        return Err(Failure::new(
            "NotSupportedError",
            "No Bluetooth adapter is available. The phone passkey flow needs Bluetooth to confirm the phone is nearby.",
        ));
    }

    let request_origin = parse_origin(&req.origin, req.top_origin.as_deref())?;

    // Related Origin Requests (WebAuthn L3 §5.11): lets e.g. example.co.uk use
    // a passkey registered for example.com when the RP publishes
    // /.well-known/webauthn, like Chrome does.
    let related_origins_source = match ReqwestRelatedOriginsSource::new() {
        Ok(source) => Some(source),
        Err(err) => {
            warn!(%err, "related origins disabled");
            None
        }
    };
    let settings = RequestSettings {
        origin: OriginValidation::Validate {
            public_suffix_list: psl.as_ref(),
            related_origins: match related_origins_source.as_ref() {
                Some(source) => RelatedOrigins::Enabled {
                    source,
                    max_labels: MaxRegistrableLabels::default(),
                },
                None => RelatedOrigins::Disabled,
            },
        },
    };

    let options_json = serde_json::to_string(&req.options)
        .map_err(|e| Failure::new("EncodingError", format!("invalid options: {e}")))?;
    let prepared = match req.cmd.as_str() {
        "create" => Prepared::Create(
            MakeCredentialRequest::prepare(&request_origin, &options_json, &settings)
                .await
                .map_err(map_create_prepare_error)?,
        ),
        "get" => Prepared::Get(
            GetAssertionRequest::prepare(&request_origin, &options_json, &settings)
                .await
                .map_err(map_get_prepare_error)?,
        ),
        other => {
            return Err(Failure::new("NotSupportedError", format!("unknown command: {other}")));
        }
    };
    info!(cmd = %req.cmd, origin = %req.origin, rp_id = prepared.rp_id(), "request prepared");
    debug!(top_origin = ?req.top_origin, options = %options_json, "request options as received");
    match &prepared {
        Prepared::Create(r) => debug!(request = ?r, client_data = %r.client_data_json(), "prepared create request"),
        Prepared::Get(r) => debug!(request = ?r, client_data = %r.client_data_json(), "prepared get request"),
    }

    let timeout = prepared.timeout().clamp(MIN_TIMEOUT, MAX_TIMEOUT);
    let deadline = Instant::now() + timeout;
    let hint = prepared.hint();
    let is_create = matches!(prepared, Prepared::Create(_));

    let mut attempts = 0;
    loop {
        attempts += 1;
        // Each attempt gets a fresh key pair and QR secret.
        let mut device = PxpQrCodeDevice::new_transient(hint, PxpTransports::CloudAssistedOnly)
            .map_err(|e| Failure::new("UnknownError", format!("could not create the QR code: {e:?}")))?;
        let fido = device.qr_code.to_string();
        let svg = crate::qr::render_svg(&fido)
            .map_err(|e| Failure::new("UnknownError", format!("could not render the QR code: {e}")))?;
        writer.send(&json!({ "type": "qr", "id": req.id, "fido": fido, "svg": svg }));
        send_state(writer, &req.id, "waiting", None);

        match attempt(&mut device, &prepared, &req.id, writer, cancel, deadline).await {
            Ok(credential) => {
                let credential = finalize(is_create, credential);
                debug!(credential = %credential, "credential returned to the browser");
                return Ok(credential);
            }
            Err(Outcome::Fatal(failure)) => return Err(failure),
            Err(Outcome::Retry(reason)) => {
                if attempts >= MAX_ATTEMPTS || Instant::now() >= deadline {
                    return Err(Failure::new(
                        "NotAllowedError",
                        format!("Could not connect to the phone: {reason}"),
                    ));
                }
                warn!(%reason, attempt = attempts, "hybrid attempt failed; issuing a new QR code");
                send_state(writer, &req.id, "restarting", Some(&reason));
                tokio::select! {
                    _ = tokio::time::sleep(Duration::from_millis(1200)) => {}
                    _ = cancel.cancelled() => {
                        return Err(Failure::new("AbortError", "The operation was cancelled."));
                    }
                }
            }
        }
    }
}

/// One QR code's worth of ceremony: open the channel (BLE advert wait, tunnel,
/// Noise handshake happen lazily inside), run the CTAP operation, close.
async fn attempt(
    device: &mut PxpQrCodeDevice,
    prepared: &Prepared,
    id: &str,
    writer: &Arc<Writer>,
    cancel: &CancellationToken,
    deadline: Instant,
) -> Result<Value, Outcome> {
    let mut channel = device
        .channel(ChannelSettings::default())
        .await
        .map_err(|e| Outcome::Retry(format!("could not open the hybrid channel: {e}")))?;
    let forwarder = tokio::spawn(forward_updates(
        channel.get_ux_update_receiver(),
        id.to_string(),
        writer.clone(),
    ));

    let outcome = {
        let operation = async {
            loop {
                let step: Result<Result<Value, Outcome>, WebAuthnError<PxpError>> = match prepared {
                    Prepared::Create(request) => {
                        channel.webauthn_make_credential(request).await.map(|response| {
                            response.to_json_value(request).map_err(|e| {
                                Outcome::Fatal(Failure::new(
                                    "UnknownError",
                                    format!("could not serialise the credential: {e}"),
                                ))
                            })
                        })
                    }
                    Prepared::Get(request) => {
                        channel.webauthn_get_assertion(request).await.map(|response| {
                            let assertion = response.assertions.first().ok_or_else(|| {
                                Outcome::Fatal(Failure::new(
                                    "NotAllowedError",
                                    "The phone returned no assertion.",
                                ))
                            })?;
                            assertion.to_json_value(request).map_err(|e| {
                                Outcome::Fatal(Failure::new(
                                    "UnknownError",
                                    format!("could not serialise the assertion: {e}"),
                                ))
                            })
                        })
                    }
                };
                match step {
                    Ok(result) => break result,
                    Err(WebAuthnError::Ctap(err)) if err.is_retryable_user_error() => {
                        debug!(%err, "retryable user error; asking the phone again");
                        continue;
                    }
                    Err(err) => break Err(map_webauthn_error(err)),
                }
            }
        };

        tokio::select! {
            result = operation => Some(result),
            _ = cancel.cancelled() => None,
            _ = tokio::time::sleep_until(deadline) => Some(Err(Outcome::Fatal(
                Failure::new("NotAllowedError", "The operation timed out."),
            ))),
        }
    };

    // Always shut the tunnel down cleanly so the phone does not show an error.
    channel.close().await;
    forwarder.abort();

    match outcome {
        Some(result) => result,
        None => Err(Outcome::Fatal(Failure::new("AbortError", "The operation was cancelled."))),
    }
}

async fn forward_updates(
    mut rx: broadcast::Receiver<HybridUxUpdate>,
    id: String,
    writer: Arc<Writer>,
) {
    loop {
        match rx.recv().await {
            Ok(HybridUxUpdate::PxpUpdate(update)) => {
                info!(?update, "hybrid transport update");
                #[allow(unreachable_patterns)]
                match update {
                    PxpUpdate::ProximityCheck => send_state(&writer, &id, "waiting", None),
                    PxpUpdate::Connecting | PxpUpdate::Authenticating => {
                        send_state(&writer, &id, "connecting", None)
                    }
                    PxpUpdate::Connected => send_state(&writer, &id, "connected", None),
                    PxpUpdate::Error(err) => debug!(?err, "hybrid transport reported an error"),
                    _ => {}
                }
            }
            Ok(HybridUxUpdate::UvUpdate(update)) => {
                #[allow(unreachable_patterns)]
                match update {
                    UvUpdate::PresenceRequired => send_state(&writer, &id, "connected", None),
                    UvUpdate::PinRequired(req) => {
                        warn!("the phone asked for a client PIN, which hybrid does not use; cancelling");
                        req.cancel();
                    }
                    UvUpdate::PinNotSet(req) => {
                        warn!("the phone asked to set a client PIN, which hybrid does not use; cancelling");
                        req.cancel();
                    }
                    UvUpdate::UvRetry { attempts_left } => {
                        debug!(?attempts_left, "user verification retry")
                    }
                    _ => {}
                }
            }
            Err(broadcast::error::RecvError::Lagged(_)) => continue,
            Err(broadcast::error::RecvError::Closed) => break,
        }
    }
}

fn send_state(writer: &Writer, id: &str, state: &str, detail: Option<&str>) {
    let mut msg = json!({ "type": "state", "id": id, "state": state });
    if let Some(detail) = detail {
        msg["detail"] = Value::String(detail.to_string());
    }
    writer.send(&msg);
}

/// Fills in the members a PublicKeyCredential must expose even if the library
/// left them out.
fn finalize(is_create: bool, mut credential: Value) -> Value {
    if credential.get("authenticatorAttachment").is_none() {
        credential["authenticatorAttachment"] = json!("cross-platform");
    }
    if is_create {
        if let Some(response) = credential.get_mut("response") {
            let missing = response
                .get("transports")
                .and_then(Value::as_array)
                .map(|a| a.is_empty())
                .unwrap_or(true);
            if missing {
                response["transports"] = json!(["hybrid"]);
            }
        }
    }
    credential
}

fn parse_origin(origin: &str, top_origin: Option<&str>) -> Result<RequestOrigin, Failure> {
    let parsed = Origin::try_from(origin)
        .map_err(|e| Failure::new("SecurityError", format!("invalid origin {origin}: {e:?}")))?;
    match top_origin {
        Some(top) if top != origin => {
            let top_parsed = Origin::try_from(top).map_err(|e| {
                Failure::new("SecurityError", format!("invalid top-level origin {top}: {e:?}"))
            })?;
            Ok(RequestOrigin::new_cross_origin(parsed, top_parsed))
        }
        _ => Ok(RequestOrigin::new(parsed)),
    }
}

#[allow(unreachable_patterns)]
fn map_create_prepare_error(err: MakeCredentialPrepareError) -> Failure {
    match err {
        MakeCredentialPrepareError::EncodingError(e) => {
            Failure::new("EncodingError", format!("invalid request: {e}"))
        }
        MakeCredentialPrepareError::InvalidRelyingPartyId(_)
        | MakeCredentialPrepareError::MismatchingRelyingPartyId(..)
        | MakeCredentialPrepareError::InvalidAppId(_) => Failure::new("SecurityError", err.to_string()),
        _ => Failure::new("NotSupportedError", err.to_string()),
    }
}

#[allow(unreachable_patterns)]
fn map_get_prepare_error(err: GetAssertionPrepareError) -> Failure {
    match err {
        GetAssertionPrepareError::EncodingError(e) => {
            Failure::new("EncodingError", format!("invalid request: {e}"))
        }
        GetAssertionPrepareError::InvalidRelyingPartyId(_)
        | GetAssertionPrepareError::MismatchingRelyingPartyId(..)
        | GetAssertionPrepareError::InvalidAppId(_) => Failure::new("SecurityError", err.to_string()),
        GetAssertionPrepareError::UnexpectedLengthError(..)
        | GetAssertionPrepareError::NotSupported(_) => {
            Failure::new("NotSupportedError", err.to_string())
        }
        _ => Failure::new("NotSupportedError", err.to_string()),
    }
}

#[allow(unreachable_patterns)]
fn map_webauthn_error(err: WebAuthnError<PxpError>) -> Outcome {
    match err {
        WebAuthnError::Ctap(ctap) => map_ctap_error(ctap),
        WebAuthnError::Transport(transport) => Outcome::Retry(transport.to_string()),
        WebAuthnError::Platform(PlatformError::Cancelled) => {
            Outcome::Fatal(Failure::new("AbortError", "The operation was cancelled."))
        }
        WebAuthnError::Platform(platform) => {
            Outcome::Fatal(Failure::new("NotAllowedError", platform.to_string()))
        }
        other => Outcome::Fatal(Failure::new("NotAllowedError", other.to_string())),
    }
}

fn map_ctap_error(err: CtapError) -> Outcome {
    let fatal = |name: &'static str, message: String| Outcome::Fatal(Failure::new(name, message));
    match err {
        CtapError::NoCredentials => {
            fatal("NotAllowedError", "Your phone has no passkey for this site.".into())
        }
        CtapError::CredentialExcluded => fatal(
            "InvalidStateError",
            "A passkey for this account already exists on your phone.".into(),
        ),
        CtapError::OperationDenied | CtapError::NotAllowed | CtapError::KeepAliveCancel => {
            fatal("NotAllowedError", "The request was declined on your phone.".into())
        }
        CtapError::UserActionTimeout | CtapError::ActionTimeout | CtapError::Timeout => {
            fatal("NotAllowedError", "Your phone did not respond in time.".into())
        }
        CtapError::UnsupportedAlgorithm
        | CtapError::UnsupportedOption
        | CtapError::UnsupportedExtension
        | CtapError::InvalidOption => fatal(
            "NotSupportedError",
            format!("Your phone does not support this request ({err})."),
        ),
        CtapError::PINAuthBlocked | CtapError::PINBlocked | CtapError::UvBlocked => fatal(
            "NotAllowedError",
            format!("User verification is blocked on your phone ({err})."),
        ),
        other => fatal("NotAllowedError", format!("Your phone reported an error: {other}")),
    }
}
