use async_trait::async_trait;
use eyre::{eyre, Result};
use futures_channel::mpsc;
use prost::Message;
use std::{
    fmt::{Display, Formatter},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use tokio::{sync::mpsc as websocket_mpsc, time};
use tokio_tungstenite::tungstenite;

use super::{
    proto_signalservice::Envelope,
    proto_websocketresources::{
        web_socket_message::Type, WebSocketMessage, WebSocketRequestMessage,
        WebSocketResponseMessage,
    },
};
use super::{
    tls,
    websocket_connection::{self, WebSocketConnection},
};
use crate::{config, db::Connection, push, utils::post_allowed};

const PUSH_TIMEOUT: Duration = Duration::from_secs(1);
const DELIVERY_CHECK_TIMEOUT: Duration = Duration::from_secs(3600);

#[derive(Debug)]
pub struct Channels {
    ws_tx: Option<websocket_mpsc::Sender<tungstenite::Message>>,
    // Retain one sender: cloning futures senders per notification can keep
    // acquiring reserved slots and defeat a nominally bounded metrics queue.
    pub on_message_tx: Option<Mutex<mpsc::Sender<u32>>>,
    pub on_push_tx: Option<Mutex<mpsc::Sender<u32>>>,
    pub on_reconnection_tx: Option<Mutex<mpsc::Sender<u32>>>,
}

impl Channels {
    fn none() -> Self {
        Self {
            ws_tx: None,
            on_message_tx: None,
            on_push_tx: None,
            on_reconnection_tx: None,
        }
    }
}

fn metric_tick(sender: &Option<Mutex<mpsc::Sender<u32>>>) {
    if let Some(sender) = sender {
        if let Ok(mut sender) = sender.try_lock() {
            let _ = sender.try_send(1);
        }
    }
}

#[derive(Debug)]
pub enum Error {
    /// Signal itself rejected the linked-device credentials. Provider outcomes
    /// can never construct this error and never authorize unlinking a device.
    RegistrationRemoved,
}
impl Display for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}
impl std::error::Error for Error {}

// No Debug: this object holds a linked-device credential and endpoint token.
pub struct SignalWebSocket {
    original: Connection,
    encrypted_mode: bool,
    creds: String,
    push_endpoint: url::Url,
    pub channels: Channels,
    push_instant: Arc<Mutex<Instant>>,
    last_keepalive: Arc<Mutex<Instant>>,
}

#[async_trait(?Send)]
impl WebSocketConnection for SignalWebSocket {
    fn get_url(&self) -> &str {
        config::get_ws_endpoint()
    }
    fn get_creds(&self) -> &str {
        &self.creds
    }
    fn get_websocket_tx(&self) -> &Option<websocket_mpsc::Sender<tungstenite::Message>> {
        &self.channels.ws_tx
    }
    fn set_websocket_tx(&mut self, tx: Option<websocket_mpsc::Sender<tungstenite::Message>>) {
        self.channels.ws_tx = tx;
    }
    fn get_last_keepalive(&self) -> Arc<Mutex<Instant>> {
        self.last_keepalive.clone()
    }

    async fn on_message(&self, message: WebSocketMessage) -> Result<()> {
        if let Some(type_int) = message.r#type {
            match Type::try_from(type_int) {
                Ok(Type::Response) => self.on_response(message.response)?,
                Ok(Type::Request) => self.on_request(message.request).await?,
                _ => (),
            }
        }
        Ok(())
    }
}

impl SignalWebSocket {
    pub fn new(
        uuid: &str,
        device_id: u32,
        password: &str,
        raw_endpoint: &str,
        encrypted_mode: bool,
    ) -> Result<Self> {
        let push_endpoint = url::Url::parse(raw_endpoint).map_err(|_| eyre!("invalid_endpoint"))?;
        let now = Instant::now();
        Ok(Self {
            // Retain the exact original text; URL normalization must not alter
            // the tuple used by guards against callbacks from obsolete sockets.
            original: Connection::new(
                uuid.to_owned(),
                device_id,
                password.to_owned(),
                raw_endpoint.to_owned(),
            ),
            encrypted_mode,
            creds: format!("{uuid}.{device_id}:{password}"),
            push_endpoint,
            channels: Channels::none(),
            push_instant: Arc::new(Mutex::new(now.checked_sub(PUSH_TIMEOUT).unwrap_or(now))),
            last_keepalive: Arc::new(Mutex::new(now)),
        })
    }

    pub async fn connection_loop(&mut self) -> Result<()> {
        let mut count: u64 = 0;
        loop {
            let start = Instant::now();
            *self
                .last_keepalive
                .lock()
                .map_err(|_| eyre!("state_unavailable"))? = start;
            if let Err(error) = self
                .connect(tls::build_tls_connector().map_err(|_| eyre!("signal_tls_unavailable"))?)
                .await
            {
                if let Some(tungstenite::Error::Http(response)) =
                    error.downcast_ref::<tungstenite::Error>()
                {
                    if response.status() == 403 {
                        return Err(eyre!(Error::RegistrationRemoved));
                    }
                    log::debug!("signal_http_error");
                } else if let Some(websocket_connection::Error::ConnectedElseWhere) =
                    error.downcast_ref::<websocket_connection::Error>()
                {
                    self.push_delivery_check().await?;
                } else {
                    log::debug!("signal_connection_error");
                }
            }
            if start.elapsed() > Duration::from_secs(60) {
                count = 0;
            }
            metric_tick(&self.channels.on_reconnection_tx);
            count = (count + 1).min(30);
            time::sleep(Duration::from_secs(count * 10)).await;
        }
    }

    fn on_response(&self, response: Option<WebSocketResponseMessage>) -> Result<()> {
        if response.is_some() {
            *self
                .last_keepalive
                .lock()
                .map_err(|_| eyre!("state_unavailable"))? = Instant::now();
        }
        Ok(())
    }

    async fn on_request(&self, request: Option<WebSocketRequestMessage>) -> Result<()> {
        if let Some(request) = request {
            if let Some(envelope) = self.request_to_envelope(request).await? {
                metric_tick(&self.channels.on_message_tx);
                if self.waiting_timeout_reached()? && envelope.urgent() {
                    self.send_push().await?;
                }
            }
        }
        Ok(())
    }

    async fn request_to_envelope(
        &self,
        request: WebSocketRequestMessage,
    ) -> Result<Option<Envelope>> {
        if !self.is_signal_service_envelope(&request) {
            return Ok(None);
        }
        self.send_response(self.create_websocket_response(&request))
            .await?;
        Ok(match request.body {
            None => Some(Envelope {
                urgent: Some(false),
                ..Envelope::default()
            }),
            Some(body) => Envelope::decode(&body[..]).ok(),
        })
    }

    fn is_signal_service_envelope(&self, request: &WebSocketRequestMessage) -> bool {
        request.verb.as_deref() == Some("PUT") && request.path.as_deref() == Some("/api/v1/message")
    }

    fn create_websocket_response(
        &self,
        request: &WebSocketRequestMessage,
    ) -> WebSocketResponseMessage {
        let (status, message) = if self.is_signal_service_envelope(request) {
            (200, "OK")
        } else {
            (400, "Unknown")
        };
        WebSocketResponseMessage {
            id: request.id,
            status: Some(status),
            message: Some(message.into()),
            headers: Vec::new(),
            body: None,
        }
    }

    async fn send_push(&self) -> Result<()> {
        *self
            .push_instant
            .lock()
            .map_err(|_| eyre!("state_unavailable"))? = Instant::now();
        let attempted = if self.encrypted_mode {
            // The guard atomically verifies the original connection tuple before
            // enqueueing. False means this socket is obsolete; never downgrade.
            push::enqueue_for_connection(&self.original, "wake", None)
                .map_err(|_| eyre!("push_enqueue_failed"))?
        } else if config::legacy_wake_enabled()
            && push::legacy_connection_is_current(&self.original)
                .map_err(|_| eyre!("state_unavailable"))?
        {
            // Response codes have no authority over Signal device linkage.
            let _ = post_allowed::post_legacy_wake(self.push_endpoint.clone()).await;
            true
        } else {
            false
        };
        if attempted {
            metric_tick(&self.channels.on_push_tx);
        }
        Ok(())
    }

    async fn push_delivery_check(&self) -> Result<()> {
        if !self.encrypted_mode {
            return Ok(());
        }
        {
            let mut instant = self
                .push_instant
                .lock()
                .map_err(|_| eyre!("state_unavailable"))?;
            if instant.elapsed() < DELIVERY_CHECK_TIMEOUT {
                return Ok(());
            }
            *instant = Instant::now();
        }
        let _ = push::enqueue_for_connection(&self.original, "status", Some("connection_conflict"))
            .map_err(|_| eyre!("push_enqueue_failed"))?;
        Ok(())
    }

    fn waiting_timeout_reached(&self) -> Result<bool> {
        Ok(self
            .push_instant
            .lock()
            .map_err(|_| eyre!("state_unavailable"))?
            .elapsed()
            > PUSH_TIMEOUT)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures_util::{FutureExt, StreamExt};

    #[tokio::test]
    async fn closed_writer_propagates_from_envelope_acknowledgement() {
        let mut connection = SignalWebSocket::new(
            "11111111-1111-4111-8111-111111111111",
            2,
            "synthetic-password-only",
            "https://push.example.test/synthetic",
            true,
        )
        .unwrap();
        let (sender, receiver) = websocket_mpsc::channel(64);
        connection.set_websocket_tx(Some(sender));
        drop(receiver);
        let result = connection
            .request_to_envelope(WebSocketRequestMessage {
                verb: Some("PUT".into()),
                path: Some("/api/v1/message".into()),
                body: None,
                headers: Vec::new(),
                id: Some(42),
            })
            .await;
        assert_eq!(result.unwrap_err().to_string(), "WriterClosed");
    }

    #[test]
    fn immutable_mode_and_exact_raw_endpoint_are_preserved() {
        let raw = "https://EXAMPLE.test:443";
        let connection =
            SignalWebSocket::new("synthetic-id", 2, "synthetic-password", raw, true).unwrap();
        assert_eq!(connection.original.endpoint, raw);
        assert_ne!(connection.push_endpoint.as_str(), raw);
        assert!(connection.encrypted_mode);
    }

    #[tokio::test]
    async fn repeated_metrics_do_not_gain_new_reserved_sender_slots() {
        // futures buffer31 plus its one retained sender slot = exactly32.
        let (sender, mut receiver) = mpsc::channel(31);
        let sender = Some(Mutex::new(sender));
        for _ in 0..10_000 {
            metric_tick(&sender);
        }
        let mut received = 0;
        while let Some(Some(value)) = receiver.next().now_or_never() {
            assert_eq!(value, 1);
            received += 1;
        }
        assert_eq!(received, 32);
        metric_tick(&sender);
        assert_eq!(receiver.next().now_or_never(), Some(Some(1)));
    }
}
