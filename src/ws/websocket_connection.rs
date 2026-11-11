use async_trait::async_trait;
use base64::{prelude::BASE64_STANDARD, Engine};
use eyre::{eyre, Result};
use futures_util::{pin_mut, select, FutureExt, SinkExt, StreamExt, TryStreamExt};
use native_tls::TlsConnector;
use prost::Message;
use std::{
    fmt::{Display, Formatter},
    sync::{Arc, Mutex},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tokio::{sync::mpsc, time};
use tokio_tungstenite::{
    tungstenite::{
        self,
        protocol::{self, frame::coding::CloseCode, CloseFrame},
        ClientRequestBuilder,
    },
    Connector::NativeTls,
};

use super::proto_websocketresources::{
    web_socket_message::Type, WebSocketMessage, WebSocketRequestMessage, WebSocketResponseMessage,
};

const KEEPALIVE: Duration = Duration::from_secs(30);
const KEEPALIVE_TIMEOUT: Duration = Duration::from_secs(40);
const WEBSOCKET_QUEUE_CAPACITY: usize = 64;
const KEEPALIVE_QUEUE_CAPACITY: usize = 4;

fn websocket_channel() -> (
    mpsc::Sender<tungstenite::Message>,
    mpsc::Receiver<tungstenite::Message>,
) {
    mpsc::channel(WEBSOCKET_QUEUE_CAPACITY)
}

fn keepalive_channel() -> (mpsc::Sender<()>, mpsc::Receiver<()>) {
    mpsc::channel(KEEPALIVE_QUEUE_CAPACITY)
}

async fn queue_keepalive(sender: &mpsc::Sender<()>) -> Result<()> {
    sender
        .send(())
        .await
        .map_err(|_| eyre!(Error::WriterClosed))
}
/// User agent from Signal-Android
///
/// USER_AGENT = "Signal-Android/" + BuildConfig.VERSION_NAME + " Android/" + Build.VERSION.SDK_INT;
///
/// UA: https://github.com/signalapp/Signal-Android/blob/c7ec3ab837b3c149d5579840317b1dc6cd4629f3/app/src/main/java/org/thoughtcrime/securesms/net/StandardUserAgentInterceptor.java#L12
/// VERSION_NAME => take latest https://github.com/signalapp/Signal-Android/releases/latest
/// Build.VERSION.SDK_INT => take last Android SDK
const USER_AGENT: &'static str = "Signal-Android/8.3.4 Android/36";

#[derive(Debug)]
pub enum Error {
    Ws,
    PushError,
    ConnectedElseWhere,
    WriterClosed,
    KeepaliveUnavailable,
    KeepaliveTimeout,
    ClockUnavailable,
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl std::error::Error for Error {}

#[async_trait(?Send)]
pub trait WebSocketConnection {
    fn get_url(&self) -> &str;
    /// return "login:password"
    fn get_creds(&self) -> &str;
    fn get_websocket_tx(&self) -> &Option<mpsc::Sender<tungstenite::Message>>;
    fn set_websocket_tx(&mut self, tx: Option<mpsc::Sender<tungstenite::Message>>);
    fn get_last_keepalive(&self) -> Arc<Mutex<Instant>>;
    async fn on_message(&self, message: WebSocketMessage) -> Result<()>;

    /// Connect to the server and handle messages
    /// Returns HTTP Error, or ConnectedElseWhere or () if disconnected normally
    async fn connect(&mut self, tls_connector: TlsConnector) -> Result<()> {
        let request = ClientRequestBuilder::new(self.get_url().parse()?)
            .with_header("X-Signal-Agent", "\"OWA\"")
            .with_header("User-Agent", USER_AGENT)
            .with_header(
                "Authorization",
                format!("Basic {}", BASE64_STANDARD.encode(self.get_creds())),
            );

        let (ws_stream, _) = tokio_tungstenite::connect_async_tls_with_config(
            request,
            None,
            false,
            Some(NativeTls(tls_connector)),
        )
        .await?;

        log::info!("WebSocket handshake has been successfully completed");

        // Websocket I/O
        let (mut ws_write, ws_read) = ws_stream.split();
        // channel to websocket ws_write
        let (tx, mut rx) = websocket_channel();
        // other channels: msg, keepalive, abort
        let (timer_tx, mut timer_rx) = keepalive_channel();

        // Saving to socket Sender
        self.set_websocket_tx(Some(tx));

        // Keep handlers scoped so all borrows end before clearing the sender.
        let result = {
            let to_ws_handle = async {
                while let Some(message) = rx.recv().await {
                    ws_write
                        .send(message)
                        .await
                        .map_err(|_| eyre!(Error::WriterClosed))?;
                }
                Ok(())
            }
            .fuse();

            let from_ws_handle = ws_read
                .map_err(|_| eyre!(Error::Ws))
                .try_for_each(|message| async {
                    log::debug!("New message");
                    // Never log Signal wire frames, headers or close reasons.
                    if message.is_close() {
                        if let protocol::Message::Close(Some(CloseFrame {
                            code: CloseCode::Library(4409),
                            reason: _,
                        })) = message
                        {
                            log::debug!("Websocket closed: connected elsewhere");
                            return Err(eyre!(Error::ConnectedElseWhere));
                        } else {
                            log::debug!("Websocket closed normally")
                        }
                    } else if message.is_binary() {
                        if let Err(e) = self.handle_message(message).await {
                            return Err(e.wrap_err(eyre!(Error::PushError)));
                        }
                    }
                    Ok(())
                })
                .fuse();

            let from_keepalive_handle = async {
                while timer_rx.recv().await.is_some() {
                    self.send_keepalive().await?;
                }
                Ok(())
            }
            .fuse();

            let to_keepalive_handle = self.loop_keepalive(timer_tx).fuse();

            pin_mut!(
                to_ws_handle,
                from_ws_handle,
                from_keepalive_handle,
                to_keepalive_handle
            );

            // handle websocket
            select!(
                result = from_ws_handle => result,
                result = to_ws_handle => result,
                result = from_keepalive_handle => result,
                result = to_keepalive_handle => result,
            )
        };
        self.set_websocket_tx(None);
        result
    }

    async fn handle_message(&self, message: tungstenite::Message) -> Result<()> {
        let data = message.into_data();
        let ws_message = match WebSocketMessage::decode(data) {
            Ok(msg) => msg,
            Err(_) => {
                // We ignore these issues, we have to the common
                // `failed to decode Protobuf message: invalid wire type value: 7`
                // but it seems to be a 'best effort' description: https://github.com/tokio-rs/prost/blob/fafa97f3e05b9ffd84769c7c606499243a6fa614/prost/src/error.rs#L15
                log::trace!("invalid_signal_frame");
                return Ok(());
            }
        };
        self.on_message(ws_message).await
    }

    async fn send_message(&self, message: WebSocketMessage) -> Result<()> {
        let tx = self
            .get_websocket_tx()
            .as_ref()
            .ok_or(Error::WriterClosed)?;
        let bytes = message.encode_to_vec();
        tx.send(tungstenite::Message::binary(bytes))
            .await
            .map_err(|_| eyre!(Error::WriterClosed))
    }

    async fn send_response(&self, response: WebSocketResponseMessage) -> Result<()> {
        let message = WebSocketMessage {
            r#type: Some(Type::Response as i32),
            response: Some(response),
            request: None,
        };
        self.send_message(message).await
    }

    async fn send_keepalive(&self) -> Result<()> {
        log::debug!("send_keepalive");
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| eyre!(Error::ClockUnavailable))?
            .as_millis();
        let timestamp = u64::try_from(timestamp).map_err(|_| eyre!(Error::ClockUnavailable))?;
        let message = WebSocketMessage {
            r#type: Some(Type::Request as i32),
            response: None,
            request: Some(WebSocketRequestMessage {
                verb: Some(String::from("GET")),
                path: Some(String::from("/v1/keepalive")),
                body: None,
                headers: Vec::new(),
                id: Some(timestamp),
            }),
        };
        self.send_message(message).await
    }

    async fn loop_keepalive(&self, timer_tx: mpsc::Sender<()>) -> Result<()> {
        // Get the ref of last_keepalive
        let last_keepalive = self.get_last_keepalive();
        loop {
            // read last_keepalive
            if last_keepalive
                .lock()
                .map_err(|_| Error::KeepaliveUnavailable)?
                .elapsed()
                > KEEPALIVE_TIMEOUT
            {
                log::warn!("Did not receive the last keepalive: aborting.");
                return Err(eyre!(Error::KeepaliveTimeout));
            }
            time::sleep(KEEPALIVE).await;
            log::debug!("Sending Keepalive");
            queue_keepalive(&timer_tx).await?;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestConnection {
        url: String,
        tx: Option<mpsc::Sender<tungstenite::Message>>,
        last_keepalive: Arc<Mutex<Instant>>,
    }

    impl TestConnection {
        fn new() -> Self {
            Self {
                url: "ws://127.0.0.1:1/".into(),
                tx: None,
                last_keepalive: Arc::new(Mutex::new(Instant::now())),
            }
        }
    }

    #[async_trait(?Send)]
    impl WebSocketConnection for TestConnection {
        fn get_url(&self) -> &str {
            &self.url
        }
        fn get_creds(&self) -> &str {
            "synthetic:test-only"
        }
        fn get_websocket_tx(&self) -> &Option<mpsc::Sender<tungstenite::Message>> {
            &self.tx
        }
        fn set_websocket_tx(&mut self, tx: Option<mpsc::Sender<tungstenite::Message>>) {
            self.tx = tx;
        }
        fn get_last_keepalive(&self) -> Arc<Mutex<Instant>> {
            self.last_keepalive.clone()
        }
        async fn on_message(&self, _: WebSocketMessage) -> Result<()> {
            Ok(())
        }
    }

    fn response() -> WebSocketResponseMessage {
        WebSocketResponseMessage {
            id: Some(42),
            status: Some(200),
            message: Some("OK".into()),
            headers: Vec::new(),
            body: None,
        }
    }

    #[tokio::test]
    async fn websocket_queue_is_bounded_and_resumes_after_drain() {
        let mut connection = TestConnection::new();
        let (sender, mut receiver) = websocket_channel();
        connection.set_websocket_tx(Some(sender));
        for _ in 0..64 {
            connection.send_response(response()).await.unwrap();
        }
        assert!(connection
            .send_response(response())
            .now_or_never()
            .is_none());
        let frame = receiver.recv().await.unwrap();
        assert!(frame.is_binary());
        let message = WebSocketMessage::decode(frame.into_data()).unwrap();
        assert_eq!(message.r#type, Some(Type::Response as i32));
        assert_eq!(message.response.unwrap().id, Some(42));
        connection.send_response(response()).await.unwrap();
        assert_eq!(receiver.len(), 64);
    }

    #[tokio::test]
    async fn missing_or_closed_writer_returns_error_without_panicking() {
        let mut connection = TestConnection::new();
        assert_eq!(
            connection
                .send_response(response())
                .await
                .unwrap_err()
                .to_string(),
            "WriterClosed"
        );
        assert_eq!(
            connection.send_keepalive().await.unwrap_err().to_string(),
            "WriterClosed"
        );
        let (sender, receiver) = websocket_channel();
        connection.set_websocket_tx(Some(sender));
        drop(receiver);
        assert_eq!(
            connection
                .send_response(response())
                .await
                .unwrap_err()
                .to_string(),
            "WriterClosed"
        );
        assert_eq!(
            connection.send_keepalive().await.unwrap_err().to_string(),
            "WriterClosed"
        );
    }

    #[tokio::test]
    async fn keepalive_queue_is_bounded_and_closed_receiver_is_an_error() {
        let (sender, mut receiver) = keepalive_channel();
        for _ in 0..4 {
            queue_keepalive(&sender).await.unwrap();
        }
        assert!(queue_keepalive(&sender).now_or_never().is_none());
        assert_eq!(receiver.recv().await, Some(()));
        queue_keepalive(&sender).await.unwrap();
        assert_eq!(receiver.len(), 4);
        drop(receiver);
        assert_eq!(
            queue_keepalive(&sender).await.unwrap_err().to_string(),
            "WriterClosed"
        );
    }

    #[tokio::test]
    async fn expired_keepalive_fails_without_queueing_another_frame() {
        let connection = TestConnection::new();
        *connection.last_keepalive.lock().unwrap() = Instant::now() - Duration::from_secs(41);
        let (sender, mut receiver) = keepalive_channel();
        assert_eq!(
            connection
                .loop_keepalive(sender)
                .await
                .unwrap_err()
                .to_string(),
            "KeepaliveTimeout"
        );
        assert_eq!(receiver.recv().await, None);
    }

    #[tokio::test]
    async fn local_peer_disconnect_clears_stored_writer() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let mut connection = TestConnection::new();
        connection.url = format!("ws://{address}/synthetic");
        let peer = async {
            let (stream, _) = listener.accept().await.unwrap();
            let mut websocket = tokio_tungstenite::accept_async(stream).await.unwrap();
            websocket.close(None).await.unwrap();
        };
        let connector = TlsConnector::new().unwrap();
        let (result, ()) = tokio::time::timeout(Duration::from_secs(5), async {
            tokio::join!(connection.connect(connector), peer)
        })
        .await
        .expect("local peer disconnect must complete");
        if let Err(error) = result {
            assert!(matches!(
                error.downcast_ref::<Error>(),
                Some(Error::Ws | Error::WriterClosed)
            ));
        }
        assert!(connection.get_websocket_tx().is_none());
    }
}
