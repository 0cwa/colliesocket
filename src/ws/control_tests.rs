//! Real loopback websocket/HTTP coverage for the enrollment-v2 control path.
//! All credentials, keys and endpoints in this module are synthetic.
use super::SignalWebSocket;
use crate::{
    config,
    control::tests::{frame_for, ACCOUNT, KEY},
    enrollment, push,
    push_store::{Enrollment, PushStore, Subscription},
    ws::{
        proto_signalservice::Envelope,
        proto_websocketresources::{
            web_socket_message::Type, WebSocketMessage, WebSocketRequestMessage,
        },
        websocket_connection::WebSocketConnection,
    },
};
use async_trait::async_trait;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use futures_util::{SinkExt, StreamExt};
use openssl::{
    bn::BigNumContext,
    derive::Deriver,
    ec::{EcGroup, EcKey, EcPoint, PointConversionForm},
    hash::MessageDigest,
    nid::Nid,
    pkey::{PKey, Private},
    sign::Signer,
    symm::{decrypt_aead, Cipher},
};
use prost::Message;
use rusqlite::Connection;
use serde_json::{json, Value};
use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::PathBuf,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::mpsc,
    time::timeout,
};
use tokio_tungstenite::{accept_async, tungstenite, WebSocketStream};

const PASSWORD: &str = "SYNTHETIC-CONTROL-TEST-PASSWORD";
type Peer = WebSocketStream<TcpStream>;

/// Only the test transport URL differs: the production codec, callbacks,
/// websocket writer and acknowledgment path all run without a config bypass.
struct LocalSignal {
    inner: SignalWebSocket,
    url: String,
}

#[async_trait(?Send)]
impl WebSocketConnection for LocalSignal {
    fn get_url(&self) -> &str {
        &self.url
    }
    fn get_creds(&self) -> &str {
        self.inner.get_creds()
    }
    fn get_websocket_tx(&self) -> &Option<mpsc::Sender<tungstenite::Message>> {
        self.inner.get_websocket_tx()
    }
    fn set_websocket_tx(&mut self, sender: Option<mpsc::Sender<tungstenite::Message>>) {
        self.inner.set_websocket_tx(sender);
    }
    fn get_last_keepalive(&self) -> Arc<Mutex<Instant>> {
        self.inner.get_last_keepalive()
    }
    async fn on_message(&self, message: WebSocketMessage) -> eyre::Result<()> {
        self.inner.on_message(message).await
    }
}

struct TestDirectory(PathBuf);
impl Drop for TestDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn database() -> Connection {
    Connection::open(config::get_db()).unwrap()
}

fn subscription() -> Subscription {
    PushStore::open(config::get_db())
        .unwrap()
        .get_subscription(ACCOUNT)
        .unwrap()
        .unwrap()
}

fn queued() -> u32 {
    database()
        .query_row("SELECT count(*) FROM encrypted_push_queue", [], |row| {
            row.get(0)
        })
        .unwrap()
}

/// Compare every durable row, including receipts/queue metadata, on rejection.
fn snapshot() -> Vec<Vec<Vec<rusqlite::types::Value>>> {
    let db = database();
    [
        "connections",
        "encrypted_subscriptions",
        "encrypted_enrollment_requests",
        "encrypted_push_queue",
        "encrypted_push_event_ids",
    ]
    .iter()
    .map(|table| {
        let mut statement = db
            .prepare(&format!("SELECT * FROM {table} ORDER BY rowid"))
            .unwrap();
        let rows = statement
            .query_map([], |row| {
                (0..row.as_ref().column_count())
                    .map(|index| row.get(index))
                    .collect::<rusqlite::Result<Vec<rusqlite::types::Value>>>()
            })
            .unwrap();
        rows.collect::<rusqlite::Result<Vec<_>>>().unwrap()
    })
    .collect()
}

async fn send(peer: &mut Peer, id: u64, content: Vec<u8>, urgent: bool) {
    let envelope = Envelope {
        r#type: Some(6),
        // Deliberately unrelated metadata: the control key is the authority.
        source_service_id: Some("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb".into()),
        source_device: Some(1234),
        destination_service_id: Some("untrusted-envelope-destination".into()),
        urgent: Some(urgent),
        content: Some(content),
        ..Envelope::default()
    };
    let message = WebSocketMessage {
        r#type: Some(Type::Request as i32),
        response: None,
        request: Some(WebSocketRequestMessage {
            verb: Some("PUT".into()),
            path: Some("/api/v1/message".into()),
            body: Some(envelope.encode_to_vec()),
            headers: Vec::new(),
            id: Some(id),
        }),
    };
    peer.send(tungstenite::Message::binary(message.encode_to_vec()))
        .await
        .unwrap();
}

async fn ack(peer: &mut Peer, id: u64) {
    let wire = timeout(Duration::from_secs(5), peer.next())
        .await
        .expect("Signal frame was not acknowledged")
        .unwrap()
        .unwrap();
    assert!(wire.is_binary());
    let message = WebSocketMessage::decode(wire.into_data()).unwrap();
    assert_eq!(message.r#type, Some(Type::Response as i32));
    let response = message.response.unwrap();
    assert_eq!(response.id, Some(id));
    assert_eq!(response.status, Some(200));
}

async fn committed_before_ack(peer: &mut Peer, id: u64, epoch: u64) {
    timeout(Duration::from_secs(5), async {
        while subscription().subscription_epoch != epoch {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("control update did not commit");
    assert_eq!(queued(), 1, "confirmation must be durable with the update");
    let queued_event: String = database()
        .query_row("SELECT event_json FROM encrypted_push_queue", [], |r| {
            r.get(0)
        })
        .unwrap();
    let event: Value = serde_json::from_str(&queued_event).unwrap();
    assert_eq!(event["subscription_epoch"], epoch);
    assert_eq!(event["code"], "subscription_updated");
    // A separate SQLite connection sees committed state before the peer reads
    // its ACK. The injected-write-failure case below also proves no early ACK.
    ack(peer, id).await;
}

fn receiver() -> PKey<Private> {
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
    PKey::from_ec_key(EcKey::generate(&group).unwrap()).unwrap()
}

fn public_key(key: &PKey<Private>) -> Vec<u8> {
    let ec = key.ec_key().unwrap();
    ec.public_key()
        .to_bytes(
            ec.group(),
            PointConversionForm::UNCOMPRESSED,
            &mut BigNumContext::new().unwrap(),
        )
        .unwrap()
}

fn update(endpoint: &str, key: &PKey<Private>, auth: &[u8; 16]) -> Vec<u8> {
    serde_json::to_vec(&json!({
        "endpoint": endpoint,
        "p256dh": URL_SAFE_NO_PAD.encode(public_key(key)),
        "auth": URL_SAFE_NO_PAD.encode(auth),
    }))
    .unwrap()
}

fn hmac(key: &[u8], data: &[u8]) -> Vec<u8> {
    let key = PKey::hmac(key).unwrap();
    let mut signer = Signer::new(MessageDigest::sha256(), &key).unwrap();
    signer.update(data).unwrap();
    signer.sign_to_vec().unwrap()
}

/// Independent OpenSSL RFC8291 receiver, not the production sender library.
fn decrypt_push(body: &[u8], receiver: &PKey<Private>, auth: &[u8; 16]) -> Option<Value> {
    if body.len() != 4096 || body[16..20] != 4096u32.to_be_bytes() || body[20] != 65 {
        return None;
    }
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).ok()?;
    let mut ctx = BigNumContext::new().ok()?;
    let sender_point = EcPoint::from_bytes(&group, &body[21..86], &mut ctx).ok()?;
    let sender = PKey::from_ec_key(EcKey::from_public_key(&group, &sender_point).ok()?).ok()?;
    let mut derive = Deriver::new(receiver).ok()?;
    derive.set_peer(&sender).ok()?;
    let shared = derive.derive_to_vec().ok()?;
    let mut info = b"WebPush: info\0".to_vec();
    info.extend_from_slice(&public_key(receiver));
    info.extend_from_slice(&body[21..86]);
    info.push(1);
    let ikm = hmac(&hmac(auth, &shared), &info);
    let prk = hmac(&body[..16], &ikm);
    let cek = hmac(&prk, b"Content-Encoding: aes128gcm\0\x01");
    let nonce = hmac(&prk, b"Content-Encoding: nonce\0\x01");
    let plaintext = decrypt_aead(
        Cipher::aes_128_gcm(),
        &cek[..16],
        Some(&nonce[..12]),
        &[],
        &body[86..4080],
        &body[4080..],
    )
    .ok()?;
    if plaintext.last() != Some(&2) {
        return None;
    }
    serde_json::from_slice(&plaintext[..plaintext.len() - 1]).ok()
}

struct CapturedPush {
    path: String,
    headers: String,
    body: Vec<u8>,
}

async fn drain_capture(provider: &TcpListener, status: u16) -> CapturedPush {
    let serve = async {
        let (mut stream, _) = provider.accept().await.unwrap();
        let mut bytes = Vec::new();
        let header_end = loop {
            if let Some(index) = bytes.windows(4).position(|w| w == b"\r\n\r\n") {
                break index + 4;
            }
            let mut block = [0; 1024];
            let length = stream.read(&mut block).await.unwrap();
            assert!(length > 0 && bytes.len() < 16384);
            bytes.extend_from_slice(&block[..length]);
        };
        let headers = String::from_utf8(bytes[..header_end].to_vec()).unwrap();
        let path = headers
            .lines()
            .next()
            .unwrap()
            .split_whitespace()
            .nth(1)
            .unwrap()
            .to_owned();
        let headers = headers.to_ascii_lowercase();
        let length: usize = headers
            .lines()
            .find_map(|line| line.strip_prefix("content-length:"))
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        assert_eq!(length, 4096);
        while bytes.len() - header_end < length {
            let mut block = [0; 4096];
            let count = stream.read(&mut block).await.unwrap();
            assert!(count > 0);
            bytes.extend_from_slice(&block[..count]);
        }
        stream
            .write_all(
                format!(
                    "HTTP/1.1 {status} Synthetic\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        CapturedPush {
            path,
            headers,
            body: bytes[header_end..header_end + length].to_vec(),
        }
    };
    let (processed, captured) = timeout(Duration::from_secs(5), async {
        tokio::join!(push::drain_once(), serve)
    })
    .await
    .expect("encrypted push was not delivered to the loopback provider");
    assert!(processed.unwrap());
    assert!(captured.headers.contains("content-encoding: aes128gcm\r\n"));
    assert!(captured
        .headers
        .contains("content-type: application/octet-stream\r\n"));
    captured
}

#[tokio::test]
async fn fake_signal_rotates_endpoint_before_ack_and_rejects_replay_and_forgery() {
    let directory = TestDirectory(std::env::temp_dir().join(format!(
        "colliesocket-control-ws-{}",
        push::uuid_v4().unwrap()
    )));
    fs::create_dir(&directory.0).unwrap();
    fs::set_permissions(&directory.0, fs::Permissions::from_mode(0o700)).unwrap();
    let provider = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("http://{}", provider.local_addr().unwrap());
    let config_path = directory.0.join("config.toml");
    fs::write(
        &config_path,
        format!(
            "db = {:?}\nallowed_endpoints = [{origin:?}]\nallowed_uuids = [{ACCOUNT:?}]\n",
            directory.0.join("state.sqlite").to_str().unwrap()
        ),
    )
    .unwrap();
    config::load_config(Some(config_path));

    let old_key = receiver();
    let new_key = receiver();
    let old_auth = [0x11; 16];
    let new_auth = [0x22; 16];
    let recovered_auth = [0x33; 16];
    let old_endpoint = format!("{origin}/old");
    let new_endpoint = format!("{origin}/new");
    let recovered_endpoint = format!("{origin}/recovered");
    let enrollment: Enrollment = serde_json::from_value(json!({
        "enrollment_version": 2,
        "request_id": push::uuid_v4().unwrap(),
        "account_id": ACCOUNT,
        "device_id": 2,
        "password": PASSWORD,
        "control_key": URL_SAFE_NO_PAD.encode(KEY),
        "subscription": {
            "endpoint": old_endpoint,
            "p256dh": URL_SAFE_NO_PAD.encode(public_key(&old_key)),
            "auth": URL_SAFE_NO_PAD.encode(old_auth),
            "instance": "fake-signal-instance",
            "subscription_epoch": 1,
            "encryption_required": true,
            "supported_event_versions": [1,2],
            "capabilities": ["wake","test","status"]
        }
    }))
    .unwrap();
    let receipt = enrollment::import(&serde_json::to_vec(&enrollment).unwrap())
        .await
        .unwrap();
    assert_eq!(receipt["selected_event_version"], 2);
    assert_eq!(receipt["enrollment_version"], 2);

    let signal = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mut socket = LocalSignal {
        inner: SignalWebSocket::new(ACCOUNT, 2, PASSWORD, &old_endpoint, true).unwrap(),
        url: format!("ws://{}/", signal.local_addr().unwrap()),
    };
    let payload = update(&new_endpoint, &new_key, &new_auth);
    let control = frame_for(ACCOUNT, 2, 2, &payload);
    let recovery = frame_for(
        ACCOUNT,
        2,
        4,
        &update(&recovered_endpoint, &new_key, &recovered_auth),
    );
    let failed_endpoint = format!("{origin}/after-retry");
    let interrupted = frame_for(
        ACCOUNT,
        2,
        6,
        &update(&failed_endpoint, &new_key, &recovered_auth),
    );

    let server = async {
        let (stream, _) = signal.accept().await.unwrap();
        let mut peer = accept_async(stream).await.unwrap();
        // Nonurgent control succeeds despite forged source metadata.
        send(&mut peer, 1, control.clone(), false).await;
        committed_before_ack(&mut peer, 1, 2).await;
        assert_eq!(subscription().endpoint, new_endpoint);
        let private: (String, u32, String, String) = database().query_row(
            "SELECT s.control_key,c.device_id,c.password,c.endpoint FROM encrypted_subscriptions s JOIN connections c ON c.uuid=s.account_id", [],
            |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?))
        ).unwrap();
        assert_eq!(
            private,
            (
                URL_SAFE_NO_PAD.encode(KEY),
                2,
                PASSWORD.into(),
                new_endpoint.clone()
            )
        );

        let captured = drain_capture(&provider, 202).await;
        assert_eq!(captured.path, "/new");
        let status = decrypt_push(&captured.body, &new_key, &new_auth).unwrap();
        assert_eq!(status["version"], 2);
        assert_eq!(status["kind"], "status");
        assert_eq!(status["code"], "subscription_updated");
        assert_eq!(status["subscription_epoch"], 2);
        assert!(decrypt_push(&captured.body, &old_key, &old_auth).is_none());

        // The very next ordinary urgent message on the same socket must wake
        // the new endpoint, rather than being rejected as an obsolete tuple.
        send(&mut peer, 2, b"ordinary Signal ciphertext".to_vec(), true).await;
        ack(&mut peer, 2).await;
        assert_eq!(queued(), 1);
        let captured = drain_capture(&provider, 202).await;
        assert_eq!(captured.path, "/new");
        let wake = decrypt_push(&captured.body, &new_key, &new_auth).unwrap();
        assert_eq!(wake["kind"], "wake");
        assert_eq!(wake["version"], 2);
        assert_eq!(wake["subscription_epoch"], 2);

        let before = snapshot();
        send(&mut peer, 3, control.clone(), true).await;
        ack(&mut peer, 3).await;
        assert_eq!(
            snapshot(),
            before,
            "identical immediate replay changed durable state"
        );

        // Provider acceptance alone is not phone receipt. Simulate the retry
        // interval elapsing without sleeping: the exact same blob can recover
        // a lost confirmation while leaving the subscription/private tuple alone.
        let unchanged = subscription();
        database()
            .execute(
                "UPDATE encrypted_subscriptions SET control_status_at=?1",
                [push::now() - 30],
            )
            .unwrap();
        send(&mut peer, 4, control.clone(), false).await;
        ack(&mut peer, 4).await;
        assert_eq!(subscription(), unchanged);
        assert_eq!(queued(), 1);
        let captured = drain_capture(&provider, 202).await;
        assert_eq!(captured.path, "/new");
        let recovered_status = decrypt_push(&captured.body, &new_key, &new_auth).unwrap();
        assert_eq!(recovered_status["subscription_epoch"], 2);
        assert_eq!(recovered_status["code"], "subscription_updated");

        let mut forged = control.clone();
        *forged.last_mut().unwrap() ^= 1;
        let mut unsupported = control.clone();
        unsupported[17] = 3;
        let unknown_field = serde_json::to_vec(&json!({
            "endpoint": new_endpoint,
            "p256dh": URL_SAFE_NO_PAD.encode(public_key(&new_key)),
            "auth": URL_SAFE_NO_PAD.encode(new_auth),
            "password": "must-remain-private-import-only"
        }))
        .unwrap();
        let denied = update("http://127.0.0.1:1/forbidden", &new_key, &new_auth);
        for (index, rejected) in [
            forged,
            unsupported,
            frame_for("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", 2, 3, &payload),
            frame_for(ACCOUNT, 3, 3, &payload),
            frame_for(ACCOUNT, 2, 3, &unknown_field),
            frame_for(ACCOUNT, 2, 3, &denied),
            frame_for(ACCOUNT, 2, 1, &payload),
            frame_for(ACCOUNT, 2, 2, &payload), // Same data, different encrypted blob.
            crate::control::MAGIC.to_vec(),
        ]
        .into_iter()
        .enumerate()
        {
            let before = snapshot();
            let id = 10 + index as u64;
            send(&mut peer, id, rejected, true).await;
            ack(&mut peer, id).await;
            assert_eq!(
                snapshot(),
                before,
                "rejected control case {index} changed durable state"
            );
        }

        // A real provider410 makes the subscription stale without touching
        // Signal credentials. Replaying epoch2 cannot reactivate it.
        push::enqueue(ACCOUNT, "test", None).unwrap();
        let captured = drain_capture(&provider, 410).await;
        assert_eq!(captured.path, "/new");
        let stale: String = database()
            .query_row("SELECT state FROM encrypted_subscriptions", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(stale, "stale");
        let before = snapshot();
        send(&mut peer, 30, control.clone(), true).await;
        ack(&mut peer, 30).await;
        assert_eq!(snapshot(), before);

        // A newer authenticated update revives stale state, including when an
        // earlier allocated phone epoch never arrived at the server.
        send(&mut peer, 31, recovery.clone(), false).await;
        committed_before_ack(&mut peer, 31, 4).await;
        assert_eq!(subscription().endpoint, recovered_endpoint);
        let captured = drain_capture(&provider, 202).await;
        assert_eq!(captured.path, "/recovered");
        let event = decrypt_push(&captured.body, &new_key, &recovered_auth).unwrap();
        assert_eq!(event["subscription_epoch"], 4);
        assert_eq!(event["code"], "subscription_updated");

        // A fault after the mutation starts must roll back subscription and
        // outbox together and produce no frame acknowledgment.
        database().execute_batch("CREATE TRIGGER inject_control_failure AFTER UPDATE OF subscription_epoch ON encrypted_subscriptions WHEN NEW.subscription_epoch=6 BEGIN SELECT RAISE(ABORT,'synthetic failure'); END;").unwrap();
        let before = snapshot();
        send(&mut peer, 40, interrupted.clone(), false).await;
        if let Ok(Some(Ok(message))) = timeout(Duration::from_millis(500), peer.next()).await {
            if message.is_binary() {
                let decoded = WebSocketMessage::decode(message.into_data()).unwrap();
                assert_ne!(
                    decoded.response.and_then(|r| r.id),
                    Some(40),
                    "failed commit was acknowledged"
                );
            }
        }
        assert_eq!(snapshot(), before, "failed update was partially committed");
        database()
            .execute_batch("DROP TRIGGER inject_control_failure")
            .unwrap();
        let _ = peer.close(None).await;
    };
    let (result, ()) = timeout(Duration::from_secs(20), async {
        tokio::join!(
            socket.connect(native_tls::TlsConnector::new().unwrap()),
            server
        )
    })
    .await
    .expect("fake Signal integration timed out");
    assert!(
        result.is_err(),
        "persistence failure must end the unacknowledged session"
    );
    assert_eq!(subscription().subscription_epoch, 4);
    assert_eq!(queued(), 0);

    // Reconnect and retry exactly the interrupted blob: no operation was lost
    // and no private re-import or externally reachable enrollment port is used.
    let mut socket = LocalSignal {
        inner: SignalWebSocket::new(ACCOUNT, 2, PASSWORD, &recovered_endpoint, true).unwrap(),
        url: format!("ws://{}/", signal.local_addr().unwrap()),
    };
    let server = async {
        let (stream, _) = signal.accept().await.unwrap();
        let mut peer = accept_async(stream).await.unwrap();
        send(&mut peer, 50, interrupted.clone(), false).await;
        committed_before_ack(&mut peer, 50, 6).await;
        let captured = drain_capture(&provider, 202).await;
        assert_eq!(captured.path, "/after-retry");
        let event = decrypt_push(&captured.body, &new_key, &recovered_auth).unwrap();
        assert_eq!(event["subscription_epoch"], 6);
        assert_eq!(event["code"], "subscription_updated");
        let _ = peer.close(None).await;
    };
    let _ = timeout(Duration::from_secs(10), async {
        tokio::join!(
            socket.connect(native_tls::TlsConnector::new().unwrap()),
            server
        )
    })
    .await
    .expect("retry session timed out");
    assert_eq!(subscription().endpoint, failed_endpoint);
    assert_eq!(subscription().instance, "fake-signal-instance");
    assert_eq!(queued(), 0);
}
