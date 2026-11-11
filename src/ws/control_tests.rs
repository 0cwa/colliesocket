//! Actual loopback Signal websocket and HTTP push transport. All keys and
//! credentials are generated for this test or taken from public test fixtures.
use super::*;
use crate::push_store::{AccountState, DeliveryOutcome, Enrollment, PushStore};
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
    symm::{decrypt_aead, encrypt_aead, Cipher},
};
use serde_json::{json, Value};
use std::{fs, os::unix::fs::DirBuilderExt, path::PathBuf};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};
use tokio_tungstenite::{accept_async, WebSocketStream};

struct TestDirectory(PathBuf);
impl Drop for TestDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

// The production Signal URL and TLS trust are unchanged. This wrapper uses the
// production transport/handler with a test-only loopback endpoint.
struct LoopbackSocket {
    signal: SignalWebSocket,
    url: String,
}
#[async_trait(?Send)]
impl WebSocketConnection for LoopbackSocket {
    fn get_url(&self) -> &str {
        &self.url
    }
    fn get_creds(&self) -> &str {
        self.signal.get_creds()
    }
    fn get_websocket_tx(&self) -> &Option<websocket_mpsc::Sender<tungstenite::Message>> {
        self.signal.get_websocket_tx()
    }
    fn set_websocket_tx(&mut self, tx: Option<websocket_mpsc::Sender<tungstenite::Message>>) {
        self.signal.set_websocket_tx(tx);
    }
    fn get_last_keepalive(&self) -> Arc<Mutex<Instant>> {
        self.signal.get_last_keepalive()
    }
    async fn on_message(&self, message: WebSocketMessage) -> Result<()> {
        self.signal.on_message(message).await
    }
}

fn socket(enrollment: &Enrollment, listener: &TcpListener) -> LoopbackSocket {
    let mut signal = SignalWebSocket::new(
        &enrollment.account_id,
        enrollment.device_id,
        &enrollment.password,
        &enrollment.subscription.endpoint,
        true,
    )
    .unwrap();
    signal.control_generation = control::generation_for_connection(&signal.original).unwrap();
    LoopbackSocket {
        signal,
        url: format!("ws://{}/", listener.local_addr().unwrap()),
    }
}

fn control_blob(
    enrollment: &Enrollment,
    endpoint: &str,
    public: &str,
    auth: &[u8],
    nonce: u8,
) -> Vec<u8> {
    let mut header = b"CollieSocket-Control\0".to_vec();
    header.push(2);
    header.extend_from_slice(&(enrollment.subscription.subscription_epoch + 1).to_be_bytes());
    let mut aad = header.clone();
    let uuid = enrollment.account_id.replace('-', "");
    for offset in (0..uuid.len()).step_by(2) {
        aad.push(u8::from_str_radix(&uuid[offset..offset + 2], 16).unwrap());
    }
    aad.extend_from_slice(&enrollment.device_id.to_be_bytes());
    let plaintext = serde_json::to_vec(&json!({
        "endpoint": endpoint, "p256dh": public, "auth": URL_SAFE_NO_PAD.encode(auth)
    }))
    .unwrap();
    let key = URL_SAFE_NO_PAD
        .decode(enrollment.control_key.as_ref().unwrap())
        .unwrap();
    let nonce = [nonce; 12];
    let mut tag = [0u8; 16];
    let ciphertext = encrypt_aead(
        Cipher::aes_256_gcm(),
        &key,
        Some(&nonce),
        &aad,
        &plaintext,
        &mut tag,
    )
    .unwrap();
    header.extend_from_slice(&nonce);
    header.extend_from_slice(&ciphertext);
    header.extend_from_slice(&tag);
    header
}

async fn send(peer: &mut WebSocketStream<TcpStream>, id: u64, content: Vec<u8>, urgent: bool) {
    let envelope = Envelope {
        content: Some(content),
        urgent: Some(urgent),
        // Deliberately untrusted metadata: successful decryption is authority.
        source_service_id: Some("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb".into()),
        source_device: Some(99),
        ..Envelope::default()
    };
    let request = WebSocketMessage {
        r#type: Some(Type::Request as i32),
        request: Some(WebSocketRequestMessage {
            verb: Some("PUT".into()),
            path: Some("/api/v1/message".into()),
            body: Some(envelope.encode_to_vec()),
            id: Some(id),
            headers: vec![],
        }),
        response: None,
    };
    peer.send(tungstenite::Message::binary(request.encode_to_vec()))
        .await
        .unwrap();
}

async fn ack(peer: &mut WebSocketStream<TcpStream>, id: u64) {
    let wire = time::timeout(Duration::from_secs(5), peer.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    let response = WebSocketMessage::decode(wire.into_data())
        .unwrap()
        .response
        .unwrap();
    assert_eq!(response.id, Some(id));
    assert_eq!(response.status, Some(200));
}

fn mac(key: &[u8], bytes: &[u8]) -> Vec<u8> {
    let key = PKey::hmac(key).unwrap();
    let mut signer = Signer::new(MessageDigest::sha256(), &key).unwrap();
    signer.update(bytes).unwrap();
    signer.sign_to_vec().unwrap()
}

// Independent OpenSSL receiver; production Web Push encryption uses RustCrypto.
fn decrypt_push(body: &[u8], private: &EcKey<Private>, auth: &[u8]) -> Value {
    assert_eq!(body.len(), 4096);
    assert_eq!(&body[16..20], &4096u32.to_be_bytes());
    assert_eq!(body[20], 65);
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
    let mut ctx = BigNumContext::new().unwrap();
    let sender = EcPoint::from_bytes(&group, &body[21..86], &mut ctx).unwrap();
    let sender = PKey::from_ec_key(EcKey::from_public_key(&group, &sender).unwrap()).unwrap();
    let receiver = private
        .public_key()
        .to_bytes(&group, PointConversionForm::UNCOMPRESSED, &mut ctx)
        .unwrap();
    let private = PKey::from_ec_key(private.clone()).unwrap();
    let mut derive = Deriver::new(&private).unwrap();
    derive.set_peer(&sender).unwrap();
    let shared = derive.derive_to_vec().unwrap();
    let mut info = b"WebPush: info\0".to_vec();
    info.extend_from_slice(&receiver);
    info.extend_from_slice(&body[21..86]);
    info.push(1);
    let ikm = mac(&mac(auth, &shared), &info);
    let prk = mac(&body[..16], &ikm);
    let cek = mac(&prk, b"Content-Encoding: aes128gcm\0\x01");
    let nonce = mac(&prk, b"Content-Encoding: nonce\0\x01");
    let record = decrypt_aead(
        Cipher::aes_128_gcm(),
        &cek[..16],
        Some(&nonce[..12]),
        b"",
        &body[86..body.len() - 16],
        &body[body.len() - 16..],
    )
    .unwrap();
    let last = record.iter().rposition(|b| *b != 0).unwrap();
    assert_eq!(record[last], 2);
    serde_json::from_slice(&record[..last]).unwrap()
}

async fn capture_push(listener: &TcpListener) -> (String, Vec<u8>) {
    let (mut stream, _) = listener.accept().await.unwrap();
    let mut request = Vec::new();
    let mut chunk = [0u8; 1024];
    let header_end = loop {
        let read = stream.read(&mut chunk).await.unwrap();
        assert!(read > 0);
        request.extend_from_slice(&chunk[..read]);
        if let Some(offset) = request.windows(4).position(|w| w == b"\r\n\r\n") {
            break offset + 4;
        }
        assert!(request.len() < 8192);
    };
    let headers = String::from_utf8(request[..header_end].to_vec()).unwrap();
    assert!(headers
        .to_ascii_lowercase()
        .contains("content-encoding: aes128gcm\r\n"));
    assert!(headers
        .to_ascii_lowercase()
        .contains("content-length: 4096\r\n"));
    while request.len() < header_end + 4096 {
        let read = stream.read(&mut chunk).await.unwrap();
        assert!(read > 0);
        request.extend_from_slice(&chunk[..read]);
    }
    stream
        .write_all(b"HTTP/1.1 202 Accepted\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    (
        headers.lines().next().unwrap().to_owned(),
        request[header_end..].to_vec(),
    )
}

#[tokio::test]
async fn signal_control_commits_before_ack_and_pushes_to_new_endpoint() {
    let root = TestDirectory(
        std::env::temp_dir().join(format!("colliesocket-signal-{}", push::uuid_v4().unwrap())),
    );
    fs::DirBuilder::new().mode(0o700).create(&root.0).unwrap();
    let database = root.0.join("state.db");
    let provider = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("http://{}", provider.local_addr().unwrap());
    let config_path = root.0.join("config.toml");
    fs::write(
        &config_path,
        format!(
            "db = {:?}\nallowed_endpoints = [{:?}]\n",
            database.to_str().unwrap(),
            origin
        ),
    )
    .unwrap();
    config::load_config(Some(config_path));

    let mut enrollment: Enrollment = serde_json::from_slice(include_bytes!(
        "../../contracts/encrypted-push/v2/fixtures/enrollment-keyed.json"
    ))
    .unwrap();
    enrollment.subscription.endpoint = format!("{origin}/old");
    let mut store = PushStore::open(&database).unwrap();
    store.enroll(&enrollment, push::now()).unwrap();
    push::enqueue(&enrollment.account_id, "wake", None).unwrap();
    let gone = store.claim_due(push::now()).unwrap().unwrap();
    store
        .complete(&gone, DeliveryOutcome::Gone, push::now())
        .unwrap();
    assert_eq!(
        store.account_state(&enrollment.account_id).unwrap(),
        Some(AccountState::Stale)
    );

    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
    let receiver = EcKey::generate(&group).unwrap();
    let public = URL_SAFE_NO_PAD.encode(
        receiver
            .public_key()
            .to_bytes(
                &group,
                PointConversionForm::UNCOMPRESSED,
                &mut BigNumContext::new().unwrap(),
            )
            .unwrap(),
    );
    let auth = [73u8; 16];
    let endpoint = format!("{origin}/new");
    let blob = control_blob(&enrollment, &endpoint, &public, &auth, 1);
    let signal = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mut client = socket(&enrollment, &signal);
    let server = async {
        let (stream, _) = signal.accept().await.unwrap();
        let mut peer = accept_async(stream).await.unwrap();
        let mut forged = blob.clone();
        *forged.last_mut().unwrap() ^= 1;
        send(&mut peer, 1, forged.clone(), true).await;
        ack(&mut peer, 1).await;
        assert_eq!(
            store
                .get_subscription(&enrollment.account_id)
                .unwrap()
                .unwrap(),
            enrollment.subscription
        );
        assert_eq!(store.pending_count(None).unwrap(), 0);

        send(&mut peer, 2, blob.clone(), false).await;
        ack(&mut peer, 2).await;
        // ACK is observable only after the durable tuple and status exist.
        let updated = store
            .get_subscription(&enrollment.account_id)
            .unwrap()
            .unwrap();
        assert_eq!(updated.subscription_epoch, 2);
        assert_eq!(updated.endpoint, endpoint);
        assert_eq!(updated.p256dh, public);
        assert_eq!(updated.auth, URL_SAFE_NO_PAD.encode(auth));
        assert_eq!(updated.instance, enrollment.subscription.instance);
        assert_eq!(
            store.account_state(&enrollment.account_id).unwrap(),
            Some(AccountState::Active)
        );
        assert_eq!(store.pending_count(None).unwrap(), 1);
        let connection = crate::db::MollySocketDb::open(&database)
            .unwrap()
            .get(&enrollment.account_id)
            .unwrap();
        assert_eq!(connection.password, enrollment.password);
        assert_eq!(connection.device_id, enrollment.device_id);
        assert_eq!(connection.endpoint, endpoint);
        assert!(!connection.forbidden);

        // Identical replay coalesces the pending confirmation. Re-encryption
        // with a new nonce at the same epoch and a forged urgent blob do nothing.
        let mut wrong_account = enrollment.clone();
        wrong_account.account_id = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb".into();
        let mut wrong_device = enrollment.clone();
        wrong_device.device_id += 1;
        for (index, rejected) in [
            blob.clone(),
            forged,
            control_blob(&enrollment, &endpoint, &public, &auth, 2),
            control_blob(&wrong_account, &endpoint, &public, &auth, 3),
            control_blob(&wrong_device, &endpoint, &public, &auth, 4),
            b"CollieSocket-Control\0".to_vec(),
        ]
        .into_iter()
        .enumerate()
        {
            send(&mut peer, 10 + index as u64, rejected, true).await;
            ack(&mut peer, 10 + index as u64).await;
            assert_eq!(
                store
                    .get_subscription(&enrollment.account_id)
                    .unwrap()
                    .unwrap(),
                updated
            );
            assert_eq!(store.pending_count(None).unwrap(), 1);
        }

        let (sent, (path, body)) = tokio::join!(push::drain_once(), capture_push(&provider));
        assert!(sent.unwrap());
        assert_eq!(path, "POST /new HTTP/1.1");
        let status = decrypt_push(&body, &receiver, &auth);
        assert_eq!(status["version"], 2);
        assert_eq!(status["kind"], "status");
        assert_eq!(status["code"], "subscription_updated");
        assert_eq!(status["subscription_epoch"], 2);

        // No reconnect or five-second manager poll: the next urgent envelope
        // uses the updated endpoint and both new Web Push keys on this socket.
        send(&mut peer, 30, vec![1, 2, 3], true).await;
        ack(&mut peer, 30).await;
        let (sent, (path, body)) = tokio::join!(push::drain_once(), capture_push(&provider));
        assert!(sent.unwrap());
        assert_eq!(path, "POST /new HTTP/1.1");
        let wake = decrypt_push(&body, &receiver, &auth);
        assert_eq!(wake["version"], 2);
        assert_eq!(wake["kind"], "wake");
        assert_eq!(wake["subscription_epoch"], 2);
        peer.close(None).await.unwrap();
        updated
    };
    let (result, updated) = time::timeout(Duration::from_secs(20), async {
        tokio::join!(client.connect(tls::build_tls_connector().unwrap()), server)
    })
    .await
    .unwrap();
    result.unwrap();
    enrollment.subscription = updated;

    // A forced outbox failure must roll back the subscription and close without
    // acknowledging. A new socket can safely retry the identical encrypted blob.
    let next = control_blob(
        &enrollment,
        &format!("{origin}/recovered"),
        &public,
        &auth,
        5,
    );
    let database_connection = rusqlite::Connection::open(&database).unwrap();
    database_connection.execute_batch("CREATE TRIGGER synthetic_queue_failure BEFORE INSERT ON encrypted_push_queue BEGIN SELECT RAISE(ABORT,'synthetic_failure'); END;").unwrap();
    let signal = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mut client = socket(&enrollment, &signal);
    let failure_peer = async {
        let (stream, _) = signal.accept().await.unwrap();
        let mut peer = accept_async(stream).await.unwrap();
        send(&mut peer, 40, next.clone(), false).await;
        let received = peer.next().await;
        assert!(!matches!(
            received,
            Some(Ok(tungstenite::Message::Binary(_)))
        ));
    };
    let (failed, ()) = time::timeout(Duration::from_secs(10), async {
        tokio::join!(
            client.connect(tls::build_tls_connector().unwrap()),
            failure_peer
        )
    })
    .await
    .unwrap();
    assert!(failed.is_err());
    assert_eq!(
        store
            .get_subscription(&enrollment.account_id)
            .unwrap()
            .unwrap(),
        enrollment.subscription
    );
    assert_eq!(store.pending_count(None).unwrap(), 0);
    database_connection
        .execute_batch("DROP TRIGGER synthetic_queue_failure;")
        .unwrap();

    let signal = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mut client = socket(&enrollment, &signal);
    let recovery_peer = async {
        let (stream, _) = signal.accept().await.unwrap();
        let mut peer = accept_async(stream).await.unwrap();
        send(&mut peer, 41, next, false).await;
        ack(&mut peer, 41).await;
        assert_eq!(
            store
                .get_subscription(&enrollment.account_id)
                .unwrap()
                .unwrap()
                .subscription_epoch,
            3
        );
        let (sent, (path, body)) = tokio::join!(push::drain_once(), capture_push(&provider));
        assert!(sent.unwrap());
        assert_eq!(path, "POST /recovered HTTP/1.1");
        assert_eq!(
            decrypt_push(&body, &receiver, &auth)["subscription_epoch"],
            3
        );
        peer.close(None).await.unwrap();
    };
    let (result, ()) = time::timeout(Duration::from_secs(10), async {
        tokio::join!(
            client.connect(tls::build_tls_connector().unwrap()),
            recovery_peer
        )
    })
    .await
    .unwrap();
    result.unwrap();
}
