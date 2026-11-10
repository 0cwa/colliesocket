//! Destination-checked HTTP transport; payload encryption and VAPID are separate.
use crate::{config, vapid};
use async_trait::async_trait;
use eyre::{eyre, Result};
use lazy_static::lazy_static;
use reqwest::{dns::Resolve, redirect::Policy};
use std::{
    fmt::{Display, Formatter},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};
use trust_dns_resolver::{lookup_ip::LookupIp, TokioAsyncResolver};
use url::{Host, Origin, Url};

const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
const LEGACY_WAKE: &[u8] = br#"{"urgent":true}"#;
lazy_static! {
    static ref RESOLVER: Option<TokioAsyncResolver> =
        TokioAsyncResolver::tokio_from_system_conf().ok();
}

#[derive(Debug)]
enum Error {
    InvalidEndpoint,
    HostNotAllowed,
    InvalidBody,
    InvalidTtl,
    LegacyDisabled,
    ClientUnavailable,
    TransportFailed,
    TransportTimeout,
}
impl Display for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::InvalidEndpoint => "invalid_endpoint",
            Self::HostNotAllowed => "destination_not_allowed",
            Self::InvalidBody => "invalid_encrypted_body",
            Self::InvalidTtl => "invalid_push_ttl",
            Self::LegacyDisabled => "legacy_disabled",
            Self::ClientUnavailable => "transport_unavailable",
            Self::TransportFailed => "transport_failed",
            Self::TransportTimeout => "transport_timeout",
        })
    }
}
impl std::error::Error for Error {}

/// Unpinned names fail closed; 0.0.0.0 is not a safe fallback address.
struct ResolveNothing;
impl Resolve for ResolveNothing {
    fn resolve(&self, _: reqwest::dns::Name) -> reqwest::dns::Resolving {
        Box::pin(async {
            Err(
                std::io::Error::new(std::io::ErrorKind::PermissionDenied, "unpinned_destination")
                    .into(),
            )
        })
    }
}

enum Payload {
    Encrypted(Vec<u8>),
    LegacyWake,
}
impl Payload {
    fn validate(&self, ttl: u32) -> Result<()> {
        if !(1..=300).contains(&ttl) {
            return Err(eyre!(Error::InvalidTtl));
        }
        if let Self::Encrypted(body) = self {
            if body.len() != 4096
                || body[16..20] != 4096_u32.to_be_bytes()
                || body[20] != 65
                || body[21] != 4
            {
                return Err(eyre!(Error::InvalidBody));
            }
        }
        Ok(())
    }
}

/// Temporary shim so this layer compiles on its own. The next PR in this stack
/// moves `ws::signalwebsocket` to the encrypted sender and removes this function.
pub async fn post_allowed(
    url: Url,
    _body: &serde_json::Value,
    _topic: Option<&str>,
) -> Result<reqwest::Response> {
    post_legacy_wake(url).await
}

/// A provider response is never proof of device delivery.
pub async fn post_encrypted(url: Url, body: Vec<u8>, ttl: u32) -> Result<reqwest::Response> {
    let payload = Payload::Encrypted(body);
    payload.validate(ttl)?;
    post_configured(url, payload, ttl).await
}

/// Exactly one generic wake payload; no caller-supplied plaintext or fake encoding.
pub async fn post_legacy_wake(url: Url) -> Result<reqwest::Response> {
    if !config::legacy_wake_enabled() {
        return Err(eyre!(Error::LegacyDisabled));
    }
    post_configured(url, Payload::LegacyWake, 300).await
}

async fn post_configured(url: Url, payload: Payload, ttl: u32) -> Result<reqwest::Response> {
    // Bound the entire operation, including policy DNS and send-time re-resolution.
    tokio::time::timeout(REQUEST_TIMEOUT, async {
        if !config::is_endpoint_valid(url.as_str()).await {
            return Err(eyre!(Error::HostNotAllowed));
        }
        let explicit_origin = config::is_endpoint_allowed_by_user(&url).then(|| url.origin());
        let authorization = vapid::get_vapid_header(url.origin()).ok();
        post_with_policy(url, payload, ttl, explicit_origin, authorization).await
    })
    .await
    .map_err(|_| eyre!(Error::TransportTimeout))?
}

fn is_explicit_origin(url: &Url, allowed: Option<&Origin>) -> bool {
    allowed.is_some_and(|origin| *origin == url.origin())
}

fn validate_destination(url: &Url, allowed: Option<&Origin>) -> Result<u16> {
    if url.as_str().len() > 2048
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
        || url.host().is_none()
        || !(url.scheme() == "https"
            || (url.scheme() == "http" && is_explicit_origin(url, allowed)))
    {
        return Err(eyre!(Error::InvalidEndpoint));
    }
    match url.port_or_known_default() {
        Some(port) if port != 0 => Ok(port),
        _ => Err(eyre!(Error::InvalidEndpoint)),
    }
}

async fn checked_client(url: &Url, allowed: Option<&Origin>) -> Result<reqwest::Client> {
    let port = validate_destination(url, allowed)?;
    let mut builder = reqwest::ClientBuilder::new()
        .no_proxy()
        .redirect(Policy::none())
        .timeout(REQUEST_TIMEOUT)
        .connect_timeout(REQUEST_TIMEOUT);
    if !is_explicit_origin(url, allowed) {
        let addresses = url
            .resolve_allowed()
            .await?
            .into_iter()
            .map(|ip| SocketAddr::new(ip, port))
            .collect::<Vec<_>>();
        if addresses.is_empty() {
            return Err(eyre!(Error::HostNotAllowed));
        }
        builder = builder
            .dns_resolver(Arc::new(ResolveNothing))
            .resolve_to_addrs(url.host_str().ok_or(Error::InvalidEndpoint)?, &addresses);
    }
    builder.build().map_err(|_| eyre!(Error::ClientUnavailable))
}

/// Tests supply explicit policy without racing global configuration.
async fn post_with_policy(
    url: Url,
    payload: Payload,
    ttl: u32,
    explicit_origin: Option<Origin>,
    authorization: Option<String>,
) -> Result<reqwest::Response> {
    payload.validate(ttl)?;
    let client = checked_client(&url, explicit_origin.as_ref()).await?;
    let mut request = client
        .post(url)
        .header("TTL", ttl)
        .header("Urgency", "normal");
    request = match payload {
        Payload::Encrypted(body) => request
            .header("Content-Type", "application/octet-stream")
            .header("Content-Encoding", "aes128gcm")
            .body(body),
        Payload::LegacyWake => request
            .header("Content-Type", "application/json")
            .body(LEGACY_WAKE),
    };
    if let Some(authorization) = authorization {
        request = request.header("Authorization", authorization);
    }
    request.send().await.map_err(|error| {
        // Drop the source error: reqwest Display/Debug includes endpoint tokens.
        if error.is_timeout() {
            eyre!(Error::TransportTimeout)
        } else {
            eyre!(Error::TransportFailed)
        }
    })
}

fn global_v4(ip: &Ipv4Addr) -> bool {
    ip_rfc::global_v4(ip) && !ip.is_multicast()
}
fn global_v6(ip: &Ipv6Addr) -> bool {
    // ip_rfc 0.1.0 otherwise admits mapped loopback/private IPv4 addresses.
    if let Some(mapped) = ip.to_ipv4() {
        return global_v4(&mapped);
    }
    let s = ip.segments();
    // Transition/translation, reserved, site-local and multicast addresses must
    // use explicit origin authorization. Public sends use global unicast.
    (s[0] & 0xe000) == 0x2000
        && ip_rfc::global_v6(ip)
        && s[0] != 0x2002
        && !(s[0] == 0x2001 && s[1] < 0x0200)
        && !(s[0] == 0x3fff && (s[1] & 0xf000) == 0)
}
fn global_unicast(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => global_v4(ip),
        IpAddr::V6(ip) => global_v6(ip),
    }
}

#[async_trait]
pub trait ResolveAllowed {
    async fn resolve_allowed(&self) -> Result<Vec<IpAddr>>;
}
#[async_trait]
impl ResolveAllowed for Url {
    async fn resolve_allowed(&self) -> Result<Vec<IpAddr>> {
        // Config resolves before deciding explicit HTTP allowance; the actual
        // send applies validate_destination's stricter scheme rule as well.
        if ["http", "https"].contains(&self.scheme()) {
            self.host()
                .ok_or(Error::HostNotAllowed)?
                .resolve_allowed()
                .await
        } else {
            Err(eyre!(Error::InvalidEndpoint))
        }
    }
}
#[async_trait]
impl ResolveAllowed for Host<&str> {
    async fn resolve_allowed(&self) -> Result<Vec<IpAddr>> {
        match self {
            Host::Domain(domain) => {
                RESOLVER
                    .as_ref()
                    .ok_or(Error::HostNotAllowed)?
                    .lookup_ip(*domain)
                    .await
                    .map_err(|_| Error::HostNotAllowed)?
                    .resolve_allowed()
                    .await
            }
            Host::Ipv4(ip) if global_v4(ip) => Ok(vec![IpAddr::V4(*ip)]),
            Host::Ipv6(ip) if global_v6(ip) => Ok(vec![IpAddr::V6(*ip)]),
            _ => Err(eyre!(Error::HostNotAllowed)),
        }
    }
}
#[async_trait]
impl ResolveAllowed for LookupIp {
    async fn resolve_allowed(&self) -> Result<Vec<IpAddr>> {
        Ok(self.iter().filter(global_unicast).collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        collections::HashMap,
        io::{Read, Write},
        net::TcpListener,
        str::FromStr,
        sync::mpsc,
        thread,
    };
    fn encrypted_fixture() -> Vec<u8> {
        include_bytes!("../../crates/colliesocket-push/fixtures/wake-v1.bin").to_vec()
    }
    #[test]
    fn rejects_private_special_and_mapped_addresses() {
        for address in [
            "0.0.0.0",
            "0.0.0.1",
            "10.1.2.3",
            "127.0.0.1",
            "169.254.169.254",
            "172.16.0.1",
            "192.168.1.1",
            "100.100.100.200",
            "192.0.2.1",
            "198.18.0.1",
            "224.0.0.1",
            "239.255.255.250",
            "255.255.255.255",
            "::",
            "::1",
            "::127.0.0.1",
            "::ffff:127.0.0.1",
            "::ffff:10.1.2.3",
            "::ffff:169.254.169.254",
            "::ffff:192.168.1.1",
            "fe80::1",
            "fec0::1",
            "fc00::1",
            "fd00::1",
            "ff0e::1",
            "2001:db8::1",
            "2001:2::1",
            "64:ff9b::7f00:1",
            "64:ff9b:1::1",
            "2002:7f00:1::1",
            "2001::1",
            "3fff::1",
        ] {
            assert!(
                !global_unicast(&address.parse().unwrap()),
                "accepted {address}"
            );
        }
        for address in [
            "8.8.8.8",
            "1.1.1.1",
            "2606:4700:4700::1111",
            "2001:4860:4860::8888",
            "::ffff:8.8.8.8",
        ] {
            assert!(
                global_unicast(&address.parse().unwrap()),
                "rejected {address}"
            );
        }
    }
    #[tokio::test]
    async fn literal_private_addresses_fail_without_network() {
        for address in [
            "https://127.1/private-token",
            "https://10.1.2.3/",
            "https://[::1]/",
            "https://[::ffff:127.0.0.1]/",
            "https://[fc00::1]/",
            "unix://example.test/",
        ] {
            assert!(Url::parse(address)
                .unwrap()
                .resolve_allowed()
                .await
                .is_err());
        }
        assert_eq!(
            Url::parse("https://8.8.8.8/")
                .unwrap()
                .resolve_allowed()
                .await
                .unwrap(),
            vec![IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))]
        );
    }
    #[test]
    fn explicit_allowance_is_exact_origin_without_credentials() {
        let allowed = Url::parse("http://127.0.0.1:8020/").unwrap().origin();
        let private = Url::parse("http://127.0.0.1:8020/token?secret=value").unwrap();
        assert!(validate_destination(&private, Some(&allowed)).is_ok());
        assert!(validate_destination(&private, None).is_err());
        for different in ["http://127.0.0.1:8021/", "http://127.0.0.2:8020/"] {
            assert!(validate_destination(&Url::parse(different).unwrap(), Some(&allowed)).is_err());
        }
        for endpoint in [
            "http://user:pass@127.0.0.1:8020/",
            "http://127.0.0.1:8020/#fragment",
            "ftp://127.0.0.1:8020/",
            "http://127.0.0.1:0/",
        ] {
            let url = Url::parse(endpoint).unwrap();
            assert!(validate_destination(&url, Some(&url.origin())).is_err());
        }
        let https = Url::parse("https://example.test:443/path").unwrap();
        assert!(is_explicit_origin(
            &https,
            Some(&Url::parse("https://example.test/").unwrap().origin())
        ));
        assert!(!is_explicit_origin(
            &https,
            Some(&Url::parse("http://example.test/").unwrap().origin())
        ));
    }
    #[tokio::test]
    async fn unresolved_fallback_fails_closed() {
        assert!(ResolveNothing
            .resolve(reqwest::dns::Name::from_str("untrusted.example").unwrap())
            .await
            .is_err());
    }
    #[test]
    fn validates_frame_budget_ttl_and_fixed_legacy_payload() {
        let frame = encrypted_fixture();
        for ttl in [1, 300] {
            assert!(Payload::Encrypted(frame.clone()).validate(ttl).is_ok());
        }
        for ttl in [0, 301, u32::MAX] {
            assert!(Payload::Encrypted(frame.clone()).validate(ttl).is_err());
        }
        for body in [
            vec![],
            br#"{"urgent":true}"#.to_vec(),
            vec![0; 4096],
            vec![0; 4097],
        ] {
            assert!(Payload::Encrypted(body).validate(300).is_err());
        }
        assert_eq!(LEGACY_WAKE, br#"{"urgent":true}"#);
    }
    struct Captured {
        start: String,
        headers: HashMap<String, String>,
        body: Vec<u8>,
    }
    fn capture_once(response: String) -> (Url, mpsc::Receiver<Captured>, thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let (send, receive) = mpsc::channel();
        let handle = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let mut bytes = Vec::new();
            let header_end = loop {
                let mut chunk = [0; 2048];
                let count = stream.read(&mut chunk).unwrap();
                assert_ne!(count, 0);
                bytes.extend_from_slice(&chunk[..count]);
                if let Some(position) = bytes.windows(4).position(|x| x == b"\r\n\r\n") {
                    break position + 4;
                }
                assert!(bytes.len() < 16_384);
            };
            let text = std::str::from_utf8(&bytes[..header_end]).unwrap();
            let mut lines = text.split("\r\n");
            let start = lines.next().unwrap().to_owned();
            let headers = lines
                .filter_map(|line| line.split_once(':'))
                .map(|(key, value)| (key.to_ascii_lowercase(), value.trim().to_owned()))
                .collect::<HashMap<_, _>>();
            let body_length = headers["content-length"].parse::<usize>().unwrap();
            assert!(body_length <= 4096);
            while bytes.len() < header_end + body_length {
                let mut chunk = [0; 4096];
                let count = stream.read(&mut chunk).unwrap();
                assert_ne!(count, 0);
                bytes.extend_from_slice(&chunk[..count]);
            }
            let body = bytes[header_end..header_end + body_length].to_vec();
            stream.write_all(response.as_bytes()).unwrap();
            send.send(Captured {
                start,
                headers,
                body,
            })
            .unwrap();
        });
        (
            Url::parse(&format!("http://{address}/synthetic-provider-token")).unwrap(),
            receive,
            handle,
        )
    }
    #[tokio::test]
    async fn encrypted_binary_body_and_headers_reach_local_socket() {
        let (url, captured, thread) = capture_once(
            "HTTP/1.1 201 Created\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".into(),
        );
        let origin = url.origin();
        let body = encrypted_fixture();
        let response = post_with_policy(
            url,
            Payload::Encrypted(body.clone()),
            42,
            Some(origin),
            Some("vapid synthetic-test-only".into()),
        )
        .await
        .unwrap();
        assert_eq!(response.status(), reqwest::StatusCode::CREATED);
        let captured = captured.recv_timeout(Duration::from_secs(5)).unwrap();
        thread.join().unwrap();
        assert_eq!(captured.start, "POST /synthetic-provider-token HTTP/1.1");
        assert_eq!(captured.body, body);
        assert_eq!(captured.headers["content-type"], "application/octet-stream");
        assert_eq!(captured.headers["content-encoding"], "aes128gcm");
        assert_eq!(captured.headers["content-length"], "4096");
        assert_eq!(captured.headers["ttl"], "42");
        assert_eq!(captured.headers["urgency"], "normal");
        assert_eq!(
            captured.headers["authorization"],
            "vapid synthetic-test-only"
        );
        assert!(!captured.headers.contains_key("topic"));
    }
    #[tokio::test]
    async fn legacy_body_is_fixed_without_fake_encryption() {
        let (url, captured, thread) = capture_once(
            "HTTP/1.1 202 Accepted\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".into(),
        );
        let origin = url.origin();
        assert_eq!(
            post_with_policy(url, Payload::LegacyWake, 300, Some(origin), None)
                .await
                .unwrap()
                .status(),
            reqwest::StatusCode::ACCEPTED
        );
        let captured = captured.recv_timeout(Duration::from_secs(5)).unwrap();
        thread.join().unwrap();
        assert_eq!(captured.body, LEGACY_WAKE);
        assert_eq!(captured.headers["content-type"], "application/json");
        assert_eq!(captured.headers["ttl"], "300");
        for forbidden in ["content-encoding", "topic", "authorization"] {
            assert!(!captured.headers.contains_key(forbidden));
        }
    }
    #[test]
    fn proxy_environment_is_ignored() {
        const CHILD: &str = "COLLIESOCKET_PROXY_TEST_CHILD";
        if std::env::var_os(CHILD).is_some() {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(async {
                    let (url, captured, thread) = capture_once(
                        "HTTP/1.1 202 Accepted\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                            .into(),
                    );
                    let origin = url.origin();
                    assert_eq!(
                        post_with_policy(url, Payload::LegacyWake, 300, Some(origin), None)
                            .await
                            .unwrap()
                            .status(),
                        reqwest::StatusCode::ACCEPTED
                    );
                    captured.recv_timeout(Duration::from_secs(5)).unwrap();
                    thread.join().unwrap();
                });
            return;
        }
        let mut command = std::process::Command::new(std::env::current_exe().unwrap());
        command.args([
            "--exact",
            "utils::post_allowed::tests::proxy_environment_is_ignored",
            "--nocapture",
        ]);
        command.env(CHILD, "1");
        for name in [
            "HTTP_PROXY",
            "HTTPS_PROXY",
            "ALL_PROXY",
            "http_proxy",
            "https_proxy",
            "all_proxy",
        ] {
            command.env(name, "http://127.0.0.1:1");
        }
        command.env("NO_PROXY", "").env("no_proxy", "");
        let output = command.output().unwrap();
        assert!(output.status.success(), "isolated proxy check failed");
        assert!(String::from_utf8(output.stdout)
            .unwrap()
            .contains("1 passed"));
    }
    #[tokio::test]
    async fn redirect_does_not_reach_another_listener() {
        let forbidden = TcpListener::bind("127.0.0.1:0").unwrap();
        forbidden.set_nonblocking(true).unwrap();
        let response_text = format!("HTTP/1.1 302 Found\r\nLocation: http://{}/forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", forbidden.local_addr().unwrap());
        let (url, captured, thread) = capture_once(response_text);
        let origin = url.origin();
        assert_eq!(
            post_with_policy(
                url,
                Payload::Encrypted(encrypted_fixture()),
                300,
                Some(origin),
                None
            )
            .await
            .unwrap()
            .status(),
            reqwest::StatusCode::FOUND
        );
        captured.recv_timeout(Duration::from_secs(5)).unwrap();
        thread.join().unwrap();
        assert_eq!(
            forbidden.accept().unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
    }
    #[tokio::test]
    async fn errors_redact_endpoint_and_discard_reqwest_source() {
        let closed = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = closed.local_addr().unwrap();
        drop(closed);
        let url = Url::parse(&format!(
            "http://{address}/CONFIDENTIAL_PATH?auth=CONFIDENTIAL_QUERY"
        ))
        .unwrap();
        let origin = url.origin();
        let error = post_with_policy(
            url,
            Payload::Encrypted(encrypted_fixture()),
            300,
            Some(origin),
            None,
        )
        .await
        .unwrap_err();
        assert_eq!(error.to_string(), "transport_failed");
        assert_eq!(error.chain().count(), 1);
        assert!(!format!("{error:?}").contains("CONFIDENTIAL"));
    }
}
