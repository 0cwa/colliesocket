use directories::ProjectDirs;
use figment::{
    providers::{Env, Format, Serialized, Toml},
    Figment,
};
use serde::{Deserialize, Serialize};
use std::{
    env,
    fmt::{self, Debug},
    path::PathBuf,
    process,
    sync::OnceLock,
};

use crate::utils::post_allowed::ResolveAllowed;

static CONFIG: OnceLock<Config> = OnceLock::new();

#[derive(Debug, Serialize, Deserialize)]
pub enum SignalEnvironment {
    Production,
    Staging,
}

#[derive(Serialize, Deserialize)]
struct Config {
    host: String,
    port: u16,
    webserver: bool,
    vapid_privkey: Option<String>,
    vapid_key_file: Option<String>,
    signal_env: SignalEnvironment,
    #[cfg(all(feature = "test-signal", debug_assertions, colliesocket_test_signal))]
    test_signal_url: Option<String>,
    #[cfg(all(feature = "test-signal", debug_assertions, colliesocket_test_signal))]
    test_signal_ca: Option<String>,
    #[cfg(all(feature = "test-signal", debug_assertions, colliesocket_test_signal))]
    #[serde(skip)]
    test_signal_root: Option<native_tls::Certificate>,
    allowed_endpoints: Vec<String>,
    allowed_uuids: Vec<String>,
    db: String,
    legacy_wake_until: i64,
    push_only: bool,
    ready_port: u16,
}

impl Debug for Config {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Config")
            .field("host", &self.host)
            .field("port", &self.port)
            .field("webserver", &self.webserver)
            .field("push_only", &self.push_only)
            .field("ready_port", &self.ready_port)
            .field("secrets", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

#[derive(Debug, PartialEq, Eq)]
enum EndpointValidity {
    Ok,
    NotInConfig,
    Private,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            host: String::from("127.0.0.1"),
            port: 8020,
            webserver: true,
            vapid_privkey: None,
            vapid_key_file: None,
            signal_env: SignalEnvironment::Production,
            #[cfg(all(feature = "test-signal", debug_assertions, colliesocket_test_signal))]
            test_signal_url: None,
            #[cfg(all(feature = "test-signal", debug_assertions, colliesocket_test_signal))]
            test_signal_ca: None,
            #[cfg(all(feature = "test-signal", debug_assertions, colliesocket_test_signal))]
            test_signal_root: None,
            allowed_endpoints: vec![String::from("*")],
            allowed_uuids: vec![String::from("*")],
            db: String::from("./mollysocket.db"),
            legacy_wake_until: 0,
            push_only: false,
            ready_port: 8021,
        }
    }
}

fn get_cfg() -> &'static Config {
    CONFIG.get().expect("Config is not initialized yet.")
}

/// Get db filename
pub fn get_db() -> &'static str {
    &get_cfg().db
}

pub fn get_host() -> &'static str {
    &get_cfg().host
}

pub fn get_port() -> u16 {
    get_cfg().port
}

pub fn get_ready_port() -> u16 {
    get_cfg().ready_port
}
pub fn push_only() -> bool {
    get_cfg().push_only
}
pub fn legacy_wake_enabled() -> bool {
    let deadline = get_cfg().legacy_wake_until;
    deadline > 0 && crate::push::now() < deadline
}

pub fn is_uuid_valid(uuid: &str) -> bool {
    get_cfg().is_uuid_valid(uuid)
}

pub fn should_start_webserver() -> bool {
    get_cfg().webserver
}

pub fn get_vapid_privkey() -> Option<&'static str> {
    get_cfg().vapid_privkey.as_deref()
}

pub fn get_ws_endpoint() -> &'static str {
    get_cfg().get_ws_endpoint()
}

#[cfg(all(feature = "test-signal", debug_assertions, colliesocket_test_signal))]
pub(crate) fn get_test_signal_root() -> Option<native_tls::Certificate> {
    // TLS unit tests can build the pinned connector before configuration loads.
    CONFIG
        .get()
        .and_then(|config| config.test_signal_root.clone())
}

pub async fn is_endpoint_valid(url: &str) -> bool {
    get_cfg().is_endpoint_valid(url).await
}

pub fn is_endpoint_allowed_by_user(url: &url::Url) -> bool {
    get_cfg().is_endpoint_allowed_by_user(url)
}

pub fn print() {
    let cfg = get_cfg();
    println!("{:#?}", cfg)
}

pub fn load_config(cli_config_path: Option<PathBuf>) {
    CONFIG.get_or_init(move || {
        let mut figment = Figment::new();

        figment = figment.merge(Serialized::defaults(Config::default()));

        if let Some(path) = get_config_path(cli_config_path) {
            log::info!("Config file supplied");
            figment = figment.merge(Toml::file(path));
        } else {
            log::info!("No config file supplied");
        }

        figment = figment.merge(Env::prefixed("MOLLY_").ignore(&["conf"]));

        let mut config: Config = match figment.extract() {
            Ok(config) => config,
            Err(_) => {
                log::error!("invalid_configuration");
                process::exit(0x0001);
            }
        };
        if let Some(file) = &config.vapid_key_file {
            config.vapid_privkey = Some(
                String::from_utf8(
                    crate::enrollment::read_protected_file(std::path::Path::new(file), 4096)
                        .unwrap_or_else(|_| {
                            eprintln!("unsafe_secret_file");
                            process::exit(1)
                        }),
                )
                .unwrap_or_else(|_| {
                    eprintln!("invalid_secret_file");
                    process::exit(1)
                })
                .trim_end()
                .to_string(),
            );
        }
        if config.legacy_wake_until < 0
            || config.legacy_wake_until > crate::push::now().saturating_add(86400)
        {
            eprintln!("invalid_legacy_deadline");
            process::exit(1);
        }
        if config.ready_port == 0 {
            eprintln!("invalid_configuration");
            process::exit(1);
        }
        #[cfg(all(feature = "test-signal", debug_assertions, colliesocket_test_signal))]
        if config.load_test_signal_root().is_err() {
            eprintln!("invalid_test_signal_configuration");
            process::exit(1);
        }
        config
    });
}

fn get_config_path(cli_config_path: Option<PathBuf>) -> Option<PathBuf> {
    let mut paths: Vec<PathBuf> = Vec::new();

    // from cli argument
    if let Some(cli_path) = cli_config_path {
        if cli_path.exists() {
            return Some(cli_path);
        } else {
            eprintln!("invalid_configuration");
            process::exit(1);
        }
    }

    // from environment variable
    if let Some(env_path) = env::var_os("MOLLY_CONF") {
        let path = Into::<PathBuf>::into(env_path);
        if path.exists() {
            return Some(path);
        } else {
            eprintln!("invalid_configuration");
            process::exit(1);
        }
    }

    // from xdg_config_home
    if let Some(proj_dirs) = ProjectDirs::from("org", "mollyim", "mollysocket") {
        paths.push(proj_dirs.config_dir().join("config.toml"));
    }

    // in current directory
    paths.push(PathBuf::from("./mollysocket.toml"));

    // in linux /etc dir
    if cfg!(target_os = "linux") {
        paths.push(PathBuf::from("/etc/mollysocket/config.toml"));
    }

    for p in paths.iter() {
        if p.exists() {
            return Some(p.to_path_buf());
        }
    }
    None
}

impl Config {
    fn is_uuid_valid(&self, uuid: &str) -> bool {
        self.allowed_uuids
            .iter()
            .any(|allowed| allowed == "*" || allowed == uuid)
    }

    async fn is_endpoint_valid(&self, url: &str) -> bool {
        if url.len() > 2048 || !url.is_ascii() || url.bytes().any(|b| b <= 32 || b == 127) {
            return false;
        }
        if url.contains('\\')
            || url.split_once("://").is_none_or(|(_, tail)| {
                tail.split(['/', '?', '#'])
                    .next()
                    .unwrap_or("")
                    .contains('@')
            })
        {
            return false;
        }
        if let Ok(url) = url::Url::parse(url) {
            let endpoint_validity = self.is_url_endpoint_valid(&url).await;
            match endpoint_validity {
                EndpointValidity::Ok => true,
                EndpointValidity::NotInConfig => {
                    log::warn!("endpoint_not_allowed");
                    false
                }
                EndpointValidity::Private => {
                    log::warn!("endpoint_address_not_allowed");
                    false
                }
            }
        } else {
            false
        }
    }

    fn get_ws_endpoint(&self) -> &str {
        #[cfg(all(feature = "test-signal", debug_assertions, colliesocket_test_signal))]
        if let Some(endpoint) = &self.test_signal_url {
            return endpoint;
        }
        match self.signal_env {
            SignalEnvironment::Production => "wss://chat.signal.org/v1/websocket/",
            SignalEnvironment::Staging => "wss://chat.staging.signal.org/v1/websocket/",
        }
    }

    #[cfg(all(feature = "test-signal", debug_assertions, colliesocket_test_signal))]
    fn valid_test_signal_options(&self) -> bool {
        let (raw_url, ca) = match (&self.test_signal_url, &self.test_signal_ca) {
            (None, None) => return true,
            (Some(raw_url), Some(ca)) => (raw_url, ca),
            _ => return false,
        };
        if ca.is_empty()
            || raw_url.len() > 2048
            || !raw_url.is_ascii()
            || raw_url.bytes().any(|b| b <= 32 || b == 127)
            || raw_url.contains(['\\', '@'])
        {
            return false;
        }
        let Ok(url) = url::Url::parse(raw_url) else {
            return false;
        };
        let loopback = match url.host() {
            Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
            Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
            _ => false,
        };
        url.scheme() == "wss"
            && loopback
            && url.username().is_empty()
            && url.password().is_none()
            && url.query().is_none()
            && url.fragment().is_none()
            && url.port_or_known_default().is_some_and(|port| port != 0)
    }

    #[cfg(all(feature = "test-signal", debug_assertions, colliesocket_test_signal))]
    fn load_test_signal_root(&mut self) -> Result<(), ()> {
        if !self.valid_test_signal_options() {
            return Err(());
        }
        if let Some(path) = &self.test_signal_ca {
            let pem = crate::enrollment::read_protected_file(std::path::Path::new(path), 16 * 1024)
                .map_err(|_| ())?;
            self.test_signal_root = Some(native_tls::Certificate::from_pem(&pem).map_err(|_| ())?);
        }
        Ok(())
    }

    async fn is_url_endpoint_valid(&self, url: &url::Url) -> EndpointValidity {
        if !matches!(url.scheme(), "http" | "https")
            || url.host().is_none()
            || !url.username().is_empty()
            || url.password().is_some()
            || url.fragment().is_some()
        {
            return EndpointValidity::NotInConfig;
        }
        if self.is_endpoint_allowed_by_user(url) {
            EndpointValidity::Ok
        } else {
            if url.scheme() == "https" && self.allowed_endpoints.iter().any(|s| s == "*") {
                if url.resolve_allowed().await.unwrap_or(vec![]).len().gt(&0) {
                    EndpointValidity::Ok
                } else {
                    EndpointValidity::Private
                }
            } else {
                EndpointValidity::NotInConfig
            }
        }
    }

    fn is_endpoint_allowed_by_user(&self, url: &url::Url) -> bool {
        if !matches!(url.scheme(), "http" | "https")
            || url.host().is_none()
            || !url.username().is_empty()
            || url.password().is_some()
            || url.fragment().is_some()
        {
            return false;
        }
        self.allowed_endpoints.iter().any(|allowed| {
            if allowed.len() > 2048
                || !allowed.is_ascii()
                || allowed.bytes().any(|b| b <= 32 || b == 127)
                || allowed.contains(['\\', '?', '#'])
                || allowed
                    .split_once("://")
                    .is_none_or(|(_, tail)| tail.split('/').next().unwrap_or("").contains('@'))
            {
                return false;
            }
            if let Ok(allowed_url) = url::Url::parse(allowed) {
                url.host() == allowed_url.host()
                    && url.port_or_known_default() == allowed_url.port_or_known_default()
                    && url.scheme() == allowed_url.scheme()
                    && allowed_url.username().is_empty()
                    && allowed_url.password().is_none()
                    && allowed_url.query().is_none()
                    && allowed_url.fragment().is_none()
                    && allowed_url.path() == "/"
                    && allowed_url.port_or_known_default().is_some_and(|p| p != 0)
            } else {
                false
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_signal_endpoints_are_pinned() {
        let mut cfg = Config::default();
        assert_eq!(cfg.get_ws_endpoint(), "wss://chat.signal.org/v1/websocket/");
        cfg.signal_env = SignalEnvironment::Staging;
        assert_eq!(
            cfg.get_ws_endpoint(),
            "wss://chat.staging.signal.org/v1/websocket/"
        );
    }

    #[cfg(not(all(feature = "test-signal", debug_assertions, colliesocket_test_signal)))]
    #[test]
    fn test_signal_overrides_are_compiled_out() {
        let cfg: Config = Figment::from(Serialized::defaults(Config::default()))
            .merge(Toml::string(
                r#"
                test_signal_url = "wss://127.0.0.1:12345/v1/websocket/"
                test_signal_ca = "/nonexistent/test-ca.pem"
                "#,
            ))
            .extract()
            .unwrap();
        assert_eq!(cfg.get_ws_endpoint(), "wss://chat.signal.org/v1/websocket/");
        let serialized = serde_json::to_value(cfg).unwrap();
        assert!(serialized.get("test_signal_url").is_none());
        assert!(serialized.get("test_signal_ca").is_none());
    }

    #[cfg(all(feature = "test-signal", debug_assertions, colliesocket_test_signal))]
    #[test]
    fn test_signal_requires_both_options_and_loopback_wss() {
        let mut cfg = Config::default();
        assert!(cfg.valid_test_signal_options());
        cfg.test_signal_url = Some("wss://127.0.0.1:12345/v1/websocket/".into());
        assert!(!cfg.valid_test_signal_options());
        cfg.test_signal_ca = Some("/synthetic-test-ca.pem".into());
        assert!(cfg.valid_test_signal_options());
        assert_eq!(
            cfg.get_ws_endpoint(),
            cfg.test_signal_url.as_deref().unwrap()
        );
        assert!(!format!("{cfg:?}").contains("synthetic-test-ca"));
        assert!(!format!("{cfg:?}").contains("wss://"));
        cfg.test_signal_url = None;
        assert!(!cfg.valid_test_signal_options());
        for url in [
            "wss://127.0.0.1:12345/v1/websocket/",
            "wss://[::1]:12345/v1/websocket/",
        ] {
            cfg.test_signal_url = Some(url.into());
            assert!(cfg.valid_test_signal_options());
        }
        for url in [
            "",
            "ws://127.0.0.1:12345/v1/websocket/",
            "https://127.0.0.1:12345/v1/websocket/",
            "wss://chat.signal.org/v1/websocket/",
            "wss://localhost:12345/v1/websocket/",
            "wss://192.0.2.1:12345/v1/websocket/",
            "wss://[::]:12345/v1/websocket/",
            "wss://127.0.0.1:0/v1/websocket/",
            "wss://user:password@127.0.0.1:12345/v1/websocket/",
            "wss://@127.0.0.1:12345/v1/websocket/",
            "wss://127.0.0.1:12345/v1/websocket/?token=value",
            "wss://127.0.0.1:12345/v1/websocket/#fragment",
            "wss://127.0.0.1:12345/\\v1/websocket/",
            " wss://127.0.0.1:12345/v1/websocket/",
            "wss://127.0.0.1:12345/v1/websocket/\n",
        ] {
            cfg.test_signal_url = Some(url.into());
            assert!(!cfg.valid_test_signal_options());
        }
        cfg.test_signal_url = Some("wss://127.0.0.1:12345/v1/websocket/".into());
        cfg.test_signal_ca = Some(String::new());
        assert!(!cfg.valid_test_signal_options());
    }

    #[cfg(all(
        feature = "test-signal",
        debug_assertions,
        colliesocket_test_signal,
        unix
    ))]
    #[test]
    fn test_signal_ca_is_bounded_protected_and_invalid_files_fail_closed() {
        use std::{
            fs,
            os::unix::{ffi::OsStrExt, fs::PermissionsExt},
        };

        let directory = std::env::temp_dir().join(format!(
            "colliesocket-test-ca-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir(&directory).unwrap();
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
        let path = directory.join("root.pem");
        let mut cfg = Config {
            test_signal_url: Some("wss://127.0.0.1:12345/v1/websocket/".into()),
            test_signal_ca: Some(path.to_str().unwrap().into()),
            ..Config::default()
        };
        assert!(cfg.load_test_signal_root().is_err());
        fs::write(&path, b"not a PEM certificate").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(cfg.load_test_signal_root().is_err());
        let pem = include_bytes!("ws/certs/signal-messenger.pem");
        // A valid PEM prefix prevents the parser itself from masking a missing
        // read bound: excess trailing whitespace must still be rejected.
        let mut oversized = pem.to_vec();
        oversized.resize(16 * 1024 + 1, b'\n');
        fs::write(&path, oversized).unwrap();
        assert!(cfg.load_test_signal_root().is_err());
        fs::write(&path, pem).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(cfg.load_test_signal_root().is_err());
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();

        let link = directory.join("root-link.pem");
        std::os::unix::fs::symlink(&path, &link).unwrap();
        cfg.test_signal_ca = Some(link.to_str().unwrap().into());
        assert!(cfg.load_test_signal_root().is_err());
        fs::remove_file(&link).unwrap();

        cfg.test_signal_ca = Some(path.to_str().unwrap().into());
        fs::hard_link(&path, &link).unwrap();
        assert!(cfg.load_test_signal_root().is_err());
        fs::remove_file(&link).unwrap();

        cfg.test_signal_ca = Some(directory.to_str().unwrap().into());
        assert!(cfg.load_test_signal_root().is_err());
        assert!(cfg.test_signal_root.is_none());

        cfg.test_signal_ca = Some(path.to_str().unwrap().into());
        cfg.load_test_signal_root().unwrap();
        assert_eq!(
            cfg.test_signal_root.as_ref().unwrap().to_der().unwrap(),
            native_tls::Certificate::from_pem(pem)
                .unwrap()
                .to_der()
                .unwrap()
        );

        let fifo = directory.join("root.fifo");
        let fifo_path = std::ffi::CString::new(fifo.as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(fifo_path.as_ptr(), 0o600) }, 0);
        cfg.test_signal_ca = Some(fifo.to_str().unwrap().into());
        cfg.test_signal_root = None;
        let (sender, receiver) = std::sync::mpsc::channel();
        let check = std::thread::spawn(move || {
            sender.send(cfg.load_test_signal_root().is_err()).unwrap();
        });
        assert!(receiver
            .recv_timeout(std::time::Duration::from_secs(2))
            .expect("test CA FIFO must be rejected without waiting for a writer"));
        check.join().unwrap();
        fs::remove_dir_all(directory).unwrap();
    }

    fn test_config(uuid: &str, endpoint: &str) -> Config {
        let allowed_uuids = vec![String::from(uuid)];
        let allowed_endpoints = vec![String::from(endpoint)];
        Config {
            allowed_endpoints,
            allowed_uuids,
            ..Config::default()
        }
    }

    #[test]
    fn check_wildcard_uuid() {
        let cfg = test_config("*", "");
        assert!(cfg.is_uuid_valid("0d2ff653-3d88-43de-bcdb-f6657d3484e4"));
    }

    #[test]
    fn check_defined_uuid() {
        let cfg = test_config("0d2ff653-3d88-43de-bcdb-f6657d3484e4", "");
        assert!(cfg.is_uuid_valid("0d2ff653-3d88-43de-bcdb-f6657d3484e4"));
        assert!(!cfg.is_uuid_valid("11111111-3d88-43de-bcdb-f6657d3484e4"));
    }

    #[tokio::test]
    async fn check_endpoint() {
        let cfg = test_config("", "https://ntfy.sh/");
        assert_eq!(
            cfg.is_url_endpoint_valid(&url::Url::parse("https://ntfy.sh/foo?blah").unwrap())
                .await,
            EndpointValidity::Ok
        );
        assert_eq!(
            cfg.is_url_endpoint_valid(&url::Url::parse("https://ntfy.sh:8080/foo?blah").unwrap())
                .await,
            EndpointValidity::NotInConfig
        );
        assert_eq!(
            cfg.is_url_endpoint_valid(
                &url::Url::parse("https://user:pass@ntfy.sh/foo?blah").unwrap()
            )
            .await,
            EndpointValidity::NotInConfig
        );
        assert_eq!(
            cfg.is_url_endpoint_valid(&url::Url::parse("http://ntfy.sh/foo?blah").unwrap())
                .await,
            EndpointValidity::NotInConfig
        );
    }

    #[tokio::test]
    async fn check_wildcard_endpoint() {
        let cfg = test_config("", "*");
        assert_eq!(
            cfg.is_url_endpoint_valid(&url::Url::parse("http://ntfy.sh/foo?blah").unwrap())
                .await,
            EndpointValidity::NotInConfig
        );
        assert_eq!(
            cfg.is_url_endpoint_valid(&url::Url::parse("https://127.0.0.1/foo?blah").unwrap())
                .await,
            EndpointValidity::Private
        );
    }
}
