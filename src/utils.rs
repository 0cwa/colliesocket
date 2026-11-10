use eyre::{eyre, Result};
use url::Url;

pub mod post_allowed;

/// Kept for callers using the upstream helper; never retain path/query tokens.
pub fn anonymize_url(_: &str) -> String {
    "[redacted endpoint]".into()
}

/// A bare endpoint has no account, epoch, or encryption capability context.
/// Account-aware CLI commands use guarded enqueue or explicit legacy wake.
pub async fn ping(_: Url) -> Result<reqwest::Response> {
    Err(eyre!("encryption_required"))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn endpoint_redaction_is_total_and_never_parses_input() {
        for input in [
            "",
            "a",
            "https://user:secret@example.test/TOKEN?secret=SECRET",
            "not a URL",
        ] {
            assert_eq!(anonymize_url(input), "[redacted endpoint]");
        }
    }
    #[tokio::test]
    async fn bare_url_ping_fails_without_configuration_or_network() {
        assert_eq!(
            ping(Url::parse("https://example.test/SECRET").unwrap())
                .await
                .unwrap_err()
                .to_string(),
            "encryption_required"
        );
    }
}
