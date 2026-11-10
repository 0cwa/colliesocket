//! Loopback-only operational readiness, never a Signal/device delivery probe.
use crate::{config, push, push_store::PushStore};
use std::{net::Ipv4Addr, sync::atomic::Ordering, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};
pub fn healthy(heartbeat: i64, now: i64) -> bool {
    heartbeat > 0 && now >= heartbeat && now - heartbeat < 10
}
pub async fn serve() -> std::io::Result<()> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, config::get_ready_port())).await?;
    loop {
        let (mut stream, peer) = listener.accept().await?;
        if !peer.ip().is_loopback() {
            continue;
        }
        let mut bytes = [0u8; 1024];
        let count =
            match tokio::time::timeout(Duration::from_secs(1), stream.read(&mut bytes)).await {
                Ok(Ok(n)) => n,
                _ => continue,
            };
        let valid = bytes[..count].starts_with(b"GET /readyz HTTP/1.");
        let ready = valid
            && healthy(push::HEARTBEAT.load(Ordering::Relaxed), push::now())
            && PushStore::open(config::get_db()).is_ok();
        let (status, body) = if !valid {
            ("404 Not Found", "{}\n")
        } else if ready {
            ("200 OK", "{\"ready\":true}\n")
        } else {
            ("503 Service Unavailable", "{\"ready\":false}\n")
        };
        let response=format!("HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",body.len());
        let _ = tokio::time::timeout(
            Duration::from_secs(1),
            stream.write_all(response.as_bytes()),
        )
        .await;
    }
}
pub async fn probe() -> Result<(), &'static str> {
    let response = reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(2))
        .build()
        .map_err(|_| "state_unavailable")?
        .get(format!(
            "http://127.0.0.1:{}/readyz",
            config::get_ready_port()
        ))
        .send()
        .await
        .map_err(|_| "state_unavailable")?;
    if response.status() != reqwest::StatusCode::OK {
        return Err("state_unavailable");
    }
    let value: serde_json::Value = response.json().await.map_err(|_| "state_unavailable")?;
    if value == serde_json::json!({"ready":true}) {
        Ok(())
    } else {
        Err("state_unavailable")
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn heartbeat_age_and_clock_rollback() {
        assert!(healthy(100, 109));
        assert!(!healthy(100, 110));
        assert!(!healthy(100, 99));
        assert!(!healthy(0, 0));
    }
}
