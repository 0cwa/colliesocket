use crate::{config, db::MollySocketDb, push_store::PushStore, server::metrics::Metrics};
use lazy_static::lazy_static;
use tokio::signal;
#[cfg(unix)]
use tokio::signal::unix::{self, SignalKind};
mod connections;
mod metrics;
pub mod ready;
mod web;
lazy_static! {
    static ref DB: MollySocketDb = MollySocketDb::new().expect("state_unavailable");
    static ref METRICS: Metrics = Metrics::new().expect("state_unavailable");
}
pub async fn run() -> Result<(), &'static str> {
    PushStore::open(config::get_db()).map_err(|e| e.code())?;
    #[cfg(unix)]
    let mut terms = unix::signal(SignalKind::terminate()).map_err(|_| "state_unavailable")?;
    #[cfg(unix)]
    let sigterm = terms.recv();
    #[cfg(not(unix))]
    let sigterm = std::future::pending::<()>();
    tokio::select! {
        _=signal::ctrl_c()=>Ok(()),
        _=sigterm=>Ok(()),
        result=ready::serve()=>result.map_err(|_|"state_unavailable"),
        result=web::launch()=>result,
        _=connections::run()=>Err("state_unavailable"),
        _=crate::push::run()=>Err("state_unavailable"),
    }
}
