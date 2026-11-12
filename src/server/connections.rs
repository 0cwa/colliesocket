//! Observe private enrollment changes without an HTTP registration channel.
use crate::{
    config,
    db::Connection,
    server::{DB, METRICS},
    ws::{SignalWebSocket, SignalWebSocketError},
};
use futures_channel::mpsc;
use futures_util::{
    future::{AbortHandle, Abortable, LocalBoxFuture},
    stream::FuturesUnordered,
    Future, FutureExt, StreamExt,
};
use std::{collections::HashMap, sync::Mutex, time::Duration};
pub async fn run() {
    if config::push_only() {
        std::future::pending::<()>().await;
        return;
    }
    let mut active: HashMap<String, ([u8; 32], u64, AbortHandle)> = HashMap::new();
    let mut jobs: FuturesUnordered<LocalBoxFuture<'static, (String, u64)>> =
        FuturesUnordered::new();
    let mut generation = 0u64;
    let mut poll = tokio::time::interval(Duration::from_secs(5));
    loop {
        tokio::select! {
            _=poll.tick()=>{
                let Ok(connections)=DB.list()else{log::warn!("connection_state_unavailable");continue};
                let store=match crate::push_store::PushStore::open(config::get_db()){
                    Ok(store)=>store,Err(_)=>{log::warn!("connection_state_unavailable");continue}
                };
                let enrolled=match store.list_enrolled_account_ids(){
                    Ok(ids)=>ids,Err(_)=>{log::warn!("connection_state_unavailable");continue}
                };
                let mut wanted=HashMap::new();
                for co in connections{
                    let encrypted_mode=enrolled.contains(&co.uuid);
                    if co.forbidden||!config::is_uuid_valid(&co.uuid)||!(encrypted_mode||config::legacy_wake_enabled()){continue}
                    if wanted.len()>=4096{log::warn!("connection_capacity_exceeded");break}
                    let private_generation=if encrypted_mode {
                        match store.private_generation_for_connection(&co) {
                            Ok(Some(value))=>Some(value),
                            Ok(None)=>continue,
                            Err(_)=>{log::warn!("connection_state_unavailable");continue}
                        }
                    }else{None};
                    // The endpoint is part of the socket fingerprint, so every endpoint update reconnects
                    // the Signal socket on purpose; a control frame redelivered after a cancel between
                    // commit and acknowledgement is a harmless replay.
                    let digest=connection_fingerprint(&co,encrypted_mode,private_generation.as_deref());
                    wanted.insert(co.uuid.clone(),digest);
                    if active.get(&co.uuid).is_some_and(|(old,_,_)|old==&digest){continue}
                    if let Some((_,_,handle))=active.remove(&co.uuid){handle.abort();}
                    let (handle,registration)=AbortHandle::new_pair();
                    let id=co.uuid.clone();generation=generation.wrapping_add(1);let current=generation;
                    active.insert(id.clone(),(digest,current,handle));
                    jobs.push(async move{let _=Abortable::new(connection_loop(co,encrypted_mode,private_generation),registration).await;(id,current)}.boxed_local());
                }
                active.retain(|id,(digest,_,handle)|if wanted.get(id)==Some(digest){true}else{handle.abort();false});
            },
            Some((id,finished))=jobs.next(),if !jobs.is_empty()=>{
                if active.get(&id).is_some_and(|(_,current,_)|*current==finished){active.remove(&id);}
            }
        }
    }
}
fn connection_fingerprint(
    co: &Connection,
    encrypted_mode: bool,
    private_generation: Option<&str>,
) -> [u8; 32] {
    let bytes = serde_json::to_vec(&serde_json::json!([
        co.device_id,
        co.password,
        co.endpoint,
        encrypted_mode,
        private_generation
    ]))
    .expect("state_unavailable");
    openssl::sha::sha256(&bytes)
}

async fn connection_loop(co: Connection, encrypted_mode: bool, private_generation: Option<String>) {
    let Ok(mut socket) = SignalWebSocket::new(
        &co.uuid,
        co.device_id,
        &co.password,
        &co.endpoint,
        encrypted_mode,
        private_generation.clone(),
    ) else {
        log::warn!("signal_connection_configuration_failed");
        return;
    };
    let metrics = set_metrics(&mut socket);
    METRICS.connections.inc();
    struct ConnectionMetric;
    impl Drop for ConnectionMetric {
        fn drop(&mut self) {
            METRICS.connections.dec();
        }
    }
    let _metric = ConnectionMetric;
    tokio::select! {
        result=socket.connection_loop()=>{
            if result.err().is_some_and(|e|matches!(e.downcast_ref::<SignalWebSocketError>(),Some(SignalWebSocketError::RegistrationRemoved))){
                // Only Signal authentication failure can mark these exact local
                // credentials forbidden. No late old-worker status or unlink.
                if socket.current_connection().ok().is_some_and(|current|DB.forbid_if_current(&current,private_generation.as_deref()).unwrap_or(false)){METRICS.forbiddens.inc();log::info!("signal_credentials_rejected");}
            }
        },
        _=metrics=>log::warn!("signal_metrics_channel_closed"),
    }
}
fn set_metrics(socket: &mut SignalWebSocket) -> impl Future<Output = ()> {
    // futures mpsc has one reserved slot per retained sender:31+1=32.
    let (message_tx, message_rx) = mpsc::channel::<u32>(31);
    let (push_tx, push_rx) = mpsc::channel::<u32>(31);
    let (reconnect_tx, reconnect_rx) = mpsc::channel::<u32>(31);
    socket.channels.on_message_tx = Some(Mutex::new(message_tx));
    socket.channels.on_push_tx = Some(Mutex::new(push_tx));
    socket.channels.on_reconnection_tx = Some(Mutex::new(reconnect_tx));
    async move {
        tokio::select! {
            _=message_rx.for_each(|_|async{METRICS.messages.inc();})=>{},
            _=push_rx.for_each(|_|async{METRICS.pushs.inc();})=>{},
            _=reconnect_rx.for_each(|_|async{METRICS.reconnections.inc();})=>{},
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn private_import_generation_replaces_a_socket_with_the_same_credential_tuple() {
        let co = Connection::new(
            "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa".into(),
            2,
            "synthetic-password".into(),
            "https://push.example.test/unchanged".into(),
        );
        assert_ne!(
            connection_fingerprint(&co, true, Some("first-private-import")),
            connection_fingerprint(&co, true, Some("replacement-private-import")),
        );
    }
}
