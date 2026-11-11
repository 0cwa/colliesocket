use eyre::Result;
use rocket_prometheus::prometheus::{
    register_int_counter, register_int_gauge, IntCounter, IntGauge,
};

pub struct Metrics {
    pub connections: IntGauge,
    pub forbiddens: IntGauge,
    pub reconnections: IntCounter,
    pub messages: IntCounter,
    pub pushs: IntCounter,
}

impl Metrics {
    pub fn new() -> Result<Self> {
        let connections =
            register_int_gauge!("mollysocket_connections", "Connections to Signal server")?;
        let forbiddens = register_int_gauge!(
            "mollysocket_forbiddens",
            "Forbidden connections to Signal server"
        )?;
        let reconnections =
            register_int_counter!("mollysocket_reconnections", "Reconnections since the start")?;
        let messages =
            register_int_counter!("mollysocket_messages", "Messages received from Signal")?;
        let pushs = register_int_counter!(
            "mollysocket_pushs",
            "Push messages sent to UnifiedPush endpoint"
        )?;

        Ok(Self {
            connections,
            forbiddens,
            reconnections,
            messages,
            pushs,
        })
    }
}
