//! Compatibility discovery only: credentials never enter through HTTP.
use crate::config;
use rocket::{
    get,
    response::content::RawHtml,
    routes,
    serde::json::{json, Json, Value},
};

#[get("/")]
fn index() -> RawHtml<&'static str> {
    RawHtml("<!doctype html><html lang=\"en\"><meta charset=\"utf-8\"><title>CollieSocket</title><h1>CollieSocket</h1><p>Encrypted UnifiedPush enrollment uses a protected private import through the service account.</p><p>This discovery listener accepts no registration credentials. Keep readiness private.</p></html>")
}
#[get("/discover")]
fn discover() -> Json<Value> {
    Json(
        json!({"mollysocket":{"version":env!("CARGO_PKG_VERSION")},"colliesocket":{"enrollment":"private_import","enrollment_versions":[1,2,3],"event_versions":[1,2,3],"encryption_required":true}}),
    )
}
pub async fn launch() -> Result<(), &'static str> {
    if !config::should_start_webserver() {
        std::future::pending::<()>().await;
        return Ok(());
    }
    let figment = rocket::Config::figment()
        .merge(("address", config::get_host()))
        .merge(("port", config::get_port()))
        .merge(("log_level", "off"));
    rocket::build()
        .configure(figment)
        .mount("/", routes![index, discover])
        .launch()
        .await
        .map(|_| ())
        .map_err(|_| "state_unavailable")
}
