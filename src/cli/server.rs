pub async fn server() {
    if let Err(code) = crate::server::run().await {
        crate::cli::print_result(Err(code));
    }
}
