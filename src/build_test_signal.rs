fn main() {
    println!("cargo::rustc-check-cfg=cfg(colliesocket_test_signal)");
    println!("cargo::rerun-if-changed=src/build_test_signal.rs");
    // Debug assertions can be enabled in release builds. Check Cargo's actual
    // profile independently, and leave overrides absent for unknown profiles.
    if std::env::var("PROFILE").is_ok_and(|profile| profile == "debug") {
        println!("cargo::rustc-cfg=colliesocket_test_signal");
    }
}
