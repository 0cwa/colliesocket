#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    mollysocket::fuzz_api::parse_enrollment(data);
});
