#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    mollysocket::fuzz_api::exercise_authenticated_control_input(data);
});
