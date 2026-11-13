//! Narrow entry points for fuzz targets. Enabled only by the `fuzzing` feature.
use base64::Engine;

/// Exercise the production enrollment parser on arbitrary bytes.
pub fn parse_enrollment(bytes: &[u8]) {
    let _ = crate::enrollment::parse(bytes);
}

/// Exercise production control-frame rejection and authenticated decoding.
pub fn decrypt_raw_control_frame(bytes: &[u8]) {
    let key = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(crate::control::tests::KEY);
    let _ = crate::control::decrypt(bytes, crate::control::tests::ACCOUNT, 2, &key);
    // The public v2 interoperability vector also uses synthetic credentials.
    let vector_key_bytes: Vec<u8> = (0..32).collect();
    let vector_key = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(vector_key_bytes);
    let _ = crate::control::decrypt(bytes, crate::control::tests::ACCOUNT, 2, &vector_key);
}

/// Authenticate arbitrary JSON bytes with synthetic credentials, then pass the
/// resulting frame through the production decoder. Optional tampering flips a
/// byte in the authenticated frame before decoding.
pub fn decrypt_synthetic_authenticated_control(plaintext: &[u8], tamper: Option<usize>) {
    if plaintext.len() > crate::control::MAX_PLAINTEXT_BYTES {
        return;
    }
    let mut frame =
        crate::control::tests::frame_for(crate::control::tests::ACCOUNT, 2, 1, plaintext);
    if let Some(offset) = tamper {
        let offset = offset % frame.len();
        if let Some(byte) = frame.get_mut(offset) {
            *byte ^= 1;
        }
    }
    let key = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(crate::control::tests::KEY);
    let _ = crate::control::decrypt(&frame, crate::control::tests::ACCOUNT, 2, &key);
}

/// Exercise the authenticated target's mode byte and payload handling.
pub fn exercise_authenticated_control_input(data: &[u8]) {
    let Some((&mode, plaintext)) = data.split_first() else {
        decrypt_synthetic_authenticated_control(data, None);
        return;
    };
    let tamper = (mode & 1 == 1).then_some((usize::from(mode) << 8) | usize::from(mode));
    decrypt_synthetic_authenticated_control(plaintext, tamper);
}

#[cfg(test)]
pub fn replay_committed_corpus(target: &str, mut replay: impl FnMut(&[u8])) {
    let directory = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("fuzz/corpus")
        .join(target);
    let mut seeds: Vec<_> = std::fs::read_dir(&directory)
        .unwrap_or_else(|error| panic!("read {}: {error}", directory.display()))
        .map(|entry| entry.expect("read corpus entry"))
        .filter_map(|entry| {
            entry
                .file_type()
                .expect("read corpus entry type")
                .is_file()
                .then_some(entry.path())
        })
        .collect();
    seeds.sort();
    assert!(
        !seeds.is_empty(),
        "committed fuzz corpus {} must not be empty",
        directory.display()
    );
    for seed in seeds {
        let bytes =
            std::fs::read(&seed).unwrap_or_else(|error| panic!("read {}: {error}", seed.display()));
        replay(&bytes);
    }
}
