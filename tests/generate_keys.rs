use std::{fs, process::Command};

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

fn transponder() -> Command {
    Command::new(env!("CARGO_BIN_EXE_transponder"))
}

fn hex_64_tokens(text: &str) -> Vec<&str> {
    text.split(|ch: char| !ch.is_ascii_hexdigit())
        .filter(|token| token.len() == 64)
        .collect()
}

fn is_hex_64(value: &str) -> bool {
    value.len() == 64 && value.chars().all(|ch| ch.is_ascii_hexdigit())
}

#[test]
fn generate_keys_hides_private_key_by_default() {
    let output = transponder()
        .arg("generate-keys")
        .output()
        .expect("generate-keys should run");

    assert!(output.status.success());

    let stdout = String::from_utf8(output.stdout).expect("stdout should be utf-8");
    let stderr = String::from_utf8(output.stderr).expect("stderr should be utf-8");

    assert!(stderr.is_empty());
    assert!(stdout.contains("Generated new Nostr key pair"));
    assert!(stdout.contains("Public key (hex):"));
    assert!(stdout.contains("Public key (npub):"));
    assert!(!stdout.contains("Private key"));
    assert!(!stdout.contains("private_key ="));
    assert!(!stdout.contains("TRANSPONDER_SERVER_PRIVATE_KEY"));
    assert_eq!(
        hex_64_tokens(&stdout).len(),
        1,
        "default output should only expose the public hex key"
    );
}

#[test]
fn generate_keys_writes_private_key_to_restricted_output_file() {
    let dir = tempfile::tempdir().expect("temp dir should be created");
    let key_path = dir.path().join("server.key");

    let output = transponder()
        .args(["generate-keys", "--output"])
        .arg(&key_path)
        .output()
        .expect("generate-keys should run");

    assert!(output.status.success());

    let stdout = String::from_utf8(output.stdout).expect("stdout should be utf-8");
    let stderr = String::from_utf8(output.stderr).expect("stderr should be utf-8");
    let secret = fs::read_to_string(&key_path).expect("private key file should be readable");
    let secret = secret.trim();

    assert!(stderr.is_empty());
    assert!(is_hex_64(secret));
    assert!(!stdout.contains(secret));
    assert!(!stdout.contains("private_key ="));
    assert!(!stdout.contains("TRANSPONDER_SERVER_PRIVATE_KEY"));
    assert!(stdout.contains("private_key_file ="));
    assert_eq!(
        hex_64_tokens(&stdout).len(),
        1,
        "file output should only expose the public hex key on stdout"
    );

    #[cfg(unix)]
    {
        let mode = fs::metadata(&key_path)
            .expect("private key file metadata should be readable")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
    }
}

#[test]
fn generate_keys_requires_explicit_opt_in_to_print_private_key() {
    let output = transponder()
        .args(["generate-keys", "--show-private-key"])
        .output()
        .expect("generate-keys should run");

    assert!(output.status.success());

    let stdout = String::from_utf8(output.stdout).expect("stdout should be utf-8");
    let stderr = String::from_utf8(output.stderr).expect("stderr should be utf-8");

    assert!(stderr.contains("WARNING"));
    assert!(stderr.contains("ALL notification tokens"));
    assert!(stdout.contains("Private key (hex):"));
    assert!(!stdout.contains("private_key ="));
    assert!(!stdout.contains("TRANSPONDER_SERVER_PRIVATE_KEY"));
    assert_eq!(
        hex_64_tokens(&stdout).len(),
        2,
        "explicit display should print one public key and one private key"
    );
}

#[test]
fn generate_keys_refuses_to_overwrite_existing_private_key_file() {
    let dir = tempfile::tempdir().expect("temp dir should be created");
    let key_path = dir.path().join("server.key");
    fs::write(&key_path, "already here\n").expect("existing file should be writable");

    let output = transponder()
        .args(["generate-keys", "--output"])
        .arg(&key_path)
        .output()
        .expect("generate-keys should run");

    assert!(!output.status.success());
    assert_eq!(
        fs::read_to_string(&key_path).expect("existing file should be readable"),
        "already here\n"
    );

    let stderr = String::from_utf8(output.stderr).expect("stderr should be utf-8");
    assert!(stderr.contains("Failed to create private key file"));
}
