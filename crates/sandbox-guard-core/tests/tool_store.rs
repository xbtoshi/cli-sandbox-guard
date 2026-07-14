#![cfg(unix)]

use std::fs;
use std::os::unix::fs::symlink;

use ed25519_dalek::{Signer, SigningKey};
use sandbox_guard_core::{install_verified_tool, verify_installed_tool};
use sha2::{Digest, Sha256};

#[test]
fn verifies_before_installing_and_detects_later_tampering() {
    let input = tempfile::tempdir().unwrap();
    let store = tempfile::tempdir().unwrap();
    let artifact = input.path().join("vendor-cli");
    fs::write(&artifact, b"#!/bin/sh\necho verified\n").unwrap();
    let signing_key = SigningKey::from_bytes(&[7_u8; 32]);
    let public_key = signing_key.verifying_key().to_bytes();
    let signature = signing_key.sign(&fs::read(&artifact).unwrap()).to_bytes();
    let public_key_file = input.path().join("public-key.hex");
    let signature_file = input.path().join("signature.hex");
    fs::write(&public_key_file, hex::encode(public_key)).unwrap();
    fs::write(&signature_file, hex::encode(signature)).unwrap();
    let fingerprint = hex::encode(Sha256::digest(public_key));

    let installed = install_verified_tool(
        &artifact,
        &signature_file,
        &public_key_file,
        &fingerprint,
        store.path(),
        "vendor-cli",
        "1.2.3",
    )
    .unwrap();
    assert_eq!(
        fs::read(&installed.executable).unwrap(),
        fs::read(&artifact).unwrap()
    );
    verify_installed_tool(&installed.root, &fingerprint).unwrap();

    fs::write(&installed.executable, b"tampered").unwrap();
    assert!(verify_installed_tool(&installed.root, &fingerprint).is_err());
}

#[test]
fn refuses_an_unexpected_signer_before_publishing_anything() {
    let input = tempfile::tempdir().unwrap();
    let store = tempfile::tempdir().unwrap();
    let artifact = input.path().join("vendor-cli");
    fs::write(&artifact, b"artifact").unwrap();
    let signing_key = SigningKey::from_bytes(&[9_u8; 32]);
    let public_key = signing_key.verifying_key().to_bytes();
    fs::write(input.path().join("key"), hex::encode(public_key)).unwrap();
    fs::write(
        input.path().join("signature"),
        hex::encode(signing_key.sign(b"artifact").to_bytes()),
    )
    .unwrap();

    assert!(
        install_verified_tool(
            &artifact,
            &input.path().join("signature"),
            &input.path().join("key"),
            &"00".repeat(32),
            store.path(),
            "vendor-cli",
            "1.0.0",
        )
        .is_err()
    );
    assert!(!store.path().join("vendor-cli/1.0.0").exists());
}

#[test]
fn refuses_a_symlinked_tool_name_directory() {
    let input = tempfile::tempdir().unwrap();
    let store = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    let artifact = input.path().join("vendor-cli");
    fs::write(&artifact, b"artifact").unwrap();
    let signing_key = SigningKey::from_bytes(&[11_u8; 32]);
    let public_key = signing_key.verifying_key().to_bytes();
    fs::write(input.path().join("key"), hex::encode(public_key)).unwrap();
    fs::write(
        input.path().join("signature"),
        hex::encode(signing_key.sign(b"artifact").to_bytes()),
    )
    .unwrap();
    symlink(outside.path(), store.path().join("vendor-cli")).unwrap();

    assert!(
        install_verified_tool(
            &artifact,
            &input.path().join("signature"),
            &input.path().join("key"),
            &hex::encode(Sha256::digest(public_key)),
            store.path(),
            "vendor-cli",
            "1.0.0",
        )
        .is_err()
    );
    assert!(fs::read_dir(outside.path()).unwrap().next().is_none());
}
