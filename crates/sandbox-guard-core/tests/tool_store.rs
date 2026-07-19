#![cfg(unix)]

use std::fs;
use std::os::unix::fs::symlink;

use ed25519_dalek::{Signer, SigningKey};
use sandbox_guard_core::{
    install_verified_tool, verify_installed_tool, verify_installed_tool_snapshot,
};
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
fn verified_snapshot_returns_the_exact_authenticated_bytes() {
    let input = tempfile::tempdir().unwrap();
    let store = tempfile::tempdir().unwrap();
    let artifact_bytes = b"opaque vendor artifact\0with bytes";
    let artifact = input.path().join("vendor-cli");
    fs::write(&artifact, artifact_bytes).unwrap();
    let signing_key = SigningKey::from_bytes(&[17_u8; 32]);
    let public_key = signing_key.verifying_key().to_bytes();
    fs::write(input.path().join("key"), hex::encode(public_key)).unwrap();
    fs::write(
        input.path().join("signature"),
        hex::encode(signing_key.sign(artifact_bytes).to_bytes()),
    )
    .unwrap();
    let fingerprint = hex::encode(Sha256::digest(public_key));
    let installed = install_verified_tool(
        &artifact,
        &input.path().join("signature"),
        &input.path().join("key"),
        &fingerprint,
        store.path(),
        "vendor-cli",
        "2.0.0",
    )
    .unwrap();

    let snapshot = verify_installed_tool_snapshot(&installed.root, &fingerprint).unwrap();
    assert_eq!(snapshot.artifact(), artifact_bytes);
    assert_eq!(snapshot.installed.manifest.name, "vendor-cli");
}

#[test]
fn verified_snapshot_rejects_tampering_bad_signatures_and_symlinks() {
    let input = tempfile::tempdir().unwrap();
    let store = tempfile::tempdir().unwrap();
    let artifact = input.path().join("vendor-cli");
    fs::write(&artifact, b"artifact").unwrap();
    let signing_key = SigningKey::from_bytes(&[19_u8; 32]);
    let public_key = signing_key.verifying_key().to_bytes();
    fs::write(input.path().join("key"), hex::encode(public_key)).unwrap();
    fs::write(
        input.path().join("signature"),
        hex::encode(signing_key.sign(b"artifact").to_bytes()),
    )
    .unwrap();
    let fingerprint = hex::encode(Sha256::digest(public_key));
    let installed = install_verified_tool(
        &artifact,
        &input.path().join("signature"),
        &input.path().join("key"),
        &fingerprint,
        store.path(),
        "vendor-cli",
        "3.0.0",
    )
    .unwrap();

    fs::write(&installed.executable, b"tampered").unwrap();
    assert!(verify_installed_tool_snapshot(&installed.root, &fingerprint).is_err());

    fs::write(&installed.executable, b"artifact").unwrap();
    fs::write(installed.root.join("signature.hex"), "00".repeat(64)).unwrap();
    assert!(verify_installed_tool_snapshot(&installed.root, &fingerprint).is_err());

    fs::write(
        installed.root.join("signature.hex"),
        hex::encode(signing_key.sign(b"artifact").to_bytes()),
    )
    .unwrap();
    fs::remove_file(&installed.executable).unwrap();
    symlink(&artifact, &installed.executable).unwrap();
    assert!(verify_installed_tool_snapshot(&installed.root, &fingerprint).is_err());
}

#[test]
fn verified_snapshot_rejects_a_symlink_to_a_valid_installation_root() {
    let input = tempfile::tempdir().unwrap();
    let store = tempfile::tempdir().unwrap();
    let aliases = tempfile::tempdir().unwrap();
    let artifact = input.path().join("vendor-cli");
    fs::write(&artifact, b"artifact").unwrap();
    let signing_key = SigningKey::from_bytes(&[23_u8; 32]);
    let public_key = signing_key.verifying_key().to_bytes();
    fs::write(input.path().join("key"), hex::encode(public_key)).unwrap();
    fs::write(
        input.path().join("signature"),
        hex::encode(signing_key.sign(b"artifact").to_bytes()),
    )
    .unwrap();
    let fingerprint = hex::encode(Sha256::digest(public_key));
    let installed = install_verified_tool(
        &artifact,
        &input.path().join("signature"),
        &input.path().join("key"),
        &fingerprint,
        store.path(),
        "vendor-cli",
        "4.0.0",
    )
    .unwrap();
    let alias = aliases.path().join("valid-looking-install");
    symlink(&installed.root, &alias).unwrap();

    assert!(verify_installed_tool_snapshot(&alias, &fingerprint).is_err());
}

#[test]
fn refuses_a_symlinked_store_root_without_touching_its_target() {
    let input = tempfile::tempdir().unwrap();
    let parent = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    let artifact = input.path().join("vendor-cli");
    fs::write(&artifact, b"artifact").unwrap();
    let signing_key = SigningKey::from_bytes(&[29_u8; 32]);
    let public_key = signing_key.verifying_key().to_bytes();
    fs::write(input.path().join("key"), hex::encode(public_key)).unwrap();
    fs::write(
        input.path().join("signature"),
        hex::encode(signing_key.sign(b"artifact").to_bytes()),
    )
    .unwrap();
    let store_alias = parent.path().join("tools");
    symlink(outside.path(), &store_alias).unwrap();

    assert!(
        install_verified_tool(
            &artifact,
            &input.path().join("signature"),
            &input.path().join("key"),
            &hex::encode(Sha256::digest(public_key)),
            &store_alias,
            "vendor-cli",
            "5.0.0",
        )
        .is_err()
    );
    assert!(fs::read_dir(outside.path()).unwrap().next().is_none());
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
