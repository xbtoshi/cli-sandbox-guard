#![cfg(unix)]

use std::ffi::CString;
use std::fs::{self, OpenOptions};
use std::os::fd::AsRawFd;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt, symlink};
use std::path::{Path, PathBuf};

use ed25519_dalek::{Signer, SigningKey};
use sandbox_guard_core::{
    MAX_INSTALLED_PROFILE_NAMES, MAX_INSTALLED_PROFILE_VERSIONS, MAX_SIGNED_PROFILE_BYTES,
    ProfileStoreError, SIGNED_PROFILE_ENVELOPE_SCHEMA_VERSION, SignedProfileEnvelope,
    builtin_grok_profile, install_verified_profile, list_installed_profiles,
    remove_installed_profile, verify_installed_profile,
};
use sha2::{Digest, Sha256};

fn signing_key() -> SigningKey {
    SigningKey::from_bytes(&[0x42_u8; 32])
}

fn envelope(name: &str, version: &str) -> SignedProfileEnvelope {
    let mut profile = builtin_grok_profile();
    profile.name = name.to_owned();
    SignedProfileEnvelope {
        schema_version: SIGNED_PROFILE_ENVELOPE_SCHEMA_VERSION,
        profile_version: version.to_owned(),
        profile,
    }
}

struct PackageInputs {
    package: PathBuf,
    signature: PathBuf,
    public_key: PathBuf,
    fingerprint: String,
}

fn write_package_inputs(directory: &Path, bytes: &[u8], key: &SigningKey) -> PackageInputs {
    let package = directory.join("profile-package.toml");
    let signature = directory.join("signature.hex");
    let public_key_path = directory.join("public-key.hex");
    fs::write(&package, bytes).unwrap();
    let public_key = key.verifying_key().to_bytes();
    fs::write(&signature, hex::encode(key.sign(bytes).to_bytes())).unwrap();
    fs::write(&public_key_path, hex::encode(public_key)).unwrap();
    PackageInputs {
        package,
        signature,
        public_key: public_key_path,
        fingerprint: hex::encode(Sha256::digest(public_key)),
    }
}

fn signed_inputs(directory: &Path, name: &str, version: &str) -> PackageInputs {
    let bytes = toml::to_string_pretty(&envelope(name, version))
        .unwrap()
        .into_bytes();
    write_package_inputs(directory, &bytes, &signing_key())
}

#[test]
fn installs_verifies_and_lists_a_signed_profile() {
    let input = tempfile::tempdir().unwrap();
    let store = tempfile::tempdir().unwrap();
    let store = store.path().join("profiles");
    let inputs = signed_inputs(input.path(), "vendor-example", "1.0.0");

    let installed = install_verified_profile(
        &inputs.package,
        &inputs.signature,
        &inputs.public_key,
        &inputs.fingerprint,
        &store,
    )
    .unwrap();
    assert_eq!(installed.manifest.name, "vendor-example");
    assert_eq!(installed.manifest.profile_version, "1.0.0");
    assert_eq!(
        installed.manifest.signer_fingerprint_sha256,
        inputs.fingerprint
    );
    assert_eq!(installed.envelope.profile.name, "vendor-example");
    assert_eq!(installed.root, store.join("vendor-example/1.0.0"));

    let mut entries = fs::read_dir(&installed.root)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .collect::<Vec<_>>();
    entries.sort();
    assert_eq!(
        entries,
        [
            "manifest.json",
            "profile-package.toml",
            "public-key.hex",
            "signature.hex"
        ]
    );
    for entry in &entries {
        let mode = fs::symlink_metadata(installed.root.join(entry))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600, "{entry} must be owner-only");
    }
    assert_eq!(
        fs::symlink_metadata(&installed.root)
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o700
    );

    let verified = verify_installed_profile(&installed.root).unwrap();
    assert_eq!(verified.manifest, installed.manifest);
    assert_eq!(verified.envelope, installed.envelope);

    let listed = list_installed_profiles(&store).unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].manifest, installed.manifest);
}

#[test]
fn wrong_signer_or_tampered_inputs_never_publish_anything() {
    let input = tempfile::tempdir().unwrap();
    let store = tempfile::tempdir().unwrap();
    let store = store.path().join("profiles");
    let inputs = signed_inputs(input.path(), "vendor-example", "1.0.0");
    let other = SigningKey::from_bytes(&[0x24_u8; 32]);
    let other_fingerprint = hex::encode(Sha256::digest(other.verifying_key().to_bytes()));

    assert!(matches!(
        install_verified_profile(
            &inputs.package,
            &inputs.signature,
            &inputs.public_key,
            &other_fingerprint,
            &store,
        ),
        Err(ProfileStoreError::SignedProfile(_))
    ));

    let mut tampered = fs::read(&inputs.package).unwrap();
    let index = tampered.iter().position(|byte| *byte == b'v').unwrap();
    tampered[index] = b'V';
    fs::write(&inputs.package, &tampered).unwrap();
    assert!(
        install_verified_profile(
            &inputs.package,
            &inputs.signature,
            &inputs.public_key,
            &inputs.fingerprint,
            &store,
        )
        .is_err()
    );
    assert!(
        !store.join("vendor-example").exists(),
        "failed installs must not publish store entries"
    );
}

#[test]
fn signature_over_equivalent_reserialization_is_rejected() {
    let input = tempfile::tempdir().unwrap();
    let store = tempfile::tempdir().unwrap();
    let original = toml::to_string_pretty(&envelope("vendor-example", "1.0.0"))
        .unwrap()
        .into_bytes();
    let key = signing_key();
    let inputs = write_package_inputs(input.path(), &original, &key);
    let mut equivalent = b"\n".to_vec();
    equivalent.extend_from_slice(&original);
    fs::write(&inputs.package, &equivalent).unwrap();

    assert!(
        install_verified_profile(
            &inputs.package,
            &inputs.signature,
            &inputs.public_key,
            &inputs.fingerprint,
            &store.path().join("profiles"),
        )
        .is_err()
    );
}

#[test]
fn builtin_names_cannot_be_installed_or_listed() {
    let input = tempfile::tempdir().unwrap();
    let store = tempfile::tempdir().unwrap();
    let store = store.path().join("profiles");
    let inputs = signed_inputs(input.path(), "grok", "1.0.0");
    assert!(matches!(
        install_verified_profile(
            &inputs.package,
            &inputs.signature,
            &inputs.public_key,
            &inputs.fingerprint,
            &store,
        ),
        Err(ProfileStoreError::ShadowsBuiltin(name)) if name == "grok"
    ));
    assert!(!store.exists() || list_installed_profiles(&store).unwrap().is_empty());
}

#[test]
fn duplicate_versions_are_never_overwritten() {
    let input = tempfile::tempdir().unwrap();
    let store = tempfile::tempdir().unwrap();
    let store = store.path().join("profiles");
    let inputs = signed_inputs(input.path(), "vendor-example", "1.0.0");
    let installed = install_verified_profile(
        &inputs.package,
        &inputs.signature,
        &inputs.public_key,
        &inputs.fingerprint,
        &store,
    )
    .unwrap();
    let original = fs::read(installed.root.join("profile-package.toml")).unwrap();

    assert!(matches!(
        install_verified_profile(
            &inputs.package,
            &inputs.signature,
            &inputs.public_key,
            &inputs.fingerprint,
            &store,
        ),
        Err(ProfileStoreError::VersionExists(_))
    ));
    assert_eq!(
        fs::read(installed.root.join("profile-package.toml")).unwrap(),
        original
    );
}

#[test]
fn stored_tampering_and_identity_mismatches_fail_verification() {
    let input = tempfile::tempdir().unwrap();
    let store = tempfile::tempdir().unwrap();
    let store = store.path().join("profiles");
    let inputs = signed_inputs(input.path(), "vendor-example", "1.0.0");
    let installed = install_verified_profile(
        &inputs.package,
        &inputs.signature,
        &inputs.public_key,
        &inputs.fingerprint,
        &store,
    )
    .unwrap();

    // Tampered stored package bytes.
    let package = installed.root.join("profile-package.toml");
    let mut bytes = fs::read(&package).unwrap();
    let index = bytes.iter().position(|byte| *byte == b'v').unwrap();
    bytes[index] = b'V';
    fs::write(&package, &bytes).unwrap();
    fs::set_permissions(&package, fs::Permissions::from_mode(0o600)).unwrap();
    assert!(verify_installed_profile(&installed.root).is_err());
    assert!(list_installed_profiles(&store).is_err());

    // Restore, then tamper the manifest identity.
    let restored = signed_inputs(input.path(), "vendor-example", "1.0.0");
    fs::write(&package, fs::read(&restored.package).unwrap()).unwrap();
    verify_installed_profile(&installed.root).unwrap();
    let manifest_path = installed.root.join("manifest.json");
    let manifest = fs::read_to_string(&manifest_path)
        .unwrap()
        .replace("\"1.0.0\"", "\"2.0.0\"");
    fs::write(&manifest_path, manifest).unwrap();
    fs::set_permissions(&manifest_path, fs::Permissions::from_mode(0o600)).unwrap();
    assert!(matches!(
        verify_installed_profile(&installed.root),
        Err(ProfileStoreError::IdentityMismatch { .. })
    ));
}

#[test]
fn moved_or_renamed_installations_fail_the_path_identity_axis() {
    let input = tempfile::tempdir().unwrap();
    let store = tempfile::tempdir().unwrap();
    let store = store.path().join("profiles");
    let inputs = signed_inputs(input.path(), "vendor-example", "1.0.0");
    let installed = install_verified_profile(
        &inputs.package,
        &inputs.signature,
        &inputs.public_key,
        &inputs.fingerprint,
        &store,
    )
    .unwrap();
    let renamed = store.join("vendor-example/9.9.9");
    fs::rename(&installed.root, &renamed).unwrap();
    assert!(matches!(
        verify_installed_profile(&renamed),
        Err(ProfileStoreError::IdentityMismatch { .. })
    ));
}

#[test]
fn unsafe_inputs_and_store_entries_are_rejected() {
    let input = tempfile::tempdir().unwrap();
    let store = tempfile::tempdir().unwrap();
    let store = store.path().join("profiles");
    let inputs = signed_inputs(input.path(), "vendor-example", "1.0.0");

    // Symlinked package input.
    let linked = input.path().join("linked-package.toml");
    symlink(&inputs.package, &linked).unwrap();
    assert!(
        install_verified_profile(
            &linked,
            &inputs.signature,
            &inputs.public_key,
            &inputs.fingerprint,
            &store,
        )
        .is_err()
    );

    // FIFO package input must not hang or install.
    let fifo = input.path().join("package.fifo");
    let fifo_path = CString::new(fifo.as_os_str().as_bytes()).unwrap();
    // SAFETY: mkfifo receives a valid NUL-terminated path in the private test directory.
    assert_eq!(unsafe { libc::mkfifo(fifo_path.as_ptr(), 0o600) }, 0);
    assert!(
        install_verified_profile(
            &fifo,
            &inputs.signature,
            &inputs.public_key,
            &inputs.fingerprint,
            &store,
        )
        .is_err()
    );

    // Oversized package input.
    let oversized = input.path().join("oversized.toml");
    fs::write(&oversized, vec![b' '; MAX_SIGNED_PROFILE_BYTES + 1]).unwrap();
    assert!(matches!(
        install_verified_profile(
            &oversized,
            &inputs.signature,
            &inputs.public_key,
            &inputs.fingerprint,
            &store,
        ),
        Err(ProfileStoreError::UnsafeInput(_))
    ));

    // Non-UTF8 package signed with a valid key still fails closed.
    let non_utf8_directory = tempfile::tempdir_in(input.path()).unwrap();
    let raw = [0xff_u8, 0xfe, 0xfd];
    let bad_inputs = write_package_inputs(non_utf8_directory.path(), &raw, &signing_key());
    assert!(matches!(
        install_verified_profile(
            &bad_inputs.package,
            &bad_inputs.signature,
            &bad_inputs.public_key,
            &bad_inputs.fingerprint,
            &store,
        ),
        Err(ProfileStoreError::SignedProfile(_))
    ));

    // A valid install whose stored file is replaced by a symlink or hardlinked fails closed.
    let installed = install_verified_profile(
        &inputs.package,
        &inputs.signature,
        &inputs.public_key,
        &inputs.fingerprint,
        &store,
    )
    .unwrap();
    let stored_signature = installed.root.join("signature.hex");
    let stolen = input.path().join("stolen.hex");
    fs::rename(&stored_signature, &stolen).unwrap();
    symlink(&stolen, &stored_signature).unwrap();
    assert!(verify_installed_profile(&installed.root).is_err());
    fs::remove_file(&stored_signature).unwrap();
    fs::rename(&stolen, &stored_signature).unwrap();
    verify_installed_profile(&installed.root).unwrap();

    let hardlink = input.path().join("hardlink.hex");
    fs::hard_link(&stored_signature, &hardlink).unwrap();
    assert!(verify_installed_profile(&installed.root).is_err());
    fs::remove_file(&hardlink).unwrap();
    verify_installed_profile(&installed.root).unwrap();

    // Extra file in the installation breaks the closed file set.
    fs::write(installed.root.join("extra.txt"), b"x").unwrap();
    assert!(matches!(
        verify_installed_profile(&installed.root),
        Err(ProfileStoreError::UnexpectedFileSet(_))
    ));
    fs::remove_file(installed.root.join("extra.txt")).unwrap();

    // Orphaned internal temporary entries fail listing explicitly.
    fs::create_dir(store.join(".install-orphan")).unwrap();
    assert!(matches!(
        list_installed_profiles(&store),
        Err(ProfileStoreError::OrphanEntry(_))
    ));
    fs::remove_dir(store.join(".install-orphan")).unwrap();
    assert_eq!(list_installed_profiles(&store).unwrap().len(), 1);
}

#[test]
fn unknown_manifest_fields_and_schemas_are_rejected() {
    let input = tempfile::tempdir().unwrap();
    let store = tempfile::tempdir().unwrap();
    let store = store.path().join("profiles");
    let inputs = signed_inputs(input.path(), "vendor-example", "1.0.0");
    let installed = install_verified_profile(
        &inputs.package,
        &inputs.signature,
        &inputs.public_key,
        &inputs.fingerprint,
        &store,
    )
    .unwrap();
    let manifest_path = installed.root.join("manifest.json");

    let original = fs::read_to_string(&manifest_path).unwrap();
    let unknown = original.replacen('{', "{\n  \"unexpected\": true,", 1);
    fs::write(&manifest_path, unknown).unwrap();
    fs::set_permissions(&manifest_path, fs::Permissions::from_mode(0o600)).unwrap();
    assert!(matches!(
        verify_installed_profile(&installed.root),
        Err(ProfileStoreError::Manifest(_))
    ));

    let unsupported = original.replacen("\"schema_version\": 1", "\"schema_version\": 2", 1);
    fs::write(&manifest_path, unsupported).unwrap();
    fs::set_permissions(&manifest_path, fs::Permissions::from_mode(0o600)).unwrap();
    assert!(matches!(
        verify_installed_profile(&installed.root),
        Err(ProfileStoreError::UnsupportedSchema(2))
    ));
}

#[test]
fn name_count_limit_is_enforced() {
    let input = tempfile::tempdir().unwrap();
    let store = tempfile::tempdir().unwrap();
    let store = store.path().join("profiles");
    for index in 0..MAX_INSTALLED_PROFILE_NAMES {
        let directory = tempfile::tempdir_in(input.path()).unwrap();
        let inputs = signed_inputs(directory.path(), &format!("vendor-{index}"), "1.0.0");
        install_verified_profile(
            &inputs.package,
            &inputs.signature,
            &inputs.public_key,
            &inputs.fingerprint,
            &store,
        )
        .unwrap();
    }
    let directory = tempfile::tempdir_in(input.path()).unwrap();
    let inputs = signed_inputs(directory.path(), "vendor-overflow", "1.0.0");
    assert!(matches!(
        install_verified_profile(
            &inputs.package,
            &inputs.signature,
            &inputs.public_key,
            &inputs.fingerprint,
            &store,
        ),
        Err(ProfileStoreError::LimitExceeded { .. })
    ));

    // An existing name may still receive a new version at the name limit.
    let directory = tempfile::tempdir_in(input.path()).unwrap();
    let inputs = signed_inputs(directory.path(), "vendor-0", "2.0.0");
    install_verified_profile(
        &inputs.package,
        &inputs.signature,
        &inputs.public_key,
        &inputs.fingerprint,
        &store,
    )
    .unwrap();
}

#[test]
fn version_count_limit_is_enforced() {
    let input = tempfile::tempdir().unwrap();
    let store = tempfile::tempdir().unwrap();
    let store = store.path().join("profiles");
    for index in 0..MAX_INSTALLED_PROFILE_VERSIONS {
        let directory = tempfile::tempdir_in(input.path()).unwrap();
        let inputs = signed_inputs(directory.path(), "vendor-example", &format!("1.0.{index}"));
        install_verified_profile(
            &inputs.package,
            &inputs.signature,
            &inputs.public_key,
            &inputs.fingerprint,
            &store,
        )
        .unwrap();
    }
    let directory = tempfile::tempdir_in(input.path()).unwrap();
    let inputs = signed_inputs(directory.path(), "vendor-example", "2.0.0");
    assert!(matches!(
        install_verified_profile(
            &inputs.package,
            &inputs.signature,
            &inputs.public_key,
            &inputs.fingerprint,
            &store,
        ),
        Err(ProfileStoreError::LimitExceeded { .. })
    ));
}

#[test]
fn removal_deletes_exactly_one_validated_version() {
    let input = tempfile::tempdir().unwrap();
    let store = tempfile::tempdir().unwrap();
    let store = store.path().join("profiles");
    for (name, version) in [
        ("vendor-example", "1.0.0"),
        ("vendor-example", "2.0.0"),
        ("vendor-other", "1.0.0"),
    ] {
        let directory = tempfile::tempdir_in(input.path()).unwrap();
        let inputs = signed_inputs(directory.path(), name, version);
        install_verified_profile(
            &inputs.package,
            &inputs.signature,
            &inputs.public_key,
            &inputs.fingerprint,
            &store,
        )
        .unwrap();
    }

    assert!(remove_installed_profile(&store, "vendor-example", "1.0.0").unwrap());
    assert!(!store.join("vendor-example/1.0.0").exists());
    assert!(store.join("vendor-example/2.0.0").exists());
    assert!(store.join("vendor-other/1.0.0").exists());
    assert_eq!(list_installed_profiles(&store).unwrap().len(), 2);

    // Idempotent for missing versions, names, and stores.
    assert!(!remove_installed_profile(&store, "vendor-example", "1.0.0").unwrap());
    assert!(!remove_installed_profile(&store, "vendor-missing", "1.0.0").unwrap());
    assert!(
        !remove_installed_profile(Path::new("/nonexistent-guard-store"), "vendor", "1").unwrap()
    );

    // Built-in names are never removable store paths.
    assert!(matches!(
        remove_installed_profile(&store, "grok", "1.0.0"),
        Err(ProfileStoreError::ShadowsBuiltin(_))
    ));

    // Removing the last version prunes the empty name directory.
    assert!(remove_installed_profile(&store, "vendor-example", "2.0.0").unwrap());
    assert!(!store.join("vendor-example").exists());

    // A symlinked target is refused, and its destination survives.
    let decoy = store.join("vendor-other/9.9.9");
    symlink(store.join("vendor-other/1.0.0"), &decoy).unwrap();
    assert!(matches!(
        remove_installed_profile(&store, "vendor-other", "9.9.9"),
        Err(ProfileStoreError::UnsafeInstallation(_))
    ));
    fs::remove_file(&decoy).unwrap();
    verify_installed_profile(&store.join("vendor-other/1.0.0")).unwrap();
}

#[test]
fn concurrent_store_use_is_refused_while_locked() {
    let input = tempfile::tempdir().unwrap();
    let store_directory = tempfile::tempdir().unwrap();
    let store = store_directory.path().join("profiles");
    let inputs = signed_inputs(input.path(), "vendor-example", "1.0.0");
    install_verified_profile(
        &inputs.package,
        &inputs.signature,
        &inputs.public_key,
        &inputs.fingerprint,
        &store,
    )
    .unwrap();

    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .mode(0o600)
        .open(store.join(".lock"))
        .unwrap();
    // SAFETY: flock receives the live test descriptor.
    assert_eq!(
        unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) },
        0
    );
    assert!(matches!(
        list_installed_profiles(&store),
        Err(ProfileStoreError::StoreBusy)
    ));
    assert!(matches!(
        remove_installed_profile(&store, "vendor-example", "1.0.0"),
        Err(ProfileStoreError::StoreBusy)
    ));
    drop(lock);
    assert_eq!(list_installed_profiles(&store).unwrap().len(), 1);
}

#[test]
fn symlinked_installation_root_is_rejected_even_when_canonical_identity_matches() {
    let input = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    let outside_store = outside.path().join("profiles");
    let inputs = signed_inputs(input.path(), "vendor-example", "1.0.0");
    let installed = install_verified_profile(
        &inputs.package,
        &inputs.signature,
        &inputs.public_key,
        &inputs.fingerprint,
        &outside_store,
    )
    .unwrap();

    // A symlink whose canonical target is a fully valid installation with matching
    // name/version components must still be rejected as a supplied root.
    let decoy = tempfile::tempdir().unwrap();
    let decoy_store = decoy.path().join("profiles/vendor-example");
    fs::create_dir_all(&decoy_store).unwrap();
    let link = decoy_store.join("1.0.0");
    symlink(&installed.root, &link).unwrap();
    assert!(matches!(
        verify_installed_profile(&link),
        Err(ProfileStoreError::UnsafeInstallation(_))
    ));
    verify_installed_profile(&installed.root).unwrap();
}

#[test]
fn symlinked_store_root_is_rejected_and_its_target_survives_removal() {
    let input = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    let real_store = outside.path().join("profiles");
    let inputs = signed_inputs(input.path(), "vendor-example", "1.0.0");
    install_verified_profile(
        &inputs.package,
        &inputs.signature,
        &inputs.public_key,
        &inputs.fingerprint,
        &real_store,
    )
    .unwrap();

    let holder = tempfile::tempdir().unwrap();
    let linked_store = holder.path().join("profiles");
    symlink(&real_store, &linked_store).unwrap();

    assert!(matches!(
        list_installed_profiles(&linked_store),
        Err(ProfileStoreError::UnsafeInstallation(_))
    ));
    assert!(matches!(
        remove_installed_profile(&linked_store, "vendor-example", "1.0.0"),
        Err(ProfileStoreError::UnsafeInstallation(_))
    ));
    verify_installed_profile(&real_store.join("vendor-example/1.0.0")).unwrap();

    // Install through a symlinked store root must also refuse and leave the target's
    // permissions and content unchanged.
    let mode_before = fs::symlink_metadata(&real_store)
        .unwrap()
        .permissions()
        .mode();
    let other = tempfile::tempdir_in(input.path()).unwrap();
    let more = signed_inputs(other.path(), "vendor-other", "1.0.0");
    assert!(matches!(
        install_verified_profile(
            &more.package,
            &more.signature,
            &more.public_key,
            &more.fingerprint,
            &linked_store,
        ),
        Err(ProfileStoreError::UnsafeInstallation(_))
    ));
    assert_eq!(
        fs::symlink_metadata(&real_store)
            .unwrap()
            .permissions()
            .mode(),
        mode_before
    );
    assert!(!real_store.join("vendor-other").exists());
}

#[test]
fn symlinked_name_directory_cannot_redirect_removal_or_listing() {
    let input = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    let victim_store = outside.path().join("profiles");
    let inputs = signed_inputs(input.path(), "vendor-victim", "1.0.0");
    install_verified_profile(
        &inputs.package,
        &inputs.signature,
        &inputs.public_key,
        &inputs.fingerprint,
        &victim_store,
    )
    .unwrap();

    let attack = tempfile::tempdir().unwrap();
    let attack_store = attack.path().join("profiles");
    let other = tempfile::tempdir_in(input.path()).unwrap();
    let filler = signed_inputs(other.path(), "vendor-filler", "1.0.0");
    install_verified_profile(
        &filler.package,
        &filler.signature,
        &filler.public_key,
        &filler.fingerprint,
        &attack_store,
    )
    .unwrap();
    symlink(
        victim_store.join("vendor-victim"),
        attack_store.join("vendor-victim"),
    )
    .unwrap();

    assert!(matches!(
        remove_installed_profile(&attack_store, "vendor-victim", "1.0.0"),
        Err(ProfileStoreError::UnsafeInstallation(_))
    ));
    verify_installed_profile(&victim_store.join("vendor-victim/1.0.0")).unwrap();
    assert!(matches!(
        list_installed_profiles(&attack_store),
        Err(ProfileStoreError::UnsafeInstallation(_))
    ));
}

#[test]
fn pre_existing_store_or_name_symlinks_refuse_install_without_touching_targets() {
    let input = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    let target = outside.path().join("victim");
    fs::create_dir(&target).unwrap();
    fs::set_permissions(&target, fs::Permissions::from_mode(0o755)).unwrap();
    fs::write(target.join("keep"), b"untouched").unwrap();
    let mode_before = fs::symlink_metadata(&target).unwrap().permissions().mode();

    // Store root is a symlink to the victim: install must refuse before any chmod.
    let holder = tempfile::tempdir().unwrap();
    let linked_store = holder.path().join("profiles");
    symlink(&target, &linked_store).unwrap();
    let inputs = signed_inputs(input.path(), "vendor-example", "1.0.0");
    assert!(matches!(
        install_verified_profile(
            &inputs.package,
            &inputs.signature,
            &inputs.public_key,
            &inputs.fingerprint,
            &linked_store,
        ),
        Err(ProfileStoreError::UnsafeInstallation(_))
    ));
    assert_eq!(
        fs::symlink_metadata(&target).unwrap().permissions().mode(),
        mode_before,
        "symlinked store root must never be chmodded through"
    );
    assert_eq!(fs::read(target.join("keep")).unwrap(), b"untouched");

    // Name directory inside a genuine store is a symlink to the victim.
    let store = holder.path().join("real-profiles");
    let seed_input = tempfile::tempdir_in(input.path()).unwrap();
    let seed = signed_inputs(seed_input.path(), "vendor-seed", "1.0.0");
    install_verified_profile(
        &seed.package,
        &seed.signature,
        &seed.public_key,
        &seed.fingerprint,
        &store,
    )
    .unwrap();
    symlink(&target, store.join("vendor-example")).unwrap();
    assert!(matches!(
        install_verified_profile(
            &inputs.package,
            &inputs.signature,
            &inputs.public_key,
            &inputs.fingerprint,
            &store,
        ),
        Err(ProfileStoreError::UnsafeInstallation(_))
    ));
    assert_eq!(
        fs::symlink_metadata(&target).unwrap().permissions().mode(),
        mode_before,
        "symlinked name directory must never be chmodded through"
    );
    assert!(!target.join("1.0.0").exists());
}

#[test]
fn install_fails_closed_on_orphaned_internal_entries() {
    let input = tempfile::tempdir().unwrap();
    let holder = tempfile::tempdir().unwrap();
    let store = holder.path().join("profiles");
    let seed_input = tempfile::tempdir_in(input.path()).unwrap();
    let seed = signed_inputs(seed_input.path(), "vendor-seed", "1.0.0");
    install_verified_profile(
        &seed.package,
        &seed.signature,
        &seed.public_key,
        &seed.fingerprint,
        &store,
    )
    .unwrap();

    // Orphan at the store root.
    fs::create_dir(store.join(".install-orphan")).unwrap();
    let inputs = signed_inputs(input.path(), "vendor-example", "1.0.0");
    assert!(matches!(
        install_verified_profile(
            &inputs.package,
            &inputs.signature,
            &inputs.public_key,
            &inputs.fingerprint,
            &store,
        ),
        Err(ProfileStoreError::OrphanEntry(_))
    ));
    fs::remove_dir(store.join(".install-orphan")).unwrap();

    // Orphan inside the target name directory.
    fs::create_dir(store.join("vendor-seed/.remove-orphan")).unwrap();
    let second = tempfile::tempdir_in(input.path()).unwrap();
    let more = signed_inputs(second.path(), "vendor-seed", "2.0.0");
    assert!(matches!(
        install_verified_profile(
            &more.package,
            &more.signature,
            &more.public_key,
            &more.fingerprint,
            &store,
        ),
        Err(ProfileStoreError::OrphanEntry(_))
    ));
    fs::remove_dir(store.join("vendor-seed/.remove-orphan")).unwrap();
    install_verified_profile(
        &more.package,
        &more.signature,
        &more.public_key,
        &more.fingerprint,
        &store,
    )
    .unwrap();
}

#[test]
fn listing_enforces_name_and_version_limits_before_verification() {
    let holder = tempfile::tempdir().unwrap();
    let store = holder.path().join("profiles");
    fs::create_dir_all(&store).unwrap();
    fs::set_permissions(&store, fs::Permissions::from_mode(0o700)).unwrap();
    for index in 0..=MAX_INSTALLED_PROFILE_NAMES {
        let name = store.join(format!("vendor-{index}"));
        fs::create_dir(&name).unwrap();
        fs::set_permissions(&name, fs::Permissions::from_mode(0o700)).unwrap();
    }
    assert!(matches!(
        list_installed_profiles(&store),
        Err(ProfileStoreError::LimitExceeded { .. })
    ));

    let versions = tempfile::tempdir().unwrap();
    let store = versions.path().join("profiles");
    let name = store.join("vendor-example");
    fs::create_dir_all(&name).unwrap();
    fs::set_permissions(&store, fs::Permissions::from_mode(0o700)).unwrap();
    fs::set_permissions(&name, fs::Permissions::from_mode(0o700)).unwrap();
    for index in 0..=MAX_INSTALLED_PROFILE_VERSIONS {
        let version = name.join(format!("1.0.{index}"));
        fs::create_dir(&version).unwrap();
        fs::set_permissions(&version, fs::Permissions::from_mode(0o700)).unwrap();
    }
    assert!(matches!(
        list_installed_profiles(&store),
        Err(ProfileStoreError::LimitExceeded { .. })
    ));
}
