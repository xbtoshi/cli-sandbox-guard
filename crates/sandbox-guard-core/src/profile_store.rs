//! Owner-private store for signed third-party vendor profiles.
//!
//! The store holds verified distribution envelopes only; nothing in this module selects a
//! profile for execution. Trust enters exclusively as the explicit signer fingerprint passed to
//! [`install_verified_profile`]; every later read re-verifies the persisted signature over the
//! exact stored bytes before any content is trusted.
//!
//! Directory trust is established on held descriptors: supplied roots are rejected if the final
//! component is a symlink, opened with `O_DIRECTORY|O_NOFOLLOW`, and validated with `fstat`.
//! Child files inside a validated installation are still read by path; a same-uid attacker who
//! can swap the validated directory during a read is outside the threat model, and verification
//! re-checks the root path/descriptor identity before returning success.

use std::collections::BTreeSet;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tempfile::Builder as TempBuilder;
use thiserror::Error;

use crate::BUILTIN_VENDOR_PROFILE_NAMES;
use crate::signed_profile::{
    MAX_SIGNED_PROFILE_BYTES, SignedProfileEnvelope, SignedProfileError,
    verify_signed_profile_bytes,
};

pub const PROFILE_STORE_MANIFEST_SCHEMA_VERSION: u32 = 1;
pub const MAX_INSTALLED_PROFILE_NAMES: usize = 64;
pub const MAX_INSTALLED_PROFILE_VERSIONS: usize = 64;

const PACKAGE_FILE: &str = "profile-package.toml";
const SIGNATURE_FILE: &str = "signature.hex";
const PUBLIC_KEY_FILE: &str = "public-key.hex";
const MANIFEST_FILE: &str = "manifest.json";
const STORE_LOCK_FILE: &str = ".lock";
const INSTALL_TEMP_PREFIX: &str = ".install-";
const REMOVE_TOMBSTONE_PREFIX: &str = ".remove-";
const MAX_HEX_FILE_BYTES: u64 = 4096;
const MAX_MANIFEST_BYTES: u64 = 64 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProfileInstallManifest {
    pub schema_version: u32,
    pub name: String,
    pub profile_version: String,
    pub installed_at: DateTime<Utc>,
    pub package_sha256: String,
    pub package_bytes: u64,
    pub signer_fingerprint_sha256: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct InstalledProfile {
    pub root: PathBuf,
    pub manifest: ProfileInstallManifest,
    pub envelope: SignedProfileEnvelope,
}

/// Verify one signed profile package from explicit owner-selected files and publish it
/// atomically into the owner-private store. Existing versions are never overwritten.
pub fn install_verified_profile(
    package_path: &Path,
    signature_path: &Path,
    public_key_path: &Path,
    expected_signer_fingerprint: &str,
    store_root: &Path,
) -> Result<InstalledProfile, ProfileStoreError> {
    let fingerprint = normalize_hex(expected_signer_fingerprint, 32, "signer fingerprint")?;
    let signature = normalize_hex_file(signature_path, 64, "signature")?;
    let public_key = normalize_hex_file(public_key_path, 32, "public key")?;
    let package_bytes = read_stable_regular_file(package_path, MAX_SIGNED_PROFILE_BYTES as u64)?;

    let envelope =
        verify_signed_profile_bytes(&package_bytes, &signature, &public_key, &fingerprint)?;
    let name = envelope.profile.name.clone();
    let version = envelope.profile_version.clone();
    validate_store_component("profile name", &name)?;
    validate_store_component("profile version", &version)?;
    if BUILTIN_VENDOR_PROFILE_NAMES.contains(&name.as_str()) {
        return Err(ProfileStoreError::ShadowsBuiltin(name));
    }

    let (store, _store_directory) = prepare_private_directory(store_root, true)?;
    let _lock = lock_store(&store)?;
    enforce_name_limit(&store, &name)?;

    let name_root = store.join(&name);
    let (name_root, name_directory) = prepare_private_directory(&name_root, false)?;
    enforce_version_limit(&name_root)?;

    let destination = name_root.join(&version);
    match fs::symlink_metadata(&destination) {
        Ok(_) => return Err(ProfileStoreError::VersionExists(destination)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(source) => {
            return Err(io_error(
                "inspect profile installation destination",
                &destination,
                source,
            ));
        }
    }

    let manifest = ProfileInstallManifest {
        schema_version: PROFILE_STORE_MANIFEST_SCHEMA_VERSION,
        name: name.clone(),
        profile_version: version.clone(),
        installed_at: Utc::now(),
        package_sha256: hex::encode(Sha256::digest(&package_bytes)),
        package_bytes: package_bytes.len() as u64,
        signer_fingerprint_sha256: fingerprint.clone(),
    };
    let manifest_bytes =
        serde_json::to_vec_pretty(&manifest).map_err(ProfileStoreError::Serialize)?;

    let temp = TempBuilder::new()
        .prefix(INSTALL_TEMP_PREFIX)
        .tempdir_in(&name_root)
        .map_err(|source| io_error("create temporary profile installation", &name_root, source))?;
    fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700))
        .map_err(|source| io_error("secure temporary profile installation", temp.path(), source))?;
    write_private(&temp.path().join(PACKAGE_FILE), &package_bytes, 0o600)?;
    write_private(
        &temp.path().join(SIGNATURE_FILE),
        format!("{signature}\n").as_bytes(),
        0o600,
    )?;
    write_private(
        &temp.path().join(PUBLIC_KEY_FILE),
        format!("{public_key}\n").as_bytes(),
        0o600,
    )?;
    write_private(&temp.path().join(MANIFEST_FILE), &manifest_bytes, 0o600)?;
    sync_directory(temp.path())?;
    let temporary = temp.keep();
    // Publish relative to the held name directory so a raced swap of the name path cannot
    // redirect the destination outside the validated store.
    if let Err(errno) = rustix::fs::renameat_with(
        rustix::fs::CWD,
        temporary.as_path(),
        &name_directory,
        version.as_str(),
        rustix::fs::RenameFlags::NOREPLACE,
    ) {
        let _ = fs::remove_dir_all(&temporary);
        return Err(io_error(
            "publish verified profile installation",
            &destination,
            std::io::Error::from(errno),
        ));
    }
    sync_directory(&name_root)?;
    Ok(InstalledProfile {
        root: destination,
        manifest,
        envelope,
    })
}

/// Re-verify one installed profile: private closed file set, manifest identity, package hash,
/// persisted signer pin, and the detached signature over the exact stored bytes.
///
/// The supplied root must not be a symlink; it is bound to a held descriptor whose identity is
/// re-checked against the path before returning success.
pub fn verify_installed_profile(
    installation_root: &Path,
) -> Result<InstalledProfile, ProfileStoreError> {
    let (directory, held) = open_private_directory(installation_root)?;
    let root = fs::canonicalize(installation_root)
        .map_err(|source| io_error("canonicalize installed profile", installation_root, source))?;
    ensure_path_matches_directory(&root, &held)?;
    validate_closed_file_set(&root)?;

    let manifest_bytes = read_stable_regular_file(&root.join(MANIFEST_FILE), MAX_MANIFEST_BYTES)?;
    let manifest: ProfileInstallManifest =
        serde_json::from_slice(&manifest_bytes).map_err(ProfileStoreError::Manifest)?;
    if manifest.schema_version != PROFILE_STORE_MANIFEST_SCHEMA_VERSION {
        return Err(ProfileStoreError::UnsupportedSchema(
            manifest.schema_version,
        ));
    }
    validate_store_component("profile name", &manifest.name)?;
    validate_store_component("profile version", &manifest.profile_version)?;
    if BUILTIN_VENDOR_PROFILE_NAMES.contains(&manifest.name.as_str()) {
        return Err(ProfileStoreError::ShadowsBuiltin(manifest.name));
    }
    let version_component = root.file_name().and_then(|name| name.to_str());
    let name_component = root
        .parent()
        .and_then(Path::file_name)
        .and_then(|name| name.to_str());
    if version_component != Some(manifest.profile_version.as_str())
        || name_component != Some(manifest.name.as_str())
    {
        return Err(ProfileStoreError::IdentityMismatch {
            expected: format!("{}/{}", manifest.name, manifest.profile_version),
            observed: format!(
                "{}/{}",
                name_component.unwrap_or("?"),
                version_component.unwrap_or("?")
            ),
        });
    }

    let fingerprint = normalize_hex(
        &manifest.signer_fingerprint_sha256,
        32,
        "signer fingerprint",
    )?;
    let package_bytes =
        read_stable_regular_file(&root.join(PACKAGE_FILE), MAX_SIGNED_PROFILE_BYTES as u64)?;
    if package_bytes.len() as u64 != manifest.package_bytes
        || hex::encode(Sha256::digest(&package_bytes)) != manifest.package_sha256
    {
        return Err(ProfileStoreError::PackageChanged(root.join(PACKAGE_FILE)));
    }
    let signature = normalize_hex_file(&root.join(SIGNATURE_FILE), 64, "signature")?;
    let public_key = normalize_hex_file(&root.join(PUBLIC_KEY_FILE), 32, "public key")?;
    let envelope =
        verify_signed_profile_bytes(&package_bytes, &signature, &public_key, &fingerprint)?;
    if envelope.profile.name != manifest.name
        || envelope.profile_version != manifest.profile_version
    {
        return Err(ProfileStoreError::IdentityMismatch {
            expected: format!("{}/{}", manifest.name, manifest.profile_version),
            observed: format!("{}/{}", envelope.profile.name, envelope.profile_version),
        });
    }
    // Detect a root swap that happened while children were being read. Individual child reads
    // are path-based (same-uid residual documented in the module header); this final identity
    // check fails closed before any successful result is returned.
    ensure_path_matches_directory(&root, &held)?;
    drop(directory);
    Ok(InstalledProfile {
        root,
        manifest,
        envelope,
    })
}

/// List every installed profile after full re-verification. Unexpected store entries,
/// including orphaned internal temporaries, fail closed with an explicit path, and stores
/// exceeding the name or version limits are rejected before content verification.
pub fn list_installed_profiles(
    store_root: &Path,
) -> Result<Vec<InstalledProfile>, ProfileStoreError> {
    match fs::symlink_metadata(store_root) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            return Err(ProfileStoreError::UnsafeInstallation(
                store_root.to_path_buf(),
            ));
        }
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(source) => return Err(io_error("inspect profile store", store_root, source)),
    }
    let (_store_directory, held) = open_private_directory(store_root)?;
    let store = fs::canonicalize(store_root)
        .map_err(|source| io_error("canonicalize profile store", store_root, source))?;
    ensure_path_matches_directory(&store, &held)?;
    let _lock = lock_store(&store)?;

    let mut names = Vec::new();
    for name in sorted_entries(&store)? {
        if name == STORE_LOCK_FILE {
            continue;
        }
        if name.starts_with('.') {
            return Err(ProfileStoreError::OrphanEntry(store.join(name)));
        }
        validate_store_component("profile name", &name)?;
        if BUILTIN_VENDOR_PROFILE_NAMES.contains(&name.as_str()) {
            return Err(ProfileStoreError::ShadowsBuiltin(name));
        }
        names.push(name);
    }
    if names.len() > MAX_INSTALLED_PROFILE_NAMES {
        return Err(ProfileStoreError::LimitExceeded {
            what: "installed profile names",
            maximum: MAX_INSTALLED_PROFILE_NAMES,
        });
    }

    let mut installed = Vec::new();
    for name in names {
        let name_path = store.join(&name);
        let (_name_directory, name_held) = open_private_directory(&name_path)?;
        ensure_path_matches_directory(&name_path, &name_held)?;
        let mut versions = Vec::new();
        for version in sorted_entries(&name_path)? {
            if version.starts_with('.') {
                return Err(ProfileStoreError::OrphanEntry(name_path.join(version)));
            }
            validate_store_component("profile version", &version)?;
            versions.push(version);
        }
        if versions.len() > MAX_INSTALLED_PROFILE_VERSIONS {
            return Err(ProfileStoreError::LimitExceeded {
                what: "installed profile versions",
                maximum: MAX_INSTALLED_PROFILE_VERSIONS,
            });
        }
        for version in versions {
            installed.push(verify_installed_profile(&name_path.join(version))?);
        }
    }
    Ok(installed)
}

/// Remove exactly one installed profile version. Returns `false` when it was not present.
///
/// Removal deliberately does not require a valid signature, so a corrupted installation can
/// still be deleted; the target must nevertheless be an owner-private real directory reached
/// through held, non-symlink store and name descriptors, renamed descriptor-relative onto a
/// unique tombstone whose identity is checked before deletion.
pub fn remove_installed_profile(
    store_root: &Path,
    name: &str,
    version: &str,
) -> Result<bool, ProfileStoreError> {
    validate_store_component("profile name", name)?;
    validate_store_component("profile version", version)?;
    if BUILTIN_VENDOR_PROFILE_NAMES.contains(&name) {
        return Err(ProfileStoreError::ShadowsBuiltin(name.to_owned()));
    }
    match fs::symlink_metadata(store_root) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            return Err(ProfileStoreError::UnsafeInstallation(
                store_root.to_path_buf(),
            ));
        }
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(source) => return Err(io_error("inspect profile store", store_root, source)),
    }
    let (_store_directory, store_held) = open_private_directory(store_root)?;
    let store = fs::canonicalize(store_root)
        .map_err(|source| io_error("canonicalize profile store", store_root, source))?;
    ensure_path_matches_directory(&store, &store_held)?;
    let _lock = lock_store(&store)?;

    let name_root = store.join(name);
    match fs::symlink_metadata(&name_root) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            return Err(ProfileStoreError::UnsafeInstallation(name_root));
        }
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(source) => {
            return Err(io_error(
                "inspect profile name directory",
                &name_root,
                source,
            ));
        }
    }
    let (name_directory, name_held) = open_private_directory(&name_root)?;
    ensure_path_matches_directory(&name_root, &name_held)?;

    // Resolve and hold the target relative to the held name directory.
    let target_fd = match rustix::fs::openat(
        &name_directory,
        version,
        rustix::fs::OFlags::RDONLY
            | rustix::fs::OFlags::DIRECTORY
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    ) {
        Ok(fd) => fd,
        Err(errno) if errno == rustix::io::Errno::NOENT => return Ok(false),
        Err(errno) if errno == rustix::io::Errno::LOOP || errno == rustix::io::Errno::NOTDIR => {
            return Err(ProfileStoreError::UnsafeInstallation(
                name_root.join(version),
            ));
        }
        Err(errno) => {
            return Err(io_error(
                "open installed profile for removal",
                &name_root.join(version),
                std::io::Error::from(errno),
            ));
        }
    };
    let target = File::from(target_fd);
    let held = target
        .metadata()
        .map_err(|source| io_error("inspect opened installed profile", &name_root, source))?;
    if !held.is_dir() || held.uid() != current_uid() || held.permissions().mode() & 0o077 != 0 {
        return Err(ProfileStoreError::UnsafeInstallation(
            name_root.join(version),
        ));
    }

    let tombstone_name = format!(
        "{REMOVE_TOMBSTONE_PREFIX}{}",
        uuid::Uuid::new_v4().as_simple()
    );
    match rustix::fs::openat(
        &name_directory,
        tombstone_name.as_str(),
        rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    ) {
        Err(errno) if errno == rustix::io::Errno::NOENT => {}
        Ok(_) | Err(_) => {
            return Err(ProfileStoreError::UnsafeInstallation(
                name_root.join(&tombstone_name),
            ));
        }
    }
    rustix::fs::renameat(
        &name_directory,
        version,
        &name_directory,
        tombstone_name.as_str(),
    )
    .map_err(|errno| {
        io_error(
            "isolate installed profile",
            &name_root.join(version),
            std::io::Error::from(errno),
        )
    })?;

    // Re-open the tombstone relative to the held parent and require descriptor identity with
    // the originally held target before anything is deleted.
    let isolated = match rustix::fs::openat(
        &name_directory,
        tombstone_name.as_str(),
        rustix::fs::OFlags::RDONLY
            | rustix::fs::OFlags::DIRECTORY
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    ) {
        Ok(fd) => File::from(fd),
        Err(_) => {
            let _ = rustix::fs::renameat(
                &name_directory,
                tombstone_name.as_str(),
                &name_directory,
                version,
            );
            return Err(ProfileStoreError::UnsafeInstallation(
                name_root.join(&tombstone_name),
            ));
        }
    };
    let isolated_metadata = isolated
        .metadata()
        .map_err(|source| io_error("inspect removal tombstone", &name_root, source))?;
    if !isolated_metadata.is_dir()
        || isolated_metadata.uid() != current_uid()
        || isolated_metadata.dev() != held.dev()
        || isolated_metadata.ino() != held.ino()
    {
        let _ = rustix::fs::renameat(
            &name_directory,
            tombstone_name.as_str(),
            &name_directory,
            version,
        );
        return Err(ProfileStoreError::UnsafeInstallation(
            name_root.join(version),
        ));
    }
    drop(target);
    drop(isolated);
    // remove_dir_all is path-based; the tombstone name is unguessable inside the held,
    // owner-private parent, and the identity above was descriptor-checked (same-uid residual).
    fs::remove_dir_all(name_root.join(&tombstone_name)).map_err(|source| {
        io_error(
            "remove installed profile",
            &name_root.join(&tombstone_name),
            source,
        )
    })?;
    let _ = fs::remove_dir(&name_root);
    sync_directory(&store)?;
    Ok(true)
}

fn validate_store_component(label: &'static str, value: &str) -> Result<(), ProfileStoreError> {
    let mut bytes = value.bytes();
    let first = bytes.next();
    if !first.is_some_and(|byte| byte.is_ascii_alphanumeric())
        || value.len() > 64
        || !bytes.all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err(ProfileStoreError::InvalidComponent {
            label,
            value: value.to_owned(),
        });
    }
    Ok(())
}

/// Install-time listing: any unexpected internal entry fails closed instead of being skipped.
fn enforce_name_limit(store: &Path, name: &str) -> Result<(), ProfileStoreError> {
    let mut names = BTreeSet::new();
    for entry in sorted_entries(store)? {
        if entry == STORE_LOCK_FILE {
            continue;
        }
        if entry.starts_with('.') {
            return Err(ProfileStoreError::OrphanEntry(store.join(entry)));
        }
        names.insert(entry);
    }
    if !names.contains(name) && names.len() >= MAX_INSTALLED_PROFILE_NAMES {
        return Err(ProfileStoreError::LimitExceeded {
            what: "installed profile names",
            maximum: MAX_INSTALLED_PROFILE_NAMES,
        });
    }
    Ok(())
}

/// Install-time listing of one name directory, before this install's own temporary exists.
fn enforce_version_limit(name_root: &Path) -> Result<(), ProfileStoreError> {
    let mut versions = 0_usize;
    for entry in sorted_entries(name_root)? {
        if entry.starts_with('.') {
            return Err(ProfileStoreError::OrphanEntry(name_root.join(entry)));
        }
        versions += 1;
    }
    if versions >= MAX_INSTALLED_PROFILE_VERSIONS {
        return Err(ProfileStoreError::LimitExceeded {
            what: "installed profile versions",
            maximum: MAX_INSTALLED_PROFILE_VERSIONS,
        });
    }
    Ok(())
}

fn sorted_entries(path: &Path) -> Result<Vec<String>, ProfileStoreError> {
    let mut entries = Vec::new();
    for entry in
        fs::read_dir(path).map_err(|source| io_error("list profile store entries", path, source))?
    {
        let entry = entry.map_err(|source| io_error("read profile store entry", path, source))?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| ProfileStoreError::OrphanEntry(entry.path()))?;
        entries.push(name);
    }
    entries.sort();
    Ok(entries)
}

fn validate_closed_file_set(root: &Path) -> Result<(), ProfileStoreError> {
    let expected: BTreeSet<&str> =
        BTreeSet::from([PACKAGE_FILE, SIGNATURE_FILE, PUBLIC_KEY_FILE, MANIFEST_FILE]);
    let observed = sorted_entries(root)?;
    let observed_set: BTreeSet<&str> = observed.iter().map(String::as_str).collect();
    if observed_set != expected || observed.len() != expected.len() {
        return Err(ProfileStoreError::UnexpectedFileSet(root.to_path_buf()));
    }
    for name in observed {
        let path = root.join(name);
        let metadata = fs::symlink_metadata(&path)
            .map_err(|source| io_error("inspect installed profile file", &path, source))?;
        if !metadata.is_file()
            || metadata.file_type().is_symlink()
            || metadata.nlink() != 1
            || metadata.uid() != current_uid()
            || metadata.permissions().mode() & 0o077 != 0
        {
            return Err(ProfileStoreError::UnsafeInstallation(path));
        }
    }
    Ok(())
}

/// Reject a symlink at `path`, open it `O_DIRECTORY|O_NOFOLLOW`, and validate the held
/// descriptor as an owner-private directory whose identity matches the pre-open inode.
fn open_private_directory(path: &Path) -> Result<(File, fs::Metadata), ProfileStoreError> {
    let initial = fs::symlink_metadata(path)
        .map_err(|source| io_error("inspect profile store directory", path, source))?;
    if initial.file_type().is_symlink() {
        return Err(ProfileStoreError::UnsafeInstallation(path.to_path_buf()));
    }
    let (directory, metadata) = open_owned_directory(path)?;
    if metadata.permissions().mode() & 0o077 != 0
        || metadata.dev() != initial.dev()
        || metadata.ino() != initial.ino()
    {
        return Err(ProfileStoreError::UnsafeInstallation(path.to_path_buf()));
    }
    Ok((directory, metadata))
}

fn open_owned_directory(path: &Path) -> Result<(File, fs::Metadata), ProfileStoreError> {
    let directory = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|source| io_error("open profile store directory", path, source))?;
    let metadata = directory
        .metadata()
        .map_err(|source| io_error("inspect opened profile store directory", path, source))?;
    if !metadata.is_dir() || metadata.uid() != current_uid() {
        return Err(ProfileStoreError::UnsafeInstallation(path.to_path_buf()));
    }
    Ok((directory, metadata))
}

fn ensure_path_matches_directory(
    path: &Path,
    held: &fs::Metadata,
) -> Result<(), ProfileStoreError> {
    let current = fs::symlink_metadata(path)
        .map_err(|source| io_error("reinspect profile store directory", path, source))?;
    if current.file_type().is_symlink()
        || current.dev() != held.dev()
        || current.ino() != held.ino()
    {
        return Err(ProfileStoreError::ConcurrentMutation(path.to_path_buf()));
    }
    Ok(())
}

/// Create-if-missing and validate one store directory without ever chmodding through a
/// symlink: pre-existing symlinks are rejected before any mode change, missing directories are
/// created with mode 0700, and the final mode is set through the held descriptor.
fn prepare_private_directory(
    path: &Path,
    recursive: bool,
) -> Result<(PathBuf, File), ProfileStoreError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            return Err(ProfileStoreError::UnsafeInstallation(path.to_path_buf()));
        }
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let mut builder = fs::DirBuilder::new();
            builder.recursive(recursive).mode(0o700);
            builder
                .create(path)
                .map_err(|source| io_error("create profile store directory", path, source))?;
        }
        Err(source) => return Err(io_error("inspect profile store directory", path, source)),
    }
    let (directory, _) = open_owned_directory(path)?;
    directory
        .set_permissions(fs::Permissions::from_mode(0o700))
        .map_err(|source| io_error("secure profile store directory", path, source))?;
    let metadata = directory
        .metadata()
        .map_err(|source| io_error("reinspect profile store directory", path, source))?;
    if !metadata.is_dir()
        || metadata.uid() != current_uid()
        || metadata.permissions().mode() & 0o077 != 0
    {
        return Err(ProfileStoreError::UnsafeInstallation(path.to_path_buf()));
    }
    let canonical = fs::canonicalize(path)
        .map_err(|source| io_error("canonicalize profile store directory", path, source))?;
    ensure_path_matches_directory(&canonical, &metadata)?;
    Ok((canonical, directory))
}

/// Serialize store mutation and enumeration with a non-blocking owner-private lock file.
///
/// Every genuine store is created by `install_verified_profile`, which also creates `.lock`;
/// taking the lock from list/remove may create the file inside a hand-assembled store, which is
/// an accepted owner-private metadata write on an otherwise read-only path.
fn lock_store(store: &Path) -> Result<File, ProfileStoreError> {
    let path = store.join(STORE_LOCK_FILE);
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&path)
        .map_err(|source| io_error("open profile store lock", &path, source))?;
    let metadata = lock
        .metadata()
        .map_err(|source| io_error("inspect profile store lock", &path, source))?;
    if !metadata.is_file()
        || metadata.nlink() != 1
        || metadata.uid() != current_uid()
        || metadata.permissions().mode() & 0o077 != 0
        || metadata.len() != 0
    {
        return Err(ProfileStoreError::UnsafeInstallation(path));
    }
    // SAFETY: flock receives a valid owned descriptor and does not retain pointers.
    let result = unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
    if result == 0 {
        return Ok(lock);
    }
    let error = std::io::Error::last_os_error();
    if error
        .raw_os_error()
        .is_some_and(|code| code == libc::EWOULDBLOCK || code == libc::EAGAIN)
    {
        Err(ProfileStoreError::StoreBusy)
    } else {
        Err(io_error("lock profile store", &path, error))
    }
}

fn normalize_hex_file(
    path: &Path,
    expected_bytes: usize,
    label: &'static str,
) -> Result<String, ProfileStoreError> {
    let bytes = read_stable_regular_file(path, MAX_HEX_FILE_BYTES)?;
    let text = std::str::from_utf8(&bytes)
        .map_err(|_| ProfileStoreError::InvalidEncoding(label))?
        .trim();
    normalize_hex(text, expected_bytes, label)
}

fn normalize_hex(
    value: &str,
    expected_bytes: usize,
    label: &'static str,
) -> Result<String, ProfileStoreError> {
    let decoded =
        hex::decode(value.trim()).map_err(|_| ProfileStoreError::InvalidEncoding(label))?;
    if decoded.len() != expected_bytes {
        return Err(ProfileStoreError::InvalidEncoding(label));
    }
    Ok(hex::encode(decoded))
}

fn read_stable_regular_file(path: &Path, limit: u64) -> Result<Vec<u8>, ProfileStoreError> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)
        .map_err(|source| io_error("open verification input", path, source))?;
    let before = file
        .metadata()
        .map_err(|source| io_error("inspect verification input", path, source))?;
    if !before.is_file() || before.nlink() != 1 || before.len() > limit {
        return Err(ProfileStoreError::UnsafeInput(path.to_path_buf()));
    }
    // Bound the read itself: a file that grows after the length check must not cause
    // unbounded memory use, so never read more than limit + 1 probe bytes.
    let mut bytes = Vec::with_capacity(before.len() as usize);
    Read::by_ref(&mut file)
        .take(limit + 1)
        .read_to_end(&mut bytes)
        .map_err(|source| io_error("read verification input", path, source))?;
    if bytes.len() as u64 > limit {
        return Err(ProfileStoreError::ConcurrentMutation(path.to_path_buf()));
    }
    let after = file
        .metadata()
        .map_err(|source| io_error("reinspect verification input", path, source))?;
    if before.dev() != after.dev()
        || before.ino() != after.ino()
        || before.len() != after.len()
        || before.mtime() != after.mtime()
        || before.mtime_nsec() != after.mtime_nsec()
        || before.ctime() != after.ctime()
        || before.ctime_nsec() != after.ctime_nsec()
        || bytes.len() as u64 != before.len()
    {
        return Err(ProfileStoreError::ConcurrentMutation(path.to_path_buf()));
    }
    Ok(bytes)
}

fn write_private(path: &Path, bytes: &[u8], mode: u32) -> Result<(), ProfileStoreError> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|source| io_error("create installed profile file", path, source))?;
    file.write_all(bytes)
        .map_err(|source| io_error("write installed profile file", path, source))?;
    file.sync_all()
        .map_err(|source| io_error("sync installed profile file", path, source))
}

fn sync_directory(path: &Path) -> Result<(), ProfileStoreError> {
    File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|source| io_error("sync profile store directory", path, source))
}

fn io_error(operation: &'static str, path: &Path, source: std::io::Error) -> ProfileStoreError {
    ProfileStoreError::Io {
        operation,
        path: path.to_path_buf(),
        source,
    }
}

fn current_uid() -> u32 {
    // SAFETY: geteuid has no preconditions.
    unsafe { libc::geteuid() }
}

#[derive(Debug, Error)]
pub enum ProfileStoreError {
    #[error(
        "invalid {label} {value:?}; expected a component starting with an ASCII letter or digit"
    )]
    InvalidComponent { label: &'static str, value: String },
    #[error("invalid {0} encoding; expected lowercase or uppercase hexadecimal")]
    InvalidEncoding(&'static str),
    #[error("installed profile name {0:?} shadows a compiled built-in profile")]
    ShadowsBuiltin(String),
    #[error("verification input is not a singly linked regular file within the size limit: {0}")]
    UnsafeInput(PathBuf),
    #[error("verification input changed while it was being read: {0}")]
    ConcurrentMutation(PathBuf),
    #[error("profile version already exists and will not be overwritten: {0}")]
    VersionExists(PathBuf),
    #[error("unsafe profile store entry: {0}")]
    UnsafeInstallation(PathBuf),
    #[error("installed profile has an unexpected file set: {0}")]
    UnexpectedFileSet(PathBuf),
    #[error("orphaned or foreign profile store entry; inspect and remove it manually: {0}")]
    OrphanEntry(PathBuf),
    #[error("another Guard process holds the profile store lock")]
    StoreBusy,
    #[error("installed package does not match its verified manifest: {0}")]
    PackageChanged(PathBuf),
    #[error("installed profile identity mismatch: manifest says {expected}, observed {observed}")]
    IdentityMismatch { expected: String, observed: String },
    #[error("profile store holds {maximum} {what}; remove one first")]
    LimitExceeded { what: &'static str, maximum: usize },
    #[error("unsupported profile manifest schema {0}")]
    UnsupportedSchema(u32),
    #[error("failed to parse installed profile manifest: {0}")]
    Manifest(serde_json::Error),
    #[error("failed to serialize profile manifest: {0}")]
    Serialize(serde_json::Error),
    #[error(transparent)]
    SignedProfile(#[from] SignedProfileError),
    #[error("failed to {operation} at {path}: {source}")]
    Io {
        operation: &'static str,
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stable_read_accepts_the_exact_limit_and_rejects_beyond_it() {
        let directory = tempfile::tempdir().unwrap();
        let at_limit = directory.path().join("at-limit");
        fs::write(&at_limit, vec![b'x'; 16]).unwrap();
        assert_eq!(read_stable_regular_file(&at_limit, 16).unwrap().len(), 16);

        let beyond = directory.path().join("beyond");
        fs::write(&beyond, vec![b'x'; 17]).unwrap();
        assert!(matches!(
            read_stable_regular_file(&beyond, 16),
            Err(ProfileStoreError::UnsafeInput(_))
        ));
    }
}
