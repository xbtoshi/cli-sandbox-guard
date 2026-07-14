use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tempfile::Builder as TempBuilder;
use thiserror::Error;

const MAX_TOOL_BYTES: u64 = 512 * 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolInstallManifest {
    pub schema_version: u32,
    pub name: String,
    pub version: String,
    pub installed_at: DateTime<Utc>,
    pub artifact_sha256: String,
    pub artifact_bytes: u64,
    pub signer_fingerprint_sha256: String,
}

#[derive(Debug, Clone)]
pub struct InstalledTool {
    pub root: PathBuf,
    pub executable: PathBuf,
    pub manifest: ToolInstallManifest,
}

#[allow(clippy::too_many_arguments)]
pub fn install_verified_tool(
    artifact: &Path,
    signature_file: &Path,
    public_key_file: &Path,
    expected_signer_fingerprint: &str,
    store_root: &Path,
    name: &str,
    version: &str,
) -> Result<InstalledTool, ToolStoreError> {
    validate_component("tool name", name)?;
    validate_component("tool version", version)?;
    let public_key_bytes = read_hex_file(public_key_file, 32, "public key")?;
    let expected = decode_hex(expected_signer_fingerprint, 32, "signer fingerprint")?;
    let observed = Sha256::digest(&public_key_bytes);
    if observed.as_slice() != expected.as_slice() {
        return Err(ToolStoreError::SignerMismatch {
            expected: hex::encode(expected),
            observed: hex::encode(observed),
        });
    }
    let signature_bytes = read_hex_file(signature_file, 64, "signature")?;
    let artifact_bytes = read_stable_regular_file(artifact, MAX_TOOL_BYTES)?;
    let verifying_key = VerifyingKey::from_bytes(
        public_key_bytes
            .as_slice()
            .try_into()
            .map_err(|_| ToolStoreError::InvalidEncoding("public key"))?,
    )
    .map_err(|_| ToolStoreError::InvalidEncoding("public key"))?;
    let signature = Signature::from_slice(&signature_bytes)
        .map_err(|_| ToolStoreError::InvalidEncoding("signature"))?;
    verifying_key
        .verify_strict(&artifact_bytes, &signature)
        .map_err(|_| ToolStoreError::SignatureVerification)?;

    let store_root = prepare_store_root(store_root)?;
    let name_root = store_root.join(name);
    fs::create_dir_all(&name_root).map_err(|source| ToolStoreError::Io {
        operation: "create tool name directory",
        path: name_root.clone(),
        source,
    })?;
    let name_metadata = fs::symlink_metadata(&name_root).map_err(|source| ToolStoreError::Io {
        operation: "inspect tool name directory",
        path: name_root.clone(),
        source,
    })?;
    if !name_metadata.is_dir()
        || name_metadata.file_type().is_symlink()
        || name_metadata.uid() != current_uid()
    {
        return Err(ToolStoreError::UnsafeInstallation(name_root));
    }
    fs::set_permissions(&name_root, fs::Permissions::from_mode(0o700)).map_err(|source| {
        ToolStoreError::Io {
            operation: "secure tool name directory",
            path: name_root.clone(),
            source,
        }
    })?;
    let destination = name_root.join(version);
    if fs::symlink_metadata(&destination).is_ok() {
        return Err(ToolStoreError::VersionExists(destination));
    }
    let temp = TempBuilder::new()
        .prefix(".install-")
        .tempdir_in(&name_root)
        .map_err(|source| ToolStoreError::Io {
            operation: "create temporary tool installation",
            path: name_root.clone(),
            source,
        })?;
    fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).map_err(|source| {
        ToolStoreError::Io {
            operation: "secure temporary tool installation",
            path: temp.path().to_path_buf(),
            source,
        }
    })?;
    write_private(&temp.path().join("tool"), &artifact_bytes, 0o700)?;
    write_private(
        &temp.path().join("public-key.hex"),
        format!("{}\n", hex::encode(&public_key_bytes)).as_bytes(),
        0o600,
    )?;
    write_private(
        &temp.path().join("signature.hex"),
        format!("{}\n", hex::encode(&signature_bytes)).as_bytes(),
        0o600,
    )?;
    let manifest = ToolInstallManifest {
        schema_version: 1,
        name: name.to_owned(),
        version: version.to_owned(),
        installed_at: Utc::now(),
        artifact_sha256: hex::encode(Sha256::digest(&artifact_bytes)),
        artifact_bytes: artifact_bytes.len() as u64,
        signer_fingerprint_sha256: hex::encode(observed),
    };
    let manifest_bytes = serde_json::to_vec_pretty(&manifest).map_err(ToolStoreError::Serialize)?;
    write_private(&temp.path().join("manifest.json"), &manifest_bytes, 0o600)?;
    sync_directory(temp.path())?;
    let temporary = temp.keep();
    fs::rename(&temporary, &destination).map_err(|source| ToolStoreError::Io {
        operation: "publish verified tool installation",
        path: destination.clone(),
        source,
    })?;
    sync_directory(&name_root)?;
    Ok(InstalledTool {
        executable: destination.join("tool"),
        root: destination,
        manifest,
    })
}

pub fn verify_installed_tool(
    installation_root: &Path,
    expected_signer_fingerprint: &str,
) -> Result<InstalledTool, ToolStoreError> {
    let root = fs::canonicalize(installation_root).map_err(|source| ToolStoreError::Io {
        operation: "canonicalize installed tool",
        path: installation_root.to_path_buf(),
        source,
    })?;
    let metadata = fs::symlink_metadata(&root).map_err(|source| ToolStoreError::Io {
        operation: "inspect installed tool",
        path: root.clone(),
        source,
    })?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(ToolStoreError::UnsafeInstallation(root));
    }
    let manifest_bytes = read_stable_regular_file(&root.join("manifest.json"), 1024 * 1024)?;
    let manifest: ToolInstallManifest =
        serde_json::from_slice(&manifest_bytes).map_err(ToolStoreError::Manifest)?;
    if manifest.schema_version != 1 {
        return Err(ToolStoreError::UnsupportedSchema(manifest.schema_version));
    }
    let expected = decode_hex(expected_signer_fingerprint, 32, "signer fingerprint")?;
    let public_key_bytes = read_hex_file(&root.join("public-key.hex"), 32, "public key")?;
    let observed = Sha256::digest(&public_key_bytes);
    if observed.as_slice() != expected.as_slice()
        || manifest.signer_fingerprint_sha256 != hex::encode(observed)
    {
        return Err(ToolStoreError::SignerMismatch {
            expected: hex::encode(expected),
            observed: hex::encode(observed),
        });
    }
    let signature_bytes = read_hex_file(&root.join("signature.hex"), 64, "signature")?;
    let executable = root.join("tool");
    let artifact = read_stable_regular_file(&executable, MAX_TOOL_BYTES)?;
    if artifact.len() as u64 != manifest.artifact_bytes
        || hex::encode(Sha256::digest(&artifact)) != manifest.artifact_sha256
    {
        return Err(ToolStoreError::ArtifactChanged(executable));
    }
    let verifying_key = VerifyingKey::from_bytes(
        public_key_bytes
            .as_slice()
            .try_into()
            .map_err(|_| ToolStoreError::InvalidEncoding("public key"))?,
    )
    .map_err(|_| ToolStoreError::InvalidEncoding("public key"))?;
    let signature = Signature::from_slice(&signature_bytes)
        .map_err(|_| ToolStoreError::InvalidEncoding("signature"))?;
    verifying_key
        .verify_strict(&artifact, &signature)
        .map_err(|_| ToolStoreError::SignatureVerification)?;
    Ok(InstalledTool {
        root,
        executable,
        manifest,
    })
}

fn validate_component(label: &'static str, value: &str) -> Result<(), ToolStoreError> {
    if value.is_empty()
        || value.len() > 128
        || matches!(value, "." | "..")
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        Err(ToolStoreError::InvalidComponent {
            label,
            value: value.to_owned(),
        })
    } else {
        Ok(())
    }
}

fn prepare_store_root(path: &Path) -> Result<PathBuf, ToolStoreError> {
    fs::create_dir_all(path).map_err(|source| ToolStoreError::Io {
        operation: "create tool store",
        path: path.to_path_buf(),
        source,
    })?;
    let root = fs::canonicalize(path).map_err(|source| ToolStoreError::Io {
        operation: "canonicalize tool store",
        path: path.to_path_buf(),
        source,
    })?;
    let metadata = fs::symlink_metadata(&root).map_err(|source| ToolStoreError::Io {
        operation: "inspect tool store",
        path: root.clone(),
        source,
    })?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() || metadata.uid() != current_uid() {
        return Err(ToolStoreError::UnsafeInstallation(root));
    }
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).map_err(|source| {
        ToolStoreError::Io {
            operation: "secure tool store",
            path: root.clone(),
            source,
        }
    })?;
    Ok(root)
}

fn read_hex_file(
    path: &Path,
    expected_bytes: usize,
    label: &'static str,
) -> Result<Vec<u8>, ToolStoreError> {
    let bytes = read_stable_regular_file(path, 4096)?;
    let text = std::str::from_utf8(&bytes)
        .map_err(|_| ToolStoreError::InvalidEncoding(label))?
        .trim();
    decode_hex(text, expected_bytes, label)
}

fn decode_hex(
    value: &str,
    expected_bytes: usize,
    label: &'static str,
) -> Result<Vec<u8>, ToolStoreError> {
    let decoded = hex::decode(value).map_err(|_| ToolStoreError::InvalidEncoding(label))?;
    if decoded.len() != expected_bytes {
        return Err(ToolStoreError::InvalidEncoding(label));
    }
    Ok(decoded)
}

fn read_stable_regular_file(path: &Path, limit: u64) -> Result<Vec<u8>, ToolStoreError> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)
        .map_err(|source| ToolStoreError::Io {
            operation: "open verification input",
            path: path.to_path_buf(),
            source,
        })?;
    let before = file.metadata().map_err(|source| ToolStoreError::Io {
        operation: "inspect verification input",
        path: path.to_path_buf(),
        source,
    })?;
    if !before.is_file() || before.nlink() != 1 || before.len() > limit {
        return Err(ToolStoreError::UnsafeInput(path.to_path_buf()));
    }
    let mut bytes = Vec::with_capacity(before.len() as usize);
    file.read_to_end(&mut bytes)
        .map_err(|source| ToolStoreError::Io {
            operation: "read verification input",
            path: path.to_path_buf(),
            source,
        })?;
    let after = file.metadata().map_err(|source| ToolStoreError::Io {
        operation: "reinspect verification input",
        path: path.to_path_buf(),
        source,
    })?;
    if before.dev() != after.dev()
        || before.ino() != after.ino()
        || before.len() != after.len()
        || before.mtime() != after.mtime()
        || before.mtime_nsec() != after.mtime_nsec()
        || before.ctime() != after.ctime()
        || before.ctime_nsec() != after.ctime_nsec()
        || bytes.len() as u64 != before.len()
    {
        return Err(ToolStoreError::ConcurrentMutation(path.to_path_buf()));
    }
    Ok(bytes)
}

fn write_private(path: &Path, bytes: &[u8], mode: u32) -> Result<(), ToolStoreError> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|source| ToolStoreError::Io {
            operation: "create installed tool file",
            path: path.to_path_buf(),
            source,
        })?;
    file.write_all(bytes).map_err(|source| ToolStoreError::Io {
        operation: "write installed tool file",
        path: path.to_path_buf(),
        source,
    })?;
    file.sync_all().map_err(|source| ToolStoreError::Io {
        operation: "sync installed tool file",
        path: path.to_path_buf(),
        source,
    })
}

fn sync_directory(path: &Path) -> Result<(), ToolStoreError> {
    File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|source| ToolStoreError::Io {
            operation: "sync installation directory",
            path: path.to_path_buf(),
            source,
        })
}

fn current_uid() -> u32 {
    // SAFETY: geteuid has no preconditions.
    unsafe { libc::geteuid() }
}

#[derive(Debug, Error)]
pub enum ToolStoreError {
    #[error("invalid {label} {value:?}")]
    InvalidComponent { label: &'static str, value: String },
    #[error("invalid {0} encoding; expected lowercase or uppercase hexadecimal")]
    InvalidEncoding(&'static str),
    #[error("signer fingerprint mismatch: expected {expected}, observed {observed}")]
    SignerMismatch { expected: String, observed: String },
    #[error("Ed25519 signature verification failed")]
    SignatureVerification,
    #[error("verification input is not a singly-linked regular file within the size limit: {0}")]
    UnsafeInput(PathBuf),
    #[error("verification input changed while it was being read: {0}")]
    ConcurrentMutation(PathBuf),
    #[error("tool version already exists and will not be overwritten: {0}")]
    VersionExists(PathBuf),
    #[error("unsafe tool installation directory: {0}")]
    UnsafeInstallation(PathBuf),
    #[error("installed artifact does not match its verified manifest: {0}")]
    ArtifactChanged(PathBuf),
    #[error("unsupported tool manifest schema {0}")]
    UnsupportedSchema(u32),
    #[error("failed to parse installed tool manifest: {0}")]
    Manifest(serde_json::Error),
    #[error("failed to serialize installed tool manifest: {0}")]
    Serialize(serde_json::Error),
    #[error("failed to {operation} at {path}: {source}")]
    Io {
        operation: &'static str,
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
}
