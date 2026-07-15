use std::collections::{BTreeMap, BTreeSet};
use std::ffi::{OsStr, OsString};
use std::fs::{self, File, Metadata};
use std::io::{Read, Write};
use std::os::fd::AsFd;
use std::os::unix::ffi::OsStringExt;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};

use rustix::fs::{
    AtFlags, Mode, OFlags, RenameFlags, fchmod, mkdirat, openat, renameat_with, unlinkat,
};
use sha2::{Digest, Sha256};
use thiserror::Error;
use uuid::Uuid;

use crate::audit::{AuditManifest, IncludedFile};
use crate::export::{ChangeExportManifest, ChangeKind, ChangeRecord};
use crate::staging::{display_path, is_valid_candidate_path, open_relative_no_links};

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ApplyReport {
    pub added: u64,
    pub modified: u64,
    pub deleted: u64,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ApplyAuthorization {
    allow_deletions: bool,
}

impl ApplyAuthorization {
    pub fn additions_and_modifications_only() -> Self {
        Self::default()
    }

    pub fn including_confirmed_deletions() -> Self {
        Self {
            allow_deletions: true,
        }
    }
}

#[derive(Debug)]
struct ValidatedChange {
    path: PathBuf,
    record: ChangeRecord,
}

#[derive(Debug)]
struct CreatedDirectory {
    parent: File,
    leaf: OsString,
}

#[derive(Debug)]
struct AppliedAction {
    parent: File,
    leaf: OsString,
    backup: Option<OsString>,
    installed: Option<FileIdentity>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FileIdentity {
    device: u64,
    inode: u64,
}

/// Apply a change export only when the host source still exactly matches the staging baseline.
///
/// Denied/rejected output disables the whole automatic transaction. Exported content and source
/// paths are reopened descriptor-relative without following links. Normal failures trigger an
/// in-process rollback; a crash may leave a hidden rollback file for manual recovery.
pub fn apply_exported_changes(
    source_root: &Path,
    baseline: &AuditManifest,
    export_root: &Path,
    manifest: &ChangeExportManifest,
    authorization: ApplyAuthorization,
) -> Result<ApplyReport, ApplyError> {
    let changes = validate_manifest(baseline, manifest)?;
    let deletion_count = changes
        .iter()
        .filter(|change| change.record.kind == ChangeKind::Deleted)
        .count();
    if deletion_count > 0 && !authorization.allow_deletions {
        return Err(ApplyError::DeletionAuthorizationRequired(deletion_count));
    }
    if changes.is_empty() {
        return Ok(ApplyReport::default());
    }

    let source_root = fs::canonicalize(source_root).map_err(|source| ApplyError::Io {
        operation: "canonicalize source root",
        path: source_root.to_path_buf(),
        source,
    })?;
    let source = File::open(&source_root).map_err(|source| ApplyError::Io {
        operation: "open source root",
        path: source_root.clone(),
        source,
    })?;
    let source_metadata = source.metadata().map_err(|source| ApplyError::Io {
        operation: "inspect source root",
        path: source_root.clone(),
        source,
    })?;
    if !source_metadata.is_dir()
        || source_metadata.uid() != current_uid()
        || source_metadata.permissions().mode() & 0o022 != 0
    {
        return Err(ApplyError::UnsafeSource(source_root));
    }
    let source_device = source_metadata.dev();

    let requested_export_metadata =
        fs::symlink_metadata(export_root).map_err(|source| ApplyError::Io {
            operation: "inspect requested change export",
            path: export_root.to_path_buf(),
            source,
        })?;
    if requested_export_metadata.file_type().is_symlink() {
        return Err(ApplyError::UnsafeExport(export_root.to_path_buf()));
    }
    let export_root = fs::canonicalize(export_root).map_err(|source| ApplyError::Io {
        operation: "canonicalize change export",
        path: export_root.to_path_buf(),
        source,
    })?;
    if export_root.starts_with(&source_root) || source_root.starts_with(&export_root) {
        return Err(ApplyError::UnsafeExport(export_root));
    }
    let export = File::open(&export_root).map_err(|source| ApplyError::Io {
        operation: "open change export",
        path: export_root.clone(),
        source,
    })?;
    let export_metadata = export.metadata().map_err(|source| ApplyError::Io {
        operation: "inspect change export",
        path: export_root.clone(),
        source,
    })?;
    if !export_metadata.is_dir()
        || export_metadata.file_type().is_symlink()
        || export_metadata.uid() != current_uid()
        || export_metadata.permissions().mode() & 0o077 != 0
    {
        return Err(ApplyError::UnsafeExport(export_root));
    }
    let files_path = export_root.join("files");
    let files = openat(
        &export,
        "files",
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::DIRECTORY,
        Mode::empty(),
    )
    .map(File::from)
    .map_err(|source| io_error("securely open change export files", &files_path, source))?;
    let files_metadata = files.metadata().map_err(|source| ApplyError::Io {
        operation: "inspect change export files",
        path: files_path.clone(),
        source,
    })?;
    if !files_metadata.is_dir()
        || files_metadata.uid() != current_uid()
        || files_metadata.permissions().mode() & 0o077 != 0
        || files_metadata.dev() != export_metadata.dev()
    {
        return Err(ApplyError::UnsafeExport(files_path));
    }

    // Check every conflict before the first host mutation.
    for change in &changes {
        match change.record.kind {
            ChangeKind::Added => ensure_source_absent(&source, &change.path)?,
            ChangeKind::Modified | ChangeKind::Deleted => {
                let baseline_file = baseline_file(baseline, &change.record.path)?;
                let _ = open_matching_source(&source, source_device, &change.path, baseline_file)?;
            }
        }
        if change.record.kind != ChangeKind::Deleted {
            verify_export_file(&files, files_metadata.dev(), change)?;
        }
    }

    let mut actions = Vec::new();
    let mut created_directories = Vec::new();
    let apply_result = (|| {
        let mut report = ApplyReport::default();
        for change in &changes {
            let (parent, leaf) = open_parent(
                &source,
                source_device,
                &change.path,
                change.record.kind == ChangeKind::Added,
                &mut created_directories,
            )?;
            match change.record.kind {
                ChangeKind::Added => {
                    ensure_leaf_absent(&parent, &leaf, &change.path)?;
                    let installed = install_export_file(
                        &files,
                        files_metadata.dev(),
                        change,
                        &parent,
                        &leaf,
                        standard_file_mode(change.record.executable == Some(true)),
                    )?;
                    actions.push(AppliedAction {
                        parent,
                        leaf,
                        backup: None,
                        installed: Some(installed),
                    });
                    sync_action_parent(&actions, &change.path, "sync added source parent")?;
                    report.added += 1;
                }
                ChangeKind::Modified => {
                    let baseline_file = baseline_file(baseline, &change.record.path)?;
                    let (current, metadata) =
                        open_matching_source(&source, source_device, &change.path, baseline_file)?;
                    let original = identity(&metadata);
                    let desired_mode = preserved_file_mode(metadata.permissions().mode());
                    let (temp, temp_name, replacement) = prepare_export_file(
                        &files,
                        files_metadata.dev(),
                        change,
                        &parent,
                        desired_mode,
                    )?;
                    drop(temp);
                    let backup = unique_leaf(".sandbox-guard-rollback-");
                    if let Err(source) =
                        renameat_with(&parent, &leaf, &parent, &backup, RenameFlags::NOREPLACE)
                    {
                        let _ = unlinkat(&parent, &temp_name, AtFlags::empty());
                        return Err(io_error(
                            "move source file to rollback slot",
                            &change.path,
                            source,
                        ));
                    }
                    actions.push(AppliedAction {
                        parent,
                        leaf,
                        backup: Some(backup),
                        installed: None,
                    });
                    let action = actions
                        .last_mut()
                        .expect("the rollback action was just added");
                    if let Err(error) = verify_rollback_source(
                        &action.parent,
                        action.backup.as_ref().unwrap(),
                        source_device,
                        &change.path,
                        baseline_file,
                        original,
                    ) {
                        let _ = unlinkat(&action.parent, &temp_name, AtFlags::empty());
                        return Err(error);
                    }
                    drop(current);
                    if let Err(source) = renameat_with(
                        &action.parent,
                        &temp_name,
                        &action.parent,
                        &action.leaf,
                        RenameFlags::NOREPLACE,
                    ) {
                        let _ = unlinkat(&action.parent, &temp_name, AtFlags::empty());
                        return Err(io_error(
                            "install modified source file",
                            &change.path,
                            source,
                        ));
                    }
                    action.installed = Some(replacement);
                    sync_action_parent(&actions, &change.path, "sync modified source parent")?;
                    report.modified += 1;
                }
                ChangeKind::Deleted => {
                    let baseline_file = baseline_file(baseline, &change.record.path)?;
                    let (_current, metadata) =
                        open_matching_source(&source, source_device, &change.path, baseline_file)?;
                    let original = identity(&metadata);
                    let backup = unique_leaf(".sandbox-guard-rollback-");
                    renameat_with(&parent, &leaf, &parent, &backup, RenameFlags::NOREPLACE)
                        .map_err(|source| {
                            io_error(
                                "move deleted source file to rollback slot",
                                &change.path,
                                source,
                            )
                        })?;
                    actions.push(AppliedAction {
                        parent,
                        leaf,
                        backup: Some(backup),
                        installed: None,
                    });
                    let action = actions.last().expect("the rollback action was just added");
                    verify_rollback_source(
                        &action.parent,
                        action.backup.as_ref().unwrap(),
                        source_device,
                        &change.path,
                        baseline_file,
                        original,
                    )?;
                    sync_action_parent(&actions, &change.path, "sync deleted source parent")?;
                    report.deleted += 1;
                }
            }
        }
        Ok(report)
    })();

    let report = match apply_result {
        Ok(report) => report,
        Err(error) => {
            if let Err(rollback) = rollback(&actions, &created_directories) {
                return Err(ApplyError::RollbackIncomplete {
                    apply: error.to_string(),
                    rollback,
                });
            }
            return Err(error);
        }
    };

    for action in &actions {
        if let Some(backup) = &action.backup {
            unlinkat(&action.parent, backup, AtFlags::empty()).map_err(|source| {
                ApplyError::AppliedButCleanupFailed {
                    path: display_path(Path::new(backup)),
                    source: std::io::Error::from(source),
                }
            })?;
            action
                .parent
                .sync_all()
                .map_err(|source| ApplyError::AppliedButCleanupFailed {
                    path: display_path(Path::new(backup)),
                    source,
                })?;
        }
    }
    Ok(report)
}

pub fn decode_change_path(rendered: &str) -> Result<PathBuf, ApplyError> {
    let input = rendered.as_bytes();
    let mut bytes = Vec::with_capacity(input.len());
    let mut index = 0;
    while index < input.len() {
        match input[index] {
            b'%' => {
                if index + 2 >= input.len() {
                    return Err(ApplyError::UnsafeManifest(
                        "truncated percent-encoded path".to_owned(),
                    ));
                }
                let high = hex_value(input[index + 1]);
                let low = hex_value(input[index + 2]);
                let (Some(high), Some(low)) = (high, low) else {
                    return Err(ApplyError::UnsafeManifest(
                        "invalid percent-encoded path".to_owned(),
                    ));
                };
                bytes.push((high << 4) | low);
                index += 3;
            }
            byte if byte.is_ascii() => {
                bytes.push(byte);
                index += 1;
            }
            _ => {
                return Err(ApplyError::UnsafeManifest(
                    "change path contains unencoded non-ASCII bytes".to_owned(),
                ));
            }
        }
    }
    if bytes.contains(&0) {
        return Err(ApplyError::UnsafeManifest(
            "change path contains NUL".to_owned(),
        ));
    }
    let path = PathBuf::from(OsString::from_vec(bytes));
    if !is_valid_candidate_path(&path) || display_path(&path) != rendered {
        return Err(ApplyError::UnsafeManifest(format!(
            "change path is not canonical and relative: {rendered:?}"
        )));
    }
    Ok(path)
}

fn validate_manifest(
    baseline: &AuditManifest,
    manifest: &ChangeExportManifest,
) -> Result<Vec<ValidatedChange>, ApplyError> {
    if manifest.schema_version != 1
        || manifest.baseline_run_id != baseline.run_id
        || manifest.policy_sha256 != baseline.policy_sha256
    {
        return Err(ApplyError::UnsafeManifest(
            "change export does not match the staging baseline".to_owned(),
        ));
    }
    if !manifest.rejected.is_empty() {
        return Err(ApplyError::RejectedOutput(manifest.rejected.len()));
    }
    let baseline_files: BTreeMap<&str, &IncludedFile> = baseline
        .included
        .iter()
        .map(|file| (file.path.as_str(), file))
        .collect();
    let mut seen = BTreeSet::new();
    let mut result = Vec::with_capacity(manifest.changes.len());
    for record in &manifest.changes {
        if !seen.insert(record.path.clone()) {
            return Err(ApplyError::UnsafeManifest(format!(
                "duplicate change path {:?}",
                record.path
            )));
        }
        let path = decode_change_path(&record.path)?;
        let baseline_file = baseline_files.get(record.path.as_str()).copied();
        match record.kind {
            ChangeKind::Added => {
                if baseline_file.is_some()
                    || record.baseline_sha256.is_some()
                    || record.exported_sha256.is_none()
                    || record.bytes.is_none()
                    || record.executable.is_none()
                {
                    return Err(invalid_record(record));
                }
            }
            ChangeKind::Modified => {
                if baseline_file.is_none()
                    || record.baseline_sha256.as_deref()
                        != baseline_file.map(|file| file.sha256.as_str())
                    || record.exported_sha256.is_none()
                    || record.bytes.is_none()
                    || record.executable.is_none()
                {
                    return Err(invalid_record(record));
                }
            }
            ChangeKind::Deleted => {
                if baseline_file.is_none()
                    || record.baseline_sha256.as_deref()
                        != baseline_file.map(|file| file.sha256.as_str())
                    || record.exported_sha256.is_some()
                    || record.bytes.is_some()
                    || record.executable.is_some()
                {
                    return Err(invalid_record(record));
                }
            }
        }
        result.push(ValidatedChange {
            path,
            record: record.clone(),
        });
    }
    result.sort_by(|left, right| left.path.cmp(&right.path));
    Ok(result)
}

fn invalid_record(record: &ChangeRecord) -> ApplyError {
    ApplyError::UnsafeManifest(format!("inconsistent change record for {:?}", record.path))
}

fn baseline_file<'a>(
    baseline: &'a AuditManifest,
    rendered: &str,
) -> Result<&'a IncludedFile, ApplyError> {
    baseline
        .included
        .iter()
        .find(|file| file.path == rendered)
        .ok_or_else(|| ApplyError::UnsafeManifest(format!("missing baseline for {rendered:?}")))
}

fn ensure_source_absent(root: &File, path: &Path) -> Result<(), ApplyError> {
    match open_relative_no_links(root, path) {
        Ok(_) => Err(ApplyError::Conflict {
            path: path.to_path_buf(),
            reason: "path was added on the host after staging".to_owned(),
        }),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(ApplyError::Conflict {
            path: path.to_path_buf(),
            reason: format!("cannot prove path is absent without following links: {error}"),
        }),
    }
}

fn ensure_leaf_absent(parent: &File, leaf: &OsStr, path: &Path) -> Result<(), ApplyError> {
    match openat(
        parent,
        leaf,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
        Mode::empty(),
    ) {
        Ok(_) => Err(ApplyError::Conflict {
            path: path.to_path_buf(),
            reason: "path appeared on the host during apply".to_owned(),
        }),
        Err(error) if std::io::Error::from(error).kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(io_error("prove added path is absent", path, error)),
    }
}

fn open_matching_source(
    root: &File,
    root_device: u64,
    path: &Path,
    baseline: &IncludedFile,
) -> Result<(File, Metadata), ApplyError> {
    let mut file = open_relative_no_links(root, path).map_err(|source| ApplyError::Conflict {
        path: path.to_path_buf(),
        reason: format!("source cannot be securely reopened: {source}"),
    })?;
    let before = file.metadata().map_err(|source| ApplyError::Io {
        operation: "inspect source file",
        path: path.to_path_buf(),
        source,
    })?;
    if !before.is_file()
        || before.dev() != root_device
        || before.uid() != current_uid()
        || before.nlink() != 1
        || before.permissions().mode() & 0o022 != 0
        || (before.permissions().mode() & 0o111 != 0) != baseline.executable
        || before.len() != baseline.bytes
    {
        return Err(ApplyError::Conflict {
            path: path.to_path_buf(),
            reason: "source type, owner, link count, size, filesystem, or executable mode changed"
                .to_owned(),
        });
    }
    let sha256 = hash_file(&mut file, path)?;
    let after = file.metadata().map_err(|source| ApplyError::Io {
        operation: "reinspect source file",
        path: path.to_path_buf(),
        source,
    })?;
    if !same_snapshot(&before, &after) || sha256 != baseline.sha256 {
        return Err(ApplyError::Conflict {
            path: path.to_path_buf(),
            reason: "source content changed since staging".to_owned(),
        });
    }
    Ok((file, after))
}

fn verify_rollback_source(
    parent: &File,
    leaf: &OsStr,
    root_device: u64,
    path: &Path,
    baseline: &IncludedFile,
    expected_identity: FileIdentity,
) -> Result<(), ApplyError> {
    let mut file = open_leaf(parent, leaf, path)?;
    let before = file.metadata().map_err(|source| ApplyError::Io {
        operation: "inspect rollback source file",
        path: path.to_path_buf(),
        source,
    })?;
    if identity(&before) != expected_identity
        || !before.is_file()
        || before.dev() != root_device
        || before.uid() != current_uid()
        || before.nlink() != 1
        || before.permissions().mode() & 0o022 != 0
        || before.len() != baseline.bytes
        || (before.permissions().mode() & 0o111 != 0) != baseline.executable
    {
        return Err(ApplyError::Conflict {
            path: path.to_path_buf(),
            reason: "source changed while entering the rollback transaction".to_owned(),
        });
    }
    let sha256 = hash_file(&mut file, path)?;
    let after = file.metadata().map_err(|source| ApplyError::Io {
        operation: "reinspect rollback source file",
        path: path.to_path_buf(),
        source,
    })?;
    if !same_snapshot(&before, &after) || sha256 != baseline.sha256 {
        return Err(ApplyError::Conflict {
            path: path.to_path_buf(),
            reason: "source content changed while entering the rollback transaction".to_owned(),
        });
    }
    Ok(())
}

fn verify_export_file(
    files: &File,
    root_device: u64,
    change: &ValidatedChange,
) -> Result<(), ApplyError> {
    let mut file =
        open_relative_no_links(files, &change.path).map_err(|source| ApplyError::Io {
            operation: "securely open exported file",
            path: change.path.clone(),
            source,
        })?;
    verify_export_metadata(&file, root_device, change)?;
    let sha256 = hash_file(&mut file, &change.path)?;
    let after = file.metadata().map_err(|source| ApplyError::Io {
        operation: "reinspect exported file",
        path: change.path.clone(),
        source,
    })?;
    verify_export_metadata_values(&after, root_device, change)?;
    if sha256 != change.record.exported_sha256.as_deref().unwrap_or_default() {
        return Err(ApplyError::UnsafeExport(change.path.clone()));
    }
    Ok(())
}

fn verify_export_metadata(
    file: &File,
    root_device: u64,
    change: &ValidatedChange,
) -> Result<Metadata, ApplyError> {
    let metadata = file.metadata().map_err(|source| ApplyError::Io {
        operation: "inspect exported file",
        path: change.path.clone(),
        source,
    })?;
    verify_export_metadata_values(&metadata, root_device, change)?;
    Ok(metadata)
}

fn verify_export_metadata_values(
    metadata: &Metadata,
    root_device: u64,
    change: &ValidatedChange,
) -> Result<(), ApplyError> {
    if !metadata.is_file()
        || metadata.dev() != root_device
        || metadata.uid() != current_uid()
        || metadata.nlink() != 1
        || metadata.permissions().mode() & 0o077 != 0
        || Some(metadata.len()) != change.record.bytes
        || Some(metadata.permissions().mode() & 0o111 != 0) != change.record.executable
    {
        return Err(ApplyError::UnsafeExport(change.path.clone()));
    }
    Ok(())
}

fn install_export_file(
    files: &File,
    export_device: u64,
    change: &ValidatedChange,
    parent: &File,
    leaf: &OsStr,
    mode: Mode,
) -> Result<FileIdentity, ApplyError> {
    let (temp, temp_name, identity) =
        prepare_export_file(files, export_device, change, parent, mode)?;
    drop(temp);
    if let Err(source) = renameat_with(parent, &temp_name, parent, leaf, RenameFlags::NOREPLACE) {
        let _ = unlinkat(parent, &temp_name, AtFlags::empty());
        return Err(io_error("install added source file", &change.path, source));
    }
    Ok(identity)
}

fn prepare_export_file(
    files: &File,
    export_device: u64,
    change: &ValidatedChange,
    parent: &File,
    mode: Mode,
) -> Result<(File, OsString, FileIdentity), ApplyError> {
    let mut input =
        open_relative_no_links(files, &change.path).map_err(|source| ApplyError::Io {
            operation: "securely reopen exported file",
            path: change.path.clone(),
            source,
        })?;
    let before = verify_export_metadata(&input, export_device, change)?;
    let (mut output, temp_name) = create_temp_file(parent, &change.path)?;
    let result = (|| {
        let mut hasher = Sha256::new();
        let mut bytes = 0_u64;
        let mut buffer = [0_u8; 64 * 1024];
        loop {
            let read = input.read(&mut buffer).map_err(|source| ApplyError::Io {
                operation: "read exported file",
                path: change.path.clone(),
                source,
            })?;
            if read == 0 {
                break;
            }
            bytes = bytes
                .checked_add(read as u64)
                .ok_or_else(|| ApplyError::UnsafeExport(change.path.clone()))?;
            hasher.update(&buffer[..read]);
            output
                .write_all(&buffer[..read])
                .map_err(|source| ApplyError::Io {
                    operation: "write source transaction file",
                    path: change.path.clone(),
                    source,
                })?;
        }
        let after = input.metadata().map_err(|source| ApplyError::Io {
            operation: "reinspect exported file",
            path: change.path.clone(),
            source,
        })?;
        if !same_snapshot(&before, &after)
            || Some(bytes) != change.record.bytes
            || hex::encode(hasher.finalize())
                != change.record.exported_sha256.as_deref().unwrap_or_default()
        {
            return Err(ApplyError::UnsafeExport(change.path.clone()));
        }
        fchmod(&output, mode)
            .map_err(|source| io_error("set source transaction file mode", &change.path, source))?;
        output.sync_all().map_err(|source| ApplyError::Io {
            operation: "sync source transaction file",
            path: change.path.clone(),
            source,
        })?;
        let metadata = output.metadata().map_err(|source| ApplyError::Io {
            operation: "inspect source transaction file",
            path: change.path.clone(),
            source,
        })?;
        Ok(identity(&metadata))
    })();
    match result {
        Ok(identity) => Ok((output, temp_name, identity)),
        Err(error) => {
            drop(output);
            let _ = unlinkat(parent, &temp_name, AtFlags::empty());
            Err(error)
        }
    }
}

fn create_temp_file(parent: &File, path: &Path) -> Result<(File, OsString), ApplyError> {
    for _ in 0..32 {
        let name = unique_leaf(".sandbox-guard-apply-");
        match openat(
            parent,
            &name,
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::from_bits_retain(0o600),
        ) {
            Ok(descriptor) => return Ok((File::from(descriptor), name)),
            Err(error)
                if std::io::Error::from(error).kind() == std::io::ErrorKind::AlreadyExists =>
            {
                continue;
            }
            Err(error) => return Err(io_error("create source transaction file", path, error)),
        }
    }
    Err(ApplyError::Conflict {
        path: path.to_path_buf(),
        reason: "could not allocate a unique transaction file".to_owned(),
    })
}

fn open_parent(
    root: &File,
    root_device: u64,
    path: &Path,
    create: bool,
    created: &mut Vec<CreatedDirectory>,
) -> Result<(File, OsString), ApplyError> {
    let components: Vec<&OsStr> = path
        .components()
        .map(|component| match component {
            Component::Normal(value) => Ok(value),
            _ => Err(ApplyError::UnsafeManifest(
                "non-relative change path".to_owned(),
            )),
        })
        .collect::<Result<_, _>>()?;
    let (leaf, parents) = components
        .split_last()
        .ok_or_else(|| ApplyError::UnsafeManifest("empty change path".to_owned()))?;
    let mut directory = File::from(
        rustix::io::dup(root.as_fd())
            .map_err(|source| io_error("duplicate source root descriptor", path, source))?,
    );
    for component in parents {
        let next = match open_directory(&directory, component) {
            Ok(next) => next,
            Err(ApplyError::Io { source, .. })
                if create && source.kind() == std::io::ErrorKind::NotFound =>
            {
                let parent_copy =
                    File::from(rustix::io::dup(directory.as_fd()).map_err(|source| {
                        io_error("duplicate source parent descriptor", path, source)
                    })?);
                match mkdirat(&directory, *component, Mode::from_bits_retain(0o755)) {
                    Ok(()) => created.push(CreatedDirectory {
                        parent: parent_copy,
                        leaf: (*component).to_os_string(),
                    }),
                    Err(error)
                        if std::io::Error::from(error).kind()
                            == std::io::ErrorKind::AlreadyExists => {}
                    Err(error) => return Err(io_error("create source directory", path, error)),
                }
                open_directory(&directory, component)?
            }
            Err(error) => return Err(error),
        };
        let metadata = next.metadata().map_err(|source| ApplyError::Io {
            operation: "inspect source directory",
            path: path.to_path_buf(),
            source,
        })?;
        if !metadata.is_dir()
            || metadata.dev() != root_device
            || metadata.uid() != current_uid()
            || metadata.permissions().mode() & 0o022 != 0
        {
            return Err(ApplyError::Conflict {
                path: path.to_path_buf(),
                reason: "source parent is not an owner-owned directory on the source filesystem"
                    .to_owned(),
            });
        }
        directory = next;
    }
    Ok((directory, (*leaf).to_os_string()))
}

fn sync_action_parent(
    actions: &[AppliedAction],
    path: &Path,
    operation: &'static str,
) -> Result<(), ApplyError> {
    actions
        .last()
        .expect("a source mutation must have a rollback action")
        .parent
        .sync_all()
        .map_err(|source| ApplyError::Io {
            operation,
            path: path.to_path_buf(),
            source,
        })
}

fn open_directory(parent: &File, leaf: &OsStr) -> Result<File, ApplyError> {
    openat(
        parent,
        leaf,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::DIRECTORY,
        Mode::empty(),
    )
    .map(File::from)
    .map_err(|source| ApplyError::Io {
        operation: "securely open source directory",
        path: PathBuf::from(leaf),
        source: std::io::Error::from(source),
    })
}

fn open_leaf(parent: &File, leaf: &OsStr, path: &Path) -> Result<File, ApplyError> {
    openat(
        parent,
        leaf,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
        Mode::empty(),
    )
    .map(File::from)
    .map_err(|source| io_error("securely open source transaction file", path, source))
}

fn rollback(actions: &[AppliedAction], created: &[CreatedDirectory]) -> Result<(), String> {
    let mut errors = Vec::new();
    for action in actions.iter().rev() {
        if let Some(installed) = action.installed {
            match open_leaf(&action.parent, &action.leaf, Path::new(&action.leaf)) {
                Ok(file) => match file.metadata() {
                    Ok(metadata) if identity(&metadata) == installed => {
                        if let Err(error) = unlinkat(&action.parent, &action.leaf, AtFlags::empty())
                        {
                            errors.push(format!("remove installed file: {error}"));
                            continue;
                        }
                    }
                    Ok(_) => {
                        errors.push("installed file changed before rollback".to_owned());
                        continue;
                    }
                    Err(error) => {
                        errors.push(format!("inspect installed file: {error}"));
                        continue;
                    }
                },
                Err(ApplyError::Io { source, .. })
                    if source.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => {
                    errors.push(error.to_string());
                    continue;
                }
            }
        }
        if let Some(backup) = &action.backup {
            if let Err(error) = renameat_with(
                &action.parent,
                backup,
                &action.parent,
                &action.leaf,
                RenameFlags::NOREPLACE,
            ) {
                errors.push(format!("restore rollback file: {error}"));
                continue;
            }
        }
        if let Err(error) = action.parent.sync_all() {
            errors.push(format!("sync rolled-back source parent: {error}"));
        }
    }
    for directory in created.iter().rev() {
        match unlinkat(&directory.parent, &directory.leaf, AtFlags::REMOVEDIR) {
            Ok(()) => {}
            Err(error) => errors.push(format!("remove transaction directory: {error}")),
        }
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors.join("; "))
    }
}

fn hash_file(file: &mut File, path: &Path) -> Result<String, ApplyError> {
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer).map_err(|source| ApplyError::Io {
            operation: "hash file",
            path: path.to_path_buf(),
            source,
        })?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(hex::encode(hasher.finalize()))
}

fn same_snapshot(before: &Metadata, after: &Metadata) -> bool {
    before.dev() == after.dev()
        && before.ino() == after.ino()
        && before.len() == after.len()
        && before.mtime() == after.mtime()
        && before.mtime_nsec() == after.mtime_nsec()
        && before.ctime() == after.ctime()
        && before.ctime_nsec() == after.ctime_nsec()
}

fn identity(metadata: &Metadata) -> FileIdentity {
    FileIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
    }
}

fn standard_file_mode(executable: bool) -> Mode {
    let mut mode = Mode::RUSR | Mode::WUSR | Mode::RGRP | Mode::ROTH;
    if executable {
        mode |= Mode::XUSR | Mode::XGRP | Mode::XOTH;
    }
    mode
}

fn preserved_file_mode(raw: u32) -> Mode {
    let mut mode = Mode::empty();
    for (bit, flag) in [
        (0o400, Mode::RUSR),
        (0o200, Mode::WUSR),
        (0o100, Mode::XUSR),
        (0o040, Mode::RGRP),
        (0o020, Mode::WGRP),
        (0o010, Mode::XGRP),
        (0o004, Mode::ROTH),
        (0o002, Mode::WOTH),
        (0o001, Mode::XOTH),
    ] {
        if raw & bit != 0 {
            mode |= flag;
        }
    }
    mode
}

fn unique_leaf(prefix: &str) -> OsString {
    OsString::from(format!("{prefix}{}", Uuid::new_v4()))
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn current_uid() -> u32 {
    // SAFETY: geteuid has no preconditions.
    unsafe { libc::geteuid() }
}

fn io_error(operation: &'static str, path: &Path, source: impl Into<std::io::Error>) -> ApplyError {
    ApplyError::Io {
        operation,
        path: path.to_path_buf(),
        source: source.into(),
    }
}

#[derive(Debug, Error)]
pub enum ApplyError {
    #[error("unsafe change export manifest: {0}")]
    UnsafeManifest(String),
    #[error(
        "automatic apply refused because the isolated tool produced {0} policy-denied or unsafe path(s)"
    )]
    RejectedOutput(usize),
    #[error("trusted deletion confirmation is required before applying {0} deletion(s)")]
    DeletionAuthorizationRequired(usize),
    #[error("source root is not a safely writable owner-owned directory: {0:?}")]
    UnsafeSource(PathBuf),
    #[error("change export is not private and descriptor-safe: {0:?}")]
    UnsafeExport(PathBuf),
    #[error("source conflict at {path:?}: {reason}")]
    Conflict { path: PathBuf, reason: String },
    #[error("failed to {operation} at {path:?}: {source}")]
    Io {
        operation: &'static str,
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error(
        "apply failed ({apply}) and rollback was incomplete ({rollback}); preserve the review bundle and inspect .sandbox-guard-rollback-* files"
    )]
    RollbackIncomplete { apply: String, rollback: String },
    #[error("changes were applied, but cleanup failed for {path}: {source}")]
    AppliedButCleanupFailed {
        path: String,
        #[source]
        source: std::io::Error,
    },
}
