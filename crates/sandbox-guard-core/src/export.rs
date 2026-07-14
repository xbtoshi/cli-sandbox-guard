use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use ignore::WalkBuilder;
use serde::{Deserialize, Serialize};
use tempfile::Builder as TempBuilder;
use thiserror::Error;
use uuid::Uuid;

use crate::audit::{AuditManifest, IncludedFile};
use crate::policy::CompiledPolicy;
use crate::staging::{
    CopyError, copy_stable_file, display_path, is_valid_candidate_path, open_relative_no_links,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChangeExportManifest {
    pub schema_version: u32,
    pub created_at: DateTime<Utc>,
    pub baseline_run_id: Uuid,
    pub policy_sha256: String,
    pub changes: Vec<ChangeRecord>,
    pub rejected: Vec<RejectedChange>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ChangeKind {
    Added,
    Modified,
    Deleted,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChangeRecord {
    pub path: String,
    pub kind: ChangeKind,
    pub baseline_sha256: Option<String>,
    pub exported_sha256: Option<String>,
    pub bytes: Option<u64>,
    pub executable: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RejectedChange {
    pub path: String,
    pub reason: String,
}

#[derive(Debug)]
pub struct ExportReport {
    pub destination: PathBuf,
    pub manifest: ChangeExportManifest,
}

pub fn export_changes(
    workspace: &Path,
    source_root: &Path,
    baseline: &AuditManifest,
    policy: &CompiledPolicy,
    destination: &Path,
) -> Result<ExportReport, ExportError> {
    let workspace = fs::canonicalize(workspace).map_err(|source| ExportError::Io {
        operation: "canonicalize staged workspace",
        path: workspace.to_path_buf(),
        source,
    })?;
    let source_root = fs::canonicalize(source_root).map_err(|source| ExportError::Io {
        operation: "canonicalize source root",
        path: source_root.to_path_buf(),
        source,
    })?;
    let destination = absolute_destination(destination)?;
    if destination.exists() {
        return Err(ExportError::DestinationExists(destination));
    }
    validate_destination_components(&destination)?;
    let requested_parent = destination
        .parent()
        .ok_or_else(|| ExportError::UnsafeDestination(destination.clone()))?;
    let existing_ancestor = nearest_existing_ancestor(requested_parent)?;
    let canonical_ancestor =
        fs::canonicalize(&existing_ancestor).map_err(|source| ExportError::Io {
            operation: "canonicalize export ancestor",
            path: existing_ancestor,
            source,
        })?;
    if canonical_ancestor.starts_with(&source_root) || canonical_ancestor.starts_with(&workspace) {
        return Err(ExportError::UnsafeDestination(destination));
    }
    fs::create_dir_all(requested_parent).map_err(|source| ExportError::Io {
        operation: "create export parent",
        path: requested_parent.to_path_buf(),
        source,
    })?;
    let parent = fs::canonicalize(requested_parent).map_err(|source| ExportError::Io {
        operation: "canonicalize export parent",
        path: requested_parent.to_path_buf(),
        source,
    })?;
    let destination = parent.join(
        destination
            .file_name()
            .ok_or_else(|| ExportError::UnsafeDestination(destination.clone()))?,
    );
    if parent.starts_with(&source_root) || parent.starts_with(&workspace) {
        return Err(ExportError::UnsafeDestination(destination));
    }
    let parent_metadata = fs::symlink_metadata(&parent).map_err(|source| ExportError::Io {
        operation: "inspect export parent",
        path: parent.clone(),
        source,
    })?;
    if !parent_metadata.is_dir()
        || parent_metadata.file_type().is_symlink()
        || parent_metadata.uid() != current_uid()
        || parent_metadata.permissions().mode() & 0o022 != 0
    {
        return Err(ExportError::UnsafeDestination(destination));
    }

    let temp = TempBuilder::new()
        .prefix(".sandbox-guard-export-")
        .tempdir_in(&parent)
        .map_err(|source| ExportError::Io {
            operation: "create temporary export",
            path: parent.clone(),
            source,
        })?;
    fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).map_err(|source| {
        ExportError::Io {
            operation: "secure temporary export",
            path: temp.path().to_path_buf(),
            source,
        }
    })?;
    let files_root = temp.path().join("files");
    fs::create_dir(&files_root).map_err(|source| ExportError::Io {
        operation: "create export files directory",
        path: files_root.clone(),
        source,
    })?;
    fs::set_permissions(&files_root, fs::Permissions::from_mode(0o700)).map_err(|source| {
        ExportError::Io {
            operation: "secure export files directory",
            path: files_root.clone(),
            source,
        }
    })?;

    let baseline_files: BTreeMap<&str, &IncludedFile> = baseline
        .included
        .iter()
        .map(|file| (file.path.as_str(), file))
        .collect();
    let workspace_root = File::open(&workspace).map_err(|source| ExportError::Io {
        operation: "open staged workspace root",
        path: workspace.clone(),
        source,
    })?;
    let root_device = workspace_root
        .metadata()
        .map_err(|source| ExportError::Io {
            operation: "inspect staged workspace root",
            path: workspace.clone(),
            source,
        })?
        .dev();
    let mut seen = BTreeSet::new();
    let mut changes = Vec::new();
    let mut rejected = Vec::new();
    let mut exported_files = 0_u64;
    let mut exported_bytes = 0_u64;

    let mut walker = WalkBuilder::new(&workspace);
    walker
        .hidden(false)
        .follow_links(false)
        .parents(false)
        .ignore(false)
        .git_ignore(false)
        .git_global(false)
        .git_exclude(false)
        .sort_by_file_path(|left, right| left.cmp(right));
    let workspace_for_filter = workspace.clone();
    walker.filter_entry(move |entry| {
        entry.path() == workspace_for_filter
            || entry
                .path()
                .strip_prefix(&workspace_for_filter)
                .ok()
                .is_none_or(|relative| relative != Path::new(".git"))
    });

    for result in walker.build() {
        let entry = result.map_err(ExportError::Walk)?;
        if entry.path() == workspace {
            continue;
        }
        let relative = entry
            .path()
            .strip_prefix(&workspace)
            .map_err(|_| ExportError::UnsafeWorkspacePath(entry.path().to_path_buf()))?;
        if !is_valid_candidate_path(relative) {
            return Err(ExportError::UnsafeWorkspacePath(relative.to_path_buf()));
        }
        let rendered = display_path(relative);
        if let Some(rule) = policy.denied_by_path_or_ancestor(relative) {
            rejected.push(RejectedChange {
                path: rendered,
                reason: format!("denied by policy rule {rule:?}"),
            });
            continue;
        }
        let metadata = fs::symlink_metadata(entry.path()).map_err(|source| ExportError::Io {
            operation: "inspect changed workspace path",
            path: entry.path().to_path_buf(),
            source,
        })?;
        if metadata.is_dir() {
            continue;
        }
        seen.insert(rendered.clone());
        if metadata.file_type().is_symlink() {
            rejected.push(RejectedChange {
                path: rendered,
                reason: "symbolic links are never exported".to_owned(),
            });
            continue;
        }
        if !metadata.is_file() {
            rejected.push(RejectedChange {
                path: rendered,
                reason: "special files are never exported".to_owned(),
            });
            continue;
        }

        let source_file = open_relative_no_links(&workspace_root, relative).map_err(|source| {
            ExportError::Io {
                operation: "securely open changed workspace file",
                path: relative.to_path_buf(),
                source,
            }
        })?;
        let before = source_file.metadata().map_err(|source| ExportError::Io {
            operation: "inspect open changed workspace file",
            path: relative.to_path_buf(),
            source,
        })?;
        if !before.is_file() || before.dev() != root_device || before.nlink() > 1 {
            rejected.push(RejectedChange {
                path: rendered,
                reason: "file is not a singly-linked regular file on the workspace filesystem"
                    .to_owned(),
            });
            continue;
        }
        if before.len() > policy.effective().max_file_bytes {
            return Err(ExportError::FileLimit {
                path: relative.to_path_buf(),
                bytes: before.len(),
                limit: policy.effective().max_file_bytes,
            });
        }
        let output = files_root.join(relative);
        let copied = copy_stable_file(
            source_file,
            &before,
            &output,
            policy.effective().max_file_bytes,
        )
        .map_err(|error| map_copy_error(error, relative, policy.effective().max_file_bytes))?;
        let baseline_file = baseline_files.get(rendered.as_str()).copied();
        if baseline_file.is_some_and(|file| file.sha256 == copied.sha256) {
            fs::remove_file(&output).map_err(|source| ExportError::Io {
                operation: "remove unchanged export candidate",
                path: output,
                source,
            })?;
            continue;
        }
        exported_files = exported_files
            .checked_add(1)
            .ok_or(ExportError::FileCountLimit(policy.effective().max_files))?;
        if exported_files > policy.effective().max_files {
            return Err(ExportError::FileCountLimit(policy.effective().max_files));
        }
        exported_bytes =
            exported_bytes
                .checked_add(copied.bytes)
                .ok_or(ExportError::TotalSizeLimit(
                    policy.effective().max_total_bytes,
                ))?;
        if exported_bytes > policy.effective().max_total_bytes {
            return Err(ExportError::TotalSizeLimit(
                policy.effective().max_total_bytes,
            ));
        }
        changes.push(ChangeRecord {
            path: rendered,
            kind: if baseline_file.is_some() {
                ChangeKind::Modified
            } else {
                ChangeKind::Added
            },
            baseline_sha256: baseline_file.map(|file| file.sha256.clone()),
            exported_sha256: Some(copied.sha256),
            bytes: Some(copied.bytes),
            executable: Some(copied.executable),
        });
    }

    for baseline_file in &baseline.included {
        if !seen.contains(&baseline_file.path) {
            changes.push(ChangeRecord {
                path: baseline_file.path.clone(),
                kind: ChangeKind::Deleted,
                baseline_sha256: Some(baseline_file.sha256.clone()),
                exported_sha256: None,
                bytes: None,
                executable: None,
            });
        }
    }
    changes.sort_by(|left, right| left.path.cmp(&right.path));
    rejected.sort_by(|left, right| left.path.cmp(&right.path));
    let manifest = ChangeExportManifest {
        schema_version: 1,
        created_at: Utc::now(),
        baseline_run_id: baseline.run_id,
        policy_sha256: policy.hash().to_owned(),
        changes,
        rejected,
    };
    write_manifest(&temp.path().join("manifest.json"), &manifest)?;
    sync_export_directories(temp.path())?;
    fs::rename(temp.path(), &destination).map_err(|source| ExportError::Io {
        operation: "publish atomic change export",
        path: destination.clone(),
        source,
    })?;
    let _published_path = temp.keep();
    File::open(&parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|source| ExportError::Io {
            operation: "sync published change export parent",
            path: parent,
            source,
        })?;
    Ok(ExportReport {
        destination,
        manifest,
    })
}

fn absolute_destination(destination: &Path) -> Result<PathBuf, ExportError> {
    if destination.is_absolute() {
        Ok(destination.to_path_buf())
    } else {
        std::env::current_dir()
            .map(|cwd| cwd.join(destination))
            .map_err(|source| ExportError::Io {
                operation: "resolve current directory",
                path: destination.to_path_buf(),
                source,
            })
    }
}

fn validate_destination_components(destination: &Path) -> Result<(), ExportError> {
    if destination
        .components()
        .any(|component| matches!(component, std::path::Component::ParentDir))
    {
        return Err(ExportError::UnsafeDestination(destination.to_path_buf()));
    }
    Ok(())
}

fn nearest_existing_ancestor(path: &Path) -> Result<PathBuf, ExportError> {
    let mut candidate = path;
    loop {
        match fs::symlink_metadata(candidate) {
            Ok(_) => return Ok(candidate.to_path_buf()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                candidate = candidate
                    .parent()
                    .ok_or_else(|| ExportError::UnsafeDestination(path.to_path_buf()))?;
            }
            Err(source) => {
                return Err(ExportError::Io {
                    operation: "inspect export ancestor",
                    path: candidate.to_path_buf(),
                    source,
                });
            }
        }
    }
}

fn current_uid() -> u32 {
    // SAFETY: geteuid has no preconditions.
    unsafe { libc::geteuid() }
}

fn sync_export_directories(path: &Path) -> Result<(), ExportError> {
    for entry in fs::read_dir(path).map_err(|source| ExportError::Io {
        operation: "read export directory for synchronization",
        path: path.to_path_buf(),
        source,
    })? {
        let entry = entry.map_err(|source| ExportError::Io {
            operation: "read export directory entry for synchronization",
            path: path.to_path_buf(),
            source,
        })?;
        let file_type = entry.file_type().map_err(|source| ExportError::Io {
            operation: "inspect export directory entry for synchronization",
            path: entry.path(),
            source,
        })?;
        if file_type.is_dir() {
            sync_export_directories(&entry.path())?;
        }
    }
    File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|source| ExportError::Io {
            operation: "sync export directory",
            path: path.to_path_buf(),
            source,
        })
}

fn map_copy_error(error: CopyError, path: &Path, limit: u64) -> ExportError {
    match error {
        CopyError::Io(source) => ExportError::Io {
            operation: "copy changed workspace file",
            path: path.to_path_buf(),
            source,
        },
        CopyError::Changed => ExportError::ConcurrentMutation(path.to_path_buf()),
        CopyError::Limit(bytes) => ExportError::FileLimit {
            path: path.to_path_buf(),
            bytes,
            limit,
        },
    }
}

fn write_manifest(path: &Path, manifest: &ChangeExportManifest) -> Result<(), ExportError> {
    let bytes = serde_json::to_vec_pretty(manifest).map_err(ExportError::Serialize)?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|source| ExportError::Io {
            operation: "create change export manifest",
            path: path.to_path_buf(),
            source,
        })?;
    file.write_all(&bytes).map_err(|source| ExportError::Io {
        operation: "write change export manifest",
        path: path.to_path_buf(),
        source,
    })?;
    file.sync_all().map_err(|source| ExportError::Io {
        operation: "sync change export manifest",
        path: path.to_path_buf(),
        source,
    })
}

#[derive(Debug, Error)]
pub enum ExportError {
    #[error("change export destination already exists: {0}")]
    DestinationExists(PathBuf),
    #[error("change export must be outside the source and staged workspace: {0}")]
    UnsafeDestination(PathBuf),
    #[error("unsafe path found in changed workspace: {0}")]
    UnsafeWorkspacePath(PathBuf),
    #[error("changed file was modified while being exported: {0}")]
    ConcurrentMutation(PathBuf),
    #[error("changed file {path} is {bytes} bytes, exceeding the {limit}-byte policy limit")]
    FileLimit {
        path: PathBuf,
        bytes: u64,
        limit: u64,
    },
    #[error("change export exceeds the policy limit of {0} files")]
    FileCountLimit(u64),
    #[error("change export exceeds the policy total-size limit of {0} bytes")]
    TotalSizeLimit(u64),
    #[error("failed while walking changed workspace: {0}")]
    Walk(ignore::Error),
    #[error("failed to serialize change export: {0}")]
    Serialize(serde_json::Error),
    #[error("failed to {operation} at {path}: {source}")]
    Io {
        operation: &'static str,
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
}
