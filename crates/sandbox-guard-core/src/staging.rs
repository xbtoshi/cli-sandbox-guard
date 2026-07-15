#[cfg(target_os = "linux")]
use std::ffi::CString;
#[cfg(not(target_os = "linux"))]
use std::ffi::OsStr;
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Read, Write};
#[cfg(not(target_os = "linux"))]
use std::os::fd::AsFd;
use std::os::fd::AsRawFd;
#[cfg(target_os = "linux")]
use std::os::fd::{FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::ffi::OsStringExt;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Stdio};

use ignore::WalkBuilder;
#[cfg(not(target_os = "linux"))]
use rustix::fs::{Mode, OFlags, openat};
use sha2::{Digest, Sha256};
use tempfile::{Builder as TempBuilder, TempDir};
use thiserror::Error;

use crate::audit::{AuditManifest, ExcludedPath, ExclusionReason, IncludedFile};
use crate::git::{self, GitError};
use crate::policy::{CompiledPolicy, PolicyError};

#[derive(Debug)]
pub struct StageOptions {
    pub source: PathBuf,
    pub policy: CompiledPolicy,
    pub staging_base: Option<PathBuf>,
    pub synthetic_git: bool,
}

impl StageOptions {
    pub fn new(source: impl Into<PathBuf>, policy: CompiledPolicy) -> Self {
        Self {
            source: source.into(),
            policy,
            staging_base: None,
            synthetic_git: true,
        }
    }
}

#[derive(Debug)]
pub struct Stage {
    temp: Option<TempDir>,
    _lock: File,
    workspace: PathBuf,
    audit_path: PathBuf,
    manifest: AuditManifest,
}

#[derive(Debug)]
pub struct PersistedStage {
    pub root: PathBuf,
    pub workspace: PathBuf,
    pub audit_path: PathBuf,
    pub manifest: AuditManifest,
}

impl Stage {
    pub fn build(options: StageOptions) -> Result<Self, StageError> {
        let source = fs::canonicalize(&options.source).map_err(|source_error| StageError::Io {
            operation: "canonicalize source",
            path: options.source.clone(),
            source: source_error,
        })?;
        let source_metadata = fs::metadata(&source).map_err(|source_error| StageError::Io {
            operation: "inspect source",
            path: source.clone(),
            source: source_error,
        })?;
        if !source_metadata.is_dir() {
            return Err(StageError::SourceNotDirectory(source));
        }

        let base = options.staging_base.unwrap_or_else(default_staging_base);
        fs::create_dir_all(&base).map_err(|source_error| StageError::Io {
            operation: "create staging base",
            path: base.clone(),
            source: source_error,
        })?;
        let base = fs::canonicalize(&base).map_err(|source_error| StageError::Io {
            operation: "canonicalize staging base",
            path: base.clone(),
            source: source_error,
        })?;
        if base.starts_with(&source) {
            return Err(StageError::StagingInsideSource {
                source_root: source,
                staging: base,
            });
        }
        let temp = TempBuilder::new()
            .prefix(STAGE_PREFIX)
            .tempdir_in(&base)
            .map_err(|source_error| StageError::Io {
                operation: "create private staging directory",
                path: base.clone(),
                source: source_error,
            })?;
        if temp.path().starts_with(&source) {
            return Err(StageError::StagingInsideSource {
                source_root: source,
                staging: temp.path().to_path_buf(),
            });
        }
        fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).map_err(
            |source_error| StageError::Io {
                operation: "secure staging directory",
                path: temp.path().to_path_buf(),
                source: source_error,
            },
        )?;
        let lock_path = temp.path().join(STAGE_LOCK);
        let lock = OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&lock_path)
            .map_err(|source| StageError::Io {
                operation: "create stage lock",
                path: lock_path,
                source,
            })?;
        // SAFETY: flock operates on a valid owned descriptor.
        if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            return Err(StageError::Io {
                operation: "lock stage",
                path: temp.path().join(STAGE_LOCK),
                source: std::io::Error::last_os_error(),
            });
        }

        let workspace = temp.path().join("workspace");
        fs::create_dir(&workspace).map_err(|source_error| StageError::Io {
            operation: "create staged workspace",
            path: workspace.clone(),
            source: source_error,
        })?;
        fs::set_permissions(&workspace, fs::Permissions::from_mode(0o700)).map_err(
            |source_error| StageError::Io {
                operation: "secure staged workspace",
                path: workspace.clone(),
                source: source_error,
            },
        )?;

        let source_root = File::open(&source).map_err(|source_error| StageError::Io {
            operation: "open source root",
            path: source.clone(),
            source: source_error,
        })?;
        let root_device = source_metadata.dev();
        let mut manifest = AuditManifest::new(&source, &options.policy);

        let candidates =
            collect_candidates(&source, temp.path(), options.policy.effective().max_files)?;
        for relative in &candidates {
            validate_relative_path(relative)?;
            let audit_path = display_path(relative);

            if let Some(rule) = options.policy.denied_by_path_or_ancestor(relative) {
                manifest.excluded.push(ExcludedPath {
                    path: audit_path,
                    reason: ExclusionReason::Policy {
                        rule: rule.to_owned(),
                    },
                });
                continue;
            }

            let entry_path = source.join(relative);
            let entry_metadata = match fs::symlink_metadata(&entry_path) {
                Ok(metadata) => metadata,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    manifest.excluded.push(ExcludedPath {
                        path: audit_path,
                        reason: ExclusionReason::MissingFromWorktree,
                    });
                    continue;
                }
                Err(source_error) => {
                    return Err(StageError::Io {
                        operation: "inspect candidate path",
                        path: entry_path,
                        source: source_error,
                    });
                }
            };
            let file_type = entry_metadata.file_type();
            if file_type.is_symlink() {
                manifest.excluded.push(ExcludedPath {
                    path: audit_path,
                    reason: ExclusionReason::Symlink,
                });
                continue;
            }
            if file_type.is_dir() {
                let destination = workspace.join(relative);
                fs::create_dir_all(&destination).map_err(|source_error| StageError::Io {
                    operation: "create staged directory",
                    path: destination.clone(),
                    source: source_error,
                })?;
                fs::set_permissions(&destination, fs::Permissions::from_mode(0o700)).map_err(
                    |source_error| StageError::Io {
                        operation: "secure staged directory",
                        path: destination,
                        source: source_error,
                    },
                )?;
                continue;
            }
            if !file_type.is_file() {
                manifest.excluded.push(ExcludedPath {
                    path: audit_path,
                    reason: ExclusionReason::SpecialFile,
                });
                continue;
            }

            let source_file =
                open_relative_no_links(&source_root, relative).map_err(|source_error| {
                    StageError::Io {
                        operation: "securely open source file",
                        path: source.join(relative),
                        source: source_error,
                    }
                })?;
            let before = source_file
                .metadata()
                .map_err(|source_error| StageError::Io {
                    operation: "inspect open source file",
                    path: source.join(relative),
                    source: source_error,
                })?;

            if !before.file_type().is_file() {
                manifest.excluded.push(ExcludedPath {
                    path: audit_path,
                    reason: ExclusionReason::SpecialFile,
                });
                continue;
            }
            if options.policy.effective().reject_cross_filesystem && before.dev() != root_device {
                manifest.excluded.push(ExcludedPath {
                    path: audit_path,
                    reason: ExclusionReason::CrossFilesystem,
                });
                continue;
            }
            if options.policy.effective().reject_multiple_hard_links && before.nlink() > 1 {
                manifest.excluded.push(ExcludedPath {
                    path: audit_path,
                    reason: ExclusionReason::MultipleHardLinks {
                        links: before.nlink(),
                    },
                });
                continue;
            }
            if before.len() > options.policy.effective().max_file_bytes {
                return Err(StageError::FileLimit {
                    path: relative.to_path_buf(),
                    bytes: before.len(),
                    limit: options.policy.effective().max_file_bytes,
                });
            }
            if manifest.totals.included_files >= options.policy.effective().max_files {
                return Err(StageError::FileCountLimit(
                    options.policy.effective().max_files,
                ));
            }
            let projected_total = manifest
                .totals
                .included_bytes
                .checked_add(before.len())
                .ok_or(StageError::TotalSizeLimit(
                    options.policy.effective().max_total_bytes,
                ))?;
            if projected_total > options.policy.effective().max_total_bytes {
                return Err(StageError::TotalSizeLimit(
                    options.policy.effective().max_total_bytes,
                ));
            }

            let destination = workspace.join(relative);
            let copied = copy_stable_file(
                source_file,
                &before,
                &destination,
                options.policy.effective().max_file_bytes,
            )
            .map_err(|error| match error {
                CopyError::Io(source_error) => StageError::Io {
                    operation: "copy source file",
                    path: relative.to_path_buf(),
                    source: source_error,
                },
                CopyError::Changed => StageError::ConcurrentMutation(relative.to_path_buf()),
                CopyError::Limit(bytes) => StageError::FileLimit {
                    path: relative.to_path_buf(),
                    bytes,
                    limit: options.policy.effective().max_file_bytes,
                },
            })?;

            manifest.totals.included_files += 1;
            manifest.totals.included_bytes += copied.bytes;
            manifest.included.push(IncludedFile {
                path: audit_path,
                bytes: copied.bytes,
                sha256: copied.sha256,
                executable: copied.executable,
            });
        }

        manifest
            .excluded
            .sort_by(|left, right| left.path.cmp(&right.path));
        manifest
            .included
            .sort_by(|left, right| left.path.cmp(&right.path));
        manifest.totals.excluded_paths = manifest.excluded.len() as u64;

        if options.synthetic_git {
            git::create_synthetic_repository(&workspace)?;
            manifest.synthetic_git = true;
        }

        let audit_path = temp.path().join("audit.json");
        write_audit(&audit_path, &manifest, false)?;

        Ok(Self {
            temp: Some(temp),
            _lock: lock,
            workspace,
            audit_path,
            manifest,
        })
    }

    pub fn root(&self) -> &Path {
        self.temp.as_ref().expect("stage must own a tempdir").path()
    }

    pub fn workspace(&self) -> &Path {
        &self.workspace
    }

    /// Publish a validated workspace as a new directory beside its private staging directory.
    /// The destination must not exist and must share the staging parent, making the rename atomic.
    pub fn publish_workspace(mut self, destination: &Path) -> Result<PathBuf, StageError> {
        if !destination.is_absolute() || destination.file_name().is_none() {
            return Err(StageError::UnsafePublishDestination(
                destination.to_path_buf(),
            ));
        }
        let destination_parent = destination
            .parent()
            .ok_or_else(|| StageError::UnsafePublishDestination(destination.to_path_buf()))?;
        let staging_parent = self
            .root()
            .parent()
            .ok_or_else(|| StageError::UnsafePublishDestination(destination.to_path_buf()))?;
        let destination_parent =
            fs::canonicalize(destination_parent).map_err(|source| StageError::Io {
                operation: "canonicalize publish parent",
                path: destination_parent.to_path_buf(),
                source,
            })?;
        let staging_parent = fs::canonicalize(staging_parent).map_err(|source| StageError::Io {
            operation: "canonicalize staging parent",
            path: staging_parent.to_path_buf(),
            source,
        })?;
        let destination_absent = matches!(
            fs::symlink_metadata(destination),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound
        );
        if destination_parent != staging_parent || !destination_absent {
            return Err(StageError::UnsafePublishDestination(
                destination.to_path_buf(),
            ));
        }
        let destination = destination_parent.join(
            destination
                .file_name()
                .ok_or_else(|| StageError::UnsafePublishDestination(destination.to_path_buf()))?,
        );
        fs::rename(&self.workspace, &destination).map_err(|source| StageError::Io {
            operation: "publish validated workspace",
            path: destination.clone(),
            source,
        })?;
        File::open(&destination_parent)
            .and_then(|directory| directory.sync_all())
            .map_err(|source| StageError::Io {
                operation: "sync publish parent",
                path: destination_parent,
                source,
            })?;
        drop(self.temp.take());
        Ok(destination)
    }

    pub fn audit_path(&self) -> &Path {
        &self.audit_path
    }

    pub fn manifest(&self) -> &AuditManifest {
        &self.manifest
    }

    pub fn manifest_mut(&mut self) -> &mut AuditManifest {
        &mut self.manifest
    }

    pub fn flush_audit(&self) -> Result<(), StageError> {
        write_audit(&self.audit_path, &self.manifest, false)
    }

    pub fn persist_audit(&self, destination: &Path) -> Result<(), StageError> {
        if let Some(parent) = destination.parent() {
            fs::create_dir_all(parent).map_err(|source| StageError::Io {
                operation: "create audit directory",
                path: parent.to_path_buf(),
                source,
            })?;
            let metadata = fs::symlink_metadata(parent).map_err(|source| StageError::Io {
                operation: "inspect audit directory",
                path: parent.to_path_buf(),
                source,
            })?;
            if !metadata.is_dir() || metadata.file_type().is_symlink() {
                return Err(StageError::UnsafeAuditDirectory(parent.to_path_buf()));
            }
            fs::set_permissions(parent, fs::Permissions::from_mode(0o700)).map_err(|source| {
                StageError::Io {
                    operation: "secure audit directory",
                    path: parent.to_path_buf(),
                    source,
                }
            })?;
        }
        write_audit(destination, &self.manifest, true)
    }

    pub fn keep(mut self) -> Result<PersistedStage, StageError> {
        self.flush_audit()?;
        let temp = self.temp.take().expect("stage must own a tempdir");
        let root = temp.keep();
        Ok(PersistedStage {
            root,
            workspace: self.workspace,
            audit_path: self.audit_path,
            manifest: self.manifest,
        })
    }
}

fn collect_candidates(
    source: &Path,
    safe_home: &Path,
    max_candidates: u64,
) -> Result<Vec<PathBuf>, StageError> {
    let git_marker = source.join(".git");
    let is_git_root = fs::symlink_metadata(&git_marker)
        .map(|metadata| !metadata.file_type().is_symlink())
        .unwrap_or(false);
    if is_git_root {
        return collect_git_candidates(source, safe_home, max_candidates);
    }

    let mut builder = WalkBuilder::new(source);
    builder
        .hidden(false)
        .follow_links(false)
        .parents(false)
        .git_ignore(true)
        .git_global(false)
        .git_exclude(true)
        .ignore(true)
        .require_git(false)
        .sort_by_file_path(|left, right| left.cmp(right));

    let mut candidates = Vec::new();
    for result in builder.build() {
        let entry = result.map_err(StageError::Walk)?;
        if entry.path() == source {
            continue;
        }
        let relative = entry
            .path()
            .strip_prefix(source)
            .map_err(|_| StageError::UnsafeRelativePath(entry.path().to_path_buf()))?;
        if candidates.len() as u64 >= max_candidates {
            return Err(StageError::FileCountLimit(max_candidates));
        }
        candidates.push(relative.to_path_buf());
    }
    Ok(candidates)
}

fn collect_git_candidates(
    source: &Path,
    safe_home: &Path,
    max_candidates: u64,
) -> Result<Vec<PathBuf>, StageError> {
    let git = which::which("git").map_err(|error| StageError::GitCandidates(error.to_string()))?;
    let output = Command::new(&git)
        .args([
            "-c",
            "core.fsmonitor=false",
            "-c",
            "core.untrackedCache=false",
            "-c",
            "core.hooksPath=/dev/null",
            "-c",
            "core.attributesFile=/dev/null",
            "-c",
            "core.excludesFile=/dev/null",
            "-C",
        ])
        .arg(source)
        .args([
            "ls-files",
            "--cached",
            "--others",
            "--exclude-standard",
            "-z",
            "--",
            ".",
        ])
        .env_clear()
        .env("HOME", safe_home)
        .env("XDG_CONFIG_HOME", safe_home)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_OPTIONAL_LOCKS", "0")
        .env("LANG", "C")
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|error| StageError::GitCandidates(error.to_string()))?;
    let mut child = output;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| StageError::GitCandidates("git stdout was not captured".to_owned()))?;
    let mut candidates = Vec::new();
    let mut reader = BufReader::new(stdout);
    loop {
        let mut bytes = Vec::new();
        let read = reader
            .read_until(0, &mut bytes)
            .map_err(|error| StageError::GitCandidates(error.to_string()))?;
        if read == 0 {
            break;
        }
        if bytes.last() == Some(&0) {
            bytes.pop();
        }
        if bytes.is_empty() {
            continue;
        }
        if bytes.len() > 1024 * 1024 {
            let _ = child.kill();
            let _ = child.wait();
            return Err(StageError::CandidatePathTooLong(bytes.len()));
        }
        if candidates.len() as u64 >= max_candidates {
            let _ = child.kill();
            let _ = child.wait();
            return Err(StageError::FileCountLimit(max_candidates));
        }
        candidates.push(PathBuf::from(std::ffi::OsString::from_vec(bytes)));
    }
    let status = child
        .wait()
        .map_err(|error| StageError::GitCandidates(error.to_string()))?;
    if !status.success() {
        return Err(StageError::GitCandidates(format!(
            "git ls-files exited with {status}"
        )));
    }
    candidates.sort();
    candidates.dedup();
    Ok(candidates)
}

fn write_audit(path: &Path, manifest: &AuditManifest, create_new: bool) -> Result<(), StageError> {
    let bytes = serde_json::to_vec_pretty(manifest).map_err(StageError::SerializeAudit)?;
    let mut options = OpenOptions::new();
    options
        .create(!create_new)
        .create_new(create_new)
        .truncate(!create_new)
        .write(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW);
    let mut output = options.open(path).map_err(|source| StageError::Io {
        operation: "open audit manifest",
        path: path.to_path_buf(),
        source,
    })?;
    output.write_all(&bytes).map_err(|source| StageError::Io {
        operation: "write audit manifest",
        path: path.to_path_buf(),
        source,
    })?;
    output.sync_all().map_err(|source| StageError::Io {
        operation: "sync audit manifest",
        path: path.to_path_buf(),
        source,
    })?;
    Ok(())
}

fn validate_relative_path(path: &Path) -> Result<(), StageError> {
    if !is_valid_candidate_path(path) {
        return Err(StageError::UnsafeRelativePath(path.to_path_buf()));
    }
    Ok(())
}

pub fn is_valid_candidate_path(path: &Path) -> bool {
    !path.as_os_str().is_empty()
        && path
            .components()
            .all(|component| matches!(component, Component::Normal(_)))
}

#[cfg(target_os = "linux")]
pub(crate) fn open_relative_no_links(root: &File, relative: &Path) -> std::io::Result<File> {
    #[repr(C)]
    struct OpenHow {
        flags: u64,
        mode: u64,
        resolve: u64,
    }

    const RESOLVE_NO_XDEV: u64 = 0x01;
    const RESOLVE_NO_MAGICLINKS: u64 = 0x02;
    const RESOLVE_NO_SYMLINKS: u64 = 0x04;
    const RESOLVE_BENEATH: u64 = 0x08;

    let path = CString::new(relative.as_os_str().as_bytes()).map_err(|_| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, "path contains a NUL byte")
    })?;
    let how = OpenHow {
        flags: (libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK) as u64,
        mode: 0,
        resolve: RESOLVE_NO_XDEV | RESOLVE_NO_MAGICLINKS | RESOLVE_NO_SYMLINKS | RESOLVE_BENEATH,
    };
    // SAFETY: `path` is NUL terminated, `how` has the kernel's open_how layout, and a successful
    // syscall returns a newly owned descriptor.
    let descriptor = unsafe {
        libc::syscall(
            libc::SYS_openat2,
            root.as_raw_fd(),
            path.as_ptr(),
            &how,
            std::mem::size_of::<OpenHow>(),
        )
    };
    if descriptor < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: the successful openat2 call transferred ownership of this descriptor to us.
    let descriptor = unsafe { OwnedFd::from_raw_fd(descriptor as i32) };
    Ok(File::from(descriptor))
}

#[cfg(not(target_os = "linux"))]
pub(crate) fn open_relative_no_links(root: &File, relative: &Path) -> std::io::Result<File> {
    let components: Vec<&OsStr> = relative
        .components()
        .map(|component| match component {
            Component::Normal(value) => Ok(value),
            _ => Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "path is not relative",
            )),
        })
        .collect::<Result<_, _>>()?;
    let (leaf, parents) = components
        .split_last()
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidInput, "empty path"))?;

    let mut directory = rustix::io::dup(root.as_fd()).map_err(std::io::Error::from)?;
    for component in parents {
        directory = openat(
            &directory,
            *component,
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::DIRECTORY,
            Mode::empty(),
        )
        .map_err(std::io::Error::from)?;
    }
    let descriptor = openat(
        &directory,
        *leaf,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
        Mode::empty(),
    )
    .map_err(std::io::Error::from)?;
    Ok(File::from(descriptor))
}

pub(crate) struct CopiedFile {
    pub(crate) bytes: u64,
    pub(crate) sha256: String,
    pub(crate) executable: bool,
}

pub(crate) enum CopyError {
    Io(std::io::Error),
    Changed,
    Limit(u64),
}

pub(crate) fn copy_stable_file(
    mut source: File,
    before: &fs::Metadata,
    destination: &Path,
    max_bytes: u64,
) -> Result<CopiedFile, CopyError> {
    if let Some(parent) = destination.parent() {
        fs::create_dir_all(parent).map_err(CopyError::Io)?;
    }
    let executable = before.mode() & 0o111 != 0;
    let destination_mode = if executable { 0o700 } else { 0o600 };
    let mut output = OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(destination_mode)
        .open(destination)
        .map_err(CopyError::Io)?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0_u8; 128 * 1024];
    let mut copied = 0_u64;

    loop {
        let read = source.read(&mut buffer).map_err(CopyError::Io)?;
        if read == 0 {
            break;
        }
        copied = copied
            .checked_add(read as u64)
            .ok_or(CopyError::Limit(u64::MAX))?;
        if copied > max_bytes {
            let _ = fs::remove_file(destination);
            return Err(CopyError::Limit(copied));
        }
        hasher.update(&buffer[..read]);
        output.write_all(&buffer[..read]).map_err(CopyError::Io)?;
    }
    output.sync_all().map_err(CopyError::Io)?;

    let after = source.metadata().map_err(CopyError::Io)?;
    let unchanged = before.dev() == after.dev()
        && before.ino() == after.ino()
        && before.len() == after.len()
        && before.mtime() == after.mtime()
        && before.mtime_nsec() == after.mtime_nsec()
        && before.ctime() == after.ctime()
        && before.ctime_nsec() == after.ctime_nsec()
        && copied == before.len();
    if !unchanged {
        drop(output);
        let _ = fs::remove_file(destination);
        return Err(CopyError::Changed);
    }

    Ok(CopiedFile {
        bytes: copied,
        sha256: hex::encode(hasher.finalize()),
        executable,
    })
}

pub const STAGE_PREFIX: &str = "sandbox-guard-";
pub const STAGE_LOCK: &str = ".lock";

pub fn default_staging_base() -> PathBuf {
    #[cfg(target_os = "linux")]
    {
        let shared_memory = PathBuf::from("/dev/shm");
        if shared_memory.is_dir() {
            return shared_memory;
        }
    }
    std::env::temp_dir()
}

/// Encode non-portable path bytes so audit entries remain unambiguous and JSON-safe.
pub fn display_path(path: &Path) -> String {
    let mut output = String::new();
    for &byte in path.as_os_str().as_bytes() {
        if byte == b'/' || (byte.is_ascii_graphic() && byte != b'%') || byte == b' ' {
            output.push(byte as char);
        } else {
            output.push('%');
            output.push_str(&format!("{byte:02X}"));
        }
    }
    output
}

#[derive(Debug, Error)]
pub enum StageError {
    #[error("source is not a directory: {0}")]
    SourceNotDirectory(PathBuf),
    #[error("validated workspace publish destination is unsafe or already exists: {0}")]
    UnsafePublishDestination(PathBuf),
    #[error("staging directory {staging} must not be inside source tree {source_root}")]
    StagingInsideSource {
        source_root: PathBuf,
        staging: PathBuf,
    },
    #[error("unsafe relative path encountered: {0}")]
    UnsafeRelativePath(PathBuf),
    #[error("could not determine file type for {0}")]
    UnknownFileType(PathBuf),
    #[error("candidate path is unreasonably long ({0} bytes)")]
    CandidatePathTooLong(usize),
    #[error("audit directory is not a real directory: {0}")]
    UnsafeAuditDirectory(PathBuf),
    #[error("source file changed while it was being staged: {0}")]
    ConcurrentMutation(PathBuf),
    #[error("file {path} is {bytes} bytes, exceeding the {limit}-byte policy limit")]
    FileLimit {
        path: PathBuf,
        bytes: u64,
        limit: u64,
    },
    #[error("staging exceeds the policy limit of {0} files")]
    FileCountLimit(u64),
    #[error("staging exceeds the policy total-size limit of {0} bytes")]
    TotalSizeLimit(u64),
    #[error("failed to {operation} at {path}: {source}")]
    Io {
        operation: &'static str,
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("failed while walking source: {0}")]
    Walk(ignore::Error),
    #[error("failed to enumerate Git worktree candidates: {0}")]
    GitCandidates(String),
    #[error("failed to create synthetic git repository: {0}")]
    Git(#[from] GitError),
    #[error("failed to serialize audit manifest: {0}")]
    SerializeAudit(serde_json::Error),
    #[error(transparent)]
    Policy(#[from] PolicyError),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::UserPolicy;

    #[test]
    fn display_path_percent_encodes_ambiguous_bytes() {
        assert_eq!(
            display_path(Path::new("hello world/%name\n")),
            "hello world/%25name%0A"
        );
    }

    #[test]
    fn stable_copy_rejects_a_file_changed_after_inspection() {
        let fixture = tempfile::tempdir().unwrap();
        let source_path = fixture.path().join("source");
        let destination = fixture.path().join("destination");
        fs::write(&source_path, b"before").unwrap();
        let source = File::open(&source_path).unwrap();
        let before = source.metadata().unwrap();
        fs::write(&source_path, b"after and longer").unwrap();

        assert!(matches!(
            copy_stable_file(source, &before, &destination, 1024),
            Err(CopyError::Changed)
        ));
        assert!(!destination.exists());
    }

    #[test]
    fn secure_open_rejects_a_symlinked_parent() {
        let fixture = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        fs::write(outside.path().join("secret"), "secret").unwrap();
        std::os::unix::fs::symlink(outside.path(), fixture.path().join("link")).unwrap();
        let root = File::open(fixture.path()).unwrap();

        assert!(open_relative_no_links(&root, Path::new("link/secret")).is_err());
    }

    #[test]
    fn validated_workspace_publishes_atomically_only_beside_its_stage() {
        let source = tempfile::tempdir().unwrap();
        fs::write(source.path().join("summary.json"), b"{}\n").unwrap();
        let staging = tempfile::tempdir().unwrap();
        let mut options = StageOptions::new(
            source.path(),
            CompiledPolicy::with_user_policy(UserPolicy::default()).unwrap(),
        );
        options.synthetic_git = false;
        options.staging_base = Some(staging.path().to_path_buf());
        let stage = Stage::build(options).unwrap();
        let destination = staging.path().join("published");

        let published = stage.publish_workspace(&destination).unwrap();
        assert_eq!(published, fs::canonicalize(&destination).unwrap());
        assert_eq!(fs::read(destination.join("summary.json")).unwrap(), b"{}\n");
    }

    #[test]
    fn validated_workspace_refuses_existing_or_unrelated_publish_destinations() {
        let source = tempfile::tempdir().unwrap();
        fs::write(source.path().join("summary.json"), b"{}\n").unwrap();
        let staging = tempfile::tempdir().unwrap();
        let unrelated = tempfile::tempdir().unwrap();

        let build = || {
            let mut options = StageOptions::new(
                source.path(),
                CompiledPolicy::with_user_policy(UserPolicy::default()).unwrap(),
            );
            options.synthetic_git = false;
            options.staging_base = Some(staging.path().to_path_buf());
            Stage::build(options).unwrap()
        };
        let existing = staging.path().join("existing");
        fs::create_dir(&existing).unwrap();
        assert!(matches!(
            build().publish_workspace(&existing),
            Err(StageError::UnsafePublishDestination(_))
        ));
        assert!(matches!(
            build().publish_workspace(&unrelated.path().join("published")),
            Err(StageError::UnsafePublishDestination(_))
        ));
    }
}
