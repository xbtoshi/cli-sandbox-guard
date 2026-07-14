use std::fs::{self, File, OpenOptions};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use thiserror::Error;

use crate::staging::{STAGE_LOCK, STAGE_PREFIX};

#[derive(Debug, Default)]
pub struct GcReport {
    pub removed: Vec<PathBuf>,
    pub would_remove: Vec<PathBuf>,
    pub active: Vec<PathBuf>,
    pub recent: Vec<PathBuf>,
}

pub fn garbage_collect(
    staging_base: &Path,
    older_than: Duration,
    dry_run: bool,
) -> Result<GcReport, GcError> {
    let mut report = GcReport::default();
    let staging_base = match fs::canonicalize(staging_base) {
        Ok(path) => path,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(report),
        Err(source) => {
            return Err(GcError::Io {
                operation: "canonicalize staging base",
                path: staging_base.to_path_buf(),
                source,
            });
        }
    };
    let entries = match fs::read_dir(&staging_base) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(report),
        Err(source) => {
            return Err(GcError::Io {
                operation: "read staging base",
                path: staging_base.clone(),
                source,
            });
        }
    };
    // SAFETY: geteuid has no preconditions.
    let effective_uid = unsafe { libc::geteuid() };

    for entry in entries {
        let entry = entry.map_err(|source| GcError::Io {
            operation: "read staging entry",
            path: staging_base.clone(),
            source,
        })?;
        let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        if !name.starts_with(STAGE_PREFIX) {
            continue;
        }
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path).map_err(|source| GcError::Io {
            operation: "inspect staging entry",
            path: path.clone(),
            source,
        })?;
        if !metadata.is_dir()
            || metadata.file_type().is_symlink()
            || metadata.uid() != effective_uid
        {
            continue;
        }
        let modified = metadata.modified().unwrap_or(SystemTime::UNIX_EPOCH);
        let age = SystemTime::now()
            .duration_since(modified)
            .unwrap_or(Duration::ZERO);
        if age < older_than {
            report.recent.push(path);
            continue;
        }

        let _lock = match try_lock(&path.join(STAGE_LOCK))? {
            LockState::Active => {
                report.active.push(path);
                continue;
            }
            LockState::Acquired(lock) => Some(lock),
            LockState::Missing => None,
        };
        if dry_run {
            report.would_remove.push(path);
        } else {
            fs::remove_dir_all(&path).map_err(|source| GcError::Io {
                operation: "remove orphaned stage",
                path: path.clone(),
                source,
            })?;
            report.removed.push(path);
        }
    }

    Ok(report)
}

enum LockState {
    Acquired(File),
    Active,
    Missing,
}

fn try_lock(path: &Path) -> Result<LockState, GcError> {
    let lock = match OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
    {
        Ok(lock) => lock,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(LockState::Missing);
        }
        Err(source) => {
            return Err(GcError::Io {
                operation: "open stage lock",
                path: path.to_path_buf(),
                source,
            });
        }
    };
    // SAFETY: flock operates on a valid owned descriptor and does not retain the pointer.
    let result = unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
    if result == 0 {
        return Ok(LockState::Acquired(lock));
    }
    let error = std::io::Error::last_os_error();
    if error
        .raw_os_error()
        .is_some_and(|code| code == libc::EWOULDBLOCK || code == libc::EAGAIN)
    {
        Ok(LockState::Active)
    } else {
        Err(GcError::Io {
            operation: "lock stage",
            path: path.to_path_buf(),
            source: error,
        })
    }
}

#[derive(Debug, Error)]
pub enum GcError {
    #[error("failed to {operation} at {path}: {source}")]
    Io {
        operation: &'static str,
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
}
