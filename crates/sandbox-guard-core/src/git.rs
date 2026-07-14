use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use thiserror::Error;

pub(crate) fn create_synthetic_repository(workspace: &Path) -> Result<(), GitError> {
    let git = which::which("git").map_err(GitError::GitNotFound)?;
    let template = workspace
        .parent()
        .expect("workspace always has a staging parent")
        .join("git-template");
    fs::create_dir(&template).map_err(|source| GitError::Io {
        path: template,
        source,
    })?;

    run_git(
        &git,
        workspace,
        &["init", "--quiet", "--initial-branch=guard-baseline"],
    )?;

    let info = workspace.join(".git/info");
    fs::create_dir_all(&info).map_err(|source| GitError::Io {
        path: info.clone(),
        source,
    })?;
    let attributes = info.join("attributes");
    fs::write(
        &attributes,
        "* -text -filter -diff -merge -working-tree-encoding\n",
    )
    .map_err(|source| GitError::Io {
        path: attributes,
        source,
    })?;

    // Force-add is required because a file may be tracked in the original repository even though
    // the current .gitignore matches it. Every file admitted by the stager belongs in the baseline.
    run_git(&git, workspace, &["add", "--force", "--all", "--", "."])?;
    run_git(
        &git,
        workspace,
        &[
            "-c",
            "user.name=Sandbox Guard",
            "-c",
            "user.email=guard@invalid.local",
            "-c",
            "commit.gpgSign=false",
            "commit",
            "--quiet",
            "--no-gpg-sign",
            "--no-verify",
            "--allow-empty",
            "-m",
            "Sanitized baseline",
        ],
    )?;

    Ok(())
}

fn run_git(git: &Path, workspace: &Path, args: &[&str]) -> Result<(), GitError> {
    let isolated_home = workspace
        .parent()
        .expect("workspace always has a staging parent")
        .join("git-home");
    let isolated_template = workspace
        .parent()
        .expect("workspace always has a staging parent")
        .join("git-template");
    let output = Command::new(git)
        .args(args)
        .current_dir(workspace)
        .env_clear()
        .env("HOME", &isolated_home)
        .env("XDG_CONFIG_HOME", &isolated_home)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_TEMPLATE_DIR", isolated_template)
        .env("GIT_AUTHOR_DATE", "2000-01-01T00:00:00Z")
        .env("GIT_COMMITTER_DATE", "2000-01-01T00:00:00Z")
        .env("LANG", "C")
        .output()
        .map_err(|source| GitError::Execute {
            git: git.to_path_buf(),
            source,
        })?;

    if output.status.success() {
        Ok(())
    } else {
        Err(GitError::Failed {
            args: args.iter().map(|arg| (*arg).to_owned()).collect(),
            output: Box::new(output),
        })
    }
}

#[derive(Debug, Error)]
pub enum GitError {
    #[error("git was not found: {0}")]
    GitNotFound(which::Error),
    #[error("failed to execute git at {git}: {source}")]
    Execute {
        git: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error(
        "git {args:?} failed with {status}: {stderr}",
        status = .output.status,
        stderr = String::from_utf8_lossy(&.output.stderr).trim()
    )]
    Failed {
        args: Vec<String>,
        output: Box<Output>,
    },
    #[error("failed to prepare synthetic git metadata at {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
}
