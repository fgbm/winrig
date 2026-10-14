//! Private files and directories: directory `0700`, file `0600` on Unix (ADR-0009).
//!
//! A shared helper for the logs (`src/logging.rs`), the profile directories
//! (`src/paths.rs`) and the profile file itself (`src/profile.rs`): the modes are
//! reapplied on every open, otherwise a new copy after rotation or rewrite would
//! get the process modes. On platforms without `cfg(unix)`, the OS defaults
//! provide the privacy.

use std::fs::{self, File, OpenOptions};
use std::io;
use std::path::Path;

#[cfg(unix)]
const DIR_MODE: u32 = 0o700;
#[cfg(unix)]
const FILE_MODE: u32 = 0o600;

/// Expected mode for private data on this platform; a wider mode warns but does not refuse (AC-PRF-25).
#[cfg(unix)]
pub const EXPECTED_FILE_MODE: u32 = FILE_MODE;

/// Makes a directory and sets the `0700` mode on Unix.
///
/// # Errors
///
/// An I/O error if the directory cannot be created.
pub fn create_private_dir(path: &Path) -> io::Result<()> {
    fs::create_dir_all(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(path, fs::Permissions::from_mode(DIR_MODE));
    }
    Ok(())
}

/// Makes a `0700` directory only when it does not exist yet.
///
/// An existing directory is left untouched: it may belong to another tool (for
/// example `~/.config/opencode`), and its mode must not change.
///
/// # Errors
///
/// An I/O error if the directory cannot be created.
pub fn ensure_private_dir(path: &Path) -> io::Result<()> {
    if path.is_dir() {
        return Ok(());
    }
    create_private_dir(path)
}

/// Opens a file for append, creating it with the `0600` mode.
///
/// # Errors
///
/// I/O error if the file cannot be opened.
pub fn open_private_append(path: &Path) -> io::Result<(File, u64)> {
    ensure_parent(path)?;
    let file = OpenOptions::new().create(true).append(true).open(path)?;
    apply_private_file_mode(path);
    let written = file.metadata().map(|meta| meta.len()).unwrap_or(0);
    Ok((file, written))
}

/// Opens a file for write with truncation, creating it with the `0600` mode.
///
/// # Errors
///
/// I/O error if the file cannot be opened.
pub fn open_private_truncate(path: &Path) -> io::Result<File> {
    ensure_parent(path)?;
    let file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(path)?;
    apply_private_file_mode(path);
    Ok(file)
}

/// Makes the parent directory with private modes, leaving an existing directory
/// untouched.
fn ensure_parent(path: &Path) -> io::Result<()> {
    match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => ensure_private_dir(parent),
        _ => Ok(()),
    }
}

/// Applies the `0600` mode to a file.
pub fn apply_private_file_mode(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(path, fs::Permissions::from_mode(FILE_MODE));
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
}

/// The file mode when it is wider than `0600`, or `None` when the check is not
/// possible.
///
/// On Unix it is the actual mode when it differs from `0600`; on other platforms
/// it is always `None`.
#[must_use]
pub fn loose_file_mode(path: &Path) -> Option<u32> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(path).ok()?.permissions().mode() & 0o777;
        if mode != FILE_MODE { Some(mode) } else { None }
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        None
    }
}

// The tests exercise the Unix modes, so they exist only where the modes do.
#[cfg(all(test, unix))]
mod tests {
    use super::*;

    fn temp_dir(name: &str) -> std::path::PathBuf {
        let dir =
            std::env::temp_dir().join(format!("winrig-private-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        dir
    }

    #[cfg(unix)]
    #[test]
    fn created_files_and_dirs_are_private() {
        use std::os::unix::fs::PermissionsExt;
        let dir = temp_dir("modes");
        let path = dir.join("secret");
        let _file = open_private_truncate(&path).expect("open");
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(
            fs::metadata(&dir).unwrap().permissions().mode() & 0o777,
            0o700
        );
        fs::remove_dir_all(&dir).ok();
    }

    #[cfg(unix)]
    #[test]
    fn loose_mode_is_detected() {
        use std::os::unix::fs::PermissionsExt;
        let dir = temp_dir("loose");
        let path = dir.join("secret");
        let _file = open_private_truncate(&path).expect("open");
        assert_eq!(loose_file_mode(&path), None);
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).expect("chmod");
        assert_eq!(loose_file_mode(&path), Some(0o644));
        fs::remove_dir_all(&dir).ok();
    }
}
