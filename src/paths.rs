//! Profile and state directories, profile selection and the process lock (ADR-0009).
//!
//! The profile directory comes from `AppDirs::config_dir` and `WINRIG_PROFILE_DIR`
//! overrides it; the state directory comes from `AppDirs::state_dir`, which follows
//! `XDG_STATE_HOME` on Linux and equals the local data directory on macOS and
//! Windows (those systems have no separate state). One profile per process: a
//! second process on the same profile is refused by the lock file.

use std::fs::{self, File, OpenOptions};
use std::path::{Path, PathBuf};

use platform_dirs::AppDirs;

use crate::config::Env;

/// Environment variable that overrides the profile directory.
pub const PROFILE_DIR_ENV: &str = "WINRIG_PROFILE_DIR";
/// Environment variable that overrides the state directory.
pub const STATE_DIR_ENV: &str = "WINRIG_STATE_DIR";
pub const PROFILE_EXTENSION: &str = "json";
/// Name of the process lock in the profile state directory.
pub const LOCK_FILE: &str = "process.lock";

#[cfg(unix)]
const DIR_MODE: u32 = 0o700;

/// Error when resolving the profile and state directories.
#[derive(Debug)]
pub enum PathError {
    /// The home directory is unavailable and the override variable is not set.
    NoHome {
        /// The override that sets the directory explicitly.
        variable: &'static str,
    },
    /// Cannot create or open the directory.
    Io {
        /// File the error occurred on.
        path: PathBuf,
        /// Underlying cause.
        source: std::io::Error,
    },
    /// The name violates a path character restriction.
    InvalidName {
        /// Value that was rejected.
        name: String,
        /// Which restriction was violated.
        reason: &'static str,
    },
    /// The requested profile is absent from the profile directory.
    NotFound {
        /// Requested profile.
        name: String,
        /// Directory that was searched.
        dir: PathBuf,
    },
    /// Several profiles exist and no name is given.
    Ambiguous {
        /// Profiles that were found.
        names: Vec<String>,
    },
    /// The profile is already held by another process.
    Locked {
        /// Lock file location.
        path: PathBuf,
    },
}

impl std::fmt::Display for PathError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoHome { variable } => write!(
                f,
                "cannot determine the home directory; set {variable} to the profile directory explicitly"
            ),
            Self::Io { path, source } => {
                write!(f, "cannot use {}: {source}", path.display())
            }
            Self::InvalidName { name, reason } => {
                write!(f, "invalid profile name {name:?}: {reason}")
            }
            Self::NotFound { name, dir } => {
                write!(f, "profile {name:?} not found in {}", dir.display())
            }
            Self::Ambiguous { names } => write!(
                f,
                "several profiles exist ({}); pass the profile name explicitly",
                names.join(", ")
            ),
            Self::Locked { path } => write!(
                f,
                "profile is already in use by another process (lock file {}); \
                 use the HTTP mode (winrig serve) to serve several projects at once",
                path.display()
            ),
        }
    }
}

impl std::error::Error for PathError {}

/// Ensures a profile name is usable as a file name.
///
/// # Errors
///
/// [`PathError::InvalidName`] if the name is empty, all dots, or contains a path
/// separator or a control character.
pub fn validate_profile_name(name: &str) -> Result<(), PathError> {
    let invalid = |reason: &'static str| PathError::InvalidName {
        name: name.to_owned(),
        reason,
    };
    if name.is_empty() {
        return Err(invalid("the name is empty"));
    }
    if name == "." || name == ".." {
        return Err(invalid("the name is a path traversal element"));
    }
    if name.starts_with('.') {
        return Err(invalid("the name starts with a dot"));
    }
    if name.contains('/') || name.contains('\\') {
        return Err(invalid("the name contains a path separator"));
    }
    if name.chars().any(char::is_control) {
        return Err(invalid("the name contains a control character"));
    }
    if name.contains(':') {
        return Err(invalid("the name contains a drive separator"));
    }
    Ok(())
}

/// Profile and state directories.
#[derive(Debug, Clone)]
pub struct Locations {
    profile_dir: PathBuf,
    state_root: PathBuf,
}

impl Locations {
    /// Resolves the directories from the environment and the OS defaults.
    ///
    /// # Errors
    ///
    /// [`PathError::NoHome`] if the OS paths are unavailable and no profile
    /// directory is set explicitly; [`PathError::Io`] on a creation error.
    pub fn resolve(env: &Env) -> Result<Self, PathError> {
        let profile_dir = match env(PROFILE_DIR_ENV)
            .map(|value| value.trim().to_owned())
            .filter(|value| !value.is_empty())
        {
            Some(dir) => PathBuf::from(dir),
            None => {
                let dirs = AppDirs::new(Some("winrig"), false).ok_or(PathError::NoHome {
                    variable: PROFILE_DIR_ENV,
                })?;
                dirs.config_dir
            }
        };
        let state_root = match env(STATE_DIR_ENV)
            .map(|value| value.trim().to_owned())
            .filter(|value| !value.is_empty())
        {
            Some(dir) => PathBuf::from(dir),
            None => match AppDirs::new(Some("winrig"), false) {
                Some(dirs) => dirs.state_dir,
                None => profile_dir.clone(),
            },
        };
        Ok(Self {
            profile_dir,
            state_root,
        })
    }

    /// Makes the directories with private modes.
    ///
    /// # Errors
    ///
    /// [`PathError::Io`] if a directory cannot be created.
    pub fn ensure(&self) -> Result<(), PathError> {
        create_private_dir(&self.profile_dir)?;
        create_private_dir(&self.state_root)?;
        Ok(())
    }

    /// Where the profiles are stored.
    #[must_use]
    pub fn profile_dir(&self) -> &Path {
        &self.profile_dir
    }

    /// Location of the profile file for a name.
    #[must_use]
    pub fn profile_path(&self, name: &str) -> PathBuf {
        self.profile_dir.join(format!("{name}.{PROFILE_EXTENSION}"))
    }

    /// Stored names, sorted.
    #[must_use]
    pub fn profile_names(&self) -> Vec<String> {
        let mut names = Vec::new();
        let Ok(entries) = fs::read_dir(&self.profile_dir) else {
            return names;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|value| value.to_str()) != Some(PROFILE_EXTENSION) {
                continue;
            }
            if let Some(stem) = path.file_stem().and_then(|value| value.to_str()) {
                names.push(stem.to_owned());
            }
        }
        names.sort();
        names
    }

    /// Chooses the profile name: the explicit one, or the only available one.
    ///
    /// # Errors
    ///
    /// [`PathError::NotFound`], [`PathError::Ambiguous`] or
    /// [`PathError::InvalidName`].
    pub fn select(&self, requested: Option<&str>) -> Result<String, PathError> {
        if let Some(name) = requested {
            let name = name.trim();
            validate_profile_name(name)?;
            if !self.profile_path(name).is_file() {
                return Err(PathError::NotFound {
                    name: name.to_owned(),
                    dir: self.profile_dir.clone(),
                });
            }
            return Ok(name.to_owned());
        }
        let names = self.profile_names();
        match names.as_slice() {
            [] => Err(PathError::NotFound {
                name: "(default)".to_owned(),
                dir: self.profile_dir.clone(),
            }),
            [only] => Ok(only.clone()),
            many => Err(PathError::Ambiguous {
                names: many.to_vec(),
            }),
        }
    }

    /// State directory of the selected profile, created on call.
    ///
    /// # Errors
    ///
    /// [`PathError::Io`] if the directory cannot be created.
    pub fn state_dir_for(&self, profile: &str) -> Result<PathBuf, PathError> {
        let dir = self.state_root.join(profile);
        create_private_dir(&dir)?;
        Ok(dir)
    }

    /// The state directory the profile name is appended to exactly once, by
    /// [`Self::state_dir_for`] (TR-PRF-15).
    #[must_use]
    pub fn state_root(&self) -> &Path {
        &self.state_root
    }

    /// State directory without a profile (HTTP with the shared secret only).
    ///
    /// # Errors
    ///
    /// [`PathError::Io`] if the directory cannot be created.
    pub fn state_dir_default(&self) -> Result<PathBuf, PathError> {
        let dir = self.state_root.join("http");
        create_private_dir(&dir)?;
        Ok(dir)
    }
}

/// Holds one profile exclusively for the life of the process.
///
/// The OS releases it when the file closes, so a crash leaves no lock (AC-PRF-55).
#[derive(Debug)]
pub struct ProcessLock {
    file: File,
    path: PathBuf,
}

impl ProcessLock {
    /// Takes the profile lock or refuses when another process holds it.
    ///
    /// # Errors
    ///
    /// [`PathError::Locked`] if another process holds the lock; [`PathError::Io`]
    /// on a file access error.
    pub fn acquire(dir: &Path) -> Result<Self, PathError> {
        create_private_dir(dir)?;
        let path = dir.join(LOCK_FILE);
        let file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(false)
            .open(&path)
            .map_err(|source| PathError::Io {
                path: path.clone(),
                source,
            })?;
        match file.try_lock() {
            Ok(()) => Ok(Self { file, path }),
            Err(std::fs::TryLockError::WouldBlock) => Err(PathError::Locked { path }),
            Err(std::fs::TryLockError::Error(source)) => Err(PathError::Io { path, source }),
        }
    }

    /// Lock file location.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for ProcessLock {
    fn drop(&mut self) {
        let _ = self.file.unlock();
    }
}

/// Makes the directory and applies private modes on Unix.
fn create_private_dir(path: &Path) -> Result<(), PathError> {
    fs::create_dir_all(path).map_err(|source| PathError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(path, fs::Permissions::from_mode(DIR_MODE));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn source(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> + use<> {
        let map: BTreeMap<String, String> = pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect();
        move |name: &str| map.get(name).cloned()
    }

    fn temp_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "winrig-paths-{name}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = fs::remove_dir_all(&dir);
        dir
    }

    fn locations(dir: &Path) -> Locations {
        let dir = dir.to_string_lossy().into_owned();
        Locations::resolve(&source(&[(PROFILE_DIR_ENV, &dir)])).expect("locations")
    }

    /// AC-PRF-27: path characters in a profile name are rejected.
    #[test]
    fn invalid_profile_names_are_rejected() {
        for name in ["", ".", "..", "../x", "a/b", "a\\b", ".hidden", "C:name"] {
            assert!(
                validate_profile_name(name).is_err(),
                "{name:?} must be rejected"
            );
        }
        for name in ["corp", "domain-user", "Домен1"] {
            assert!(validate_profile_name(name).is_ok(), "{name:?} must pass");
        }
    }

    /// AC-PRF-27: no file outside the profile directory is created.
    #[test]
    fn path_traversal_creates_nothing() {
        let base = temp_dir("traversal");
        let loc = locations(&base);
        loc.ensure().expect("ensure");
        let escape = base.parent().unwrap().join("winrig-escape");
        let _ = fs::remove_dir_all(&escape);
        for name in ["../winrig-escape", "..\\winrig-escape"] {
            assert!(validate_profile_name(name).is_err());
        }
        assert!(!escape.exists());
        fs::remove_dir_all(&base).ok();
    }

    /// AC-PRF-20: several profiles without a name are refused.
    #[test]
    fn ambiguous_selection_is_rejected() {
        let base = temp_dir("ambiguous");
        let loc = locations(&base);
        loc.ensure().expect("ensure");
        fs::write(loc.profile_path("one"), b"{}").expect("write");
        fs::write(loc.profile_path("two"), b"{}").expect("write");
        match loc.select(None) {
            Err(PathError::Ambiguous { names }) => assert_eq!(names, ["one", "two"]),
            other => panic!("expected ambiguous, got {other:?}"),
        }
        assert_eq!(loc.select(Some("two")).expect("explicit"), "two");
        fs::remove_dir_all(&base).ok();
    }

    /// AC-PRF-04: the only profile is chosen without a name.
    #[test]
    fn single_profile_is_default() {
        let base = temp_dir("single");
        let loc = locations(&base);
        loc.ensure().expect("ensure");
        fs::write(loc.profile_path("only"), b"{}").expect("write");
        assert_eq!(loc.select(None).expect("default"), "only");
        fs::remove_dir_all(&base).ok();
    }

    /// AC-PRF-43: the profile is not found.
    #[test]
    fn missing_profile_is_reported() {
        let base = temp_dir("missing");
        let loc = locations(&base);
        loc.ensure().expect("ensure");
        match loc.select(Some("nope")) {
            Err(PathError::NotFound { name, .. }) => assert_eq!(name, "nope"),
            other => panic!("expected not found, got {other:?}"),
        }
        fs::remove_dir_all(&base).ok();
    }

    /// AC-PRF-54: a second process on the same profile is refused.
    #[test]
    fn second_process_lock_is_refused() {
        let base = temp_dir("lock");
        let dir = base.join("profile-state");
        let first = ProcessLock::acquire(&dir).expect("first lock");
        match ProcessLock::acquire(&dir) {
            Err(PathError::Locked { path }) => assert_eq!(path, first.path()),
            other => panic!("expected locked, got {other:?}"),
        }
        drop(first);
        ProcessLock::acquire(&dir).expect("lock is released on drop");
        fs::remove_dir_all(&base).ok();
    }

    /// AC-PRF-08: the state directory is split by profile name.
    #[test]
    fn state_dir_is_per_profile() {
        let base = temp_dir("state");
        let loc = locations(&base);
        let one = loc.state_dir_for("one").expect("one");
        let two = loc.state_dir_for("two").expect("two");
        assert_ne!(one, two);
        assert!(one.is_dir() && two.is_dir());
        fs::remove_dir_all(&base).ok();
    }

    #[test]
    fn profile_dir_override_wins() {
        let base = temp_dir("override");
        let loc = locations(&base);
        assert_eq!(loc.profile_dir(), base.as_path());
        fs::remove_dir_all(&base).ok();
    }

    /// AC-PRF-08: a separate variable overrides the state directory.
    #[test]
    fn state_dir_override_wins() {
        let base = temp_dir("stateoverride");
        let profile = base.join("profiles");
        let state = base.join("state");
        let profile_s = profile.to_string_lossy().into_owned();
        let state_s = state.to_string_lossy().into_owned();
        let loc = Locations::resolve(&move |name: &str| match name {
            PROFILE_DIR_ENV => Some(profile_s.clone()),
            STATE_DIR_ENV => Some(state_s.clone()),
            _ => None,
        })
        .expect("locations");
        assert_eq!(
            loc.state_dir_for("corp").expect("state"),
            state.join("corp")
        );
        fs::remove_dir_all(&base).ok();
    }
}
