//! Каталоги профилей и состояния, выбор профиля и блокировка процесса (ADR-0009).
//!
//! Каталог профилей берётся из `AppDirs::config_dir` с переопределением
//! `WINRIG_PROFILE_DIR`; каталог состояния — из `AppDirs::state_dir`, который
//! на Linux следует `XDG_STATE_HOME`, а на macOS и Windows совпадает с
//! локальным каталогом данных (на этих ОС отдельного состояния нет). Один
//! профиль на процесс: второй процесс с тем же профилем отказывает по
//! lock-файлу.

use std::fs::{self, File, OpenOptions};
use std::path::{Path, PathBuf};

use platform_dirs::AppDirs;

use crate::config::Env;

/// Имя переменной окружения с переопределением каталога профилей.
pub const PROFILE_DIR_ENV: &str = "WINRIG_PROFILE_DIR";
/// Имя переменной окружения с переопределением каталога состояния.
pub const STATE_DIR_ENV: &str = "WINRIG_STATE_DIR";
/// Расширение файла профиля.
pub const PROFILE_EXTENSION: &str = "json";
/// Имя lock-файла процесса в каталоге состояния профиля.
pub const LOCK_FILE: &str = "process.lock";

#[cfg(unix)]
const DIR_MODE: u32 = 0o700;

/// Ошибка разрешения каталогов профилей и состояния.
#[derive(Debug)]
pub enum PathError {
    /// Домашний каталог недоступен и переопределение не задано.
    NoHome {
        /// Имя переменной, которой каталог можно задать явно.
        variable: &'static str,
    },
    /// Каталог нельзя создать или открыть.
    Io {
        /// Путь, на котором произошла ошибка.
        path: PathBuf,
        /// Причина.
        source: std::io::Error,
    },
    /// Ограничение на символы пути нарушено.
    InvalidName {
        /// Отвергнутое имя.
        name: String,
        /// Что именно нарушено.
        reason: &'static str,
    },
    /// Профиль не найден в каталоге профилей.
    NotFound {
        /// Запрошенное имя.
        name: String,
        /// Каталог, в котором искали.
        dir: PathBuf,
    },
    /// Профилей несколько, а имя не указано.
    Ambiguous {
        /// Найденные имена.
        names: Vec<String>,
    },
    /// Профиль уже занят другим процессом.
    Locked {
        /// Путь lock-файла.
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

/// Проверяет, что имя профиля допустимо как имя файла.
///
/// # Errors
///
/// [`PathError::InvalidName`], если имя пустое, состоит из точек, содержит
/// разделитель пути или управляющий символ.
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

/// Каталоги профилей и состояния.
#[derive(Debug, Clone)]
pub struct Locations {
    profile_dir: PathBuf,
    state_root: PathBuf,
}

impl Locations {
    /// Разрешает каталоги из окружения и стандартных путей ОС.
    ///
    /// # Errors
    ///
    /// [`PathError::NoHome`], если стандартные пути недоступны и каталог
    /// профилей не задан явно; [`PathError::Io`] при ошибке создания.
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

    /// Создаёт каталоги с приватными правами.
    ///
    /// # Errors
    ///
    /// [`PathError::Io`], если каталог нельзя создать.
    pub fn ensure(&self) -> Result<(), PathError> {
        create_private_dir(&self.profile_dir)?;
        create_private_dir(&self.state_root)?;
        Ok(())
    }

    /// Каталог профилей.
    #[must_use]
    pub fn profile_dir(&self) -> &Path {
        &self.profile_dir
    }

    /// Путь к файлу профиля по имени.
    #[must_use]
    pub fn profile_path(&self, name: &str) -> PathBuf {
        self.profile_dir.join(format!("{name}.{PROFILE_EXTENSION}"))
    }

    /// Имена профилей в каталоге, отсортированные.
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

    /// Выбирает имя профиля: явное, либо единственное доступное.
    ///
    /// # Errors
    ///
    /// [`PathError::NotFound`], [`PathError::Ambiguous`] или
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

    /// Каталог состояния выбранного профиля, создаваемый при вызове.
    ///
    /// # Errors
    ///
    /// [`PathError::Io`], если каталог нельзя создать.
    pub fn state_dir_for(&self, profile: &str) -> Result<PathBuf, PathError> {
        let dir = self.state_root.join(profile);
        create_private_dir(&dir)?;
        Ok(dir)
    }

    /// Корень каталога состояния: к нему имя профиля добавляется ровно один
    /// раз, и делает это [`Self::state_dir_for`] (TR-PRF-15).
    #[must_use]
    pub fn state_root(&self) -> &Path {
        &self.state_root
    }

    /// Каталог состояния без профиля (HTTP только по общему секрету).
    ///
    /// # Errors
    ///
    /// [`PathError::Io`], если каталог нельзя создать.
    pub fn state_dir_default(&self) -> Result<PathBuf, PathError> {
        let dir = self.state_root.join("http");
        create_private_dir(&dir)?;
        Ok(dir)
    }
}

/// Держатель эксклюзивной блокировки процесса на профиль.
///
/// Блокировка снимается операционной системой при закрытии файла, поэтому
/// аварийное завершение процесса её не оставляет (AC-PRF-55).
#[derive(Debug)]
pub struct ProcessLock {
    file: File,
    path: PathBuf,
}

impl ProcessLock {
    /// Захватывает блокировку профиля или отказывает, если он занят.
    ///
    /// # Errors
    ///
    /// [`PathError::Locked`], если блокировку держит другой процесс;
    /// [`PathError::Io`] при ошибке доступа к файлу.
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

    /// Путь lock-файла.
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

/// Создаёт каталог и выставляет приватные права на Unix.
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

    /// AC-PRF-27: символы пути в имени профиля отвергаются.
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

    /// AC-PRF-27: ни один файл вне каталога профилей не создаётся.
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

    /// AC-PRF-20: несколько профилей без имени — отказ.
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

    /// AC-PRF-04: единственный профиль выбирается без имени.
    #[test]
    fn single_profile_is_default() {
        let base = temp_dir("single");
        let loc = locations(&base);
        loc.ensure().expect("ensure");
        fs::write(loc.profile_path("only"), b"{}").expect("write");
        assert_eq!(loc.select(None).expect("default"), "only");
        fs::remove_dir_all(&base).ok();
    }

    /// AC-PRF-43: профиль не найден.
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

    /// AC-PRF-54: второй процесс с тем же профилем отказывает.
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

    /// AC-PRF-08: каталог состояния делится по имени профиля.
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

    /// AC-PRF-08: каталог состояния переопределяется отдельной переменной.
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
