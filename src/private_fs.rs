//! Приватные файлы и каталоги: каталог `0700`, файл `0600` на Unix (ADR-0009).
//!
//! Общий хелпер для журналов (`src/logging.rs`), каталогов профилей
//! (`src/paths.rs`) и самого файла профиля (`src/profile.rs`): права
//! переприменяются на каждом открытии, иначе новая копия после ротации или
//! перезаписи получила бы права процесса. На платформах без `cfg(unix)`
//! приватность обеспечивается средствами ОС по умолчанию.

use std::fs::{self, File, OpenOptions};
use std::io;
use std::path::Path;

#[cfg(unix)]
const DIR_MODE: u32 = 0o700;
#[cfg(unix)]
const FILE_MODE: u32 = 0o600;

/// Режим файла, ожидаемый для приватных данных на текущей платформе.
#[cfg(unix)]
pub const EXPECTED_FILE_MODE: u32 = FILE_MODE;

/// Создаёт каталог и выставляет права `0700` на Unix.
///
/// # Errors
///
/// Ошибка ввода-вывода, если каталог нельзя создать.
pub fn create_private_dir(path: &Path) -> io::Result<()> {
    fs::create_dir_all(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(path, fs::Permissions::from_mode(DIR_MODE));
    }
    Ok(())
}

/// Создаёт каталог с правами `0700`, только если его ещё нет.
///
/// Существующий каталог не трогается: это может быть чужой каталог конфигов
/// (например `~/.config/opencode`), и менять его режим нельзя.
///
/// # Errors
///
/// Ошибка ввода-вывода, если каталог нельзя создать.
pub fn ensure_private_dir(path: &Path) -> io::Result<()> {
    if path.is_dir() {
        return Ok(());
    }
    create_private_dir(path)
}

/// Открывает файл на дозапись, создавая его с правами `0600`.
///
/// # Errors
///
/// Ошибка ввода-вывода, если файл нельзя открыть.
pub fn open_private_append(path: &Path) -> io::Result<(File, u64)> {
    ensure_parent(path)?;
    let file = OpenOptions::new().create(true).append(true).open(path)?;
    apply_private_file_mode(path);
    let written = file.metadata().map(|meta| meta.len()).unwrap_or(0);
    Ok((file, written))
}

/// Открывает файл на запись с усечением, создавая его с правами `0600`.
///
/// # Errors
///
/// Ошибка ввода-вывода, если файл нельзя открыть.
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

/// Создаёт родительский каталог файла с приватными правами, не трогая
/// существующий каталог.
fn ensure_parent(path: &Path) -> io::Result<()> {
    match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => ensure_private_dir(parent),
        _ => Ok(()),
    }
}

/// Выставляет права `0600` на файл.
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

/// Проверяет, что права файла не шире ожидаемых; `None` — проверка невозможна.
///
/// На Unix возвращает фактический режим, если он отличается от `0600`.
/// На остальных платформах всегда `None`.
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

#[cfg(test)]
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
