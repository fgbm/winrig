//! Журналирование с ротацией по размеру и приватными правами.
//!
//! Порт поведения `_PrivateRotatingFileHandler`: каталог создаётся `0700`,
//! файлы — `0600`, ротация по `WINRIG_LOG_MAX_BYTES` с хранением `WINRIG_LOG_BACKUP_COUNT`
//! копий. Права переприменяются на каждом открытии, иначе новая копия после
//! ротации получила бы права процесса.

use std::fs::{self, File};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use tracing_subscriber::fmt::MakeWriter;

use crate::private_fs::{create_private_dir, open_private_append};

/// Файл журнала с ротацией по размеру.
#[derive(Debug)]
pub struct RotatingFile {
    inner: Mutex<Inner>,
}

#[derive(Debug)]
struct Inner {
    path: PathBuf,
    file: Option<File>,
    written: u64,
    max_bytes: u64,
    backups: u32,
}

impl RotatingFile {
    /// Открывает журнал, создавая каталог и файл с приватными правами.
    ///
    /// # Errors
    ///
    /// Ошибка ввода-вывода, если каталог или файл нельзя создать.
    pub fn new(path: impl AsRef<Path>, max_bytes: u64, backups: u32) -> io::Result<Self> {
        let path = path.as_ref().to_path_buf();
        if let Some(parent) = path.parent() {
            create_private_dir(parent)?;
        }
        let (file, written) = open_private(&path)?;
        Ok(Self {
            inner: Mutex::new(Inner {
                path,
                file: Some(file),
                written,
                max_bytes,
                backups,
            }),
        })
    }
}

impl Inner {
    /// Записывает байты, ротируя файл при превышении размера.
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if self.max_bytes > 0 && self.written + buf.len() as u64 > self.max_bytes {
            self.rotate()?;
        }
        let file = match &mut self.file {
            Some(file) => file,
            None => {
                let (file, written) = open_private(&self.path)?;
                self.written = written;
                self.file = Some(file);
                self.file.as_mut().expect("just set")
            }
        };
        file.write_all(buf)?;
        self.written += buf.len() as u64;
        Ok(buf.len())
    }

    /// Сдвигает копии и открывает новый файл.
    fn rotate(&mut self) -> io::Result<()> {
        self.file = None;
        if self.backups > 0 {
            // Удаляем самый старый слот, затем сдвигаем нумерацию вверх.
            let oldest = backup_path(&self.path, self.backups);
            let _ = fs::remove_file(&oldest);
            for index in (1..self.backups).rev() {
                let from = backup_path(&self.path, index);
                let to = backup_path(&self.path, index + 1);
                if from.exists() {
                    let _ = fs::rename(&from, &to);
                }
            }
            let first = backup_path(&self.path, 1);
            let _ = fs::rename(&self.path, &first);
        } else {
            let _ = fs::remove_file(&self.path);
        }
        let (file, written) = open_private(&self.path)?;
        self.file = Some(file);
        self.written = written;
        Ok(())
    }
}

fn backup_path(path: &Path, index: u32) -> PathBuf {
    PathBuf::from(format!("{}.{index}", path.display()))
}

fn open_private(path: &Path) -> io::Result<(File, u64)> {
    open_private_append(path)
}

impl<'a> MakeWriter<'a> for RotatingFile {
    type Writer = RotatingGuard<'a>;

    fn make_writer(&'a self) -> Self::Writer {
        RotatingGuard {
            inner: self.inner.lock().unwrap_or_else(|error| error.into_inner()),
        }
    }
}

/// Временный держатель блокировки журнала.
pub struct RotatingGuard<'a> {
    inner: std::sync::MutexGuard<'a, Inner>,
}

impl Write for RotatingGuard<'_> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.inner.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        match &mut self.inner.file {
            Some(file) => file.flush(),
            None => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("winrig-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("temp dir");
        dir
    }

    #[test]
    fn writes_and_reads_back() {
        let dir = temp_dir("write");
        let path = dir.join("test.log");
        let writer = RotatingFile::new(&path, 0, 0).expect("writer");
        {
            let mut guard = writer.make_writer();
            guard.write_all(b"hello\n").expect("write");
        }
        assert_eq!(fs::read_to_string(&path).expect("read"), "hello\n");
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn rotates_when_exceeding_max_bytes() {
        let dir = temp_dir("rotate");
        let path = dir.join("test.log");
        let writer = RotatingFile::new(&path, 10, 3).expect("writer");
        for _ in 0..5 {
            let mut guard = writer.make_writer();
            guard.write_all(b"0123456789").expect("write");
        }
        assert!(path.exists());
        assert!(backup_path(&path, 1).exists(), "first backup must exist");
        fs::remove_dir_all(&dir).ok();
    }

    #[cfg(unix)]
    #[test]
    fn file_is_private() {
        use std::os::unix::fs::PermissionsExt;
        let dir = temp_dir("private");
        let path = dir.join("test.log");
        let _writer = RotatingFile::new(&path, 0, 0).expect("writer");
        let mode = fs::metadata(&path).expect("metadata").permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
        fs::remove_dir_all(&dir).ok();
    }
}
