//! Профиль учётной записи: аутентифицированный шифртекст пароля (ADR-0009).
//!
//! На диске лежит только шифртекст. Ключ выводится из токена доступа, который
//! печатается один раз при создании и хранится у клиента; на сервере ключа нет.
//! Формат несёт номер версии, каноническое имя пользователя (оно же — связанные
//! данные AEAD, поэтому подмена имени обнаруживается), соль KDF и nonce.
//!
//! Ошибка расшифровки (неверный токен) и ошибка разбора (повреждённый файл или
//! неподдерживаемая версия) — разные варианты [`ProfileError`]: журнал должен
//! их различать, клиент получает одинаковый отказ (AC-PRF-40, AC-PRF-41).

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use winrm_rs::SecretString;
use zeroize::Zeroizing;

use crate::paths::validate_profile_name;

/// Версия текущего формата профиля.
pub const FORMAT_VERSION: u32 = 1;
/// Длина соли KDF в байтах.
pub const SALT_LEN: usize = 32;
/// Длина nonce XChaCha20 в байтах.
pub const NONCE_LEN: usize = 24;
/// Длина ключа шифрования в байтах.
pub const KEY_LEN: usize = 32;
/// Длина генерируемого токена доступа в байтах.
pub const TOKEN_LEN: usize = 32;
/// Контекст вывода ключа HKDF, отделяющий этот ключ от любых других применений.
const HKDF_INFO: &[u8] = b"winrig-profile-v1";
/// Ошибка работы с профилем.
#[derive(Debug)]
pub enum ProfileError {
    /// Ошибка ввода-вывода.
    Io {
        /// Путь, на котором произошла ошибка.
        path: PathBuf,
        /// Причина.
        source: std::io::Error,
    },
    /// Профиль уже существует, перезапись не запрошена.
    Exists {
        /// Путь к существующему профилю.
        path: PathBuf,
    },
    /// Файл повреждён или не является профилем.
    Corrupt {
        /// Путь к файлу.
        path: PathBuf,
        /// Что именно не так.
        reason: String,
    },
    /// Версия формата новее известной.
    UnsupportedVersion {
        /// Путь к файлу.
        path: PathBuf,
        /// Версия из файла.
        version: u32,
    },
    /// Расшифровка не удалась: неверный токен или подменённые данные.
    InvalidToken {
        /// Путь к файлу.
        path: PathBuf,
    },
    /// Недопустимое имя профиля.
    InvalidName {
        /// Отвергнутое имя.
        name: String,
    },
    /// Пустой пароль или имя пользователя.
    EmptyInput {
        /// Что именно пусто.
        field: &'static str,
    },
    /// Учётная запись без домена: ни `DOMAIN\user`, ни UPN (TR-PRF-16).
    InvalidAccount {
        /// Отвергнутая учётная запись.
        account: String,
    },
}

impl std::fmt::Display for ProfileError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io { path, source } => write!(f, "cannot use {}: {source}", path.display()),
            Self::Exists { path } => write!(
                f,
                "profile {} already exists; pass --overwrite to replace it",
                path.display()
            ),
            Self::Corrupt { path, reason } => {
                write!(f, "profile {} is corrupt: {reason}", path.display())
            }
            Self::UnsupportedVersion { path, version } => write!(
                f,
                "profile {} uses format version {version}, which this build does not support",
                path.display()
            ),
            Self::InvalidToken { path } => {
                write!(
                    f,
                    "profile {} could not be decrypted: wrong token",
                    path.display()
                )
            }
            Self::InvalidName { name } => write!(f, "invalid profile name {name:?}"),
            Self::EmptyInput { field } => write!(f, "{field} must not be empty"),
            Self::InvalidAccount { account } => write!(
                f,
                "account {account:?} has no domain; expected DOMAIN\\user or user@domain. \
                 In a shell, quote the backslash: 'DOMAIN\\user'"
            ),
        }
    }
}

impl std::error::Error for ProfileError {}

/// Развёрнутый профиль: имя пользователя и пароль в памяти.
#[derive(Debug)]
pub struct LoadedProfile {
    /// Каноническое имя учётной записи.
    pub username: String,
    /// Пароль AD; обнуляется при освобождении.
    pub password: SecretString,
}

/// Сведения о профиле для вывода списка, без секретов.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProfileSummary {
    /// Имя профиля (имя файла без расширения).
    pub name: String,
    /// Каноническое имя учётной записи.
    pub username: String,
    /// Время создания в секундах Unix.
    pub created_at: u64,
    /// Путь к файлу профиля.
    pub path: PathBuf,
}

#[derive(Debug, Serialize, Deserialize)]
struct ProfileFile {
    version: u32,
    username: String,
    kdf: KdfSection,
    cipher: CipherSection,
    created_at: u64,
    #[serde(default)]
    rotated_at: Option<u64>,
}

#[derive(Debug, Serialize, Deserialize)]
struct KdfSection {
    algorithm: String,
    salt: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct CipherSection {
    algorithm: String,
    nonce: String,
    ciphertext: String,
}

/// Генерирует токен доступа из системного источника случайности.
#[must_use]
pub fn generate_token() -> String {
    let mut bytes = [0u8; TOKEN_LEN];
    rand::fill(&mut bytes);
    hex_encode(&bytes)
}

/// Выводит ключ шифрования из токена и соли.
fn derive_key(token: &str, salt: &[u8]) -> Zeroizing<[u8; KEY_LEN]> {
    let hkdf = Hkdf::<Sha256>::new(Some(salt), token.as_bytes());
    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    hkdf.expand(HKDF_INFO, key.as_mut())
        .expect("32 bytes is a valid HKDF output length");
    key
}

fn associated_data(username: &str) -> Vec<u8> {
    format!("winrig-profile-v{FORMAT_VERSION}\n{username}").into_bytes()
}

fn encrypt(
    key: &[u8; KEY_LEN],
    username: &str,
    password: &str,
    nonce: &[u8; NONCE_LEN],
) -> Vec<u8> {
    let cipher = XChaCha20Poly1305::new(&Key::from(*key));
    let payload = Payload {
        msg: password.as_bytes(),
        aad: &associated_data(username),
    };
    cipher
        .encrypt(&XNonce::from(*nonce), payload)
        .expect("encryption is infallible for valid parameters")
}

fn decrypt(
    key: &[u8; KEY_LEN],
    username: &str,
    ciphertext: &[u8],
    nonce: &[u8; NONCE_LEN],
) -> Result<Vec<u8>, ProfileError> {
    let cipher = XChaCha20Poly1305::new(&Key::from(*key));
    let payload = Payload {
        msg: ciphertext,
        aad: &associated_data(username),
    };
    cipher
        .decrypt(&XNonce::from(*nonce), payload)
        .map_err(|_| ProfileError::InvalidToken {
            path: PathBuf::new(),
        })
}

fn parse_file(path: &Path, raw: &str) -> Result<ProfileFile, ProfileError> {
    let file: ProfileFile = serde_json::from_str(raw).map_err(|error| ProfileError::Corrupt {
        path: path.to_path_buf(),
        reason: error.to_string(),
    })?;
    if file.version > FORMAT_VERSION {
        return Err(ProfileError::UnsupportedVersion {
            path: path.to_path_buf(),
            version: file.version,
        });
    }
    if file.kdf.algorithm != "hkdf-sha256" {
        return Err(ProfileError::Corrupt {
            path: path.to_path_buf(),
            reason: format!("unsupported KDF {}", file.kdf.algorithm),
        });
    }
    if file.cipher.algorithm != "xchacha20poly1305" {
        return Err(ProfileError::Corrupt {
            path: path.to_path_buf(),
            reason: format!("unsupported cipher {}", file.cipher.algorithm),
        });
    }
    Ok(file)
}

/// Отвергает учётную запись без домена (TR-PRF-16).
///
/// `split_account` делит по первому `\`, а UPN не делит вовсе. Голое имя
/// поэтому уходит в NTLM с пустым доменом, и AD отвечает отказом — но уже
/// на первом `connect`, далеко от места ошибки. Разделитель легко теряется по
/// дороге: в shell без кавычек, в JSON, в аргументе, собранном агентом.
///
/// # Errors
///
/// [`ProfileError::InvalidAccount`], если нет ни `\`, ни `@`.
fn validate_account(account: &str) -> Result<(), ProfileError> {
    if account.contains('\\') || account.contains('@') {
        return Ok(());
    }
    Err(ProfileError::InvalidAccount {
        account: account.to_owned(),
    })
}

/// Создаёт профиль и возвращает токен, которым зашифрован пароль.
///
/// # Errors
///
/// [`ProfileError::InvalidName`], [`ProfileError::EmptyInput`],
/// [`ProfileError::Exists`] без `overwrite`, [`ProfileError::Io`].
pub fn create(
    path: &Path,
    name: &str,
    username: &str,
    password: &str,
    overwrite: bool,
) -> Result<String, ProfileError> {
    validate_profile_name(name).map_err(|_| ProfileError::InvalidName {
        name: name.to_owned(),
    })?;
    if username.trim().is_empty() {
        return Err(ProfileError::EmptyInput { field: "username" });
    }
    if password.is_empty() {
        return Err(ProfileError::EmptyInput { field: "password" });
    }
    validate_account(username.trim())?;
    if path.exists() && !overwrite {
        return Err(ProfileError::Exists {
            path: path.to_path_buf(),
        });
    }
    let username = crate::identity::canonical_username(username.trim());
    let token = generate_token();
    let file = build_file(&username, password, &token, now_seconds(), None);
    write_atomic(
        path,
        &serde_json::to_vec_pretty(&file).expect("serializable"),
    )?;
    Ok(token)
}

/// Перешифровывает профиль новым токеном, сохраняя имя пользователя.
///
/// # Errors
///
/// [`ProfileError::UnsupportedVersion`], [`ProfileError::Corrupt`],
/// [`ProfileError::EmptyInput`], [`ProfileError::Io`].
pub fn rotate(path: &Path, password: &str) -> Result<String, ProfileError> {
    if password.is_empty() {
        return Err(ProfileError::EmptyInput { field: "password" });
    }
    let raw = fs::read_to_string(path).map_err(|source| ProfileError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    let file = parse_file(path, &raw)?;
    let created_at = file.created_at;
    let token = generate_token();
    let rotated = build_file(
        &file.username,
        password,
        &token,
        created_at,
        Some(now_seconds()),
    );
    write_atomic(
        path,
        &serde_json::to_vec_pretty(&rotated).expect("serializable"),
    )?;
    Ok(token)
}

/// Загружает профиль, расшифровывая пароль предъявленным токеном.
///
/// # Errors
///
/// [`ProfileError::Corrupt`] при повреждённом файле или неизвестной версии,
/// [`ProfileError::InvalidToken`] при неверном токене, [`ProfileError::Io`].
pub fn load(path: &Path, token: &str) -> Result<LoadedProfile, ProfileError> {
    let raw = fs::read_to_string(path).map_err(|source| ProfileError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    let file = parse_file(path, &raw)?;
    let salt: [u8; SALT_LEN] = decode_fixed(path, &file.kdf.salt, "salt")?;
    let nonce: [u8; NONCE_LEN] = decode_fixed(path, &file.cipher.nonce, "nonce")?;
    let ciphertext = decode_field(path, &file.cipher.ciphertext, "ciphertext")?;
    let key = derive_key(token, &salt);
    let plaintext =
        decrypt(&key, &file.username, &ciphertext, &nonce).map_err(|error| match error {
            ProfileError::InvalidToken { .. } => ProfileError::InvalidToken {
                path: path.to_path_buf(),
            },
            other => other,
        })?;
    let password = String::from_utf8(plaintext).map_err(|_| ProfileError::Corrupt {
        path: path.to_path_buf(),
        reason: "decrypted password is not valid UTF-8".to_owned(),
    })?;
    Ok(LoadedProfile {
        username: file.username,
        password: SecretString::from(password),
    })
}

/// Читает сведения о профилях каталога без секретов.
#[must_use]
pub fn list(paths: &[PathBuf], names: &[String]) -> Vec<ProfileSummary> {
    let mut out = Vec::new();
    for (path, name) in paths.iter().zip(names.iter()) {
        let Ok(raw) = fs::read_to_string(path) else {
            continue;
        };
        let Ok(file) = serde_json::from_str::<ProfileFile>(&raw) else {
            continue;
        };
        out.push(ProfileSummary {
            name: name.clone(),
            username: file.username,
            created_at: file.created_at,
            path: path.clone(),
        });
    }
    out
}

/// Удаляет профиль; отсутствие файла не считается ошибкой.
///
/// # Errors
///
/// [`ProfileError::Io`], если файл существует, но его нельзя удалить.
pub fn forget(path: &Path) -> Result<bool, ProfileError> {
    match fs::remove_file(path) {
        Ok(()) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(source) => Err(ProfileError::Io {
            path: path.to_path_buf(),
            source,
        }),
    }
}

/// Ожидаемый на текущей платформе режим файла профиля.
#[must_use]
pub fn permissions_warning(path: &Path) -> Option<String> {
    crate::private_fs::loose_file_mode(path).map(|mode| {
        format!(
            "profile {} is readable by other users (mode {mode:o}); expected 600",
            path.display()
        )
    })
}

/// Истина, если токен расшифровывает профиль. Для проверки совпадения ключей.
#[must_use]
pub fn decrypts(path: &Path, token: &str) -> bool {
    load(path, token).is_ok()
}

fn build_file(
    username: &str,
    password: &str,
    token: &str,
    created_at: u64,
    rotated_at: Option<u64>,
) -> ProfileFile {
    let mut salt = [0u8; SALT_LEN];
    rand::fill(&mut salt);
    let mut nonce = [0u8; NONCE_LEN];
    rand::fill(&mut nonce);
    let key = derive_key(token, &salt);
    let ciphertext = encrypt(&key, username, password, &nonce);
    ProfileFile {
        version: FORMAT_VERSION,
        username: username.to_owned(),
        kdf: KdfSection {
            algorithm: "hkdf-sha256".to_owned(),
            salt: hex_encode(&salt),
        },
        cipher: CipherSection {
            algorithm: "xchacha20poly1305".to_owned(),
            nonce: hex_encode(&nonce),
            ciphertext: hex_encode(&ciphertext),
        },
        created_at,
        rotated_at,
    }
}

/// Пишет файл атомарно: временный файл в том же каталоге, затем переименование.
///
/// Имя временного файла случайно, чтобы его нельзя было предугадать и
/// подготовить по нему симлинк; существующий временный файл удаляется до
/// открытия (AC-PRF-31).
fn write_atomic(path: &Path, contents: &[u8]) -> Result<(), ProfileError> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    crate::private_fs::create_private_dir(parent).map_err(|source| ProfileError::Io {
        path: parent.to_path_buf(),
        source,
    })?;
    let mut suffix = [0u8; 8];
    rand::fill(&mut suffix);
    let stem = path
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("profile");
    let temp = parent.join(format!("{stem}.{}.tmp", hex_encode(&suffix)));
    let _ = fs::remove_file(&temp);
    {
        let mut file =
            crate::private_fs::open_private_truncate(&temp).map_err(|source| ProfileError::Io {
                path: temp.clone(),
                source,
            })?;
        file.write_all(contents)
            .map_err(|source| ProfileError::Io {
                path: temp.clone(),
                source,
            })?;
        file.sync_all().map_err(|source| ProfileError::Io {
            path: temp.clone(),
            source,
        })?;
    }
    if let Err(source) = fs::rename(&temp, path) {
        // Windows не заменяет существующий файл переименованием.
        if path.exists() {
            fs::remove_file(path).map_err(|source| ProfileError::Io {
                path: path.to_path_buf(),
                source,
            })?;
            fs::rename(&temp, path).map_err(|source| ProfileError::Io {
                path: path.to_path_buf(),
                source,
            })?;
        } else {
            let _ = fs::remove_file(&temp);
            return Err(ProfileError::Io {
                path: path.to_path_buf(),
                source,
            });
        }
    }
    crate::private_fs::apply_private_file_mode(path);
    Ok(())
}

fn decode_field(path: &Path, value: &str, field: &str) -> Result<Vec<u8>, ProfileError> {
    hex_decode(value).ok_or_else(|| ProfileError::Corrupt {
        path: path.to_path_buf(),
        reason: format!("{field} is not valid hex"),
    })
}

/// Декодирует hex-поле фиксированной длины.
fn decode_fixed<const N: usize>(
    path: &Path,
    value: &str,
    field: &str,
) -> Result<[u8; N], ProfileError> {
    let bytes = decode_field(path, value, field)?;
    <[u8; N]>::try_from(bytes.as_slice()).map_err(|_| ProfileError::Corrupt {
        path: path.to_path_buf(),
        reason: format!("{field} must be {N} bytes, got {}", bytes.len()),
    })
}

fn now_seconds() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|value| value.as_secs())
        .unwrap_or(0)
}

fn hex_encode(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

fn hex_decode(value: &str) -> Option<Vec<u8>> {
    if !value.len().is_multiple_of(2) {
        return None;
    }
    let mut out = Vec::with_capacity(value.len() / 2);
    let bytes = value.as_bytes();
    for pair in bytes.as_chunks::<2>().0 {
        let high = (pair[0] as char).to_digit(16)?;
        let low = (pair[1] as char).to_digit(16)?;
        out.push(((high << 4) | low) as u8);
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "winrig-profile-{name}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = fs::remove_dir_all(&dir);
        dir
    }

    fn setup(dir: &Path, name: &str, username: &str, password: &str) -> (PathBuf, String) {
        let path = dir.join(format!("{name}.json"));
        let token = create(&path, name, username, password, false).expect("create");
        (path, token)
    }

    /// AC-PRF-01: файл не содержит пароль, токен не сохранён, права приватны.
    #[test]
    fn create_writes_only_ciphertext() {
        let dir = temp_dir("create");
        let (path, token) = setup(&dir, "corp", "domain\\alice", "s3cret-pass");
        let raw = fs::read_to_string(&path).expect("read");
        assert!(
            !raw.contains("s3cret-pass"),
            "password must not be plaintext"
        );
        assert!(!raw.contains(&token), "token must not be stored");
        assert!(raw.contains("domain\\\\alice") || raw.contains("domain\\alice"));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        fs::remove_dir_all(&dir).ok();
    }

    /// AC-PRF-02: верный токен возвращает имя и пароль.
    #[test]
    fn load_with_correct_token() {
        let dir = temp_dir("load");
        let (path, token) = setup(&dir, "corp", "domain\\alice", "s3cret-pass");
        let loaded = load(&path, &token).expect("load");
        assert_eq!(loaded.username, "domain\\alice");
        use winrm_rs::ExposeSecret;
        assert_eq!(loaded.password.expose_secret(), "s3cret-pass");
        fs::remove_dir_all(&dir).ok();
    }

    /// AC-PRF-67: учётка без разделителя не создаёт профиль молча. Именно так
    /// был потерян `\` в `contoso\alice`: NTLM ушёл с пустым доменом, и
    /// оператор узнал об этом только по отказу AD.
    #[test]
    fn account_without_a_separator_is_refused() {
        let dir = temp_dir("bareaccount");
        let path = dir.join("corp.json");
        let error = create(&path, "corp", "contosoalice", "s3cret-pass", false)
            .expect_err("bare account must be refused");
        let text = error.to_string();
        assert!(
            text.contains("DOMAIN\\user"),
            "отказ называет ожидаемую форму: {text}"
        );
        assert!(!path.exists(), "профиль не создан");
        fs::remove_dir_all(&dir).ok();
    }

    /// AC-PRF-67: обе законные формы проходят.
    #[test]
    fn domain_and_upn_accounts_are_accepted() {
        let dir = temp_dir("goodaccount");
        for (file, account) in [
            ("down.json", "contoso\\alice"),
            ("upn.json", "alice@contoso.local"),
        ] {
            let path = dir.join(file);
            create(&path, "corp", account, "s3cret-pass", false).expect("must be accepted");
            assert!(path.exists());
        }
        fs::remove_dir_all(&dir).ok();
    }

    /// AC-PRF-40: неверный токен — отдельная ошибка InvalidToken.
    #[test]
    fn wrong_token_is_invalid_token_error() {
        let dir = temp_dir("wrongtoken");
        let (path, _) = setup(&dir, "corp", "domain\\alice", "s3cret-pass");
        assert!(matches!(
            load(&path, &generate_token()),
            Err(ProfileError::InvalidToken { .. })
        ));
        fs::remove_dir_all(&dir).ok();
    }

    /// AC-PRF-41: повреждённый файл — Corrupt, не InvalidToken.
    #[test]
    fn corrupt_file_is_distinct_error() {
        let dir = temp_dir("corrupt");
        let (path, token) = setup(&dir, "corp", "domain\\alice", "s3cret-pass");
        fs::write(&path, b"{ not json").expect("write");
        assert!(matches!(
            load(&path, &token),
            Err(ProfileError::Corrupt { .. })
        ));
        fs::remove_dir_all(&dir).ok();
    }

    /// `hex_decode` отвергает вход, который не является парами hex-цифр.
    ///
    /// Тест держит гвард на чётность. `as_chunks::<2>()` молча отбрасывает
    /// хвостовой байт: без проверки `is_multiple_of(2)` строка "abc"
    /// декодировалась бы в один байт 0xab вместо отказа, и обрезанные соль,
    /// nonce или шифротекст ушли бы в расшифровку как якобы целые — вместо
    /// `ProfileError::Corrupt` операторa ждал бы отказ аутентификации AEAD
    /// или просто более короткий ключевой материал. Вторая ветка — `?` от
    /// `to_digit(16)` — единственное, что отсеивает не-hex символ.
    #[test]
    fn hex_decode_rejects_odd_length_and_non_hex() {
        assert_eq!(hex_decode(""), Some(vec![]), "пустая строка — ноль байт");
        assert_eq!(hex_decode("00ff10"), Some(vec![0x00, 0xff, 0x10]));
        assert_eq!(hex_decode("AbCd"), Some(vec![0xab, 0xcd]), "регистр любой");

        assert_eq!(hex_decode("a"), None, "нечётная длина: одна цифра");
        assert_eq!(
            hex_decode("abc"),
            None,
            "нечётная длина: хвост не отбросить"
        );

        // Все входы ниже чётной длины В БАЙТАХ, иначе их отсеял бы гвард
        // выше и ветка `to_digit` осталась бы непроверенной.
        assert_eq!(hex_decode("zz"), None, "не-hex буква");
        assert_eq!(hex_decode("0g"), None, "не-hex во второй цифре пары");
        assert_eq!(hex_decode("00 1"), None, "пробел как цифра не проходит");
        assert_eq!(
            hex_decode("é"),
            None,
            "не-ASCII: два байта, ни один не цифра"
        );
    }

    /// AC-PRF-46: версия выше известной отвергается отдельно.
    #[test]
    fn unsupported_version_is_reported() {
        let dir = temp_dir("version");
        let (path, token) = setup(&dir, "corp", "domain\\alice", "s3cret-pass");
        let raw = fs::read_to_string(&path).unwrap();
        let bumped = raw.replace("\"version\": 1", "\"version\": 99");
        fs::write(&path, bumped).unwrap();
        assert!(matches!(
            load(&path, &token),
            Err(ProfileError::UnsupportedVersion { version: 99, .. })
        ));
        fs::remove_dir_all(&dir).ok();
    }

    /// AC-PRF-23: без метаданных шифрования пароль не восстановим.
    #[test]
    fn stripped_crypto_metadata_is_unrecoverable() {
        let dir = temp_dir("stripped");
        let (path, token) = setup(&dir, "corp", "domain\\alice", "s3cret-pass");
        let raw = fs::read_to_string(&path).unwrap();
        let broke = raw.replace("\"ciphertext\": \"", "\"ciphertext\": \"zz");
        fs::write(&path, broke).unwrap();
        assert!(load(&path, &token).is_err());
        fs::remove_dir_all(&dir).ok();
    }

    /// AC-PRF-24: повторное создание без overwrite отвергается, файл не меняется.
    #[test]
    fn create_twice_without_overwrite_fails() {
        let dir = temp_dir("exists");
        let (path, _) = setup(&dir, "corp", "domain\\alice", "s3cret-pass");
        let before = fs::read(&path).unwrap();
        assert!(matches!(
            create(&path, "corp", "domain\\alice", "other", false),
            Err(ProfileError::Exists { .. })
        ));
        assert_eq!(fs::read(&path).unwrap(), before);
        fs::remove_dir_all(&dir).ok();
    }

    /// AC-PRF-45: пустой ввод отвергается без создания файла.
    #[test]
    fn empty_input_is_rejected() {
        let dir = temp_dir("empty");
        let path = dir.join("corp.json");
        assert!(matches!(
            create(&path, "corp", "  ", "pass", false),
            Err(ProfileError::EmptyInput { field: "username" })
        ));
        assert!(matches!(
            create(&path, "corp", "domain\\alice", "", false),
            Err(ProfileError::EmptyInput { field: "password" })
        ));
        assert!(!path.exists());
        fs::remove_dir_all(&dir).ok();
    }

    /// AC-PRF-11: ротация меняет токен, сохраняя имя и пароль.
    #[test]
    fn rotate_changes_token_only() {
        let dir = temp_dir("rotate");
        let (path, old) = setup(&dir, "corp", "domain\\alice", "s3cret-pass");
        let new = rotate(&path, "s3cret-pass").expect("rotate");
        assert_ne!(old, new);
        let loaded = load(&path, &new).expect("load new");
        assert_eq!(loaded.username, "domain\\alice");
        use winrm_rs::ExposeSecret;
        assert_eq!(loaded.password.expose_secret(), "s3cret-pass");
        assert!(matches!(
            load(&path, &old),
            Err(ProfileError::InvalidToken { .. })
        ));
        fs::remove_dir_all(&dir).ok();
    }

    /// AC-PRF-12 и AC-PRF-30: удаление идемпотентно.
    #[test]
    fn forget_is_idempotent() {
        let dir = temp_dir("forget");
        let (path, _) = setup(&dir, "corp", "domain\\alice", "s3cret-pass");
        assert!(forget(&path).expect("first"));
        assert!(!forget(&path).expect("second"));
        assert!(!path.exists());
        fs::remove_dir_all(&dir).ok();
    }

    /// AC-PRF-10: список не содержит секретов.
    #[test]
    fn list_exposes_no_secrets() {
        let dir = temp_dir("list");
        let (one, token) = setup(&dir, "one", "domain\\alice", "s3cret-pass");
        let (two, _) = setup(&dir, "two", "domain\\bob", "other-pass");
        let names = vec!["one".to_owned(), "two".to_owned()];
        let summaries = list(&[one, two], &names);
        assert_eq!(summaries.len(), 2);
        let rendered = format!("{summaries:?}");
        assert!(!rendered.contains("s3cret-pass"));
        assert!(!rendered.contains(&token));
        assert!(
            summaries
                .iter()
                .any(|item| item.username == "domain\\alice")
        );
        fs::remove_dir_all(&dir).ok();
    }

    /// Расширение файла профиля — `.json`.
    #[test]
    fn profile_files_use_json_extension() {
        let dir = temp_dir("extension");
        let (path, _) = setup(&dir, "corp", "domain\\alice", "s3cret-pass");
        assert_eq!(
            path.extension().and_then(|value| value.to_str()),
            Some("json")
        );
        let names = vec!["corp".to_owned()];
        assert_eq!(list(std::slice::from_ref(&path), &names).len(), 1);
        fs::remove_dir_all(&dir).ok();
    }

    /// AC-PRF-27: имя с символами пути отвергается.
    #[test]
    fn invalid_name_is_rejected() {
        let dir = temp_dir("badname");
        let path = dir.join("corp.json");
        for name in ["../x", "a/b", "a\\b", ""] {
            assert!(matches!(
                create(&path, name, "domain\\alice", "pass", false),
                Err(ProfileError::InvalidName { .. })
            ));
        }
        assert!(!dir.exists() || fs::read_dir(&dir).unwrap().next().is_none());
        fs::remove_dir_all(&dir).ok();
    }

    /// AC-PRF-25: слишком широкие права дают предупреждение, не отказ.
    #[cfg(unix)]
    #[test]
    fn loose_permissions_warn_but_load() {
        use std::os::unix::fs::PermissionsExt;
        let dir = temp_dir("loose");
        let (path, token) = setup(&dir, "corp", "domain\\alice", "s3cret-pass");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).expect("chmod");
        assert!(permissions_warning(&path).is_some());
        assert!(load(&path, &token).is_ok());
        fs::remove_dir_all(&dir).ok();
    }

    /// AC-PRF-03: токена нет в файле и каталоге.
    #[test]
    fn token_is_absent_from_disk() {
        let dir = temp_dir("notoken");
        let (path, token) = setup(&dir, "corp", "domain\\alice", "s3cret-pass");
        assert!(!fs::read_to_string(&path).unwrap().contains(&token));
        for entry in fs::read_dir(&dir).unwrap().flatten() {
            let contents = fs::read_to_string(entry.path()).unwrap_or_default();
            assert!(!contents.contains(&token));
        }
        fs::remove_dir_all(&dir).ok();
    }

    /// AC-PRF-26: канонизация имени совпадает с заголовком.
    #[test]
    fn canonical_username_matches_identity() {
        let dir = temp_dir("canon");
        let (path, token) = setup(&dir, "corp", "DOMAIN\\Alice", "s3cret-pass");
        let loaded = load(&path, &token).expect("load");
        assert_eq!(
            loaded.username,
            crate::identity::canonical_username("domain\\ALICE")
        );
        fs::remove_dir_all(&dir).ok();
    }

    /// AC-PRF-31: ротация оставляет каталог без временных файлов.
    #[test]
    fn rotation_leaves_no_temp_files() {
        let dir = temp_dir("notemp");
        let (path, _) = setup(&dir, "corp", "domain\\alice", "s3cret-pass");
        let _ = rotate(&path, "s3cret-pass").expect("rotate");
        let leftovers: Vec<_> = fs::read_dir(&dir)
            .unwrap()
            .flatten()
            .map(|entry| entry.file_name().to_string_lossy().into_owned())
            .filter(|name| name.ends_with(".tmp"))
            .collect();
        assert!(leftovers.is_empty(), "temp files left: {leftovers:?}");
        fs::remove_dir_all(&dir).ok();
    }

    /// AC-PRF-32: повторная загрузка не меняет файл.
    #[test]
    fn repeated_load_keeps_file_unchanged() {
        let dir = temp_dir("repeat");
        let (path, token) = setup(&dir, "corp", "domain\\alice", "s3cret-pass");
        let before = fs::read(&path).unwrap();
        for _ in 0..3 {
            let _ = load(&path, &token).expect("load");
        }
        assert_eq!(fs::read(&path).unwrap(), before);
        fs::remove_dir_all(&dir).ok();
    }
}
