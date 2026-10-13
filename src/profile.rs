//! Account profile: the authenticated ciphertext of the password (ADR-0009).
//!
//! Only ciphertext is on disk. The key is derived from the access token, which
//! is printed once at creation and kept by the client; the server has no key.
//! The format carries a version number, the canonical user name (which is also
//! the AEAD associated data, so a swapped name is detected), the KDF salt and
//! the nonce.
//!
//! A decryption error (wrong token) and a parse error (a damaged file or an
//! unsupported version) are different [`ProfileError`] variants: the journal
//! must tell them apart, the client gets the same refusal (AC-PRF-40, AC-PRF-41).

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

pub const FORMAT_VERSION: u32 = 1;
/// KDF salt length in bytes.
pub const SALT_LEN: usize = 32;
/// XChaCha20 nonce length in bytes.
pub const NONCE_LEN: usize = 24;
/// Encryption key length in bytes.
pub const KEY_LEN: usize = 32;
/// Generated access token length in bytes.
pub const TOKEN_LEN: usize = 32;
/// HKDF key-output context that separates this key from any other use.
const HKDF_INFO: &[u8] = b"winrig-profile-v1";
/// Failure in a profile operation.
#[derive(Debug)]
pub enum ProfileError {
    /// Input or output error.
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
    /// The profile already exists and overwrite was not requested.
    Exists {
        /// File that already exists.
        path: PathBuf,
    },
    /// Damaged file or a file that is not a profile.
    Corrupt {
        /// File that failed the parse.
        path: PathBuf,
        /// Cause of the failure.
        reason: String,
    },
    /// Format version newer than this build knows.
    UnsupportedVersion {
        /// File with the newer version.
        path: PathBuf,
        /// Number read from the file.
        version: u32,
    },
    /// Decryption failed: wrong token or substituted data.
    InvalidToken {
        /// File that could not be opened.
        path: PathBuf,
    },
    /// Profile name that is not allowed.
    InvalidName {
        /// Rejected profile string.
        name: String,
    },
    /// Empty password or user name.
    EmptyInput {
        /// Which input was empty.
        field: &'static str,
    },
    /// An account with no domain: neither `DOMAIN\user` nor a UPN (TR-PRF-16).
    InvalidAccount {
        /// Login string without a domain.
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

/// A loaded profile: the user name and the password in memory.
#[derive(Debug)]
pub struct LoadedProfile {
    /// Canonical account name.
    pub username: String,
    /// AD secret, zeroized on drop.
    pub password: SecretString,
}

/// Profile information for the list output, without secrets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProfileSummary {
    /// Profile file stem without its extension.
    pub name: String,
    /// Canonical account name.
    pub username: String,
    /// Creation time in Unix seconds.
    pub created_at: u64,
    /// Location of the profile file.
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

/// Generates an access token from the system random source.
#[must_use]
pub fn generate_token() -> String {
    let mut bytes = [0u8; TOKEN_LEN];
    rand::fill(&mut bytes);
    hex_encode(&bytes)
}

/// Derives the encryption key from the token and the salt.
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

/// Rejects an account with no domain (TR-PRF-16).
///
/// `split_account` splits at the first `\` and a UPN not at all. A bare name
/// therefore goes to NTLM with an empty domain, and AD answers with a refusal —
/// but only at the first `connect`, far from the place of the error. The
/// separator is easily lost on the way: in a shell without quotes, in JSON, in
/// an argument built by an agent.
///
/// # Errors
///
/// [`ProfileError::InvalidAccount`] when there is neither `\` nor `@`.
fn validate_account(account: &str) -> Result<(), ProfileError> {
    if account.contains('\\') || account.contains('@') {
        return Ok(());
    }
    Err(ProfileError::InvalidAccount {
        account: account.to_owned(),
    })
}

/// Creates a profile and returns the token that encrypts the password.
///
/// # Errors
///
/// [`ProfileError::InvalidName`], [`ProfileError::EmptyInput`],
/// [`ProfileError::Exists`] without `overwrite`, [`ProfileError::Io`].
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

/// Re-encrypts the profile with a new token and keeps the user name.
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

/// Loads the profile and decrypts the password with the presented token.
///
/// # Errors
///
/// [`ProfileError::Corrupt`] for a damaged file or an unknown version,
/// [`ProfileError::InvalidToken`] for a wrong token, [`ProfileError::Io`].
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

/// Profile summaries of a directory, without secrets.
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

/// Deletes the profile; a missing file is not an error.
///
/// # Errors
///
/// [`ProfileError::Io`] when the file exists but cannot be removed.
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

/// Warning when the profile mode is looser than expected on this platform.
#[must_use]
pub fn permissions_warning(path: &Path) -> Option<String> {
    crate::private_fs::loose_file_mode(path).map(|mode| {
        format!(
            "profile {} is readable by other users (mode {mode:o}); expected 600",
            path.display()
        )
    })
}

/// True when the given token opens the profile, for key comparison.
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

/// Writes the file atomically: a temporary file in the same directory, then a rename.
///
/// The temporary name is random so it cannot be predicted and used to plant a
/// symlink; an existing temporary file is removed before the open (AC-PRF-31).
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
        // Windows does not replace an existing file by rename.
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

/// Decodes a hex field of fixed length.
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

    /// AC-PRF-01: the file holds no password, the token is not stored, the permissions are private.
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

    /// AC-PRF-02: the correct token returns the user name and the password.
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

    /// AC-PRF-67: an account without a separator does not create a profile
    /// silently. This is how the `\` in `contoso\alice` was lost: NTLM left
    /// with an empty domain, and the operator learned it only from the AD
    /// refusal.
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

    /// AC-PRF-67: both legal forms pass.
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

    /// AC-PRF-40: a wrong token is a separate InvalidToken error.
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

    /// AC-PRF-41: a damaged file is Corrupt, not InvalidToken.
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

    /// `hex_decode` rejects input that is not pairs of hex digits.
    ///
    /// The test holds the even-length guard. `as_chunks::<2>()` silently drops
    /// a trailing byte: without the `is_multiple_of(2)` check the string "abc"
    /// would decode to one byte 0xab instead of failing, and a truncated salt,
    /// nonce or ciphertext would reach decryption as if whole; instead of
    /// `ProfileError::Corrupt` the operator would get an AEAD authentication
    /// failure or just shorter key material. The second branch, the `?` from
    /// `to_digit(16)`, is the only thing that rejects a non-hex character.
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

        // All inputs below are of even length IN BYTES, otherwise the guard
        // above would drop them and the `to_digit` branch would stay untested.
        assert_eq!(hex_decode("zz"), None, "не-hex буква");
        assert_eq!(hex_decode("0g"), None, "не-hex во второй цифре пары");
        assert_eq!(hex_decode("00 1"), None, "пробел как цифра не проходит");
        assert_eq!(
            hex_decode("é"),
            None,
            "не-ASCII: два байта, ни один не цифра"
        );
    }

    /// AC-PRF-46: a version above the known one is refused separately.
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

    /// AC-PRF-23: without the crypto metadata the password cannot be recovered.
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

    /// AC-PRF-24: a second create without overwrite is refused and the file does not change.
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

    /// AC-PRF-45: empty input is refused with no file created.
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

    /// AC-PRF-11: rotation changes the token and keeps the user name and the password.
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

    /// AC-PRF-12 and AC-PRF-30: removal is idempotent.
    #[test]
    fn forget_is_idempotent() {
        let dir = temp_dir("forget");
        let (path, _) = setup(&dir, "corp", "domain\\alice", "s3cret-pass");
        assert!(forget(&path).expect("first"));
        assert!(!forget(&path).expect("second"));
        assert!(!path.exists());
        fs::remove_dir_all(&dir).ok();
    }

    /// AC-PRF-10: the list holds no secrets.
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

    /// Profile file extension is `.json`.
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

    /// AC-PRF-27: a name with path characters is refused.
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

    /// AC-PRF-25: loose permissions give a warning, not a refusal.
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

    /// AC-PRF-03: the token is absent from the file and the directory.
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

    /// AC-PRF-26: the name canonicalization matches the header path.
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

    /// AC-PRF-31: rotation leaves no temporary files in the directory.
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

    /// AC-PRF-32: a repeated load does not change the file.
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
