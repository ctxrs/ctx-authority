use crate::{AuthorityError, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt;
use std::fs;
use std::path::PathBuf;
use std::process::Command;

#[derive(Clone)]
pub struct SecretLease {
    value: String,
}

impl SecretLease {
    pub fn expose_to_provider(&self) -> &str {
        &self.value
    }
}

impl fmt::Debug for SecretLease {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretLease")
            .field("value", &"<redacted>")
            .finish()
    }
}

pub trait SecretBackend: Send + Sync {
    fn resolve(&self, reference: &str) -> Result<SecretLease>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SecretBackendKind {
    Fake,
    EnvFile,
    OnePassword,
    OsKeychain,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case", deny_unknown_fields)]
pub enum SecretBackendConfig {
    Fake {
        #[serde(default)]
        values: BTreeMap<String, String>,
    },
    EnvFile {
        path: PathBuf,
    },
    OnePassword {
        #[serde(default)]
        op_path: Option<PathBuf>,
    },
    OsKeychain {
        service: String,
    },
}

impl fmt::Debug for SecretBackendConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Fake { values } => formatter
                .debug_struct("Fake")
                .field("values", &format_args!("<{} redacted>", values.len()))
                .finish(),
            Self::EnvFile { path } => formatter
                .debug_struct("EnvFile")
                .field("path", path)
                .finish(),
            Self::OnePassword { op_path } => formatter
                .debug_struct("OnePassword")
                .field("op_path", op_path)
                .finish(),
            Self::OsKeychain { service } => formatter
                .debug_struct("OsKeychain")
                .field("service", service)
                .finish(),
        }
    }
}

impl SecretBackendConfig {
    pub fn kind(&self) -> SecretBackendKind {
        match self {
            Self::Fake { .. } => SecretBackendKind::Fake,
            Self::EnvFile { .. } => SecretBackendKind::EnvFile,
            Self::OnePassword { .. } => SecretBackendKind::OnePassword,
            Self::OsKeychain { .. } => SecretBackendKind::OsKeychain,
        }
    }

    pub fn build(&self) -> Result<Box<dyn SecretBackend>> {
        match self {
            Self::Fake { values } => Ok(Box::new(FakeBackend::new(values.clone()))),
            Self::EnvFile { path } => Ok(Box::new(EnvFileBackend::load(path.clone())?)),
            Self::OnePassword { op_path } => {
                let backend = op_path
                    .clone()
                    .map(OnePasswordBackend::with_command)
                    .unwrap_or_default();
                Ok(Box::new(backend))
            }
            Self::OsKeychain { service } => Ok(Box::new(OsKeychainBackend::new(service.clone()))),
        }
    }
}

#[derive(Clone)]
pub struct FakeBackend {
    values: BTreeMap<String, String>,
}

impl fmt::Debug for FakeBackend {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FakeBackend")
            .field("values", &format_args!("<{} redacted>", self.values.len()))
            .finish()
    }
}

impl FakeBackend {
    pub fn new(values: BTreeMap<String, String>) -> Self {
        Self { values }
    }
}

impl SecretBackend for FakeBackend {
    fn resolve(&self, reference: &str) -> Result<SecretLease> {
        let value = self
            .values
            .get(reference)
            .ok_or_else(|| AuthorityError::SecretBackend("secret reference not found".into()))?;
        Ok(SecretLease {
            value: value.clone(),
        })
    }
}

#[derive(Clone)]
pub struct EnvFileBackend {
    values: BTreeMap<String, String>,
}

impl fmt::Debug for EnvFileBackend {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EnvFileBackend")
            .field("values", &format_args!("<{} redacted>", self.values.len()))
            .finish()
    }
}

impl EnvFileBackend {
    pub fn load(path: PathBuf) -> Result<Self> {
        let text = fs::read_to_string(path)
            .map_err(|_| AuthorityError::SecretBackend("failed to read .env file".into()))?;
        Self::parse(&text)
    }

    pub fn parse(text: &str) -> Result<Self> {
        let mut values = BTreeMap::new();
        for (index, line) in text.lines().enumerate() {
            parse_env_line(index + 1, line, &mut values)?;
        }
        Ok(Self { values })
    }
}

fn parse_env_line(
    line_number: usize,
    line: &str,
    values: &mut BTreeMap<String, String>,
) -> Result<()> {
    let line = line.strip_prefix('\u{feff}').unwrap_or(line).trim_start();
    if line.is_empty() || line.starts_with('#') {
        return Ok(());
    }

    let line = line.strip_prefix("export ").unwrap_or(line).trim_start();
    let Some((raw_key, raw_value)) = line.split_once('=') else {
        return Err(env_parse_error(line_number, "missing '=' separator"));
    };

    let key = raw_key.trim();
    if !is_valid_env_key(key) {
        return Err(env_parse_error(line_number, "invalid key"));
    }

    let value = parse_env_value(raw_value, line_number)?;
    values.insert(key.to_string(), value);
    Ok(())
}

fn parse_env_value(raw_value: &str, line_number: usize) -> Result<String> {
    let raw_value = raw_value.trim_start();
    if raw_value.is_empty() {
        return Ok(String::new());
    }

    let mut chars = raw_value.chars();
    match chars.next() {
        Some('\'') => parse_single_quoted_value(chars, line_number),
        Some('"') => parse_double_quoted_value(chars, line_number),
        Some(first) => Ok(parse_unquoted_value(first, chars)),
        None => Ok(String::new()),
    }
}

fn parse_single_quoted_value(
    chars: impl Iterator<Item = char>,
    line_number: usize,
) -> Result<String> {
    let mut value = String::new();
    let mut closed = false;
    let mut remainder = String::new();

    for char in chars {
        if closed {
            remainder.push(char);
        } else if char == '\'' {
            closed = true;
        } else {
            value.push(char);
        }
    }

    if !closed {
        return Err(env_parse_error(line_number, "unterminated single quote"));
    }
    validate_value_remainder(&remainder, line_number)?;
    Ok(value)
}

fn parse_double_quoted_value(
    chars: impl Iterator<Item = char>,
    line_number: usize,
) -> Result<String> {
    let mut value = String::new();
    let mut closed = false;
    let mut escaped = false;
    let mut remainder = String::new();

    for char in chars {
        if closed {
            remainder.push(char);
        } else if escaped {
            value.push(match char {
                'n' => '\n',
                'r' => '\r',
                't' => '\t',
                '"' => '"',
                '\\' => '\\',
                '$' => '$',
                other => other,
            });
            escaped = false;
        } else if char == '\\' {
            escaped = true;
        } else if char == '"' {
            closed = true;
        } else {
            value.push(char);
        }
    }

    if escaped {
        value.push('\\');
    }
    if !closed {
        return Err(env_parse_error(line_number, "unterminated double quote"));
    }
    validate_value_remainder(&remainder, line_number)?;
    Ok(value)
}

fn parse_unquoted_value(first: char, chars: impl Iterator<Item = char>) -> String {
    let mut value = String::new();
    let mut escaped = false;
    let mut previous_was_whitespace = true;

    for char in std::iter::once(first).chain(chars) {
        if escaped {
            value.push(char);
            escaped = false;
            previous_was_whitespace = char.is_whitespace();
            continue;
        }

        if char == '\\' {
            escaped = true;
            continue;
        }

        if char == '#' && previous_was_whitespace {
            break;
        }

        previous_was_whitespace = char.is_whitespace();
        value.push(char);
    }

    if escaped {
        value.push('\\');
    }
    value.trim_end().to_string()
}

fn validate_value_remainder(remainder: &str, line_number: usize) -> Result<()> {
    let remainder = remainder.trim_start();
    if remainder.is_empty() || remainder.starts_with('#') {
        return Ok(());
    }
    Err(env_parse_error(
        line_number,
        "unexpected characters after quoted value",
    ))
}

fn is_valid_env_key(key: &str) -> bool {
    let mut chars = key.chars();
    matches!(chars.next(), Some(first) if first == '_' || first.is_ascii_alphabetic())
        && chars.all(|char| char == '_' || char.is_ascii_alphanumeric())
}

fn env_parse_error(line_number: usize, reason: &str) -> AuthorityError {
    AuthorityError::SecretBackend(format!("invalid .env file at line {line_number}: {reason}"))
}

impl SecretBackend for EnvFileBackend {
    fn resolve(&self, reference: &str) -> Result<SecretLease> {
        let value = self
            .values
            .get(reference)
            .ok_or_else(|| AuthorityError::SecretBackend("secret reference not found".into()))?;
        Ok(SecretLease {
            value: value.clone(),
        })
    }
}

#[derive(Debug, Clone)]
pub struct OnePasswordBackend {
    command: PathBuf,
}

impl Default for OnePasswordBackend {
    fn default() -> Self {
        Self {
            command: PathBuf::from("op"),
        }
    }
}

impl OnePasswordBackend {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_command(command: PathBuf) -> Self {
        Self { command }
    }
}

impl SecretBackend for OnePasswordBackend {
    fn resolve(&self, reference: &str) -> Result<SecretLease> {
        if !reference.starts_with("op://") {
            return Err(AuthorityError::SecretBackend(
                "1Password references must use op:// secret reference syntax".into(),
            ));
        }

        let output = Command::new(&self.command)
            .arg("read")
            .arg(reference)
            .output()
            .map_err(|err| AuthorityError::SecretBackend(format!("failed to run op: {err}")))?;
        if !output.status.success() {
            return Err(AuthorityError::SecretBackend(
                "1Password CLI read failed".into(),
            ));
        }
        let value = String::from_utf8(output.stdout).map_err(|_| {
            AuthorityError::SecretBackend("1Password CLI returned non-UTF-8 secret".into())
        })?;
        let value = strip_trailing_line_ending(value);
        Ok(SecretLease { value })
    }
}

fn strip_trailing_line_ending(mut value: String) -> String {
    if value.ends_with('\n') {
        value.pop();
        if value.ends_with('\r') {
            value.pop();
        }
    }
    value
}

pub trait KeychainStore: Send + Sync {
    fn get_password(&self, service: &str, account: &str) -> Result<String>;
}

#[derive(Debug, Clone, Default)]
pub struct SystemKeychainStore;

impl KeychainStore for SystemKeychainStore {
    fn get_password(&self, service: &str, account: &str) -> Result<String> {
        let entry = keyring::Entry::new(service, account)
            .map_err(|_| AuthorityError::SecretBackend("keychain entry error".into()))?;
        entry
            .get_password()
            .map_err(|_| AuthorityError::SecretBackend("keychain read error".into()))
    }
}

#[derive(Debug, Clone)]
pub struct OsKeychainBackend<S = SystemKeychainStore> {
    service: String,
    store: S,
}

impl OsKeychainBackend<SystemKeychainStore> {
    pub fn new(service: impl Into<String>) -> Self {
        Self {
            service: service.into(),
            store: SystemKeychainStore,
        }
    }
}

impl<S> OsKeychainBackend<S>
where
    S: KeychainStore,
{
    pub fn with_store(service: impl Into<String>, store: S) -> Self {
        Self {
            service: service.into(),
            store,
        }
    }
}

impl<S> SecretBackend for OsKeychainBackend<S>
where
    S: KeychainStore,
{
    fn resolve(&self, reference: &str) -> Result<SecretLease> {
        let value = self
            .store
            .get_password(&self.service, reference)
            .map_err(|_| AuthorityError::SecretBackend("keychain read error".into()))?;
        Ok(SecretLease { value })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(unix)]
    use std::io::Write;
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn fake_backend_resolves_without_exposing_in_error() {
        let backend = FakeBackend::new(BTreeMap::from([("github".into(), "secret-value".into())]));
        assert_eq!(
            backend.resolve("github").unwrap().expose_to_provider(),
            "secret-value"
        );
        let err = backend.resolve("missing").unwrap_err().to_string();
        assert!(!err.contains("secret-value"));
    }

    #[test]
    fn secret_lease_debug_redacts_value() {
        let lease = SecretLease {
            value: "secret-value".into(),
        };
        assert!(!format!("{lease:?}").contains("secret-value"));

        let backend = FakeBackend::new(BTreeMap::from([("github".into(), "secret-value".into())]));
        assert!(!format!("{backend:?}").contains("secret-value"));

        let config = SecretBackendConfig::Fake {
            values: BTreeMap::from([("github".into(), "secret-value".into())]),
        };
        assert!(!format!("{config:?}").contains("secret-value"));
    }

    #[test]
    fn env_file_parser_handles_common_dotenv_syntax() {
        let backend = EnvFileBackend::parse(include_str!("../tests/fixtures/env-backend.env"))
            .expect("fixture should parse");

        assert_eq!(
            backend.resolve("PLAIN").unwrap().expose_to_provider(),
            "abc"
        );
        assert_eq!(
            backend.resolve("SPACED").unwrap().expose_to_provider(),
            "value with spaces"
        );
        assert_eq!(
            backend.resolve("QUOTED_HASH").unwrap().expose_to_provider(),
            "value#not-comment"
        );
        assert_eq!(
            backend
                .resolve("SINGLE_QUOTED")
                .unwrap()
                .expose_to_provider(),
            "literal \\n value"
        );
        assert_eq!(
            backend
                .resolve("DOUBLE_QUOTED")
                .unwrap()
                .expose_to_provider(),
            "line\nnext\tend"
        );
        assert_eq!(
            backend
                .resolve("ESCAPED_HASH")
                .unwrap()
                .expose_to_provider(),
            "value#still-value"
        );
        assert_eq!(backend.resolve("EMPTY").unwrap().expose_to_provider(), "");
    }

    #[test]
    fn env_file_parser_rejects_invalid_lines_without_value_leakage() {
        let secret = "super-secret-value";
        for text in [
            format!("BAD-KEY={secret}"),
            format!("TOKEN=\"{secret}"),
            format!("TOKEN='{secret}"),
            format!("TOKEN=\"{secret}\" trailing"),
        ] {
            let err = EnvFileBackend::parse(&text).unwrap_err().to_string();
            assert!(!err.contains(secret), "{err}");
        }
    }

    #[test]
    fn backend_config_builds_fake_backend() {
        let config = SecretBackendConfig::Fake {
            values: BTreeMap::from([("token".into(), "secret-value".into())]),
        };
        assert_eq!(config.kind(), SecretBackendKind::Fake);
        assert_eq!(
            config
                .build()
                .unwrap()
                .resolve("token")
                .unwrap()
                .expose_to_provider(),
            "secret-value"
        );
    }

    #[test]
    fn one_password_rejects_non_secret_references_before_running_command() {
        let backend = OnePasswordBackend::with_command(PathBuf::from("missing-op"));
        let err = backend.resolve("plain-reference").unwrap_err().to_string();
        assert!(err.contains("op://"));
        assert!(!err.contains("plain-reference"));
    }

    #[test]
    fn one_password_preserves_secret_whitespace_except_trailing_line_ending() {
        assert_eq!(
            strip_trailing_line_ending("  secret value  \n".into()),
            "  secret value  "
        );
        assert_eq!(
            strip_trailing_line_ending("secret value\r\n".into()),
            "secret value"
        );
    }

    #[cfg(unix)]
    #[test]
    fn one_password_uses_op_read_without_real_account() {
        let dir = tempfile::tempdir().unwrap();
        let op = dir.path().join("op");
        let mut file = fs::File::create(&op).unwrap();
        writeln!(
            file,
            r#"#!/bin/sh
if [ "$1" != "read" ]; then exit 9; fi
if [ "$2" != "op://vault/item/field" ]; then exit 8; fi
printf '  secret value  \n'
"#
        )
        .unwrap();
        file.flush().unwrap();
        let mut permissions = fs::metadata(&op).unwrap().permissions();
        permissions.set_mode(0o700);
        fs::set_permissions(&op, permissions).unwrap();

        let backend = OnePasswordBackend::with_command(op);
        assert_eq!(
            backend
                .resolve("op://vault/item/field")
                .unwrap()
                .expose_to_provider(),
            "  secret value  "
        );
    }

    #[cfg(unix)]
    #[test]
    fn one_password_failure_does_not_leak_command_output() {
        let dir = tempfile::tempdir().unwrap();
        let op = dir.path().join("op");
        let mut file = fs::File::create(&op).unwrap();
        writeln!(
            file,
            r#"#!/bin/sh
printf 'secret-from-stdout\n'
printf 'secret-from-stderr\n' >&2
exit 1
"#
        )
        .unwrap();
        file.flush().unwrap();
        let mut permissions = fs::metadata(&op).unwrap().permissions();
        permissions.set_mode(0o700);
        fs::set_permissions(&op, permissions).unwrap();

        let backend = OnePasswordBackend::with_command(op);
        let err = backend
            .resolve("op://vault/item/field")
            .unwrap_err()
            .to_string();
        assert!(!err.contains("secret-from-stdout"), "{err}");
        assert!(!err.contains("secret-from-stderr"), "{err}");
        assert!(!err.contains("op://vault/item/field"), "{err}");
    }

    #[derive(Debug, Clone)]
    struct FakeKeychainStore {
        values: BTreeMap<(String, String), String>,
    }

    impl KeychainStore for FakeKeychainStore {
        fn get_password(&self, service: &str, account: &str) -> Result<String> {
            self.values
                .get(&(service.to_string(), account.to_string()))
                .cloned()
                .ok_or_else(|| AuthorityError::SecretBackend("fake keychain miss".into()))
        }
    }

    #[test]
    fn os_keychain_backend_can_use_fake_store() {
        let backend = OsKeychainBackend::with_store(
            "authority-broker",
            FakeKeychainStore {
                values: BTreeMap::from([(
                    ("authority-broker".into(), "github".into()),
                    "secret-value".into(),
                )]),
            },
        );

        assert_eq!(
            backend.resolve("github").unwrap().expose_to_provider(),
            "secret-value"
        );
        let err = backend.resolve("missing").unwrap_err().to_string();
        assert!(!err.contains("secret-value"));
    }
}
