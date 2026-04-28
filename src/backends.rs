use crate::{AuthorityError, Result};
use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;
use std::process::Command;

#[derive(Debug, Clone)]
pub struct SecretLease {
    value: String,
}

impl SecretLease {
    pub fn expose_to_provider(&self) -> &str {
        &self.value
    }
}

pub trait SecretBackend: Send + Sync {
    fn resolve(&self, reference: &str) -> Result<SecretLease>;
}

#[derive(Debug, Clone)]
pub struct FakeBackend {
    values: BTreeMap<String, String>,
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

#[derive(Debug, Clone)]
pub struct EnvFileBackend {
    values: BTreeMap<String, String>,
}

impl EnvFileBackend {
    pub fn load(path: PathBuf) -> Result<Self> {
        let text = fs::read_to_string(path)?;
        let mut values = BTreeMap::new();
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if let Some((key, value)) = line.split_once('=') {
                values.insert(key.trim().into(), value.trim_matches('"').into());
            }
        }
        Ok(Self { values })
    }
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
pub struct OnePasswordBackend;

impl SecretBackend for OnePasswordBackend {
    fn resolve(&self, reference: &str) -> Result<SecretLease> {
        let output = Command::new("op")
            .arg("read")
            .arg(reference)
            .output()
            .map_err(|err| AuthorityError::SecretBackend(format!("failed to run op: {err}")))?;
        if !output.status.success() {
            return Err(AuthorityError::SecretBackend(
                "1Password did not return secret reference".into(),
            ));
        }
        let value = String::from_utf8_lossy(&output.stdout).trim().to_string();
        Ok(SecretLease { value })
    }
}

#[derive(Debug, Clone)]
pub struct OsKeychainBackend {
    service: String,
}

impl OsKeychainBackend {
    pub fn new(service: impl Into<String>) -> Self {
        Self {
            service: service.into(),
        }
    }
}

impl SecretBackend for OsKeychainBackend {
    fn resolve(&self, reference: &str) -> Result<SecretLease> {
        let entry = keyring::Entry::new(&self.service, reference)
            .map_err(|err| AuthorityError::SecretBackend(format!("keychain entry error: {err}")))?;
        let value = entry
            .get_password()
            .map_err(|err| AuthorityError::SecretBackend(format!("keychain read error: {err}")))?;
        Ok(SecretLease { value })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
