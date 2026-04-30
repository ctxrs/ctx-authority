use crate::backends::SecretBackendConfig;
use crate::capabilities::validate_capability_grants;
use crate::grants::validate_http_grants;
use crate::policy::is_valid_http_path_prefix;
use crate::{AuthorityError, Result};
use directories::ProjectDirs;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub struct AppPaths {
    pub home: PathBuf,
    pub config_file: PathBuf,
    pub audit_db: PathBuf,
    pub signing_key: PathBuf,
}

impl AppPaths {
    pub fn discover() -> Result<Self> {
        if let Ok(home) = std::env::var("CTXA_HOME") {
            return Ok(Self::for_home(PathBuf::from(home)));
        }

        let dirs = ProjectDirs::from("rs", "ctx", "authority").ok_or_else(|| {
            AuthorityError::Config("could not resolve project directories".into())
        })?;
        Ok(Self::for_home(dirs.config_dir().to_path_buf()))
    }

    pub fn for_home(home: PathBuf) -> Self {
        Self {
            config_file: home.join("config.yaml"),
            audit_db: home.join("audit.sqlite3"),
            signing_key: home.join("receipt-signing.key"),
            home,
        }
    }

    pub fn ensure(&self) -> Result<()> {
        fs::create_dir_all(&self.home)?;
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct AppConfig {
    #[serde(default)]
    pub agents: Vec<AgentConfig>,
    #[serde(default)]
    pub policies: Vec<PolicyConfig>,
    #[serde(default)]
    pub profiles: Vec<ProfileConfig>,
    #[serde(default)]
    pub grants: Vec<HttpGrantConfig>,
    #[serde(default)]
    pub capability_providers: Vec<CapabilityProviderConfig>,
    #[serde(default)]
    pub capability_grants: Vec<CapabilityGrantConfig>,
    #[serde(default)]
    pub secret_backend: Option<SecretBackendConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentConfig {
    pub id: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub policy: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyConfig {
    pub id: String,
    pub path: String,
    pub hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProfileConfig {
    pub id: String,
    #[serde(default)]
    pub agent: Option<String>,
    #[serde(default, rename = "env")]
    pub env_vars: BTreeMap<String, String>,
    #[serde(default)]
    pub http_resources: Vec<HttpResourceConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct HttpResourceConfig {
    pub id: String,
    #[serde(default = "default_http_resource_scheme")]
    pub scheme: HttpResourceScheme,
    pub host: String,
    pub secret_ref: String,
    #[serde(default)]
    pub auth: HttpAuthConfig,
    #[serde(default)]
    pub allow: HttpAllowConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct HttpGrantConfig {
    pub id: String,
    #[serde(default)]
    pub parent: Option<String>,
    pub profile: String,
    pub subject: String,
    #[serde(default = "default_http_resource_scheme")]
    pub scheme: HttpResourceScheme,
    pub host: String,
    #[serde(default)]
    pub secret_ref: Option<String>,
    #[serde(default)]
    pub allow: HttpAllowConfig,
    #[serde(default)]
    pub delegation: GrantDelegationConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CapabilityProviderConfig {
    pub id: String,
    #[serde(rename = "type")]
    pub kind: CapabilityProviderKind,
    pub api_base: String,
    pub auth: CapabilityProviderAuthConfig,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum CapabilityProviderKind {
    Github,
    Google,
    Microsoft,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "kebab-case", deny_unknown_fields)]
pub enum CapabilityProviderAuthConfig {
    Bearer {
        token_ref: String,
    },
    GithubAppInstallation {
        app_jwt_ref: String,
        installation_id: u64,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CapabilityGrantConfig {
    pub id: String,
    #[serde(default)]
    pub parent: Option<String>,
    pub profile: String,
    pub subject: String,
    pub provider: String,
    pub capabilities: Vec<String>,
    pub resources: Vec<String>,
    #[serde(default)]
    pub constraints: CapabilityGrantConstraints,
    #[serde(default)]
    pub delegation: GrantDelegationConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CapabilityGrantConstraints {
    #[serde(default)]
    pub operation_equals: BTreeMap<String, Value>,
    #[serde(default)]
    pub payload_equals: BTreeMap<String, Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct GrantDelegationConfig {
    #[serde(default)]
    pub allowed: bool,
    #[serde(default)]
    pub remaining_depth: u8,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum HttpResourceScheme {
    Http,
    Https,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct HttpAuthConfig {
    #[serde(rename = "type", default = "default_http_auth_type")]
    pub kind: HttpAuthType,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum HttpAuthType {
    Bearer,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct HttpAllowConfig {
    #[serde(default)]
    pub methods: Vec<String>,
    #[serde(default)]
    pub path_prefixes: Vec<String>,
}

impl Default for HttpAuthConfig {
    fn default() -> Self {
        Self {
            kind: default_http_auth_type(),
        }
    }
}

fn default_http_auth_type() -> HttpAuthType {
    HttpAuthType::Bearer
}

fn default_http_resource_scheme() -> HttpResourceScheme {
    HttpResourceScheme::Https
}

impl AppConfig {
    pub fn load(path: &Path) -> Result<Self> {
        if !path.exists() {
            return Ok(Self::default());
        }
        let text = fs::read_to_string(path)?;
        let config: Self = serde_yaml::from_str(&text)?;
        config.validate()?;
        Ok(config)
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        self.validate()?;
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(path, serde_yaml::to_string(self)?)?;
        Ok(())
    }

    pub fn validate(&self) -> Result<()> {
        ensure_unique_ids("agent", self.agents.iter().map(|agent| agent.id.as_str()))?;
        ensure_unique_ids(
            "policy",
            self.policies.iter().map(|policy| policy.id.as_str()),
        )?;
        ensure_unique_ids(
            "profile",
            self.profiles.iter().map(|profile| profile.id.as_str()),
        )?;
        ensure_unique_ids("grant", self.grants.iter().map(|grant| grant.id.as_str()))?;
        ensure_unique_ids(
            "capability provider",
            self.capability_providers
                .iter()
                .map(|provider| provider.id.as_str()),
        )?;
        ensure_unique_ids(
            "capability grant",
            self.capability_grants.iter().map(|grant| grant.id.as_str()),
        )?;
        for profile in &self.profiles {
            profile.validate()?;
        }
        for grant in &self.grants {
            grant.validate()?;
        }
        for provider in &self.capability_providers {
            provider.validate()?;
        }
        for grant in &self.capability_grants {
            grant.validate()?;
        }
        validate_http_grants(&self.profiles, &self.grants)?;
        validate_capability_grants(
            &self.profiles,
            &self.capability_providers,
            &self.capability_grants,
        )?;
        Ok(())
    }

    pub fn profile(&self, id: &str) -> Option<&ProfileConfig> {
        self.profiles.iter().find(|profile| profile.id == id)
    }

    pub fn profile_mut(&mut self, id: &str) -> Option<&mut ProfileConfig> {
        self.profiles.iter_mut().find(|profile| profile.id == id)
    }

    pub fn grant(&self, id: &str) -> Option<&HttpGrantConfig> {
        self.grants.iter().find(|grant| grant.id == id)
    }

    pub fn capability_provider(&self, id: &str) -> Option<&CapabilityProviderConfig> {
        self.capability_providers
            .iter()
            .find(|provider| provider.id == id)
    }

    pub fn capability_grant(&self, id: &str) -> Option<&CapabilityGrantConfig> {
        self.capability_grants.iter().find(|grant| grant.id == id)
    }
}

impl ProfileConfig {
    pub fn validate(&self) -> Result<()> {
        validate_id("profile", &self.id)?;
        if let Some(agent) = &self.agent {
            validate_id("profile agent", agent)?;
        }
        for key in self.env_vars.keys() {
            validate_env_key(key)?;
        }
        ensure_unique_ids(
            "http resource",
            self.http_resources
                .iter()
                .map(|resource| resource.id.as_str()),
        )?;
        for resource in &self.http_resources {
            resource.validate()?;
        }
        Ok(())
    }
}

impl HttpResourceConfig {
    pub fn validate(&self) -> Result<()> {
        validate_id("http resource", &self.id)?;
        validate_host(&self.host, self.scheme)?;
        if self.secret_ref.trim().is_empty() {
            return Err(AuthorityError::Config(format!(
                "http resource {} must specify secret_ref",
                self.id
            )));
        }
        if self.allow.methods.is_empty() {
            return Err(AuthorityError::Config(format!(
                "http resource {} must specify at least one method",
                self.id
            )));
        }
        if self.allow.path_prefixes.is_empty() {
            return Err(AuthorityError::Config(format!(
                "http resource {} must specify at least one path_prefix",
                self.id
            )));
        }
        for method in &self.allow.methods {
            validate_http_method(method)?;
        }
        for prefix in &self.allow.path_prefixes {
            if !is_valid_http_path_prefix(prefix) {
                return Err(AuthorityError::Config(format!(
                    "http resource {} has invalid path_prefix {}",
                    self.id, prefix
                )));
            }
        }
        Ok(())
    }
}

impl HttpGrantConfig {
    pub fn validate(&self) -> Result<()> {
        validate_id("grant", &self.id)?;
        if let Some(parent) = &self.parent {
            validate_id("grant parent", parent)?;
        }
        validate_id("grant profile", &self.profile)?;
        validate_id("grant subject", &self.subject)?;
        validate_host(&self.host, self.scheme)?;
        if let Some(secret_ref) = &self.secret_ref {
            if secret_ref.trim().is_empty() {
                return Err(AuthorityError::Config(format!(
                    "grant {} has an empty secret_ref",
                    self.id
                )));
            }
        }
        if self.allow.methods.is_empty() {
            return Err(AuthorityError::Config(format!(
                "grant {} must specify at least one method",
                self.id
            )));
        }
        if self.allow.path_prefixes.is_empty() {
            return Err(AuthorityError::Config(format!(
                "grant {} must specify at least one path_prefix",
                self.id
            )));
        }
        for method in &self.allow.methods {
            validate_http_method(method)?;
        }
        for prefix in &self.allow.path_prefixes {
            if !is_valid_http_path_prefix(prefix) {
                return Err(AuthorityError::Config(format!(
                    "grant {} has invalid path_prefix {}",
                    self.id, prefix
                )));
            }
        }
        if !self.delegation.allowed && self.delegation.remaining_depth != 0 {
            return Err(AuthorityError::Config(format!(
                "grant {} has remaining_depth without delegation",
                self.id
            )));
        }
        if self.delegation.allowed && self.delegation.remaining_depth == 0 {
            return Err(AuthorityError::Config(format!(
                "grant {} allows delegation but has zero remaining_depth",
                self.id
            )));
        }
        Ok(())
    }
}

impl CapabilityProviderConfig {
    pub fn validate(&self) -> Result<()> {
        validate_id("capability provider", &self.id)?;
        validate_api_base(&self.api_base)?;
        match (&self.kind, &self.auth) {
            (
                CapabilityProviderKind::Github,
                CapabilityProviderAuthConfig::Bearer { token_ref },
            ) => validate_secret_ref("capability provider token_ref", token_ref),
            (
                CapabilityProviderKind::Github,
                CapabilityProviderAuthConfig::GithubAppInstallation {
                    app_jwt_ref,
                    installation_id,
                },
            ) => {
                validate_secret_ref("capability provider app_jwt_ref", app_jwt_ref)?;
                if *installation_id == 0 {
                    return Err(AuthorityError::Config(format!(
                        "capability provider {} has invalid installation_id",
                        self.id
                    )));
                }
                Ok(())
            }
            (
                CapabilityProviderKind::Google | CapabilityProviderKind::Microsoft,
                CapabilityProviderAuthConfig::Bearer { token_ref },
            ) => validate_secret_ref("capability provider token_ref", token_ref),
            (
                CapabilityProviderKind::Google | CapabilityProviderKind::Microsoft,
                CapabilityProviderAuthConfig::GithubAppInstallation { .. },
            ) => Err(AuthorityError::Config(format!(
                "capability provider {} uses GitHub App auth with a non-GitHub provider",
                self.id
            ))),
        }
    }
}

impl CapabilityGrantConfig {
    pub fn validate(&self) -> Result<()> {
        validate_id("capability grant", &self.id)?;
        if let Some(parent) = &self.parent {
            validate_id("capability grant parent", parent)?;
        }
        validate_id("capability grant profile", &self.profile)?;
        validate_id("capability grant subject", &self.subject)?;
        validate_id("capability grant provider", &self.provider)?;
        if self.capabilities.is_empty() {
            return Err(AuthorityError::Config(format!(
                "capability grant {} must specify at least one capability",
                self.id
            )));
        }
        if self.resources.is_empty() {
            return Err(AuthorityError::Config(format!(
                "capability grant {} must specify at least one resource",
                self.id
            )));
        }
        for capability in &self.capabilities {
            validate_capability_name(capability)?;
        }
        for resource in &self.resources {
            validate_resource_name(resource)?;
        }
        self.constraints.validate(self.id.as_str())?;
        if !self.delegation.allowed && self.delegation.remaining_depth != 0 {
            return Err(AuthorityError::Config(format!(
                "capability grant {} has remaining_depth without delegation",
                self.id
            )));
        }
        if self.delegation.allowed && self.delegation.remaining_depth == 0 {
            return Err(AuthorityError::Config(format!(
                "capability grant {} allows delegation but has zero remaining_depth",
                self.id
            )));
        }
        Ok(())
    }
}

impl CapabilityGrantConstraints {
    pub fn validate(&self, grant_id: &str) -> Result<()> {
        for key in self
            .operation_equals
            .keys()
            .chain(self.payload_equals.keys())
        {
            if key.is_empty() || key.len() > 128 || key.bytes().any(|byte| byte.is_ascii_control())
            {
                return Err(AuthorityError::Config(format!(
                    "capability grant {grant_id} has invalid constraint key"
                )));
            }
        }
        Ok(())
    }
}

fn ensure_unique_ids<'a>(label: &str, ids: impl Iterator<Item = &'a str>) -> Result<()> {
    let mut seen = std::collections::BTreeSet::new();
    for id in ids {
        if !seen.insert(id) {
            return Err(AuthorityError::Config(format!("duplicate {label} id {id}")));
        }
    }
    Ok(())
}

pub(crate) fn validate_id(label: &str, id: &str) -> Result<()> {
    if id.is_empty()
        || id.len() > 64
        || !id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err(AuthorityError::Config(format!(
            "invalid {label} id {id}; use letters, digits, '.', '_', or '-'"
        )));
    }
    Ok(())
}

fn validate_secret_ref(label: &str, secret_ref: &str) -> Result<()> {
    if secret_ref.trim().is_empty() {
        return Err(AuthorityError::Config(format!("{label} must not be empty")));
    }
    Ok(())
}

fn validate_capability_name(capability: &str) -> Result<()> {
    if capability.is_empty()
        || capability.len() > 128
        || capability.starts_with('.')
        || capability.ends_with('.')
        || capability.contains("..")
        || !capability
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'.')
    {
        return Err(AuthorityError::Config(format!(
            "invalid capability {capability}; use lowercase dotted names"
        )));
    }
    Ok(())
}

fn validate_resource_name(resource: &str) -> Result<()> {
    if resource.is_empty()
        || resource.len() > 512
        || resource.bytes().any(|byte| byte.is_ascii_control())
        || resource.contains(' ')
        || !resource.contains(':')
    {
        return Err(AuthorityError::Config(format!(
            "invalid resource {resource}; use a provider-prefixed resource id"
        )));
    }
    Ok(())
}

fn validate_api_base(api_base: &str) -> Result<()> {
    let url = reqwest::Url::parse(api_base)
        .map_err(|_| AuthorityError::Config("invalid api_base".into()))?;
    let Some(host) = url.host_str() else {
        return Err(AuthorityError::Config("invalid api_base".into()));
    };
    let loopback_http = url.scheme() == "http" && is_loopback_host(host);
    if !(url.scheme() == "https" || loopback_http)
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(AuthorityError::Config("invalid api_base".into()));
    }
    Ok(())
}

fn is_loopback_host(host: &str) -> bool {
    host.eq_ignore_ascii_case("localhost")
        || host
            .parse::<std::net::IpAddr>()
            .is_ok_and(|addr| addr.is_loopback())
}

fn validate_env_key(key: &str) -> Result<()> {
    const RESERVED_ENV_KEYS: &[&str] = &[
        "HTTP_PROXY",
        "http_proxy",
        "HTTPS_PROXY",
        "https_proxy",
        "ALL_PROXY",
        "all_proxy",
        "NO_PROXY",
        "no_proxy",
        "CTXA_PROFILE",
        "CTXA_PROXY_URL",
        "CTXA_PROXY_TOKEN",
    ];
    if RESERVED_ENV_KEYS.iter().any(|reserved| reserved == &key) {
        return Err(AuthorityError::Config(format!(
            "profile env key {key} is reserved"
        )));
    }
    let mut bytes = key.bytes();
    let Some(first) = bytes.next() else {
        return Err(AuthorityError::Config("empty profile env key".into()));
    };
    if !(first == b'_' || first.is_ascii_alphabetic()) {
        return Err(AuthorityError::Config(format!(
            "invalid profile env key {key}"
        )));
    }
    if !bytes.all(|byte| byte == b'_' || byte.is_ascii_alphanumeric()) {
        return Err(AuthorityError::Config(format!(
            "invalid profile env key {key}"
        )));
    }
    Ok(())
}

pub fn validate_http_method(method: &str) -> Result<()> {
    if method.is_empty()
        || method.len() > 32
        || !method
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'-')
    {
        return Err(AuthorityError::Config(format!(
            "invalid HTTP method {method}"
        )));
    }
    Ok(())
}

fn validate_host(host: &str, scheme: HttpResourceScheme) -> Result<()> {
    if canonical_host_port_for_scheme(host, scheme).is_none() {
        return Err(AuthorityError::Config(format!("invalid host {host}")));
    }
    Ok(())
}

pub fn canonical_host_port(host: &str) -> Option<String> {
    canonical_host_port_for_scheme(host, HttpResourceScheme::Http)
}

pub fn canonical_host_port_for_scheme(host: &str, scheme: HttpResourceScheme) -> Option<String> {
    if host.is_empty()
        || host.contains('@')
        || host.contains('[')
        || host.contains(']')
        || host.bytes().any(|byte| byte.is_ascii_control())
    {
        return None;
    }
    let (raw_host, port) = match host.rsplit_once(':') {
        Some((raw_host, raw_port)) => {
            if raw_host.contains(':') {
                return None;
            }
            let port = raw_port.parse::<u16>().ok()?;
            (raw_host, port)
        }
        None => (
            host,
            match scheme {
                HttpResourceScheme::Http => 80,
                HttpResourceScheme::Https => 443,
            },
        ),
    };
    let raw_host = raw_host.strip_suffix('.').unwrap_or(raw_host);
    if raw_host.is_empty() {
        return None;
    }
    if raw_host.starts_with('-') || raw_host.ends_with('-') || raw_host.contains("..") {
        return None;
    }
    if !raw_host
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-'))
    {
        return None;
    }
    Some(format!("{}:{port}", raw_host.to_ascii_lowercase()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn app_config_loads_secret_backend_without_requiring_cli_wiring() {
        let config: AppConfig = serde_yaml::from_str(
            r#"
secret_backend:
  type: env-file
  path: .env.local
"#,
        )
        .unwrap();

        let secret_backend = config.secret_backend.expect("secret backend");
        assert!(matches!(
            secret_backend,
            SecretBackendConfig::EnvFile { ref path } if path == Path::new(".env.local")
        ));
    }

    #[test]
    fn app_config_loads_profile_http_resources() {
        let config: AppConfig = serde_yaml::from_str(
            r#"
profiles:
  - id: github-reader
    agent: my-agent
    env:
      GITHUB_API_BASE: https://api.github.com
    http_resources:
      - id: github-issues
        scheme: https
        host: api.github.com
        secret_ref: op://example-vault/github-token/token
        auth:
          type: bearer
        allow:
          methods: [GET]
          path_prefixes: [/repos/example/repo/issues]
"#,
        )
        .unwrap();
        config.validate().unwrap();

        let profile = config.profile("github-reader").expect("profile");
        assert_eq!(
            profile.env_vars.get("GITHUB_API_BASE").map(String::as_str),
            Some("https://api.github.com")
        );
        let resource = profile.http_resources.first().expect("resource");
        assert_eq!(resource.id, "github-issues");
        assert_eq!(resource.scheme, HttpResourceScheme::Https);
        assert_eq!(resource.auth.kind, HttpAuthType::Bearer);
    }

    #[test]
    fn handwritten_http_resources_default_to_https() {
        let config: AppConfig = serde_yaml::from_str(
            r#"
profiles:
  - id: github-reader
    http_resources:
      - id: github-issues
        host: api.github.com
        secret_ref: github-token
        allow:
          methods: [GET]
          path_prefixes: [/repos/example/repo/issues]
"#,
        )
        .unwrap();
        config.validate().unwrap();

        let resource = &config.profile("github-reader").unwrap().http_resources[0];
        assert_eq!(resource.scheme, HttpResourceScheme::Https);
    }

    #[test]
    fn canonical_host_port_uses_scheme_default_ports() {
        assert_eq!(
            canonical_host_port_for_scheme("api.github.com", HttpResourceScheme::Http).as_deref(),
            Some("api.github.com:80")
        );
        assert_eq!(
            canonical_host_port_for_scheme("api.github.com", HttpResourceScheme::Https).as_deref(),
            Some("api.github.com:443")
        );
        assert_eq!(
            canonical_host_port_for_scheme("api.github.com:443", HttpResourceScheme::Https)
                .as_deref(),
            Some("api.github.com:443")
        );
        assert_eq!(
            canonical_host_port_for_scheme("api.github.com:80", HttpResourceScheme::Https)
                .as_deref(),
            Some("api.github.com:80")
        );
    }

    #[test]
    fn app_config_rejects_reserved_profile_env_keys() {
        let config: AppConfig = serde_yaml::from_str(
            r#"
profiles:
  - id: demo
    env:
      HTTP_PROXY: http://proxy.invalid
"#,
        )
        .unwrap();
        let err = config.validate().unwrap_err().to_string();
        assert!(err.contains("reserved"));
    }

    #[test]
    fn capability_provider_api_base_rejects_non_loopback_http_without_echoing_url() {
        let config: AppConfig = serde_yaml::from_str(
            r#"
capability_providers:
  - id: github
    type: github
    api_base: http://token@example.com:80/path?secret=value
    auth:
      type: bearer
      token_ref: github-token
"#,
        )
        .unwrap();
        let err = config.validate().unwrap_err().to_string();
        assert!(err.contains("invalid api_base"));
        assert!(!err.contains("token"));
        assert!(!err.contains("secret"));

        let config: AppConfig = serde_yaml::from_str(
            r#"
capability_providers:
  - id: github
    type: github
    api_base: http://127.0.0.1:8080
    auth:
      type: bearer
      token_ref: github-token
"#,
        )
        .unwrap();
        config.validate().unwrap();
    }

    #[test]
    fn canonical_host_port_normalizes_default_ports() {
        assert_eq!(
            canonical_host_port("API.Example.COM"),
            Some("api.example.com:80".into())
        );
        assert_eq!(
            canonical_host_port("api.example.com:8080"),
            Some("api.example.com:8080".into())
        );
        assert_eq!(
            canonical_host_port("api.example.com."),
            Some("api.example.com:80".into())
        );
        assert_eq!(canonical_host_port("[::1]:80"), None);
    }
}
