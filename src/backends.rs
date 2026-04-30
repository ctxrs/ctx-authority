use crate::{AuthorityError, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt;
use std::fs;
use std::io::{Read, Seek, SeekFrom};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};
#[cfg(unix)]
use std::{os::unix::process::CommandExt, process::Child};

const DEFAULT_COMMAND_TIMEOUT_MS: u64 = 10_000;
const MAX_COMMAND_OUTPUT_BYTES: usize = 1024 * 1024;

#[cfg(unix)]
const SIGKILL: i32 = 9;
#[cfg(unix)]
const RLIMIT_FSIZE: i32 = 1;

#[cfg(unix)]
unsafe extern "C" {
    fn kill(pid: i32, sig: i32) -> i32;
    fn setrlimit(resource: i32, rlp: *const RLimit) -> i32;
}

#[cfg(unix)]
#[repr(C)]
struct RLimit {
    rlim_cur: u64,
    rlim_max: u64,
}

#[derive(Clone)]
pub struct SecretLease {
    value: String,
}

impl SecretLease {
    pub fn new(value: impl Into<String>) -> Self {
        Self {
            value: value.into(),
        }
    }

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
    BitwardenSecretsManager,
    Doppler,
    Infisical,
    HashicorpVault,
    AwsSecretsManager,
    AwsSsmParameterStore,
    GcpSecretManager,
    AzureKeyVault,
    Sops,
    TrustedCommand,
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
        #[serde(default)]
        timeout_ms: Option<u64>,
    },
    OsKeychain {
        service: String,
    },
    BitwardenSecretsManager {
        #[serde(default)]
        bws_path: Option<PathBuf>,
        #[serde(default)]
        timeout_ms: Option<u64>,
    },
    Doppler {
        #[serde(default)]
        doppler_path: Option<PathBuf>,
        #[serde(default)]
        project: Option<String>,
        #[serde(default)]
        config: Option<String>,
        #[serde(default)]
        timeout_ms: Option<u64>,
    },
    Infisical {
        #[serde(default)]
        infisical_path: Option<PathBuf>,
        #[serde(default)]
        env: Option<String>,
        #[serde(default)]
        path: Option<String>,
        #[serde(default)]
        project_id: Option<String>,
        #[serde(default)]
        timeout_ms: Option<u64>,
    },
    HashicorpVault {
        #[serde(default)]
        vault_path: Option<PathBuf>,
        #[serde(default)]
        mount: Option<String>,
        #[serde(default)]
        timeout_ms: Option<u64>,
    },
    AwsSecretsManager {
        #[serde(default)]
        aws_path: Option<PathBuf>,
        #[serde(default)]
        profile: Option<String>,
        #[serde(default)]
        region: Option<String>,
        #[serde(default)]
        timeout_ms: Option<u64>,
    },
    AwsSsmParameterStore {
        #[serde(default)]
        aws_path: Option<PathBuf>,
        #[serde(default)]
        profile: Option<String>,
        #[serde(default)]
        region: Option<String>,
        #[serde(default)]
        timeout_ms: Option<u64>,
    },
    GcpSecretManager {
        #[serde(default)]
        gcloud_path: Option<PathBuf>,
        #[serde(default)]
        project: Option<String>,
        #[serde(default)]
        default_version: Option<String>,
        #[serde(default)]
        timeout_ms: Option<u64>,
    },
    AzureKeyVault {
        vault_name: String,
        #[serde(default)]
        az_path: Option<PathBuf>,
        #[serde(default)]
        timeout_ms: Option<u64>,
    },
    Sops {
        file: PathBuf,
        #[serde(default)]
        sops_path: Option<PathBuf>,
        #[serde(default)]
        timeout_ms: Option<u64>,
    },
    TrustedCommand {
        command: PathBuf,
        #[serde(default)]
        args: Vec<String>,
        #[serde(default)]
        json_pointer: Option<String>,
        #[serde(default)]
        timeout_ms: Option<u64>,
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
            Self::OnePassword {
                op_path,
                timeout_ms,
            } => formatter
                .debug_struct("OnePassword")
                .field("op_path", op_path)
                .field("timeout_ms", timeout_ms)
                .finish(),
            Self::OsKeychain { service } => formatter
                .debug_struct("OsKeychain")
                .field("service", service)
                .finish(),
            Self::BitwardenSecretsManager {
                bws_path,
                timeout_ms,
            } => formatter
                .debug_struct("BitwardenSecretsManager")
                .field("bws_path", bws_path)
                .field("timeout_ms", timeout_ms)
                .finish(),
            Self::Doppler {
                doppler_path,
                project,
                config,
                timeout_ms,
            } => formatter
                .debug_struct("Doppler")
                .field("doppler_path", doppler_path)
                .field("project", project)
                .field("config", config)
                .field("timeout_ms", timeout_ms)
                .finish(),
            Self::Infisical {
                infisical_path,
                env,
                path,
                project_id,
                timeout_ms,
            } => formatter
                .debug_struct("Infisical")
                .field("infisical_path", infisical_path)
                .field("env", env)
                .field("path", path)
                .field("project_id", project_id)
                .field("timeout_ms", timeout_ms)
                .finish(),
            Self::HashicorpVault {
                vault_path,
                mount,
                timeout_ms,
            } => formatter
                .debug_struct("HashicorpVault")
                .field("vault_path", vault_path)
                .field("mount", mount)
                .field("timeout_ms", timeout_ms)
                .finish(),
            Self::AwsSecretsManager {
                aws_path,
                profile,
                region,
                timeout_ms,
            } => formatter
                .debug_struct("AwsSecretsManager")
                .field("aws_path", aws_path)
                .field("profile", profile)
                .field("region", region)
                .field("timeout_ms", timeout_ms)
                .finish(),
            Self::AwsSsmParameterStore {
                aws_path,
                profile,
                region,
                timeout_ms,
            } => formatter
                .debug_struct("AwsSsmParameterStore")
                .field("aws_path", aws_path)
                .field("profile", profile)
                .field("region", region)
                .field("timeout_ms", timeout_ms)
                .finish(),
            Self::GcpSecretManager {
                gcloud_path,
                project,
                default_version,
                timeout_ms,
            } => formatter
                .debug_struct("GcpSecretManager")
                .field("gcloud_path", gcloud_path)
                .field("project", project)
                .field("default_version", default_version)
                .field("timeout_ms", timeout_ms)
                .finish(),
            Self::AzureKeyVault {
                vault_name,
                az_path,
                timeout_ms,
            } => formatter
                .debug_struct("AzureKeyVault")
                .field("vault_name", vault_name)
                .field("az_path", az_path)
                .field("timeout_ms", timeout_ms)
                .finish(),
            Self::Sops {
                file,
                sops_path,
                timeout_ms,
            } => formatter
                .debug_struct("Sops")
                .field("file", file)
                .field("sops_path", sops_path)
                .field("timeout_ms", timeout_ms)
                .finish(),
            Self::TrustedCommand {
                command,
                args,
                json_pointer,
                timeout_ms,
            } => formatter
                .debug_struct("TrustedCommand")
                .field("command", command)
                .field("args", &format_args!("<{} redacted>", args.len()))
                .field("json_pointer", json_pointer)
                .field("timeout_ms", timeout_ms)
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
            Self::BitwardenSecretsManager { .. } => SecretBackendKind::BitwardenSecretsManager,
            Self::Doppler { .. } => SecretBackendKind::Doppler,
            Self::Infisical { .. } => SecretBackendKind::Infisical,
            Self::HashicorpVault { .. } => SecretBackendKind::HashicorpVault,
            Self::AwsSecretsManager { .. } => SecretBackendKind::AwsSecretsManager,
            Self::AwsSsmParameterStore { .. } => SecretBackendKind::AwsSsmParameterStore,
            Self::GcpSecretManager { .. } => SecretBackendKind::GcpSecretManager,
            Self::AzureKeyVault { .. } => SecretBackendKind::AzureKeyVault,
            Self::Sops { .. } => SecretBackendKind::Sops,
            Self::TrustedCommand { .. } => SecretBackendKind::TrustedCommand,
        }
    }

    pub fn build(&self) -> Result<Box<dyn SecretBackend>> {
        match self {
            Self::Fake { values } => Ok(Box::new(FakeBackend::new(values.clone()))),
            Self::EnvFile { path } => Ok(Box::new(EnvFileBackend::load(path.clone())?)),
            Self::OnePassword {
                op_path,
                timeout_ms,
            } => {
                let backend = op_path
                    .clone()
                    .map(OnePasswordBackend::with_command)
                    .unwrap_or_default()
                    .with_timeout_ms(*timeout_ms);
                Ok(Box::new(backend))
            }
            Self::OsKeychain { service } => Ok(Box::new(OsKeychainBackend::new(service.clone()))),
            Self::BitwardenSecretsManager {
                bws_path,
                timeout_ms,
            } => Ok(Box::new(BitwardenSecretsManagerBackend::new(
                bws_path.clone().unwrap_or_else(|| PathBuf::from("bws")),
                timeout_from_config(*timeout_ms),
            ))),
            Self::Doppler {
                doppler_path,
                project,
                config,
                timeout_ms,
            } => Ok(Box::new(DopplerBackend::new(
                doppler_path
                    .clone()
                    .unwrap_or_else(|| PathBuf::from("doppler")),
                project.clone(),
                config.clone(),
                timeout_from_config(*timeout_ms),
            ))),
            Self::Infisical {
                infisical_path,
                env,
                path,
                project_id,
                timeout_ms,
            } => Ok(Box::new(InfisicalBackend::new(
                infisical_path
                    .clone()
                    .unwrap_or_else(|| PathBuf::from("infisical")),
                env.clone(),
                path.clone(),
                project_id.clone(),
                timeout_from_config(*timeout_ms),
            ))),
            Self::HashicorpVault {
                vault_path,
                mount,
                timeout_ms,
            } => Ok(Box::new(HashicorpVaultBackend::new(
                vault_path.clone().unwrap_or_else(|| PathBuf::from("vault")),
                mount.clone(),
                timeout_from_config(*timeout_ms),
            ))),
            Self::AwsSecretsManager {
                aws_path,
                profile,
                region,
                timeout_ms,
            } => Ok(Box::new(AwsSecretsManagerBackend::new(
                aws_path.clone().unwrap_or_else(|| PathBuf::from("aws")),
                profile.clone(),
                region.clone(),
                timeout_from_config(*timeout_ms),
            ))),
            Self::AwsSsmParameterStore {
                aws_path,
                profile,
                region,
                timeout_ms,
            } => Ok(Box::new(AwsSsmParameterStoreBackend::new(
                aws_path.clone().unwrap_or_else(|| PathBuf::from("aws")),
                profile.clone(),
                region.clone(),
                timeout_from_config(*timeout_ms),
            ))),
            Self::GcpSecretManager {
                gcloud_path,
                project,
                default_version,
                timeout_ms,
            } => Ok(Box::new(GcpSecretManagerBackend::new(
                gcloud_path
                    .clone()
                    .unwrap_or_else(|| PathBuf::from("gcloud")),
                project.clone(),
                default_version.clone().unwrap_or_else(|| "latest".into()),
                timeout_from_config(*timeout_ms),
            ))),
            Self::AzureKeyVault {
                vault_name,
                az_path,
                timeout_ms,
            } => Ok(Box::new(AzureKeyVaultBackend::new(
                az_path.clone().unwrap_or_else(|| PathBuf::from("az")),
                vault_name.clone(),
                timeout_from_config(*timeout_ms),
            ))),
            Self::Sops {
                file,
                sops_path,
                timeout_ms,
            } => Ok(Box::new(SopsBackend::new(
                sops_path.clone().unwrap_or_else(|| PathBuf::from("sops")),
                file.clone(),
                timeout_from_config(*timeout_ms),
            ))),
            Self::TrustedCommand {
                command,
                args,
                json_pointer,
                timeout_ms,
            } => Ok(Box::new(TrustedCommandBackend::new(
                command.clone(),
                args.clone(),
                json_pointer.clone(),
                timeout_from_config(*timeout_ms),
            ))),
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
        Ok(SecretLease::new(value.clone()))
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
        Ok(SecretLease::new(value.clone()))
    }
}

#[derive(Debug, Clone, Copy)]
enum SecretCommandOutput {
    Plain,
    JsonPointer(&'static str),
    ConfiguredJsonPointer,
}

#[derive(Debug, Clone)]
struct SecretCommand {
    provider: &'static str,
    command: PathBuf,
    args: Vec<String>,
    env: Vec<(String, String)>,
    timeout: Duration,
    output: SecretCommandOutput,
    configured_json_pointer: Option<String>,
}

fn timeout_from_config(timeout_ms: Option<u64>) -> Duration {
    Duration::from_millis(timeout_ms.unwrap_or(DEFAULT_COMMAND_TIMEOUT_MS).max(1))
}

fn provider_error(provider: &str, reason: &str) -> AuthorityError {
    AuthorityError::SecretBackend(format!("{provider} {reason}"))
}

fn run_secret_command(spec: SecretCommand) -> Result<SecretLease> {
    let mut stdout_file = tempfile::tempfile()
        .map_err(|_| provider_error(spec.provider, "temporary output file failed"))?;
    let stderr_file = tempfile::tempfile()
        .map_err(|_| provider_error(spec.provider, "temporary output file failed"))?;
    let child_stdout = stdout_file
        .try_clone()
        .map_err(|_| provider_error(spec.provider, "temporary output file failed"))?;
    let child_stderr = stderr_file
        .try_clone()
        .map_err(|_| provider_error(spec.provider, "temporary output file failed"))?;

    let mut command = Command::new(&spec.command);
    command
        .args(&spec.args)
        .stdin(Stdio::null())
        .stdout(Stdio::from(child_stdout))
        .stderr(Stdio::from(child_stderr));
    configure_command_process_boundary(&mut command);
    for (key, value) in &spec.env {
        command.env(key, value);
    }

    let mut child = command
        .spawn()
        .map_err(|_| provider_error(spec.provider, "command failed to start"))?;
    let started = Instant::now();

    let status = loop {
        if command_output_exceeds_limit(spec.provider, &stdout_file, &stderr_file)? {
            terminate_child_command(&mut child);
            return Err(provider_error(spec.provider, "command output too large"));
        }
        match child
            .try_wait()
            .map_err(|_| provider_error(spec.provider, "command wait failed"))?
        {
            Some(status) => break status,
            None if started.elapsed() >= spec.timeout => {
                terminate_child_command(&mut child);
                return Err(provider_error(spec.provider, "command timed out"));
            }
            None => thread::sleep(Duration::from_millis(10)),
        }
    };
    terminate_child_process_group(&child);
    if command_output_exceeds_limit(spec.provider, &stdout_file, &stderr_file)? {
        return Err(provider_error(spec.provider, "command output too large"));
    }

    if !status.success() {
        return Err(provider_error(spec.provider, "command returned an error"));
    }

    let stdout = read_limited_command_output(spec.provider, &mut stdout_file)?;
    match spec.output {
        SecretCommandOutput::Plain => {
            let value = String::from_utf8(stdout)
                .map_err(|_| provider_error(spec.provider, "command returned non-UTF-8 output"))?;
            Ok(SecretLease::new(strip_trailing_line_ending(value)))
        }
        SecretCommandOutput::JsonPointer(pointer) => secret_from_json_pointer(
            spec.provider,
            &stdout,
            pointer,
            PreserveJsonStringWhitespace::Yes,
        ),
        SecretCommandOutput::ConfiguredJsonPointer => {
            let pointer = spec.configured_json_pointer.as_deref().ok_or_else(|| {
                provider_error(spec.provider, "command JSON pointer is not configured")
            })?;
            secret_from_json_pointer(
                spec.provider,
                &stdout,
                pointer,
                PreserveJsonStringWhitespace::Yes,
            )
        }
    }
}

#[cfg(unix)]
fn configure_command_process_boundary(command: &mut Command) {
    command.process_group(0);
    unsafe {
        command.pre_exec(|| {
            let limit = RLimit {
                rlim_cur: MAX_COMMAND_OUTPUT_BYTES as u64,
                rlim_max: MAX_COMMAND_OUTPUT_BYTES as u64,
            };
            if setrlimit(RLIMIT_FSIZE, &limit) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
}

#[cfg(not(unix))]
fn configure_command_process_boundary(_command: &mut Command) {}

fn terminate_child_command(child: &mut std::process::Child) {
    terminate_child_process_group(child);
    let _ = child.kill();
    let _ = child.wait();
}

#[cfg(unix)]
fn terminate_child_process_group(child: &Child) {
    let process_group_id = child.id() as i32;
    if process_group_id > 0 {
        unsafe {
            let _ = kill(-process_group_id, SIGKILL);
        }
    }
}

#[cfg(not(unix))]
fn terminate_child_process_group(_child: &std::process::Child) {}

fn command_output_exceeds_limit(
    provider: &'static str,
    stdout_file: &fs::File,
    stderr_file: &fs::File,
) -> Result<bool> {
    let stdout_len = stdout_file
        .metadata()
        .map_err(|_| provider_error(provider, "command output read failed"))?
        .len();
    let stderr_len = stderr_file
        .metadata()
        .map_err(|_| provider_error(provider, "command output read failed"))?
        .len();
    Ok(stdout_len >= MAX_COMMAND_OUTPUT_BYTES as u64
        || stderr_len >= MAX_COMMAND_OUTPUT_BYTES as u64)
}

fn read_limited_command_output(provider: &'static str, file: &mut fs::File) -> Result<Vec<u8>> {
    file.seek(SeekFrom::Start(0))
        .map_err(|_| provider_error(provider, "command output read failed"))?;
    let mut stdout = Vec::new();
    file.take((MAX_COMMAND_OUTPUT_BYTES + 1) as u64)
        .read_to_end(&mut stdout)
        .map_err(|_| provider_error(provider, "command output read failed"))?;
    if stdout.len() > MAX_COMMAND_OUTPUT_BYTES {
        return Err(provider_error(provider, "command output too large"));
    }
    Ok(stdout)
}

#[derive(Debug, Clone, Copy)]
enum PreserveJsonStringWhitespace {
    Yes,
}

fn secret_from_json_pointer(
    provider: &'static str,
    stdout: &[u8],
    pointer: &str,
    _preserve: PreserveJsonStringWhitespace,
) -> Result<SecretLease> {
    let value: serde_json::Value = serde_json::from_slice(stdout)
        .map_err(|_| provider_error(provider, "command returned invalid JSON"))?;
    let secret = value
        .pointer(pointer)
        .and_then(|value| value.as_str())
        .ok_or_else(|| provider_error(provider, "command JSON did not contain a string secret"))?;
    Ok(SecretLease::new(secret.to_string()))
}

fn parse_prefixed_reference<'a>(
    provider: &'static str,
    reference: &'a str,
    prefix: &str,
) -> Result<&'a str> {
    let value = reference.strip_prefix(prefix).ok_or_else(|| {
        AuthorityError::SecretBackend(format!("{provider} reference has unsupported syntax"))
    })?;
    validate_reference_value(provider, value)?;
    Ok(value)
}

fn validate_reference_value(provider: &'static str, value: &str) -> Result<()> {
    if value.is_empty()
        || value.starts_with('-')
        || value
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
    {
        return Err(provider_error(provider, "reference has unsupported syntax"));
    }
    Ok(())
}

fn parse_fragment_reference<'a>(
    provider: &'static str,
    reference: &'a str,
    prefix: &str,
    default_fragment: Option<&'a str>,
) -> Result<(&'a str, &'a str)> {
    let value = reference.strip_prefix(prefix).ok_or_else(|| {
        AuthorityError::SecretBackend(format!("{provider} reference has unsupported syntax"))
    })?;
    let (path, fragment) = match value.split_once('#') {
        Some((path, fragment)) => (path, fragment),
        None => (
            value,
            default_fragment
                .ok_or_else(|| provider_error(provider, "reference has unsupported syntax"))?,
        ),
    };
    validate_reference_value(provider, path)?;
    validate_reference_value(provider, fragment)?;
    Ok((path, fragment))
}

#[derive(Debug, Clone)]
pub struct OnePasswordBackend {
    command: PathBuf,
    timeout: Duration,
}

impl Default for OnePasswordBackend {
    fn default() -> Self {
        Self {
            command: PathBuf::from("op"),
            timeout: timeout_from_config(None),
        }
    }
}

impl OnePasswordBackend {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_command(command: PathBuf) -> Self {
        Self {
            command,
            timeout: timeout_from_config(None),
        }
    }

    pub fn with_timeout_ms(mut self, timeout_ms: Option<u64>) -> Self {
        self.timeout = timeout_from_config(timeout_ms);
        self
    }
}

impl SecretBackend for OnePasswordBackend {
    fn resolve(&self, reference: &str) -> Result<SecretLease> {
        if !reference.starts_with("op://") {
            return Err(AuthorityError::SecretBackend(
                "1Password references must use op:// secret reference syntax".into(),
            ));
        }

        run_secret_command(SecretCommand {
            provider: "1Password",
            command: self.command.clone(),
            args: vec!["read".into(), reference.into()],
            env: Vec::new(),
            timeout: self.timeout,
            output: SecretCommandOutput::Plain,
            configured_json_pointer: None,
        })
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

#[derive(Debug, Clone)]
pub struct BitwardenSecretsManagerBackend {
    command: PathBuf,
    timeout: Duration,
}

impl BitwardenSecretsManagerBackend {
    pub fn new(command: PathBuf, timeout: Duration) -> Self {
        Self { command, timeout }
    }
}

impl SecretBackend for BitwardenSecretsManagerBackend {
    fn resolve(&self, reference: &str) -> Result<SecretLease> {
        let id = parse_prefixed_reference("Bitwarden Secrets Manager", reference, "bws://")?;
        run_secret_command(SecretCommand {
            provider: "Bitwarden Secrets Manager",
            command: self.command.clone(),
            args: vec![
                "secret".into(),
                "get".into(),
                id.into(),
                "--output".into(),
                "json".into(),
            ],
            env: Vec::new(),
            timeout: self.timeout,
            output: SecretCommandOutput::JsonPointer("/value"),
            configured_json_pointer: None,
        })
    }
}

#[derive(Debug, Clone)]
pub struct DopplerBackend {
    command: PathBuf,
    project: Option<String>,
    config: Option<String>,
    timeout: Duration,
}

impl DopplerBackend {
    pub fn new(
        command: PathBuf,
        project: Option<String>,
        config: Option<String>,
        timeout: Duration,
    ) -> Self {
        Self {
            command,
            project,
            config,
            timeout,
        }
    }
}

impl SecretBackend for DopplerBackend {
    fn resolve(&self, reference: &str) -> Result<SecretLease> {
        let name = parse_prefixed_reference("Doppler", reference, "doppler://")?;
        let mut args = vec![
            "secrets".into(),
            "get".into(),
            name.into(),
            "--plain".into(),
        ];
        if let Some(project) = &self.project {
            args.extend(["--project".into(), project.clone()]);
        }
        if let Some(config) = &self.config {
            args.extend(["--config".into(), config.clone()]);
        }
        run_secret_command(SecretCommand {
            provider: "Doppler",
            command: self.command.clone(),
            args,
            env: Vec::new(),
            timeout: self.timeout,
            output: SecretCommandOutput::Plain,
            configured_json_pointer: None,
        })
    }
}

#[derive(Debug, Clone)]
pub struct InfisicalBackend {
    command: PathBuf,
    env_name: Option<String>,
    path: Option<String>,
    project_id: Option<String>,
    timeout: Duration,
}

impl InfisicalBackend {
    pub fn new(
        command: PathBuf,
        env_name: Option<String>,
        path: Option<String>,
        project_id: Option<String>,
        timeout: Duration,
    ) -> Self {
        Self {
            command,
            env_name,
            path,
            project_id,
            timeout,
        }
    }
}

impl SecretBackend for InfisicalBackend {
    fn resolve(&self, reference: &str) -> Result<SecretLease> {
        let name = parse_prefixed_reference("Infisical", reference, "infisical://")?;
        let mut args = vec![
            "secrets".into(),
            "get".into(),
            name.into(),
            "--plain".into(),
            "--silent".into(),
        ];
        if let Some(env_name) = &self.env_name {
            args.extend(["--env".into(), env_name.clone()]);
        }
        if let Some(path) = &self.path {
            args.extend(["--path".into(), path.clone()]);
        }
        if let Some(project_id) = &self.project_id {
            args.extend(["--projectId".into(), project_id.clone()]);
        }
        run_secret_command(SecretCommand {
            provider: "Infisical",
            command: self.command.clone(),
            args,
            env: vec![("INFISICAL_DISABLE_UPDATE_CHECK".into(), "true".into())],
            timeout: self.timeout,
            output: SecretCommandOutput::Plain,
            configured_json_pointer: None,
        })
    }
}

#[derive(Debug, Clone)]
pub struct HashicorpVaultBackend {
    command: PathBuf,
    mount: Option<String>,
    timeout: Duration,
}

impl HashicorpVaultBackend {
    pub fn new(command: PathBuf, mount: Option<String>, timeout: Duration) -> Self {
        Self {
            command,
            mount,
            timeout,
        }
    }
}

impl SecretBackend for HashicorpVaultBackend {
    fn resolve(&self, reference: &str) -> Result<SecretLease> {
        let (path, field) =
            parse_fragment_reference("HashiCorp Vault", reference, "vault://", None)?;
        let mut args = vec!["kv".into(), "get".into()];
        if let Some(mount) = &self.mount {
            args.push(format!("-mount={mount}"));
        }
        args.push(format!("-field={field}"));
        args.push(path.into());
        run_secret_command(SecretCommand {
            provider: "HashiCorp Vault",
            command: self.command.clone(),
            args,
            env: Vec::new(),
            timeout: self.timeout,
            output: SecretCommandOutput::Plain,
            configured_json_pointer: None,
        })
    }
}

#[derive(Debug, Clone)]
pub struct AwsSecretsManagerBackend {
    command: PathBuf,
    profile: Option<String>,
    region: Option<String>,
    timeout: Duration,
}

impl AwsSecretsManagerBackend {
    pub fn new(
        command: PathBuf,
        profile: Option<String>,
        region: Option<String>,
        timeout: Duration,
    ) -> Self {
        Self {
            command,
            profile,
            region,
            timeout,
        }
    }
}

impl SecretBackend for AwsSecretsManagerBackend {
    fn resolve(&self, reference: &str) -> Result<SecretLease> {
        let id =
            parse_prefixed_reference("AWS Secrets Manager", reference, "aws-secretsmanager://")?;
        let mut args = aws_common_args(&self.profile, &self.region);
        args.extend([
            "secretsmanager".into(),
            "get-secret-value".into(),
            "--secret-id".into(),
            id.into(),
            "--output".into(),
            "json".into(),
            "--no-cli-pager".into(),
            "--no-cli-auto-prompt".into(),
        ]);
        run_secret_command(SecretCommand {
            provider: "AWS Secrets Manager",
            command: self.command.clone(),
            args,
            env: Vec::new(),
            timeout: self.timeout,
            output: SecretCommandOutput::JsonPointer("/SecretString"),
            configured_json_pointer: None,
        })
    }
}

#[derive(Debug, Clone)]
pub struct AwsSsmParameterStoreBackend {
    command: PathBuf,
    profile: Option<String>,
    region: Option<String>,
    timeout: Duration,
}

impl AwsSsmParameterStoreBackend {
    pub fn new(
        command: PathBuf,
        profile: Option<String>,
        region: Option<String>,
        timeout: Duration,
    ) -> Self {
        Self {
            command,
            profile,
            region,
            timeout,
        }
    }
}

impl SecretBackend for AwsSsmParameterStoreBackend {
    fn resolve(&self, reference: &str) -> Result<SecretLease> {
        let name = parse_prefixed_reference("AWS SSM Parameter Store", reference, "aws-ssm://")?;
        let mut args = aws_common_args(&self.profile, &self.region);
        args.extend([
            "ssm".into(),
            "get-parameter".into(),
            "--name".into(),
            name.into(),
            "--with-decryption".into(),
            "--output".into(),
            "json".into(),
            "--no-cli-pager".into(),
            "--no-cli-auto-prompt".into(),
        ]);
        run_secret_command(SecretCommand {
            provider: "AWS SSM Parameter Store",
            command: self.command.clone(),
            args,
            env: Vec::new(),
            timeout: self.timeout,
            output: SecretCommandOutput::JsonPointer("/Parameter/Value"),
            configured_json_pointer: None,
        })
    }
}

fn aws_common_args(profile: &Option<String>, region: &Option<String>) -> Vec<String> {
    let mut args = Vec::new();
    if let Some(profile) = profile {
        args.extend(["--profile".into(), profile.clone()]);
    }
    if let Some(region) = region {
        args.extend(["--region".into(), region.clone()]);
    }
    args
}

#[derive(Debug, Clone)]
pub struct GcpSecretManagerBackend {
    command: PathBuf,
    project: Option<String>,
    default_version: String,
    timeout: Duration,
}

impl GcpSecretManagerBackend {
    pub fn new(
        command: PathBuf,
        project: Option<String>,
        default_version: String,
        timeout: Duration,
    ) -> Self {
        Self {
            command,
            project,
            default_version,
            timeout,
        }
    }
}

impl SecretBackend for GcpSecretManagerBackend {
    fn resolve(&self, reference: &str) -> Result<SecretLease> {
        let (name, version) = parse_fragment_reference(
            "GCP Secret Manager",
            reference,
            "gcp-secretmanager://",
            Some(&self.default_version),
        )?;
        let mut args = vec![
            "secrets".into(),
            "versions".into(),
            "access".into(),
            version.into(),
            "--secret".into(),
            name.into(),
        ];
        if let Some(project) = &self.project {
            args.extend(["--project".into(), project.clone()]);
        }
        run_secret_command(SecretCommand {
            provider: "GCP Secret Manager",
            command: self.command.clone(),
            args,
            env: Vec::new(),
            timeout: self.timeout,
            output: SecretCommandOutput::Plain,
            configured_json_pointer: None,
        })
    }
}

#[derive(Debug, Clone)]
pub struct AzureKeyVaultBackend {
    command: PathBuf,
    vault_name: String,
    timeout: Duration,
}

impl AzureKeyVaultBackend {
    pub fn new(command: PathBuf, vault_name: String, timeout: Duration) -> Self {
        Self {
            command,
            vault_name,
            timeout,
        }
    }
}

impl SecretBackend for AzureKeyVaultBackend {
    fn resolve(&self, reference: &str) -> Result<SecretLease> {
        let name = parse_prefixed_reference("Azure Key Vault", reference, "azure-keyvault://")?;
        run_secret_command(SecretCommand {
            provider: "Azure Key Vault",
            command: self.command.clone(),
            args: vec![
                "keyvault".into(),
                "secret".into(),
                "show".into(),
                "--vault-name".into(),
                self.vault_name.clone(),
                "--name".into(),
                name.into(),
                "--query".into(),
                "value".into(),
                "-o".into(),
                "tsv".into(),
                "--only-show-errors".into(),
            ],
            env: Vec::new(),
            timeout: self.timeout,
            output: SecretCommandOutput::Plain,
            configured_json_pointer: None,
        })
    }
}

#[derive(Debug, Clone)]
pub struct SopsBackend {
    command: PathBuf,
    file: PathBuf,
    timeout: Duration,
}

impl SopsBackend {
    pub fn new(command: PathBuf, file: PathBuf, timeout: Duration) -> Self {
        Self {
            command,
            file,
            timeout,
        }
    }
}

impl SecretBackend for SopsBackend {
    fn resolve(&self, reference: &str) -> Result<SecretLease> {
        let extract = sops_extract_expression(reference)?;
        run_secret_command(SecretCommand {
            provider: "SOPS",
            command: self.command.clone(),
            args: vec![
                "--decrypt".into(),
                "--extract".into(),
                extract,
                self.file.to_string_lossy().into_owned(),
            ],
            env: Vec::new(),
            timeout: self.timeout,
            output: SecretCommandOutput::Plain,
            configured_json_pointer: None,
        })
    }
}

fn sops_extract_expression(reference: &str) -> Result<String> {
    let value = reference.strip_prefix("sops://").ok_or_else(|| {
        AuthorityError::SecretBackend("SOPS reference has unsupported syntax".into())
    })?;
    let segments: Vec<&str> = if let Some(path) = value.strip_prefix('/') {
        path.split('/').collect()
    } else {
        vec![value]
    };
    if segments.is_empty()
        || segments
            .iter()
            .any(|segment| !is_safe_sops_segment(segment))
    {
        return Err(provider_error("SOPS", "reference has unsupported syntax"));
    }
    Ok(segments
        .into_iter()
        .map(|segment| format!("[\"{segment}\"]"))
        .collect::<String>())
}

fn is_safe_sops_segment(segment: &str) -> bool {
    !segment.is_empty()
        && segment
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
}

#[derive(Debug, Clone)]
pub struct TrustedCommandBackend {
    command: PathBuf,
    args: Vec<String>,
    json_pointer: Option<String>,
    timeout: Duration,
}

impl TrustedCommandBackend {
    pub fn new(
        command: PathBuf,
        args: Vec<String>,
        json_pointer: Option<String>,
        timeout: Duration,
    ) -> Self {
        Self {
            command,
            args,
            json_pointer,
            timeout,
        }
    }
}

impl SecretBackend for TrustedCommandBackend {
    fn resolve(&self, reference: &str) -> Result<SecretLease> {
        let args = self
            .args
            .iter()
            .map(|arg| arg.replace("{ref}", reference))
            .collect();
        let output = if self.json_pointer.is_some() {
            SecretCommandOutput::ConfiguredJsonPointer
        } else {
            SecretCommandOutput::Plain
        };
        run_secret_command(SecretCommand {
            provider: "trusted command",
            command: self.command.clone(),
            args,
            env: Vec::new(),
            timeout: self.timeout,
            output,
            configured_json_pointer: self.json_pointer.clone(),
        })
    }
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
        Ok(SecretLease::new(value))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(unix)]
    use std::io::Write;
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;

    #[cfg(unix)]
    fn write_executable_script(dir: &tempfile::TempDir, name: &str, script: &str) -> PathBuf {
        let path = dir.path().join(name);
        let mut file = fs::File::create(&path).unwrap();
        file.write_all(script.as_bytes()).unwrap();
        file.flush().unwrap();
        let mut permissions = fs::metadata(&path).unwrap().permissions();
        permissions.set_mode(0o700);
        fs::set_permissions(&path, permissions).unwrap();
        path
    }

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
        let lease = SecretLease::new("secret-value");
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

    #[cfg(unix)]
    #[test]
    fn command_backend_times_out_and_redacts_reference() {
        let dir = tempfile::tempdir().unwrap();
        let cmd = write_executable_script(
            &dir,
            "slow",
            r#"#!/bin/sh
sleep 2
printf 'secret-after-sleep\n'
"#,
        );
        let backend =
            TrustedCommandBackend::new(cmd, vec!["{ref}".into()], None, Duration::from_millis(20));
        let err = backend
            .resolve("secret-ref-that-must-not-leak")
            .unwrap_err()
            .to_string();
        assert!(err.contains("timed out"), "{err}");
        assert!(!err.contains("secret-ref-that-must-not-leak"), "{err}");
        assert!(!err.contains("secret-after-sleep"), "{err}");
    }

    #[cfg(unix)]
    #[test]
    fn command_backend_timeout_kills_descendant_processes() {
        let dir = tempfile::tempdir().unwrap();
        let marker = dir.path().join("descendant-marker");
        let cmd = write_executable_script(
            &dir,
            "slow-tree",
            &format!(
                r#"#!/bin/sh
(sleep 1; touch '{}') &
sleep 5
"#,
                marker.display()
            ),
        );
        let backend = TrustedCommandBackend::new(cmd, Vec::new(), None, Duration::from_millis(50));
        let err = backend.resolve("anything").unwrap_err().to_string();
        assert!(err.contains("timed out"), "{err}");
        thread::sleep(Duration::from_millis(1_300));
        assert!(!marker.exists());
    }

    #[cfg(unix)]
    #[test]
    fn command_backend_errors_do_not_leak_output_reference_or_args() {
        let dir = tempfile::tempdir().unwrap();
        let cmd = write_executable_script(
            &dir,
            "fail",
            r#"#!/bin/sh
printf 'secret-from-stdout\n'
printf 'secret-from-stderr\n' >&2
exit 3
"#,
        );
        let backend = TrustedCommandBackend::new(
            cmd,
            vec!["--secret-id".into(), "{ref}".into()],
            None,
            Duration::from_secs(10),
        );
        let err = backend
            .resolve("secret-ref-that-must-not-leak")
            .unwrap_err()
            .to_string();
        assert!(!err.contains("secret-from-stdout"), "{err}");
        assert!(!err.contains("secret-from-stderr"), "{err}");
        assert!(!err.contains("secret-ref-that-must-not-leak"), "{err}");
        assert!(!err.contains("--secret-id"), "{err}");
    }

    #[cfg(unix)]
    #[test]
    fn command_backend_handles_large_stdout_without_pipe_deadlock() {
        let dir = tempfile::tempdir().unwrap();
        let cmd = write_executable_script(
            &dir,
            "large",
            r#"#!/bin/sh
dd if=/dev/zero bs=70000 count=1 2>/dev/null | tr '\0' x
printf '\n'
"#,
        );
        let backend = TrustedCommandBackend::new(cmd, Vec::new(), None, Duration::from_secs(10));
        let value = backend.resolve("anything").unwrap();
        assert_eq!(value.expose_to_provider().len(), 70_000);
    }

    #[cfg(unix)]
    #[test]
    fn command_backend_caps_captured_stdout() {
        let dir = tempfile::tempdir().unwrap();
        let cmd = write_executable_script(
            &dir,
            "too-large",
            r#"#!/bin/sh
dd if=/dev/zero bs=1048577 count=1 2>/dev/null | tr '\0' x
"#,
        );
        let backend = TrustedCommandBackend::new(cmd, Vec::new(), None, Duration::from_secs(10));
        let err = backend.resolve("anything").unwrap_err().to_string();
        assert!(err.contains("too large"), "{err}");
    }

    #[cfg(unix)]
    #[test]
    fn command_backend_does_not_wait_for_inherited_stdout_handles() {
        if !PathBuf::from("/usr/bin/perl").exists() {
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let marker = dir.path().join("inherited-stdout-marker");
        let cmd = write_executable_script(
            &dir,
            "forks",
            &format!(
                r#"#!/bin/sh
exec /usr/bin/perl -e 'if (fork() == 0) {{ sleep 1; open(my $fh, ">", "{}"); print $fh "done\n"; close($fh); exit 0 }} print "secret\n"; exit 0'
"#,
                marker.display()
            ),
        );
        let backend = TrustedCommandBackend::new(cmd, Vec::new(), None, Duration::from_secs(10));
        let value = backend.resolve("anything").unwrap();
        assert_eq!(value.expose_to_provider(), "secret");
        thread::sleep(Duration::from_millis(1_300));
        assert!(!marker.exists());
    }

    #[test]
    fn command_not_found_errors_do_not_leak_reference_or_args() {
        let backend = TrustedCommandBackend::new(
            PathBuf::from("ctxa-definitely-missing-secret-command"),
            vec!["--secret-id".into(), "{ref}".into()],
            None,
            Duration::from_millis(20),
        );
        let err = backend
            .resolve("secret-ref-that-must-not-leak")
            .unwrap_err()
            .to_string();
        assert!(!err.contains("secret-ref-that-must-not-leak"), "{err}");
        assert!(!err.contains("--secret-id"), "{err}");
    }

    #[cfg(unix)]
    #[test]
    fn json_pointer_backend_preserves_secret_newline() {
        let dir = tempfile::tempdir().unwrap();
        let cmd = write_executable_script(
            &dir,
            "json",
            r#"#!/bin/sh
printf '%s' '{"secret":"line\n"}'
"#,
        );
        let backend = TrustedCommandBackend::new(
            cmd,
            Vec::new(),
            Some("/secret".into()),
            Duration::from_secs(10),
        );
        assert_eq!(
            backend.resolve("anything").unwrap().expose_to_provider(),
            "line\n"
        );
    }

    #[cfg(unix)]
    #[test]
    fn command_backend_rejects_bad_json_outputs_without_leakage() {
        for (script, expected) in [
            (
                r#"#!/bin/sh
printf 'not-json-secret'
"#,
                "invalid JSON",
            ),
            (
                r#"#!/bin/sh
printf '{"other":"secret-value"}'
"#,
                "did not contain",
            ),
            (
                r#"#!/bin/sh
printf '{"secret":7}'
"#,
                "did not contain",
            ),
        ] {
            let dir = tempfile::tempdir().unwrap();
            let cmd = write_executable_script(&dir, "json", script);
            let backend = TrustedCommandBackend::new(
                cmd,
                Vec::new(),
                Some("/secret".into()),
                Duration::from_secs(10),
            );
            let err = backend.resolve("ignored").unwrap_err().to_string();
            assert!(err.contains(expected), "{err}");
            assert!(!err.contains("secret-value"), "{err}");
        }
    }

    #[cfg(unix)]
    #[test]
    fn plain_command_backend_strips_exactly_one_terminal_line_ending() {
        let dir = tempfile::tempdir().unwrap();
        let cmd = write_executable_script(
            &dir,
            "plain",
            r#"#!/bin/sh
printf 'secret\n\n'
"#,
        );
        let backend = TrustedCommandBackend::new(cmd, Vec::new(), None, Duration::from_secs(10));
        assert_eq!(
            backend.resolve("anything").unwrap().expose_to_provider(),
            "secret\n"
        );
    }

    #[cfg(unix)]
    #[test]
    fn trusted_command_passes_shell_metacharacters_as_one_arg() {
        let dir = tempfile::tempdir().unwrap();
        let marker = dir.path().join("shell-injection-marker");
        let cmd = write_executable_script(
            &dir,
            "argv",
            r#"#!/bin/sh
if [ "$#" -ne 2 ]; then exit 10; fi
if [ "$1" != "--ref" ]; then exit 11; fi
if [ "$2" != 'abc; touch shell-injection-marker; $(echo bad) "quoted"' ]; then exit 12; fi
printf 'safe-secret\n'
"#,
        );
        let backend = TrustedCommandBackend::new(
            cmd,
            vec!["--ref".into(), "{ref}".into()],
            None,
            Duration::from_secs(10),
        );
        assert_eq!(
            backend
                .resolve(r#"abc; touch shell-injection-marker; $(echo bad) "quoted""#)
                .unwrap()
                .expose_to_provider(),
            "safe-secret"
        );
        assert!(!marker.exists());
    }

    #[cfg(unix)]
    #[test]
    fn provider_backends_use_expected_commands_without_real_accounts() {
        let dir = tempfile::tempdir().unwrap();
        let bws = write_executable_script(
            &dir,
            "bws",
            r#"#!/bin/sh
if [ "$1" != "secret" ] || [ "$2" != "get" ] || [ "$3" != "secret-id" ] || [ "$4" != "--output" ] || [ "$5" != "json" ]; then exit 9; fi
printf '{"value":"bws-secret"}'
"#,
        );
        let doppler = write_executable_script(
            &dir,
            "doppler",
            r#"#!/bin/sh
if [ "$1" != "secrets" ] || [ "$2" != "get" ] || [ "$3" != "TOKEN" ] || [ "$4" != "--plain" ] || [ "$5" != "--project" ] || [ "$6" != "proj" ] || [ "$7" != "--config" ] || [ "$8" != "dev" ]; then exit 9; fi
printf 'doppler-secret\n'
"#,
        );
        let cases: Vec<(&str, Box<dyn SecretBackend>, &str, &str)> = vec![
            (
                "bws",
                Box::new(BitwardenSecretsManagerBackend::new(
                    bws,
                    Duration::from_secs(10),
                )),
                "bws://secret-id",
                "bws-secret",
            ),
            (
                "doppler",
                Box::new(DopplerBackend::new(
                    doppler,
                    Some("proj".into()),
                    Some("dev".into()),
                    Duration::from_secs(10),
                )),
                "doppler://TOKEN",
                "doppler-secret",
            ),
        ];

        for (_name, backend, reference, expected) in cases {
            assert_eq!(
                backend.resolve(reference).unwrap().expose_to_provider(),
                expected
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn more_provider_backends_use_expected_commands_without_real_accounts() {
        let dir = tempfile::tempdir().unwrap();
        let infisical = write_executable_script(
            &dir,
            "infisical",
            r#"#!/bin/sh
if [ "$INFISICAL_DISABLE_UPDATE_CHECK" != "true" ]; then exit 8; fi
if [ "$1" != "secrets" ] || [ "$2" != "get" ] || [ "$3" != "TOKEN" ] || [ "$4" != "--plain" ] || [ "$5" != "--silent" ] || [ "$6" != "--env" ] || [ "$7" != "dev" ] || [ "$8" != "--path" ] || [ "$9" != "/app" ] || [ "${10}" != "--projectId" ] || [ "${11}" != "project-id" ]; then exit 9; fi
printf 'infisical-secret\n'
"#,
        );
        let vault = write_executable_script(
            &dir,
            "vault",
            r#"#!/bin/sh
if [ "$1" != "kv" ] || [ "$2" != "get" ] || [ "$3" != "-mount=secret" ] || [ "$4" != "-field=token" ] || [ "$5" != "app/config" ]; then exit 9; fi
printf 'vault-secret\n'
"#,
        );
        let aws = write_executable_script(
            &dir,
            "aws",
            r#"#!/bin/sh
if [ "$1" = "--profile" ] && [ "$2" = "dev" ] && [ "$3" = "--region" ] && [ "$4" = "us-east-1" ] && [ "$5" = "secretsmanager" ]; then
  printf '%s' '{"SecretString":"aws-secret\n"}'
  exit 0
fi
if [ "$1" = "--profile" ] && [ "$2" = "dev" ] && [ "$3" = "--region" ] && [ "$4" = "us-east-1" ] && [ "$5" = "ssm" ]; then
  printf '{"Parameter":{"Value":"ssm-secret"}}'
  exit 0
fi
exit 9
"#,
        );
        let gcloud = write_executable_script(
            &dir,
            "gcloud",
            r#"#!/bin/sh
if [ "$1" != "secrets" ] || [ "$2" != "versions" ] || [ "$3" != "access" ] || [ "$4" != "7" ] || [ "$5" != "--secret" ] || [ "$6" != "api-token" ] || [ "$7" != "--project" ] || [ "$8" != "proj" ]; then exit 9; fi
printf 'gcp-secret\n'
"#,
        );
        let az = write_executable_script(
            &dir,
            "az",
            r#"#!/bin/sh
if [ "$1" != "keyvault" ] || [ "$2" != "secret" ] || [ "$3" != "show" ] || [ "$4" != "--vault-name" ] || [ "$5" != "vault" ] || [ "$6" != "--name" ] || [ "$7" != "api-token" ] || [ "$8" != "--query" ] || [ "$9" != "value" ] || [ "${10}" != "-o" ] || [ "${11}" != "tsv" ] || [ "${12}" != "--only-show-errors" ]; then exit 9; fi
printf 'azure-secret\n'
"#,
        );
        let sops = write_executable_script(
            &dir,
            "sops",
            r#"#!/bin/sh
if [ "$1" != "--decrypt" ] || [ "$2" != "--extract" ] || [ "$3" != '["nested"]["token"]' ]; then exit 9; fi
printf 'sops-secret\n'
"#,
        );

        let backends: Vec<(Box<dyn SecretBackend>, &str, &str)> = vec![
            (
                Box::new(InfisicalBackend::new(
                    infisical,
                    Some("dev".into()),
                    Some("/app".into()),
                    Some("project-id".into()),
                    Duration::from_secs(10),
                )),
                "infisical://TOKEN",
                "infisical-secret",
            ),
            (
                Box::new(HashicorpVaultBackend::new(
                    vault,
                    Some("secret".into()),
                    Duration::from_secs(10),
                )),
                "vault://app/config#token",
                "vault-secret",
            ),
            (
                Box::new(AwsSecretsManagerBackend::new(
                    aws.clone(),
                    Some("dev".into()),
                    Some("us-east-1".into()),
                    Duration::from_secs(10),
                )),
                "aws-secretsmanager://app-token",
                "aws-secret\n",
            ),
            (
                Box::new(AwsSsmParameterStoreBackend::new(
                    aws,
                    Some("dev".into()),
                    Some("us-east-1".into()),
                    Duration::from_secs(10),
                )),
                "aws-ssm:///prod/db",
                "ssm-secret",
            ),
            (
                Box::new(GcpSecretManagerBackend::new(
                    gcloud,
                    Some("proj".into()),
                    "latest".into(),
                    Duration::from_secs(10),
                )),
                "gcp-secretmanager://api-token#7",
                "gcp-secret",
            ),
            (
                Box::new(AzureKeyVaultBackend::new(
                    az,
                    "vault".into(),
                    Duration::from_secs(10),
                )),
                "azure-keyvault://api-token",
                "azure-secret",
            ),
            (
                Box::new(SopsBackend::new(
                    sops,
                    dir.path().join("secrets.yaml"),
                    Duration::from_secs(10),
                )),
                "sops:///nested/token",
                "sops-secret",
            ),
        ];

        for (backend, reference, expected) in backends {
            assert_eq!(
                backend.resolve(reference).unwrap().expose_to_provider(),
                expected
            );
        }
    }

    #[test]
    fn provider_backends_reject_invalid_references_before_command_invocation() {
        let missing = PathBuf::from("ctxa-missing-provider-command");
        let cases: Vec<(Box<dyn SecretBackend>, &str)> = vec![
            (
                Box::new(BitwardenSecretsManagerBackend::new(
                    missing.clone(),
                    Duration::from_millis(20),
                )),
                "plain",
            ),
            (
                Box::new(DopplerBackend::new(
                    missing.clone(),
                    None,
                    None,
                    Duration::from_millis(20),
                )),
                "doppler://bad ref",
            ),
            (
                Box::new(InfisicalBackend::new(
                    missing.clone(),
                    None,
                    None,
                    None,
                    Duration::from_millis(20),
                )),
                "infisical://",
            ),
            (
                Box::new(HashicorpVaultBackend::new(
                    missing.clone(),
                    None,
                    Duration::from_millis(20),
                )),
                "vault://path-only",
            ),
            (
                Box::new(AwsSecretsManagerBackend::new(
                    missing.clone(),
                    None,
                    None,
                    Duration::from_millis(20),
                )),
                "aws-secretsmanager://bad ref",
            ),
            (
                Box::new(AwsSsmParameterStoreBackend::new(
                    missing.clone(),
                    None,
                    None,
                    Duration::from_millis(20),
                )),
                "aws-ssm://",
            ),
            (
                Box::new(GcpSecretManagerBackend::new(
                    missing.clone(),
                    None,
                    "latest".into(),
                    Duration::from_millis(20),
                )),
                "gcp-secretmanager://bad ref",
            ),
            (
                Box::new(AzureKeyVaultBackend::new(
                    missing.clone(),
                    "vault".into(),
                    Duration::from_millis(20),
                )),
                "azure-keyvault://",
            ),
            (
                Box::new(SopsBackend::new(
                    missing,
                    PathBuf::from("secrets.yaml"),
                    Duration::from_millis(20),
                )),
                "sops:///bad segment",
            ),
        ];

        for (backend, reference) in cases {
            let err = backend.resolve(reference).unwrap_err().to_string();
            assert!(err.contains("unsupported syntax"), "{err}");
            assert!(!err.contains("ctxa-missing-provider-command"), "{err}");
        }
    }

    #[test]
    fn backend_config_serdes_and_debug_redacts_all_command_backends() {
        let yaml = r#"
- type: bitwarden-secrets-manager
  bws_path: /opt/bin/bws
  timeout_ms: 123
- type: doppler
  doppler_path: /opt/bin/doppler
  project: app
  config: dev
- type: infisical
  infisical_path: /opt/bin/infisical
  env: dev
  path: /app
  project_id: project-id
- type: hashicorp-vault
  vault_path: /opt/bin/vault
  mount: secret
- type: aws-secrets-manager
  aws_path: /opt/bin/aws
  profile: dev
  region: us-east-1
- type: aws-ssm-parameter-store
  aws_path: /opt/bin/aws
  profile: dev
  region: us-east-1
- type: gcp-secret-manager
  gcloud_path: /opt/bin/gcloud
  project: proj
  default_version: latest
- type: azure-key-vault
  vault_name: vault
  az_path: /opt/bin/az
- type: sops
  file: secrets.enc.yaml
  sops_path: /opt/bin/sops
- type: trusted-command
  command: /opt/bin/custom
  args: ["get", "{ref}", "secret-value"]
  json_pointer: /value
"#;
        let configs: Vec<SecretBackendConfig> = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(configs.len(), 10);
        for config in configs {
            let debug = format!("{config:?}");
            assert!(!debug.contains("secret-value"));
            let encoded = serde_yaml::to_string(&config).unwrap();
            let reparsed: SecretBackendConfig = serde_yaml::from_str(&encoded).unwrap();
            assert_eq!(reparsed.kind(), config.kind());
        }
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
            "ctx-authority",
            FakeKeychainStore {
                values: BTreeMap::from([(
                    ("ctx-authority".into(), "github".into()),
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
