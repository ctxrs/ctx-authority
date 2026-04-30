use anyhow::Context;
use clap::{Parser, Subcommand, ValueEnum};
use ctxa::audit::AuditLog;
use ctxa::boundary::action_request_from_json_str;
use ctxa::config::{
    AgentConfig, AppConfig, AppPaths, HttpAllowConfig, HttpAuthConfig, HttpResourceConfig,
    HttpResourceScheme, PolicyConfig, ProfileConfig,
};
use ctxa::execution_context::{load_policy_file, ExecutionContext};
use ctxa::models::{ActionRequest, Receipt};
use ctxa::policy::PolicyDocument;
use ctxa::proxy::{can_create_process_ca_file, profile_allows_url, ProxyConfig, ProxyServer};
use ctxa::receipts::{receipt_from_json_str_strict, ReceiptSigner};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;
use std::process::Command as ProcessCommand;
use std::sync::Arc;

const CTX_AUTHORITY_SKILL: &str = include_str!("../skills/ctx-authority/SKILL.md");
const DISMISS_REASON_MAX_CHARS: usize = 200;

#[derive(Debug, Parser)]
#[command(name = "ctxa", about = "Local capability broker for agents")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    Init,
    Agent {
        #[command(subcommand)]
        command: AgentCommand,
    },
    Policy {
        #[command(subcommand)]
        command: PolicyCommand,
    },
    Profile {
        #[command(subcommand)]
        command: ProfileCommand,
    },
    Setup {
        #[command(subcommand)]
        command: SetupCommand,
    },
    Proposals {
        #[command(subcommand)]
        command: ProposalCommand,
    },
    Ca {
        #[command(subcommand)]
        command: CaCommand,
    },
    Doctor {
        #[arg(long)]
        profile: Option<String>,
    },
    Action {
        #[command(subcommand)]
        command: ActionCommand,
    },
    Run {
        #[arg(long)]
        profile: String,
        #[arg(required = true, trailing_var_arg = true, allow_hyphen_values = true)]
        command: Vec<String>,
    },
    Receipts {
        #[command(subcommand)]
        command: ReceiptCommand,
    },
    Log {
        #[arg(long, default_value_t = 20)]
        limit: usize,
    },
    Mcp {
        #[command(subcommand)]
        command: McpCommand,
    },
}

#[derive(Debug, Subcommand)]
enum AgentCommand {
    Create {
        id: String,
        #[arg(long)]
        policy: Option<String>,
    },
}

#[derive(Debug, Subcommand)]
enum PolicyCommand {
    Check {
        #[arg(long)]
        policy: PathBuf,
        #[arg(long)]
        file: PathBuf,
    },
    Trust {
        #[arg(long)]
        id: String,
        #[arg(long)]
        path: PathBuf,
    },
}

#[derive(Debug, Subcommand)]
enum ProfileCommand {
    Create {
        id: String,
        #[arg(long)]
        agent: Option<String>,
    },
    AddHttp {
        profile: String,
        #[arg(long)]
        id: String,
        #[arg(long)]
        host: String,
        #[arg(long)]
        secret_ref: String,
        #[arg(long = "allow-method", required = true)]
        allow_methods: Vec<String>,
        #[arg(long = "path-prefix", required = true)]
        path_prefixes: Vec<String>,
    },
    AddHttps {
        profile: String,
        #[arg(long)]
        id: String,
        #[arg(long)]
        host: String,
        #[arg(long)]
        secret_ref: String,
        #[arg(long = "allow-method", required = true)]
        allow_methods: Vec<String>,
        #[arg(long = "path-prefix", required = true)]
        path_prefixes: Vec<String>,
    },
    Test {
        profile: String,
        #[arg(long)]
        url: String,
        #[arg(long, default_value = "GET")]
        method: String,
    },
}

#[derive(Debug, Subcommand)]
enum ActionCommand {
    Request {
        #[arg(long)]
        file: PathBuf,
    },
}

#[derive(Debug, Subcommand)]
enum ProposalCommand {
    List {
        #[arg(long, default_value_t = 20)]
        limit: usize,
        #[arg(long)]
        all: bool,
    },
    Show {
        id: String,
    },
    Apply {
        id: String,
        #[arg(long)]
        secret_ref: String,
        #[arg(long)]
        resource_id: Option<String>,
        #[arg(long)]
        path_prefix: Option<String>,
        #[arg(long = "allow-method")]
        allow_methods: Vec<String>,
        #[arg(long)]
        replace: bool,
    },
    Dismiss {
        id: String,
        #[arg(long)]
        reason: Option<String>,
    },
}

#[derive(Debug, Subcommand)]
enum SetupCommand {
    Runtime {
        runtime: AgentRuntime,
        #[arg(long)]
        profile: String,
        #[arg(long)]
        agent: Option<String>,
    },
}

#[derive(Debug, Clone, Copy, ValueEnum)]
#[value(rename_all = "kebab-case")]
enum AgentRuntime {
    Codex,
    ClaudeCode,
    Openclaw,
    Generic,
}

impl AgentRuntime {
    fn command(self) -> &'static str {
        match self {
            Self::Codex => "codex",
            Self::ClaudeCode => "claude",
            Self::Openclaw => "openclaw",
            Self::Generic => "agent-command",
        }
    }

    fn agent_id(self) -> &'static str {
        match self {
            Self::Codex => "codex",
            Self::ClaudeCode => "claude-code",
            Self::Openclaw => "openclaw",
            Self::Generic => "agent",
        }
    }
}

#[derive(Debug, Subcommand)]
enum CaCommand {
    Status,
}

#[derive(Debug, Subcommand)]
enum ReceiptCommand {
    List {
        #[arg(long, default_value_t = 20)]
        limit: usize,
    },
    Show {
        id: String,
    },
    Verify {
        file: PathBuf,
    },
}

#[derive(Debug, Subcommand)]
enum McpCommand {
    Serve,
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Init => init(),
        Command::Agent { command } => agent(command),
        Command::Policy { command } => policy(command),
        Command::Profile { command } => profile(command),
        Command::Setup { command } => setup(command),
        Command::Proposals { command } => proposals(command),
        Command::Ca { command } => ca(command),
        Command::Doctor { profile } => doctor(profile),
        Command::Action { command } => action(command),
        Command::Run { profile, command } => run(profile, command),
        Command::Receipts { command } => receipts(command),
        Command::Log { limit } => log(limit),
        Command::Mcp { command } => mcp(command),
    }
}

fn profile(command: ProfileCommand) -> anyhow::Result<()> {
    match command {
        ProfileCommand::Create { id, agent } => {
            let paths = AppPaths::discover()?;
            paths.ensure()?;
            let mut config = AppConfig::load(&paths.config_file)?;
            if let Some(profile) = config.profile_mut(&id) {
                if agent.is_some() {
                    profile.agent = agent;
                }
            } else {
                config.profiles.push(ProfileConfig {
                    id: id.clone(),
                    agent,
                    env_vars: Default::default(),
                    http_resources: Vec::new(),
                });
            }
            config.save(&paths.config_file)?;
            println!("profile {id}");
            Ok(())
        }
        ProfileCommand::AddHttp {
            profile,
            id,
            host,
            secret_ref,
            allow_methods,
            path_prefixes,
        } => add_profile_resource(
            profile,
            id,
            HttpResourceScheme::Http,
            host,
            secret_ref,
            allow_methods,
            path_prefixes,
        ),
        ProfileCommand::AddHttps {
            profile,
            id,
            host,
            secret_ref,
            allow_methods,
            path_prefixes,
        } => add_profile_resource(
            profile,
            id,
            HttpResourceScheme::Https,
            host,
            secret_ref,
            allow_methods,
            path_prefixes,
        ),
        ProfileCommand::Test {
            profile,
            url,
            method,
        } => profile_test(profile, method, url),
    }
}

fn add_profile_resource(
    profile: String,
    id: String,
    scheme: HttpResourceScheme,
    host: String,
    secret_ref: String,
    allow_methods: Vec<String>,
    path_prefixes: Vec<String>,
) -> anyhow::Result<()> {
    let paths = AppPaths::discover()?;
    paths.ensure()?;
    let mut config = AppConfig::load(&paths.config_file)?;
    let profile_config = config
        .profile_mut(&profile)
        .ok_or_else(|| anyhow::anyhow!("profile {profile} is not configured"))?;
    let resource = HttpResourceConfig {
        id: id.clone(),
        scheme,
        host,
        secret_ref,
        auth: HttpAuthConfig::default(),
        allow: HttpAllowConfig {
            methods: allow_methods
                .into_iter()
                .map(|method| method.to_ascii_uppercase())
                .collect(),
            path_prefixes,
        },
    };
    if let Some(existing) = profile_config
        .http_resources
        .iter_mut()
        .find(|resource| resource.id == id)
    {
        *existing = resource;
    } else {
        profile_config.http_resources.push(resource);
    }
    config.save(&paths.config_file)?;
    println!("{} resource {id} on profile {profile}", scheme_name(scheme));
    Ok(())
}

fn profile_test(profile: String, method: String, url: String) -> anyhow::Result<()> {
    let paths = AppPaths::discover()?;
    let config = AppConfig::load(&paths.config_file)?;
    let profile_config = config
        .profile(&profile)
        .ok_or_else(|| anyhow::anyhow!("profile {profile} is not configured"))?;
    match profile_allows_url(profile_config, &method, &url)? {
        Some(resource) => {
            println!("allowed resource={resource}");
            Ok(())
        }
        None => anyhow::bail!("denied by profile {profile}"),
    }
}

fn run(profile_id: String, command: Vec<String>) -> anyhow::Result<()> {
    if command.is_empty() {
        anyhow::bail!("run requires a command");
    }
    let paths = AppPaths::discover()?;
    paths.ensure()?;
    let config = AppConfig::load(&paths.config_file)?;
    let profile = config
        .profile(&profile_id)
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("profile {profile_id} is not configured"))?;
    let secret_backend = config
        .secret_backend
        .as_ref()
        .ok_or_else(|| {
            anyhow::anyhow!("configure `secret_backend` in config.yaml before running `ctxa run`")
        })?
        .build()?;
    let proxy = ProxyServer::start(ProxyConfig {
        profile: profile.clone(),
        secret_backend: Arc::from(secret_backend),
        audit: AuditLog::open(&paths.audit_db)?,
        signer: ReceiptSigner::load_or_create(&paths)?,
        upstream_root_certs_pem: Vec::new(),
    })?;
    let proxy_url = proxy.proxy_url();
    let ca_cert_path = proxy.ca_cert_path().to_path_buf();
    let mut child = ProcessCommand::new(&command[0]);
    child.args(&command[1..]);
    for (key, value) in &profile.env_vars {
        child.env(key, value);
    }
    child
        .env("CTXA_PROFILE", &profile.id)
        .env("CTXA_PROXY_URL", &proxy_url)
        .env("CTXA_PROXY_TOKEN", proxy.token())
        .env("HTTP_PROXY", &proxy_url)
        .env("http_proxy", &proxy_url)
        .env("HTTPS_PROXY", &proxy_url)
        .env("https_proxy", &proxy_url)
        .env("SSL_CERT_FILE", &ca_cert_path)
        .env("REQUESTS_CA_BUNDLE", &ca_cert_path)
        .env("CURL_CA_BUNDLE", &ca_cert_path)
        .env("NODE_EXTRA_CA_CERTS", &ca_cert_path)
        .env("GIT_SSL_CAINFO", &ca_cert_path)
        .env("NO_PROXY", "")
        .env("no_proxy", "")
        .env_remove("ALL_PROXY")
        .env_remove("all_proxy");
    let status = child
        .status()
        .with_context(|| format!("failed to run {}", command[0]))?;
    proxy.stop();
    std::process::exit(status.code().unwrap_or(1));
}

fn doctor(profile: Option<String>) -> anyhow::Result<()> {
    let paths = AppPaths::discover()?;
    paths.ensure()?;
    let config = AppConfig::load(&paths.config_file)?;
    println!("config ok {}", paths.config_file.display());
    if let Some(secret_backend) = &config.secret_backend {
        let _backend = secret_backend.build()?;
        println!(
            "secret backend ok {}",
            serde_json::to_string(&secret_backend.kind())?.trim_matches('"')
        );
    } else {
        println!("secret backend not configured");
    }
    can_create_process_ca_file()?;
    println!("process CA ok");
    let listener = std::net::TcpListener::bind(("127.0.0.1", 0))?;
    println!("proxy bind ok {}", listener.local_addr()?);
    drop(listener);
    if let Some(profile_id) = profile {
        let profile = config
            .profile(&profile_id)
            .ok_or_else(|| anyhow::anyhow!("profile {profile_id} is not configured"))?;
        profile.validate()?;
        println!("profile ok {profile_id}");
    }
    Ok(())
}

fn setup(command: SetupCommand) -> anyhow::Result<()> {
    match command {
        SetupCommand::Runtime {
            runtime,
            profile,
            agent,
        } => setup_runtime(runtime, profile, agent),
    }
}

fn setup_runtime(
    runtime: AgentRuntime,
    profile_id: String,
    agent: Option<String>,
) -> anyhow::Result<()> {
    let paths = AppPaths::discover()?;
    paths.ensure()?;
    if !paths.config_file.exists() {
        AppConfig::default().save(&paths.config_file)?;
    }
    AuditLog::open(&paths.audit_db)?;
    ReceiptSigner::load_or_create(&paths)?;

    let mut config = AppConfig::load(&paths.config_file)?;
    let requested_agent_id = agent.unwrap_or_else(|| runtime.agent_id().to_string());
    let effective_agent_id;
    if let Some(profile) = config.profile_mut(&profile_id) {
        if profile.agent.is_none() {
            profile.agent = Some(requested_agent_id.clone());
        }
        effective_agent_id = profile
            .agent
            .clone()
            .unwrap_or_else(|| requested_agent_id.clone());
    } else {
        config.profiles.push(ProfileConfig {
            id: profile_id.clone(),
            agent: Some(requested_agent_id.clone()),
            env_vars: Default::default(),
            http_resources: Vec::new(),
        });
        effective_agent_id = requested_agent_id;
    }
    config.save(&paths.config_file)?;

    let skill_dir = paths.home.join("skills").join("ctx-authority");
    fs::create_dir_all(&skill_dir)?;
    let skill_path = skill_dir.join("SKILL.md");
    fs::write(&skill_path, CTX_AUTHORITY_SKILL)?;

    can_create_process_ca_file()?;
    println!("profile {profile_id}");
    println!("agent {effective_agent_id}");
    println!("skill {}", skill_path.display());
    println!("doctor ok");
    println!(
        "next add resource: ctxa profile add-https {profile_id} --id <resource-id> --host <host> --secret-ref <ref> --allow-method GET --path-prefix <path>"
    );
    println!(
        "next run: ctxa run --profile {profile_id} -- {}",
        runtime.command()
    );
    println!("next proposals: ctxa proposals list");
    println!("next receipts: ctxa receipts list");
    Ok(())
}

fn proposals(command: ProposalCommand) -> anyhow::Result<()> {
    match command {
        ProposalCommand::List { limit, all } => {
            let paths = AppPaths::discover()?;
            let audit = AuditLog::open(&paths.audit_db)?;
            let mut printed = 0usize;
            for record in proposal_records(&audit)? {
                if !all && record.status != ProposalStatus::Open {
                    continue;
                }
                println!(
                    "{} {} {}",
                    record.at,
                    record.status.as_str(),
                    serde_json::to_string(&record.data)?
                );
                printed += 1;
                if printed >= limit {
                    break;
                }
            }
            Ok(())
        }
        ProposalCommand::Show { id } => {
            let paths = AppPaths::discover()?;
            let audit = AuditLog::open(&paths.audit_db)?;
            let record = find_proposal_record(&audit, &id)?;
            println!(
                "{}",
                serde_json::to_string_pretty(&json!({
                    "status": record.status.as_str(),
                    "proposal": record.data,
                }))?
            );
            Ok(())
        }
        ProposalCommand::Apply {
            id,
            secret_ref,
            resource_id,
            path_prefix,
            allow_methods,
            replace,
        } => apply_proposal(
            id,
            secret_ref,
            resource_id,
            path_prefix,
            allow_methods,
            replace,
        ),
        ProposalCommand::Dismiss { id, reason } => dismiss_proposal(id, reason),
    }
}

fn apply_proposal(
    id: String,
    secret_ref: String,
    resource_id: Option<String>,
    path_prefix: Option<String>,
    allow_methods: Vec<String>,
    replace: bool,
) -> anyhow::Result<()> {
    let paths = AppPaths::discover()?;
    paths.ensure()?;
    let audit = AuditLog::open(&paths.audit_db)?;
    let record = find_proposal_record(&audit, &id)?;
    match record.status {
        ProposalStatus::Applied => {
            println!("proposal {id} already applied");
            return Ok(());
        }
        ProposalStatus::Dismissed => anyhow::bail!("proposal {id} is dismissed"),
        ProposalStatus::Open => {}
    }
    let proposal = ProposalData::from_value(&record.data)?;
    let mut config = AppConfig::load(&paths.config_file)?;
    let profile = config
        .profile_mut(&proposal.profile)
        .ok_or_else(|| anyhow::anyhow!("profile {} is not configured", proposal.profile))?;
    let resource_id = resource_id.unwrap_or_else(|| default_resource_id(&proposal.id));
    let methods = if allow_methods.is_empty() {
        vec![proposal.method.clone()]
    } else {
        allow_methods
            .into_iter()
            .map(|method| method.to_ascii_uppercase())
            .collect()
    };
    let path_prefix = path_prefix.unwrap_or_else(|| proposal.path.clone());
    let resource = HttpResourceConfig {
        id: resource_id.clone(),
        scheme: proposal.scheme,
        host: proposal.host.clone(),
        secret_ref,
        auth: HttpAuthConfig::default(),
        allow: HttpAllowConfig {
            methods,
            path_prefixes: vec![path_prefix],
        },
    };

    if let Some(existing) = profile
        .http_resources
        .iter_mut()
        .find(|resource| resource.id == resource_id)
    {
        if !replace {
            anyhow::bail!("resource {resource_id} already exists; pass --replace to overwrite it");
        }
        *existing = resource;
    } else {
        profile.http_resources.push(resource);
    }
    config.save(&paths.config_file)?;
    audit.record(
        "proxy_request_proposal_applied",
        &json!({
            "id": proposal.id,
            "profile": proposal.profile,
            "resource": resource_id,
            "replace": replace,
        }),
    )?;
    println!("applied proposal {id} as resource {resource_id}");
    Ok(())
}

fn dismiss_proposal(id: String, reason: Option<String>) -> anyhow::Result<()> {
    let paths = AppPaths::discover()?;
    let audit = AuditLog::open(&paths.audit_db)?;
    let record = find_proposal_record(&audit, &id)?;
    match record.status {
        ProposalStatus::Dismissed => {
            println!("proposal {id} already dismissed");
            return Ok(());
        }
        ProposalStatus::Applied => anyhow::bail!("proposal {id} is already applied"),
        ProposalStatus::Open => {}
    }
    let mut data = json!({ "id": id });
    if let Some(reason) = reason {
        data["reason"] = json!(sanitize_dismiss_reason(&reason));
    }
    audit.record("proxy_request_proposal_dismissed", &data)?;
    println!("dismissed proposal {}", data["id"].as_str().unwrap_or(""));
    Ok(())
}

#[derive(Debug, Clone)]
struct ProposalRecord {
    at: String,
    data: Value,
    status: ProposalStatus,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProposalStatus {
    Open,
    Applied,
    Dismissed,
}

impl ProposalStatus {
    fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Applied => "applied",
            Self::Dismissed => "dismissed",
        }
    }
}

#[derive(Debug, Clone)]
struct ProposalData {
    id: String,
    profile: String,
    scheme: HttpResourceScheme,
    method: String,
    host: String,
    path: String,
}

impl ProposalData {
    fn from_value(value: &Value) -> anyhow::Result<Self> {
        let id = required_string(value, "id")?;
        let profile = required_string(value, "profile")?;
        let scheme = match required_string(value, "scheme")?.as_str() {
            "http" => HttpResourceScheme::Http,
            "https" => HttpResourceScheme::Https,
            other => anyhow::bail!("proposal {id} has unsupported scheme {other}"),
        };
        let method = required_string(value, "method")?.to_ascii_uppercase();
        if method == "CONNECT" {
            anyhow::bail!("proposal {id} cannot apply CONNECT as an allowed method");
        }
        let host = required_string(value, "host")?;
        let path = required_string(value, "path")?;
        Ok(Self {
            id,
            profile,
            scheme,
            method,
            host,
            path,
        })
    }
}

fn required_string(value: &Value, key: &str) -> anyhow::Result<String> {
    value
        .get(key)
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
        .ok_or_else(|| anyhow::anyhow!("proposal is missing {key}"))
}

fn proposal_records(audit: &AuditLog) -> anyhow::Result<Vec<ProposalRecord>> {
    let events = audit.list_all()?;
    let mut statuses = BTreeMap::new();
    for (_, kind, data) in &events {
        let status = match kind.as_str() {
            "proxy_request_proposal_applied" => ProposalStatus::Applied,
            "proxy_request_proposal_dismissed" => ProposalStatus::Dismissed,
            _ => continue,
        };
        if let Some(id) = data.get("id").and_then(Value::as_str) {
            statuses.entry(id.to_string()).or_insert(status);
        }
    }

    let records = events
        .into_iter()
        .filter_map(|(at, kind, data)| {
            if kind != "proxy_request_proposal" {
                return None;
            }
            let id = data.get("id")?.as_str()?.to_string();
            let status = statuses.get(&id).copied().unwrap_or(ProposalStatus::Open);
            Some(ProposalRecord { at, data, status })
        })
        .collect();
    Ok(records)
}

fn find_proposal_record(audit: &AuditLog, id: &str) -> anyhow::Result<ProposalRecord> {
    proposal_records(audit)?
        .into_iter()
        .find(|record| record.data.get("id").and_then(Value::as_str) == Some(id))
        .ok_or_else(|| anyhow::anyhow!("proposal {id} not found"))
}

fn default_resource_id(proposal_id: &str) -> String {
    let suffix: String = proposal_id
        .trim_start_matches("prop_")
        .chars()
        .filter(|char| char.is_ascii_alphanumeric() || matches!(char, '-' | '_' | '.'))
        .take(16)
        .collect();
    if suffix.is_empty() {
        "proposal-resource".into()
    } else {
        format!("proposal-{suffix}")
    }
}

fn sanitize_dismiss_reason(reason: &str) -> String {
    reason
        .chars()
        .map(|char| if char.is_control() { ' ' } else { char })
        .take(DISMISS_REASON_MAX_CHARS)
        .collect::<String>()
        .trim()
        .to_string()
}

fn ca(command: CaCommand) -> anyhow::Result<()> {
    match command {
        CaCommand::Status => {
            can_create_process_ca_file()?;
            println!("process-scoped CA is generated per ctxa run; no persistent CA is installed");
            Ok(())
        }
    }
}

fn scheme_name(scheme: HttpResourceScheme) -> &'static str {
    match scheme {
        HttpResourceScheme::Http => "http",
        HttpResourceScheme::Https => "https",
    }
}

fn init() -> anyhow::Result<()> {
    let paths = AppPaths::discover()?;
    paths.ensure()?;
    if paths.config_file.exists() {
        AppConfig::load(&paths.config_file)
            .with_context(|| format!("failed to load {}", paths.config_file.display()))?;
    } else {
        AppConfig::default().save(&paths.config_file)?;
    }
    AuditLog::open(&paths.audit_db)?;
    ReceiptSigner::load_or_create(&paths)?;
    println!("initialized {}", paths.home.display());
    Ok(())
}

fn agent(command: AgentCommand) -> anyhow::Result<()> {
    match command {
        AgentCommand::Create { id, policy } => {
            let paths = AppPaths::discover()?;
            paths.ensure()?;
            let mut config = AppConfig::load(&paths.config_file)?;
            if let Some(policy_id) = &policy {
                ensure_policy_exists(&config, policy_id)?;
            }

            if let Some(agent) = config.agents.iter_mut().find(|agent| agent.id == id) {
                if policy.is_some() {
                    agent.policy = policy;
                }
            } else {
                config.agents.push(AgentConfig {
                    id: id.clone(),
                    description: None,
                    policy,
                });
            }
            config.save(&paths.config_file)?;
            println!("agent {id}");
            Ok(())
        }
    }
}

fn policy(command: PolicyCommand) -> anyhow::Result<()> {
    match command {
        PolicyCommand::Check { policy, file } => {
            let policy = load_policy(policy)?;
            let request = load_action(file)?;
            let decision = policy.evaluate(&request)?;
            println!("{}", serde_json::to_string_pretty(&decision)?);
            Ok(())
        }
        PolicyCommand::Trust { id, path } => {
            let paths = AppPaths::discover()?;
            paths.ensure()?;
            let policy_path = fs::canonicalize(&path)
                .with_context(|| format!("failed to canonicalize policy {}", path.display()))?;
            let policy = load_policy(policy_path.clone())?;
            let hash = policy.hash()?;
            let mut config = AppConfig::load(&paths.config_file)?;
            let policy_path = policy_path.to_string_lossy().to_string();
            if let Some(existing) = config.policies.iter_mut().find(|policy| policy.id == id) {
                existing.path = policy_path;
                existing.hash = hash.clone();
            } else {
                config.policies.push(PolicyConfig {
                    id: id.clone(),
                    path: policy_path,
                    hash: hash.clone(),
                });
            }
            config.save(&paths.config_file)?;
            println!("trusted policy {id} {hash}");
            Ok(())
        }
    }
}

fn action(command: ActionCommand) -> anyhow::Result<()> {
    match command {
        ActionCommand::Request { file } => {
            let paths = AppPaths::discover()?;
            let request = load_action(file)?;
            let context = ExecutionContext::from_paths(&paths)?;
            let receipt = context.execute(&request)?;
            println!("{}", serde_json::to_string_pretty(&receipt)?);
            Ok(())
        }
    }
}

fn receipts(command: ReceiptCommand) -> anyhow::Result<()> {
    match command {
        ReceiptCommand::List { limit } => {
            let paths = AppPaths::discover()?;
            let audit = AuditLog::open(&paths.audit_db)?;
            for (_, receipt, _) in receipt_records(&audit)?.into_iter().take(limit) {
                println!(
                    "{} {} {} {} {} {}",
                    receipt.issued_at.to_rfc3339(),
                    receipt.receipt_id,
                    receipt.action,
                    receipt.resource,
                    receipt.agent,
                    receipt.execution.status,
                );
            }
            Ok(())
        }
        ReceiptCommand::Show { id } => {
            let paths = AppPaths::discover()?;
            let audit = AuditLog::open(&paths.audit_db)?;
            let (_, _, value) = receipt_records(&audit)?
                .into_iter()
                .find(|(_, receipt, _)| receipt.receipt_id == id)
                .ok_or_else(|| anyhow::anyhow!("receipt {id} not found"))?;
            println!("{}", serde_json::to_string_pretty(&value)?);
            Ok(())
        }
        ReceiptCommand::Verify { file } => {
            let paths = AppPaths::discover()?;
            let text = fs::read_to_string(file)?;
            let receipt = receipt_from_json_str_strict(&text)?;
            let signer = ReceiptSigner::load(&paths)?;
            signer.verify_local_receipt(&receipt)?;
            println!("receipt verified with local key {}", signer.key_id());
            Ok(())
        }
    }
}

fn receipt_records(audit: &AuditLog) -> anyhow::Result<Vec<(String, Receipt, Value)>> {
    let mut receipts = Vec::new();
    for (at, kind, data) in audit.list_all()? {
        if !matches!(kind.as_str(), "action_executed" | "proxy_request_receipt") {
            continue;
        }
        if let Ok(receipt) = serde_json::from_value::<Receipt>(data.clone()) {
            receipts.push((at, receipt, data));
        }
    }
    Ok(receipts)
}

fn log(limit: usize) -> anyhow::Result<()> {
    let paths = AppPaths::discover()?;
    let audit = AuditLog::open(&paths.audit_db)?;
    for (at, kind, data) in audit.list(limit)? {
        println!("{at} {kind} {}", serde_json::to_string(&data)?);
    }
    Ok(())
}

fn mcp(command: McpCommand) -> anyhow::Result<()> {
    match command {
        McpCommand::Serve => {
            let stdin = std::io::stdin();
            let mut stdout = std::io::stdout();
            ctxa::mcp::serve_stdio(stdin.lock(), &mut stdout)?;
            Ok(())
        }
    }
}

fn load_policy(path: PathBuf) -> anyhow::Result<PolicyDocument> {
    load_policy_file(&path).with_context(|| format!("failed to read policy {}", path.display()))
}

fn load_action(path: PathBuf) -> anyhow::Result<ActionRequest> {
    let text = fs::read_to_string(&path)
        .with_context(|| format!("failed to read action {}", path.display()))?;
    Ok(action_request_from_json_str(&text)?)
}

fn ensure_policy_exists(config: &AppConfig, policy_id: &str) -> anyhow::Result<()> {
    if config.policies.iter().any(|policy| policy.id == policy_id) {
        Ok(())
    } else {
        anyhow::bail!("trusted policy {policy_id:?} is not configured")
    }
}
