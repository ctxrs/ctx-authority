use anyhow::Context;
use clap::{Parser, Subcommand};
use ctxa::audit::AuditLog;
use ctxa::boundary::action_request_from_json_str;
use ctxa::config::{
    AgentConfig, AppConfig, AppPaths, HttpAllowConfig, HttpAuthConfig, HttpResourceConfig,
    PolicyConfig, ProfileConfig,
};
use ctxa::execution_context::{load_policy_file, ExecutionContext};
use ctxa::models::ActionRequest;
use ctxa::policy::PolicyDocument;
use ctxa::proxy::{ProxyConfig, ProxyServer};
use ctxa::receipts::{receipt_from_json_str_strict, ReceiptSigner};
use std::fs;
use std::path::PathBuf;
use std::process::Command as ProcessCommand;
use std::sync::Arc;

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
}

#[derive(Debug, Subcommand)]
enum ActionCommand {
    Request {
        #[arg(long)]
        file: PathBuf,
    },
}

#[derive(Debug, Subcommand)]
enum ReceiptCommand {
    Verify { file: PathBuf },
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
        } => {
            let paths = AppPaths::discover()?;
            paths.ensure()?;
            let mut config = AppConfig::load(&paths.config_file)?;
            let profile_config = config
                .profile_mut(&profile)
                .ok_or_else(|| anyhow::anyhow!("profile {profile} is not configured"))?;
            let resource = HttpResourceConfig {
                id: id.clone(),
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
            println!("http resource {id} on profile {profile}");
            Ok(())
        }
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
    })?;
    let proxy_url = proxy.proxy_url();
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
        .env("NO_PROXY", "")
        .env("no_proxy", "")
        .env_remove("HTTPS_PROXY")
        .env_remove("https_proxy")
        .env_remove("ALL_PROXY")
        .env_remove("all_proxy");
    let status = child
        .status()
        .with_context(|| format!("failed to run {}", command[0]))?;
    proxy.stop();
    std::process::exit(status.code().unwrap_or(1));
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
