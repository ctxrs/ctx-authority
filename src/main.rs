use anyhow::Context;
use authority_broker::approvals::ApprovalProvider;
use authority_broker::audit::AuditLog;
use authority_broker::backends::FakeBackend;
use authority_broker::config::{AgentConfig, AppConfig, AppPaths, PolicyConfig};
use authority_broker::models::ActionRequest;
use authority_broker::policy::PolicyDocument;
use authority_broker::providers::FakeProvider;
use authority_broker::receipts::{
    json_value_from_str_no_duplicates, receipt_from_json_str_strict, ReceiptSigner,
};
use authority_broker::runtime::BrokerRuntime;
use clap::{Parser, Subcommand};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

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
    Action {
        #[command(subcommand)]
        command: ActionCommand,
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
        Command::Action { command } => action(command),
        Command::Receipts { command } => receipts(command),
        Command::Log { limit } => log(limit),
        Command::Mcp { command } => mcp(command),
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
            paths.ensure()?;
            let config = AppConfig::load(&paths.config_file)?;
            let (agent, policy_config) = trusted_execution_context(&config)?;
            let policy = load_trusted_policy(policy_config)?;
            let request = load_action(file)?;
            let audit = AuditLog::open(&paths.audit_db)?;
            let approvals = ApprovalProvider::require_explicit();
            let provider = FakeProvider::new(&request.resource);
            let backend = FakeBackend::new(BTreeMap::from([(
                "default".to_string(),
                "fake-secret-value".to_string(),
            )]));
            let signer = ReceiptSigner::load_or_create(&paths)?;
            let runtime = BrokerRuntime {
                trusted_agent_id: &agent.id,
                policy: &policy,
                audit: &audit,
                approvals: &approvals,
                provider: &provider,
                secret_backend: Some(&backend),
                signer: &signer,
            };
            let receipt = runtime.execute(&request)?;
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
            authority_broker::mcp::serve_stdio(stdin.lock(), &mut stdout)?;
            Ok(())
        }
    }
}

fn load_policy(path: PathBuf) -> anyhow::Result<PolicyDocument> {
    let text = fs::read_to_string(&path)
        .with_context(|| format!("failed to read policy {}", path.display()))?;
    Ok(serde_yaml::from_str(&text)?)
}

fn load_action(path: PathBuf) -> anyhow::Result<ActionRequest> {
    let text = fs::read_to_string(&path)
        .with_context(|| format!("failed to read action {}", path.display()))?;
    let value = json_value_from_str_no_duplicates(&text)?;
    Ok(serde_json::from_value(value)?)
}

fn ensure_policy_exists(config: &AppConfig, policy_id: &str) -> anyhow::Result<()> {
    if config.policies.iter().any(|policy| policy.id == policy_id) {
        Ok(())
    } else {
        anyhow::bail!("trusted policy {policy_id:?} is not configured")
    }
}

fn trusted_execution_context(config: &AppConfig) -> anyhow::Result<(&AgentConfig, &PolicyConfig)> {
    let executable_agents = config
        .agents
        .iter()
        .filter(|agent| agent.policy.is_some())
        .collect::<Vec<_>>();

    let agent = match executable_agents.as_slice() {
        [agent] => *agent,
        [] => anyhow::bail!("no trusted executable agent is configured"),
        _ => anyhow::bail!(
            "multiple executable agents are configured; local CLI execution requires exactly one trusted agent"
        ),
    };

    let policy_id = agent
        .policy
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("trusted agent has no policy"))?;
    let policy = config
        .policies
        .iter()
        .find(|policy| policy.id == policy_id)
        .ok_or_else(|| anyhow::anyhow!("trusted policy {policy_id:?} is not configured"))?;

    Ok((agent, policy))
}

fn load_trusted_policy(policy_config: &PolicyConfig) -> anyhow::Result<PolicyDocument> {
    let path = Path::new(&policy_config.path);
    let policy = load_policy(path.to_path_buf())?;
    let hash = policy.hash()?;
    if hash != policy_config.hash {
        anyhow::bail!(
            "trusted policy {:?} hash changed; re-run ctxa policy trust before execution",
            policy_config.id
        );
    }
    Ok(policy)
}
