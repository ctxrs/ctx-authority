use anyhow::Context;
use authority_broker::approvals::ApprovalProvider;
use authority_broker::audit::AuditLog;
use authority_broker::backends::FakeBackend;
use authority_broker::config::{AppConfig, AppPaths};
use authority_broker::models::ActionRequest;
use authority_broker::policy::PolicyDocument;
use authority_broker::providers::FakeProvider;
use authority_broker::receipts::ReceiptSigner;
use authority_broker::runtime::BrokerRuntime;
use clap::{Parser, Subcommand, ValueEnum};
use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;

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
    Create { id: String },
}

#[derive(Debug, Subcommand)]
enum PolicyCommand {
    Check {
        #[arg(long)]
        policy: PathBuf,
        #[arg(long)]
        file: PathBuf,
    },
}

#[derive(Debug, Subcommand)]
enum ActionCommand {
    Request {
        #[arg(long)]
        policy: PathBuf,
        #[arg(long)]
        file: PathBuf,
        #[arg(long, value_enum)]
        approval: Option<CliApprovalMode>,
    },
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum CliApprovalMode {
    Approve,
    Reject,
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
        AgentCommand::Create { id } => {
            let paths = AppPaths::discover()?;
            paths.ensure()?;
            let mut config = AppConfig::load(&paths.config_file)?;
            if !config.agents.iter().any(|agent| agent.id == id) {
                config.agents.push(authority_broker::config::AgentConfig {
                    id: id.clone(),
                    description: None,
                });
                config.save(&paths.config_file)?;
            }
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
    }
}

fn action(command: ActionCommand) -> anyhow::Result<()> {
    match command {
        ActionCommand::Request {
            policy,
            file,
            approval,
        } => {
            let paths = AppPaths::discover()?;
            paths.ensure()?;
            let policy = load_policy(policy)?;
            let request = load_action(file)?;
            let audit = AuditLog::open(&paths.audit_db)?;
            let approvals = approval_provider(approval)?;
            let provider = FakeProvider::new(&request.resource);
            let backend = FakeBackend::new(BTreeMap::from([(
                "default".to_string(),
                "fake-secret-value".to_string(),
            )]));
            let signer = ReceiptSigner::load_or_create(&paths)?;
            let runtime = BrokerRuntime {
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
            let receipt: authority_broker::models::Receipt = serde_json::from_str(&text)?;
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
    Ok(serde_json::from_str(&text)?)
}

fn approval_provider(mode: Option<CliApprovalMode>) -> anyhow::Result<ApprovalProvider> {
    let mode = match mode {
        Some(mode) => mode,
        None => match std::env::var("CTXA_APPROVAL_MODE") {
            Ok(value) if value == "approve" || value == "auto" => CliApprovalMode::Approve,
            Ok(value) if value == "reject" => CliApprovalMode::Reject,
            Ok(value) => anyhow::bail!(
                "unsupported CTXA_APPROVAL_MODE {value:?}; expected \"approve\" or \"reject\""
            ),
            Err(_) => return Ok(ApprovalProvider::require_explicit()),
        },
    };

    Ok(match mode {
        CliApprovalMode::Approve => ApprovalProvider::auto_approve_for_tests(),
        CliApprovalMode::Reject => ApprovalProvider::reject(),
    })
}
