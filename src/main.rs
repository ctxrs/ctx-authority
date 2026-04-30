use anyhow::Context;
use clap::{Parser, Subcommand, ValueEnum};
use ctxa::audit::AuditLog;
use ctxa::boundary::{action_request_from_json_str, json_value_from_str_no_duplicates};
use ctxa::capabilities::{
    capability_grant_chain, child_capability_grant_is_subset, execute_capability,
    normalize_capability_list, CapabilityExecuteRequest,
};
use ctxa::config::{
    AgentConfig, AppConfig, AppPaths, CapabilityGrantConfig, CapabilityGrantConstraints,
    CapabilityProviderAuthConfig, CapabilityProviderConfig, CapabilityProviderKind,
    GrantDelegationConfig, HttpAllowConfig, HttpAuthConfig, HttpGrantConfig, HttpResourceConfig,
    HttpResourceScheme, PolicyConfig, ProfileConfig,
};
use ctxa::execution_context::{load_policy_file, ExecutionContext};
use ctxa::grants::{child_grant_is_subset, grant_chain, normalize_methods, profile_subject};
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
    #[command(about = "Initialize local ctx authority state")]
    Init,
    #[command(about = "Manage trusted agent records")]
    Agent {
        #[command(subcommand)]
        command: AgentCommand,
    },
    #[command(about = "Check and trust local policy files")]
    Policy {
        #[command(subcommand)]
        command: PolicyCommand,
    },
    #[command(about = "Manage run profiles and scoped HTTP resources")]
    Profile {
        #[command(subcommand)]
        command: ProfileCommand,
    },
    #[command(about = "Manage attenuable HTTP grants")]
    Grants {
        #[command(subcommand)]
        command: GrantCommand,
    },
    #[command(about = "Manage and execute provider capabilities")]
    Capability {
        #[command(subcommand)]
        command: CapabilityCommand,
    },
    #[command(about = "Install local runtime instructions")]
    Setup {
        #[command(subcommand)]
        command: SetupCommand,
    },
    #[command(about = "Inspect and apply redacted denied-request proposals")]
    Proposals {
        #[command(subcommand)]
        command: ProposalCommand,
    },
    #[command(about = "Inspect local certificate authority state")]
    Ca {
        #[command(subcommand)]
        command: CaCommand,
    },
    #[command(about = "Run local diagnostics")]
    Doctor {
        #[arg(long)]
        profile: Option<String>,
    },
    #[command(about = "Request an explicit structured action")]
    Action {
        #[command(subcommand)]
        command: ActionCommand,
    },
    #[command(about = "Run an agent command inside a scoped profile")]
    Run {
        #[arg(long)]
        profile: String,
        #[arg(required = true, trailing_var_arg = true, allow_hyphen_values = true)]
        command: Vec<String>,
    },
    #[command(about = "List, show, and verify local receipts")]
    Receipts {
        #[command(subcommand)]
        command: ReceiptCommand,
    },
    #[command(about = "Print local audit events")]
    Log {
        #[arg(long, default_value_t = 20)]
        limit: usize,
    },
    #[command(about = "Run the stdio MCP server")]
    Mcp {
        #[command(subcommand)]
        command: McpCommand,
    },
}

#[derive(Debug, Subcommand)]
enum AgentCommand {
    #[command(about = "Create or update a trusted agent")]
    Create {
        id: String,
        #[arg(long)]
        policy: Option<String>,
    },
}

#[derive(Debug, Subcommand)]
enum PolicyCommand {
    #[command(about = "Evaluate a policy against an action file")]
    Check {
        #[arg(long)]
        policy: PathBuf,
        #[arg(long)]
        file: PathBuf,
    },
    #[command(about = "Pin a policy file hash in local config")]
    Trust {
        #[arg(long)]
        id: String,
        #[arg(long)]
        path: PathBuf,
    },
}

#[derive(Debug, Subcommand)]
enum ProfileCommand {
    #[command(about = "Create or update a run profile")]
    Create {
        id: String,
        #[arg(long)]
        agent: Option<String>,
    },
    #[command(about = "Add or replace an HTTP resource on a profile")]
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
    #[command(about = "Add or replace an HTTPS resource on a profile")]
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
    #[command(about = "Check whether a profile allows a URL")]
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
    #[command(about = "Execute a structured action through trusted local policy")]
    Request {
        #[arg(long)]
        file: PathBuf,
    },
}

#[derive(Debug, Subcommand)]
enum ProposalCommand {
    #[command(about = "List denied-request proposals")]
    List {
        #[arg(long, default_value_t = 20)]
        limit: usize,
        #[arg(long)]
        all: bool,
    },
    #[command(about = "Show a redacted proposal")]
    Show { id: String },
    #[command(about = "Apply a proposal as a profile resource")]
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
    #[command(about = "Dismiss a proposal")]
    Dismiss {
        id: String,
        #[arg(long)]
        reason: Option<String>,
    },
}

#[derive(Debug, Subcommand)]
enum GrantCommand {
    #[command(about = "List configured HTTP grants")]
    List {
        #[arg(long)]
        profile: Option<String>,
    },
    #[command(about = "Show a grant without printing secret references")]
    Show { id: String },
    #[command(about = "Create a root HTTP grant")]
    CreateHttp(GrantCreateOptions),
    #[command(about = "Create a root HTTPS grant")]
    CreateHttps(GrantCreateOptions),
    #[command(about = "Delegate a mechanically narrower child grant")]
    Delegate {
        #[arg(long = "from")]
        from: String,
        #[arg(long)]
        id: String,
        #[arg(long)]
        profile: String,
        #[arg(long = "allow-method", required = true)]
        allow_methods: Vec<String>,
        #[arg(long = "path-prefix", required = true)]
        path_prefixes: Vec<String>,
        #[arg(long)]
        delegable: bool,
        #[arg(long, default_value_t = 0)]
        max_depth: u8,
    },
}

#[derive(Debug, Subcommand)]
enum CapabilityCommand {
    #[command(about = "Manage provider adapters")]
    Provider {
        #[command(subcommand)]
        command: CapabilityProviderCommand,
    },
    #[command(about = "Manage attenuable provider capability grants")]
    Grant {
        #[command(subcommand)]
        command: CapabilityGrantCommand,
    },
    #[command(about = "Execute a granted provider capability")]
    Execute {
        #[arg(long)]
        profile: String,
        #[arg(long)]
        provider: String,
        #[arg(long)]
        capability: String,
        #[arg(long)]
        resource: String,
        #[arg(long, default_value = "{}")]
        operation: String,
        #[arg(long, default_value = "{}")]
        payload: String,
    },
}

#[derive(Debug, Subcommand)]
enum CapabilityProviderCommand {
    #[command(name = "add-github", about = "Add or replace a GitHub provider")]
    Github {
        #[arg(long)]
        id: String,
        #[arg(long, default_value = "https://api.github.com")]
        api_base: String,
        #[arg(long)]
        token_ref: Option<String>,
        #[arg(long)]
        app_jwt_ref: Option<String>,
        #[arg(long)]
        installation_id: Option<u64>,
    },
    #[command(name = "add-google", about = "Add or replace a Google provider")]
    Google {
        #[arg(long)]
        id: String,
        #[arg(long, default_value = "https://www.googleapis.com")]
        api_base: String,
        #[arg(long)]
        token_ref: String,
    },
    #[command(
        name = "add-microsoft",
        about = "Add or replace a Microsoft Graph provider"
    )]
    Microsoft {
        #[arg(long)]
        id: String,
        #[arg(long, default_value = "https://graph.microsoft.com")]
        api_base: String,
        #[arg(long)]
        token_ref: String,
    },
}

#[derive(Debug, Subcommand)]
enum CapabilityGrantCommand {
    #[command(about = "List configured capability grants")]
    List {
        #[arg(long)]
        profile: Option<String>,
        #[arg(long)]
        provider: Option<String>,
    },
    #[command(about = "Show a capability grant")]
    Show { id: String },
    #[command(about = "Create a root capability grant")]
    Create(CapabilityGrantCreateOptions),
    #[command(about = "Delegate a mechanically narrower capability grant")]
    Delegate(CapabilityGrantDelegateOptions),
}

#[derive(Debug, clap::Args)]
struct CapabilityGrantCreateOptions {
    #[arg(long)]
    id: String,
    #[arg(long)]
    profile: String,
    #[arg(long)]
    provider: String,
    #[arg(long = "capability", required = true)]
    capabilities: Vec<String>,
    #[arg(long = "resource", required = true)]
    resources: Vec<String>,
    #[arg(long = "operation-equals")]
    operation_equals: Vec<String>,
    #[arg(long = "payload-equals")]
    payload_equals: Vec<String>,
    #[arg(long)]
    delegable: bool,
    #[arg(long, default_value_t = 0)]
    max_depth: u8,
}

#[derive(Debug, clap::Args)]
struct CapabilityGrantDelegateOptions {
    #[arg(long = "from")]
    from: String,
    #[arg(long)]
    id: String,
    #[arg(long)]
    profile: String,
    #[arg(long = "capability", required = true)]
    capabilities: Vec<String>,
    #[arg(long = "resource", required = true)]
    resources: Vec<String>,
    #[arg(long = "operation-equals")]
    operation_equals: Vec<String>,
    #[arg(long = "payload-equals")]
    payload_equals: Vec<String>,
    #[arg(long)]
    delegable: bool,
    #[arg(long, default_value_t = 0)]
    max_depth: u8,
}

#[derive(Debug, clap::Args)]
struct GrantCreateOptions {
    #[arg(long)]
    id: String,
    #[arg(long)]
    profile: String,
    #[arg(long)]
    host: String,
    #[arg(long)]
    secret_ref: String,
    #[arg(long = "allow-method", required = true)]
    allow_methods: Vec<String>,
    #[arg(long = "path-prefix", required = true)]
    path_prefixes: Vec<String>,
    #[arg(long)]
    delegable: bool,
    #[arg(long, default_value_t = 0)]
    max_depth: u8,
}

#[derive(Debug, Subcommand)]
enum SetupCommand {
    #[command(about = "Create a profile and install runtime instructions")]
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
    #[command(about = "Show local profile proxy CA support")]
    Status,
}

#[derive(Debug, Subcommand)]
enum ReceiptCommand {
    #[command(about = "List local receipts")]
    List {
        #[arg(long, default_value_t = 20)]
        limit: usize,
    },
    #[command(about = "Show a stored local receipt")]
    Show { id: String },
    #[command(about = "Verify a receipt with the local signing key")]
    Verify { file: PathBuf },
}

#[derive(Debug, Subcommand)]
enum McpCommand {
    #[command(about = "Serve MCP over stdio")]
    Serve,
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Init => init(),
        Command::Agent { command } => agent(command),
        Command::Policy { command } => policy(command),
        Command::Profile { command } => profile(command),
        Command::Grants { command } => grants(command),
        Command::Capability { command } => capability(command),
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
    match profile_allows_url(profile_config, &config.grants, &method, &url)? {
        Some(resource) => {
            println!("allowed authority={resource}");
            Ok(())
        }
        None => anyhow::bail!("denied by profile {profile}"),
    }
}

fn grants(command: GrantCommand) -> anyhow::Result<()> {
    match command {
        GrantCommand::List { profile } => list_grants(profile),
        GrantCommand::Show { id } => show_grant(id),
        GrantCommand::CreateHttp(options) => create_root_grant(HttpResourceScheme::Http, options),
        GrantCommand::CreateHttps(options) => create_root_grant(HttpResourceScheme::Https, options),
        GrantCommand::Delegate {
            from,
            id,
            profile,
            allow_methods,
            path_prefixes,
            delegable,
            max_depth,
        } => delegate_grant(
            from,
            id,
            profile,
            allow_methods,
            path_prefixes,
            delegable,
            max_depth,
        ),
    }
}

fn list_grants(profile: Option<String>) -> anyhow::Result<()> {
    let paths = AppPaths::discover()?;
    let config = AppConfig::load(&paths.config_file)?;
    for grant in &config.grants {
        if profile
            .as_deref()
            .is_some_and(|profile| profile != grant.profile)
        {
            continue;
        }
        let parent = grant.parent.as_deref().unwrap_or("-");
        println!(
            "{} profile={} subject={} parent={} scheme={} host={} delegable={} depth={}",
            grant.id,
            grant.profile,
            grant.subject,
            parent,
            scheme_name(grant.scheme),
            grant.host,
            grant.delegation.allowed,
            grant.delegation.remaining_depth
        );
    }
    Ok(())
}

fn show_grant(id: String) -> anyhow::Result<()> {
    let paths = AppPaths::discover()?;
    let config = AppConfig::load(&paths.config_file)?;
    let grant = config
        .grant(&id)
        .ok_or_else(|| anyhow::anyhow!("grant {id} is not configured"))?;
    let chain = grant_chain(&config.grants, &id)?;
    let chain_ids: Vec<&str> = chain.iter().map(|grant| grant.id.as_str()).collect();
    let value = json!({
        "id": grant.id,
        "parent": grant.parent,
        "profile": grant.profile,
        "subject": grant.subject,
        "scheme": scheme_name(grant.scheme),
        "host": grant.host,
        "has_secret_ref": grant.secret_ref.is_some(),
        "allow": grant.allow,
        "delegation": grant.delegation,
        "chain": chain_ids,
    });
    println!("{}", serde_json::to_string_pretty(&value)?);
    Ok(())
}

fn create_root_grant(
    scheme: HttpResourceScheme,
    options: GrantCreateOptions,
) -> anyhow::Result<()> {
    let paths = AppPaths::discover()?;
    paths.ensure()?;
    let mut config = AppConfig::load(&paths.config_file)?;
    if config.grant(&options.id).is_some() {
        anyhow::bail!("grant {} already exists", options.id);
    }
    if options.delegable && options.max_depth == 0 {
        anyhow::bail!("delegable grants must specify --max-depth greater than zero");
    }
    if !options.delegable && options.max_depth != 0 {
        anyhow::bail!("--max-depth requires --delegable");
    }
    let profile = config
        .profile(&options.profile)
        .ok_or_else(|| anyhow::anyhow!("profile {} is not configured", options.profile))?;
    let grant = HttpGrantConfig {
        id: options.id.clone(),
        parent: None,
        profile: options.profile.clone(),
        subject: profile_subject(profile),
        scheme,
        host: options.host,
        secret_ref: Some(options.secret_ref),
        allow: HttpAllowConfig {
            methods: normalize_methods(options.allow_methods),
            path_prefixes: options.path_prefixes,
        },
        delegation: GrantDelegationConfig {
            allowed: options.delegable,
            remaining_depth: if options.delegable {
                options.max_depth
            } else {
                0
            },
        },
    };
    let audit_data = redacted_grant_audit("grant_created", &grant);
    config.grants.push(grant);
    config.save(&paths.config_file)?;
    AuditLog::open(&paths.audit_db)?.record("grant_created", &audit_data)?;
    println!("grant {}", options.id);
    Ok(())
}

fn delegate_grant(
    from: String,
    id: String,
    profile: String,
    allow_methods: Vec<String>,
    path_prefixes: Vec<String>,
    delegable: bool,
    max_depth: u8,
) -> anyhow::Result<()> {
    let paths = AppPaths::discover()?;
    paths.ensure()?;
    let mut config = AppConfig::load(&paths.config_file)?;
    if config.grant(&id).is_some() {
        anyhow::bail!("grant {id} already exists");
    }
    let parent = config
        .grant(&from)
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("grant {from} is not configured"))?;
    if delegable && max_depth == 0 {
        anyhow::bail!("delegable grants must specify --max-depth greater than zero");
    }
    if !delegable && max_depth != 0 {
        anyhow::bail!("--max-depth requires --delegable");
    }
    let child_profile = config
        .profile(&profile)
        .ok_or_else(|| anyhow::anyhow!("profile {profile} is not configured"))?;
    let child = HttpGrantConfig {
        id: id.clone(),
        parent: Some(parent.id.clone()),
        profile: profile.clone(),
        subject: profile_subject(child_profile),
        scheme: parent.scheme,
        host: parent.host.clone(),
        secret_ref: None,
        allow: HttpAllowConfig {
            methods: normalize_methods(allow_methods),
            path_prefixes,
        },
        delegation: GrantDelegationConfig {
            allowed: delegable,
            remaining_depth: if delegable { max_depth } else { 0 },
        },
    };
    child_grant_is_subset(&parent, &child)?;
    let audit_data = redacted_grant_audit("grant_delegated", &child);
    config.grants.push(child);
    config.save(&paths.config_file)?;
    AuditLog::open(&paths.audit_db)?.record("grant_delegated", &audit_data)?;
    println!("grant {id}");
    Ok(())
}

fn redacted_grant_audit(kind: &str, grant: &HttpGrantConfig) -> Value {
    json!({
        "kind": kind,
        "id": grant.id,
        "parent": grant.parent,
        "profile": grant.profile,
        "subject": grant.subject,
        "scheme": scheme_name(grant.scheme),
        "host": grant.host,
        "has_secret_ref": grant.secret_ref.is_some(),
        "allow": grant.allow,
        "delegation": grant.delegation,
    })
}

fn capability(command: CapabilityCommand) -> anyhow::Result<()> {
    match command {
        CapabilityCommand::Provider { command } => capability_provider(command),
        CapabilityCommand::Grant { command } => capability_grant(command),
        CapabilityCommand::Execute {
            profile,
            provider,
            capability,
            resource,
            operation,
            payload,
        } => capability_execute(profile, provider, capability, resource, operation, payload),
    }
}

fn capability_provider(command: CapabilityProviderCommand) -> anyhow::Result<()> {
    match command {
        CapabilityProviderCommand::Github {
            id,
            api_base,
            token_ref,
            app_jwt_ref,
            installation_id,
        } => {
            let auth = match (token_ref, app_jwt_ref, installation_id) {
                (Some(token_ref), None, None) => CapabilityProviderAuthConfig::Bearer { token_ref },
                (None, Some(app_jwt_ref), Some(installation_id)) => {
                    CapabilityProviderAuthConfig::GithubAppInstallation {
                        app_jwt_ref,
                        installation_id,
                    }
                }
                _ => anyhow::bail!(
                    "GitHub provider requires either --token-ref or both --app-jwt-ref and --installation-id"
                ),
            };
            upsert_capability_provider(CapabilityProviderConfig {
                id,
                kind: CapabilityProviderKind::Github,
                api_base,
                auth,
            })
        }
        CapabilityProviderCommand::Google {
            id,
            api_base,
            token_ref,
        } => upsert_capability_provider(CapabilityProviderConfig {
            id,
            kind: CapabilityProviderKind::Google,
            api_base,
            auth: CapabilityProviderAuthConfig::Bearer { token_ref },
        }),
        CapabilityProviderCommand::Microsoft {
            id,
            api_base,
            token_ref,
        } => upsert_capability_provider(CapabilityProviderConfig {
            id,
            kind: CapabilityProviderKind::Microsoft,
            api_base,
            auth: CapabilityProviderAuthConfig::Bearer { token_ref },
        }),
    }
}

fn upsert_capability_provider(provider: CapabilityProviderConfig) -> anyhow::Result<()> {
    let paths = AppPaths::discover()?;
    paths.ensure()?;
    let mut config = AppConfig::load(&paths.config_file)?;
    let id = provider.id.clone();
    let kind = capability_provider_kind_name(provider.kind);
    if let Some(existing) = config
        .capability_providers
        .iter_mut()
        .find(|existing| existing.id == id)
    {
        *existing = provider;
    } else {
        config.capability_providers.push(provider);
    }
    config.save(&paths.config_file)?;
    AuditLog::open(&paths.audit_db)?.record(
        "capability_provider_saved",
        &json!({
            "id": id,
            "kind": kind,
        }),
    )?;
    println!("capability provider {id}");
    Ok(())
}

fn capability_grant(command: CapabilityGrantCommand) -> anyhow::Result<()> {
    match command {
        CapabilityGrantCommand::List { profile, provider } => {
            list_capability_grants(profile, provider)
        }
        CapabilityGrantCommand::Show { id } => show_capability_grant(id),
        CapabilityGrantCommand::Create(options) => create_root_capability_grant(options),
        CapabilityGrantCommand::Delegate(options) => delegate_capability_grant(options),
    }
}

fn list_capability_grants(profile: Option<String>, provider: Option<String>) -> anyhow::Result<()> {
    let paths = AppPaths::discover()?;
    let config = AppConfig::load(&paths.config_file)?;
    for grant in &config.capability_grants {
        if profile
            .as_deref()
            .is_some_and(|profile| profile != grant.profile)
        {
            continue;
        }
        if provider
            .as_deref()
            .is_some_and(|provider| provider != grant.provider)
        {
            continue;
        }
        let parent = grant.parent.as_deref().unwrap_or("-");
        println!(
            "{} profile={} subject={} parent={} provider={} capabilities={} resources={} delegable={} depth={}",
            grant.id,
            grant.profile,
            grant.subject,
            parent,
            grant.provider,
            grant.capabilities.join(","),
            grant.resources.join(","),
            grant.delegation.allowed,
            grant.delegation.remaining_depth
        );
    }
    Ok(())
}

fn show_capability_grant(id: String) -> anyhow::Result<()> {
    let paths = AppPaths::discover()?;
    let config = AppConfig::load(&paths.config_file)?;
    let grant = config
        .capability_grant(&id)
        .ok_or_else(|| anyhow::anyhow!("capability grant {id} is not configured"))?;
    let chain = capability_grant_chain(&config.capability_grants, &id)?;
    let chain_ids: Vec<&str> = chain.iter().map(|grant| grant.id.as_str()).collect();
    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "id": grant.id,
            "parent": grant.parent,
            "profile": grant.profile,
            "subject": grant.subject,
            "provider": grant.provider,
            "capabilities": grant.capabilities,
            "resources": grant.resources,
            "constraints": grant.constraints,
            "delegation": grant.delegation,
            "chain": chain_ids,
        }))?
    );
    Ok(())
}

fn create_root_capability_grant(options: CapabilityGrantCreateOptions) -> anyhow::Result<()> {
    let paths = AppPaths::discover()?;
    paths.ensure()?;
    let mut config = AppConfig::load(&paths.config_file)?;
    if config.capability_grant(&options.id).is_some() {
        anyhow::bail!("capability grant {} already exists", options.id);
    }
    if options.delegable && options.max_depth == 0 {
        anyhow::bail!("delegable capability grants must specify --max-depth greater than zero");
    }
    if !options.delegable && options.max_depth != 0 {
        anyhow::bail!("--max-depth requires --delegable");
    }
    if config.capability_provider(&options.provider).is_none() {
        anyhow::bail!("capability provider {} is not configured", options.provider);
    }
    let profile = config
        .profile(&options.profile)
        .ok_or_else(|| anyhow::anyhow!("profile {} is not configured", options.profile))?;
    let grant = CapabilityGrantConfig {
        id: options.id.clone(),
        parent: None,
        profile: options.profile.clone(),
        subject: profile_subject(profile),
        provider: options.provider,
        capabilities: normalize_capability_list(options.capabilities),
        resources: normalize_capability_list(options.resources),
        constraints: parse_capability_constraints(
            options.operation_equals,
            options.payload_equals,
        )?,
        delegation: GrantDelegationConfig {
            allowed: options.delegable,
            remaining_depth: if options.delegable {
                options.max_depth
            } else {
                0
            },
        },
    };
    let audit_data = redacted_capability_grant_audit("capability_grant_created", &grant);
    config.capability_grants.push(grant);
    config.save(&paths.config_file)?;
    AuditLog::open(&paths.audit_db)?.record("capability_grant_created", &audit_data)?;
    println!("capability grant {}", options.id);
    Ok(())
}

fn delegate_capability_grant(options: CapabilityGrantDelegateOptions) -> anyhow::Result<()> {
    let paths = AppPaths::discover()?;
    paths.ensure()?;
    let mut config = AppConfig::load(&paths.config_file)?;
    if config.capability_grant(&options.id).is_some() {
        anyhow::bail!("capability grant {} already exists", options.id);
    }
    if options.delegable && options.max_depth == 0 {
        anyhow::bail!("delegable capability grants must specify --max-depth greater than zero");
    }
    if !options.delegable && options.max_depth != 0 {
        anyhow::bail!("--max-depth requires --delegable");
    }
    let parent = config
        .capability_grant(&options.from)
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("capability grant {} is not configured", options.from))?;
    let child_profile = config
        .profile(&options.profile)
        .ok_or_else(|| anyhow::anyhow!("profile {} is not configured", options.profile))?;
    let child = CapabilityGrantConfig {
        id: options.id.clone(),
        parent: Some(parent.id.clone()),
        profile: options.profile.clone(),
        subject: profile_subject(child_profile),
        provider: parent.provider.clone(),
        capabilities: normalize_capability_list(options.capabilities),
        resources: normalize_capability_list(options.resources),
        constraints: parse_capability_constraints(
            options.operation_equals,
            options.payload_equals,
        )?,
        delegation: GrantDelegationConfig {
            allowed: options.delegable,
            remaining_depth: if options.delegable {
                options.max_depth
            } else {
                0
            },
        },
    };
    child_capability_grant_is_subset(&parent, &child)?;
    let audit_data = redacted_capability_grant_audit("capability_grant_delegated", &child);
    config.capability_grants.push(child);
    config.save(&paths.config_file)?;
    AuditLog::open(&paths.audit_db)?.record("capability_grant_delegated", &audit_data)?;
    println!("capability grant {}", options.id);
    Ok(())
}

fn capability_execute(
    profile: String,
    provider: String,
    capability: String,
    resource: String,
    operation: String,
    payload: String,
) -> anyhow::Result<()> {
    let paths = AppPaths::discover()?;
    paths.ensure()?;
    let config = AppConfig::load(&paths.config_file)?;
    let provider_config = config
        .capability_provider(&provider)
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("capability provider {provider} is not configured"))?;
    let secret_backend = config
        .secret_backend
        .as_ref()
        .ok_or_else(|| {
            anyhow::anyhow!(
                "configure `secret_backend` in config.yaml before executing capabilities"
            )
        })?
        .build()?;
    let request = CapabilityExecuteRequest {
        profile,
        provider,
        capability,
        resource,
        operation: json_value_from_str_no_duplicates(&operation)?,
        payload: json_value_from_str_no_duplicates(&payload)?,
    };
    let envelope = execute_capability(
        &config.profiles,
        &config.capability_grants,
        &provider_config,
        request,
        secret_backend.as_ref(),
        &AuditLog::open(&paths.audit_db)?,
        &ReceiptSigner::load_or_create(&paths)?,
    )?;
    println!("{}", serde_json::to_string_pretty(&envelope)?);
    Ok(())
}

fn redacted_capability_grant_audit(kind: &str, grant: &CapabilityGrantConfig) -> Value {
    json!({
        "kind": kind,
        "id": grant.id,
        "parent": grant.parent,
        "profile": grant.profile,
        "subject": grant.subject,
        "provider": grant.provider,
        "capabilities": grant.capabilities,
        "resources": grant.resources,
        "constraints": grant.constraints,
        "delegation": grant.delegation,
    })
}

fn parse_capability_constraints(
    operation_equals: Vec<String>,
    payload_equals: Vec<String>,
) -> anyhow::Result<CapabilityGrantConstraints> {
    Ok(CapabilityGrantConstraints {
        operation_equals: parse_constraint_pairs(operation_equals)?,
        payload_equals: parse_constraint_pairs(payload_equals)?,
    })
}

fn parse_constraint_pairs(pairs: Vec<String>) -> anyhow::Result<BTreeMap<String, Value>> {
    let mut parsed = BTreeMap::new();
    for pair in pairs {
        let (key, raw_value) = pair
            .split_once('=')
            .ok_or_else(|| anyhow::anyhow!("constraint must use key=value syntax"))?;
        if key.trim().is_empty() {
            anyhow::bail!("constraint key must not be empty");
        }
        let value = json_value_from_str_no_duplicates(raw_value)
            .unwrap_or_else(|_| Value::String(raw_value.to_string()));
        parsed.insert(key.to_string(), value);
    }
    Ok(parsed)
}

fn capability_provider_kind_name(kind: CapabilityProviderKind) -> &'static str {
    match kind {
        CapabilityProviderKind::Github => "github",
        CapabilityProviderKind::Google => "google",
        CapabilityProviderKind::Microsoft => "microsoft",
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
        profiles: config.profiles.clone(),
        profile: profile.clone(),
        grants: config.grants.clone(),
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
        if !matches!(
            kind.as_str(),
            "action_executed" | "proxy_request_receipt" | "capability_receipt"
        ) {
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
