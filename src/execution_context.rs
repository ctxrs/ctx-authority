use crate::approvals::ApprovalProvider;
use crate::audit::AuditLog;
use crate::backends::SecretBackend;
use crate::config::{AgentConfig, AppConfig, AppPaths, PolicyConfig};
use crate::models::{ActionRequest, Receipt};
use crate::policy::PolicyDocument;
use crate::providers::FakeProvider;
use crate::receipts::ReceiptSigner;
use crate::runtime::BrokerRuntime;
use crate::{AuthorityError, Result};
use std::fs;
use std::path::Path;

pub struct ExecutionContext {
    trusted_agent_id: String,
    policy: PolicyDocument,
    audit: AuditLog,
    approvals: ApprovalProvider,
    secret_backend: Option<Box<dyn SecretBackend>>,
    signer: ReceiptSigner,
}

impl ExecutionContext {
    pub fn from_paths(paths: &AppPaths) -> Result<Self> {
        paths.ensure()?;
        let config = AppConfig::load(&paths.config_file)?;
        Self::from_config(paths, &config)
    }

    pub fn from_config(paths: &AppPaths, config: &AppConfig) -> Result<Self> {
        let (agent, policy_config) = trusted_execution_context(config)?;
        let policy = load_trusted_policy(policy_config)?;
        let secret_backend = config
            .secret_backend
            .as_ref()
            .map(|backend| backend.build())
            .transpose()?;

        Ok(Self {
            trusted_agent_id: agent.id.clone(),
            policy,
            audit: AuditLog::open(&paths.audit_db)?,
            approvals: ApprovalProvider::require_explicit(),
            secret_backend,
            signer: ReceiptSigner::load_or_create(paths)?,
        })
    }

    pub fn execute(&self, request: &ActionRequest) -> Result<Receipt> {
        let provider = FakeProvider::new(&request.resource);
        let runtime = BrokerRuntime {
            trusted_agent_id: &self.trusted_agent_id,
            policy: &self.policy,
            audit: &self.audit,
            approvals: &self.approvals,
            provider: &provider,
            secret_backend: self.secret_backend.as_deref(),
            signer: &self.signer,
        };
        runtime.execute(request)
    }
}

pub fn load_policy_file(path: &Path) -> Result<PolicyDocument> {
    let text = fs::read_to_string(path)?;
    Ok(serde_yaml::from_str(&text)?)
}

fn trusted_execution_context(config: &AppConfig) -> Result<(&AgentConfig, &PolicyConfig)> {
    let executable_agents = config
        .agents
        .iter()
        .filter(|agent| agent.policy.is_some())
        .collect::<Vec<_>>();

    let agent = match executable_agents.as_slice() {
        [agent] => *agent,
        [] => {
            return Err(AuthorityError::Config(
                "no trusted executable agent is configured".into(),
            ));
        }
        _ => {
            return Err(AuthorityError::Config(
                "multiple executable agents are configured; local CLI execution requires exactly one trusted agent".into(),
            ));
        }
    };

    let policy_id = agent
        .policy
        .as_deref()
        .ok_or_else(|| AuthorityError::Config("trusted agent has no policy".into()))?;
    let policy = config
        .policies
        .iter()
        .find(|policy| policy.id == policy_id)
        .ok_or_else(|| {
            AuthorityError::Config(format!("trusted policy {policy_id:?} is not configured"))
        })?;

    Ok((agent, policy))
}

fn load_trusted_policy(policy_config: &PolicyConfig) -> Result<PolicyDocument> {
    let path = Path::new(&policy_config.path);
    let policy = load_policy_file(path)?;
    let hash = policy.hash()?;
    if hash != policy_config.hash {
        return Err(AuthorityError::Config(format!(
            "trusted policy {:?} hash changed; re-run ctxa policy trust before execution",
            policy_config.id
        )));
    }
    Ok(policy)
}
