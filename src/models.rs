use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;

pub type AgentId = String;
pub type Capability = String;
pub type ResourceId = String;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AgentProfile {
    pub id: AgentId,
    #[serde(default)]
    pub description: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ActionRequest {
    pub id: String,
    pub agent_id: AgentId,
    #[serde(default)]
    pub task_id: Option<String>,
    pub capability: Capability,
    pub resource: ResourceId,
    #[serde(default)]
    pub operation: Value,
    #[serde(default)]
    pub payload: Value,
    #[serde(default)]
    pub payload_hash: Option<String>,
    #[serde(default)]
    pub idempotency_key: Option<String>,
    #[serde(default)]
    pub requested_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PolicyDecisionKind {
    Allow,
    Deny,
    RequireApproval,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PolicyDecision {
    pub decision: PolicyDecisionKind,
    #[serde(default)]
    pub reasons: Vec<String>,
    #[serde(default)]
    pub matched_grants: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ApprovalRecord {
    pub approval_id: String,
    pub action_request_id: String,
    pub payload_hash: String,
    pub policy_hash: String,
    pub approved_by: String,
    pub approved_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ProviderExecution {
    pub status: String,
    pub provider: String,
    #[serde(default)]
    pub provider_request_id: Option<String>,
    #[serde(default)]
    pub result: BTreeMap<String, Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Receipt {
    pub receipt_version: String,
    pub receipt_id: String,
    pub principal: String,
    pub agent: String,
    #[serde(default)]
    pub task: Option<String>,
    pub action: String,
    pub resource: String,
    pub payload_hash: String,
    pub policy_hash: String,
    #[serde(default)]
    pub approval: Option<ReceiptApproval>,
    pub execution: ProviderExecution,
    pub issued_at: DateTime<Utc>,
    pub signature: ReceiptSignature,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReceiptApproval {
    pub required: bool,
    #[serde(default)]
    pub approved_by: Option<String>,
    #[serde(default)]
    pub approved_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReceiptSignature {
    pub alg: String,
    pub kid: String,
    pub sig: String,
}
