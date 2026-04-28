use crate::canonical::canonical_json_bytes;
use crate::models::{ActionRequest, PolicyDecision, PolicyDecisionKind};
use crate::Result;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct PolicyDocument {
    pub version: u32,
    #[serde(default)]
    pub grants: Vec<Grant>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Grant {
    pub id: String,
    pub agent: String,
    pub capability: String,
    pub resource: String,
    #[serde(default)]
    pub allow: AllowRule,
    #[serde(default)]
    pub require_approval: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct AllowRule {
    #[serde(default)]
    pub methods: Vec<String>,
    #[serde(default)]
    pub hosts: Vec<String>,
    #[serde(default)]
    pub path_prefixes: Vec<String>,
}

impl PolicyDocument {
    pub fn evaluate(&self, request: &ActionRequest) -> PolicyDecision {
        let mut matched = Vec::new();
        let mut approval = false;

        for grant in &self.grants {
            if !grant.matches(request) {
                continue;
            }
            matched.push(grant.id.clone());
            if grant.require_approval {
                approval = true;
            }
        }

        if matched.is_empty() {
            return PolicyDecision {
                decision: PolicyDecisionKind::Deny,
                reasons: vec!["no matching grant".into()],
                matched_grants: vec![],
            };
        }

        PolicyDecision {
            decision: if approval {
                PolicyDecisionKind::RequireApproval
            } else {
                PolicyDecisionKind::Allow
            },
            reasons: vec![],
            matched_grants: matched,
        }
    }

    pub fn hash(&self) -> Result<String> {
        let bytes = canonical_json_bytes(self)?;
        let digest = Sha256::digest(bytes);
        Ok(format!("sha256:{}", hex::encode(digest)))
    }
}

impl Grant {
    fn matches(&self, request: &ActionRequest) -> bool {
        if self.agent != request.agent_id
            || self.capability != request.capability
            || self.resource != request.resource
        {
            return false;
        }

        if request.capability == "http.request" {
            let method = request
                .operation
                .get("method")
                .and_then(|value| value.as_str())
                .unwrap_or_default();
            let host = request
                .operation
                .get("host")
                .and_then(|value| value.as_str())
                .unwrap_or_default();
            let path = request
                .operation
                .get("path")
                .and_then(|value| value.as_str())
                .unwrap_or_default();

            if !self.allow.methods.is_empty()
                && !self.allow.methods.iter().any(|allowed| allowed == method)
            {
                return false;
            }
            if !self.allow.hosts.is_empty()
                && !self.allow.hosts.iter().any(|allowed| allowed == host)
            {
                return false;
            }
            if !self.allow.path_prefixes.is_empty()
                && !self
                    .allow
                    .path_prefixes
                    .iter()
                    .any(|prefix| path.starts_with(prefix))
            {
                return false;
            }
        }

        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn allows_matching_http_grant() {
        let policy = PolicyDocument {
            version: 1,
            grants: vec![Grant {
                id: "github_read".into(),
                agent: "openclaw".into(),
                capability: "http.request".into(),
                resource: "github".into(),
                allow: AllowRule {
                    methods: vec!["GET".into()],
                    hosts: vec!["api.github.com".into()],
                    path_prefixes: vec!["/repos/example/repo/issues".into()],
                },
                require_approval: false,
            }],
        };
        let request = ActionRequest {
            id: "act_1".into(),
            agent_id: "openclaw".into(),
            task_id: None,
            capability: "http.request".into(),
            resource: "github".into(),
            operation: json!({
                "method": "GET",
                "host": "api.github.com",
                "path": "/repos/example/repo/issues/1"
            }),
            payload: json!({}),
            payload_hash: None,
            idempotency_key: None,
            requested_at: None,
        };

        assert_eq!(
            policy.evaluate(&request).decision,
            PolicyDecisionKind::Allow
        );
    }

    #[test]
    fn rejects_unknown_policy_fields() {
        let error = serde_yaml::from_str::<PolicyDocument>(
            r#"
version: 1
grants:
  - id: github_read
    agent: openclaw
    capability: http.request
    resource: github
    allow:
      method: [GET]
"#,
        )
        .unwrap_err()
        .to_string();

        assert!(error.contains("unknown field"));
    }
}
