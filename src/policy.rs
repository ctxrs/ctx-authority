use crate::canonical::canonical_json_bytes;
use crate::models::{ActionRequest, PolicyDecision, PolicyDecisionKind};
use crate::{AuthorityError, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const SUPPORTED_POLICY_VERSION: u32 = 1;
const SUPPORTED_CAPABILITIES: &[&str] = &["http.request", "email.send"];

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
    #[serde(default)]
    pub recipient_domains: Vec<String>,
}

impl PolicyDocument {
    pub fn validate(&self) -> Result<()> {
        if self.version != SUPPORTED_POLICY_VERSION {
            return Err(AuthorityError::Config(format!(
                "unsupported policy version {}; expected {}",
                self.version, SUPPORTED_POLICY_VERSION
            )));
        }
        for grant in &self.grants {
            grant.validate()?;
        }
        Ok(())
    }

    pub fn evaluate(&self, request: &ActionRequest) -> Result<PolicyDecision> {
        self.validate()?;
        if !is_supported_capability(&request.capability) {
            return Ok(PolicyDecision {
                decision: PolicyDecisionKind::Deny,
                reasons: vec![format!("unsupported capability {}", request.capability)],
                matched_grants: vec![],
            });
        }

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
            return Ok(PolicyDecision {
                decision: PolicyDecisionKind::Deny,
                reasons: vec!["no matching grant".into()],
                matched_grants: vec![],
            });
        }

        Ok(PolicyDecision {
            decision: if approval {
                PolicyDecisionKind::RequireApproval
            } else {
                PolicyDecisionKind::Allow
            },
            reasons: vec![],
            matched_grants: matched,
        })
    }

    pub fn hash(&self) -> Result<String> {
        self.validate()?;
        let bytes = canonical_json_bytes(self)?;
        let digest = Sha256::digest(bytes);
        Ok(format!("sha256:{}", hex::encode(digest)))
    }
}

impl Grant {
    fn validate(&self) -> Result<()> {
        if !is_supported_capability(&self.capability) {
            return Err(AuthorityError::Config(format!(
                "grant {} has unsupported capability {}",
                self.id, self.capability
            )));
        }

        if self.capability == "http.request" {
            if self.allow.methods.is_empty()
                || self.allow.hosts.is_empty()
                || self.allow.path_prefixes.is_empty()
            {
                return Err(AuthorityError::Config(format!(
                    "http.request grant {} must specify methods, hosts, and path_prefixes",
                    self.id
                )));
            }

            if self.allow.methods.iter().any(|method| method.is_empty()) {
                return Err(AuthorityError::Config(format!(
                    "http.request grant {} has an empty method",
                    self.id
                )));
            }
            if self.allow.hosts.iter().any(|host| host.is_empty()) {
                return Err(AuthorityError::Config(format!(
                    "http.request grant {} has an empty host",
                    self.id
                )));
            }
            if self
                .allow
                .path_prefixes
                .iter()
                .any(|prefix| !is_safe_http_path_prefix(prefix))
            {
                return Err(AuthorityError::Config(format!(
                    "http.request grant {} has an invalid path_prefix",
                    self.id
                )));
            }
        }
        if self.capability == "email.send" {
            if self.allow.recipient_domains.is_empty() {
                return Err(AuthorityError::Config(format!(
                    "email.send grant {} must specify recipient_domains",
                    self.id
                )));
            }
            if self
                .allow
                .recipient_domains
                .iter()
                .any(|domain| !is_safe_email_domain(domain))
            {
                return Err(AuthorityError::Config(format!(
                    "email.send grant {} has an invalid recipient_domain",
                    self.id
                )));
            }
        }
        Ok(())
    }

    fn matches(&self, request: &ActionRequest) -> bool {
        if self.agent != request.agent_id
            || self.capability != request.capability
            || self.resource != request.resource
        {
            return false;
        }

        match request.capability.as_str() {
            "http.request" => self.matches_http_request(request),
            "email.send" => self.matches_email_send(request),
            _ => false,
        }
    }

    fn matches_http_request(&self, request: &ActionRequest) -> bool {
        let Some(operation) = request.operation.as_object() else {
            return false;
        };
        if operation
            .keys()
            .any(|key| !matches!(key.as_str(), "method" | "host" | "path"))
        {
            return false;
        }

        let method = operation
            .get("method")
            .and_then(|value| value.as_str())
            .unwrap_or_default();
        let host = operation
            .get("host")
            .and_then(|value| value.as_str())
            .unwrap_or_default();
        let path = operation
            .get("path")
            .and_then(|value| value.as_str())
            .unwrap_or_default();

        if !is_safe_http_path(path) {
            return false;
        }

        if !self.allow.methods.is_empty()
            && !self.allow.methods.iter().any(|allowed| allowed == method)
        {
            return false;
        }
        if !self.allow.hosts.is_empty() && !self.allow.hosts.iter().any(|allowed| allowed == host) {
            return false;
        }
        if !self.allow.path_prefixes.is_empty()
            && !self
                .allow
                .path_prefixes
                .iter()
                .any(|prefix| path_matches_prefix(path, prefix))
        {
            return false;
        }

        true
    }

    fn matches_email_send(&self, request: &ActionRequest) -> bool {
        let Some(operation) = request.operation.as_object() else {
            return false;
        };
        if operation
            .keys()
            .any(|key| !matches!(key.as_str(), "to" | "subject" | "secret_ref"))
        {
            return false;
        }

        let Some(to) = operation.get("to").and_then(|value| value.as_str()) else {
            return false;
        };
        let Some(domain) = recipient_domain(to) else {
            return false;
        };

        self.allow
            .recipient_domains
            .iter()
            .any(|allowed| allowed.eq_ignore_ascii_case(domain))
    }
}

fn is_supported_capability(capability: &str) -> bool {
    SUPPORTED_CAPABILITIES.contains(&capability)
}

fn path_matches_prefix(path: &str, prefix: &str) -> bool {
    if !is_safe_http_path(path) || !is_safe_http_path_prefix(prefix) {
        return false;
    }

    path == prefix
        || path
            .strip_prefix(prefix)
            .is_some_and(|suffix| suffix.starts_with('/'))
}

fn is_safe_http_path(path: &str) -> bool {
    if path.is_empty() || !path.starts_with('/') || path.contains('\\') {
        return false;
    }

    let mut current = path.to_owned();
    for _ in 0..4 {
        if has_unsafe_http_path_chars_or_segments(&current) {
            return false;
        }

        let Some(decoded) = percent_decode_once(&current) else {
            return false;
        };
        if decoded == current {
            return true;
        }
        current = decoded;
    }

    !current.contains('%') && !has_unsafe_http_path_chars_or_segments(&current)
}

fn is_safe_http_path_prefix(path: &str) -> bool {
    is_safe_http_path(path) && path != "/" && !path.ends_with('/')
}

fn has_unsafe_http_path_chars_or_segments(path: &str) -> bool {
    path.bytes()
        .any(|byte| byte.is_ascii_control() || matches!(byte, b'\\' | b'?' | b'#'))
        || path
            .split('/')
            .any(|segment| segment == "." || segment == "..")
}

fn percent_decode_once(input: &str) -> Option<String> {
    let bytes = input.as_bytes();
    let mut output = Vec::with_capacity(bytes.len());
    let mut index = 0;

    while index < bytes.len() {
        if bytes[index] == b'%' {
            let high = *bytes.get(index + 1)?;
            let low = *bytes.get(index + 2)?;
            output.push((hex_value(high)? << 4) | hex_value(low)?);
            index += 3;
        } else {
            output.push(bytes[index]);
            index += 1;
        }
    }

    String::from_utf8(output).ok()
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn recipient_domain(address: &str) -> Option<&str> {
    if address != address.trim() {
        return None;
    }
    if address
        .bytes()
        .any(|byte| byte.is_ascii_whitespace() || matches!(byte, b',' | b';' | b'<' | b'>'))
    {
        return None;
    }

    let mut parts = address.split('@');
    let local = parts.next()?;
    let domain = parts.next()?;
    if parts.next().is_some() || local.is_empty() || !is_safe_email_domain(domain) {
        return None;
    }
    Some(domain)
}

fn is_safe_email_domain(domain: &str) -> bool {
    !domain.is_empty()
        && domain.contains('.')
        && !domain.starts_with('.')
        && !domain.ends_with('.')
        && !domain.contains("..")
        && domain
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'.')
        && domain
            .split('.')
            .all(|label| !label.is_empty() && !label.starts_with('-') && !label.ends_with('-'))
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
                    recipient_domains: vec![],
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
            policy.evaluate(&request).unwrap().decision,
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

    #[test]
    fn rejects_unsupported_policy_versions() {
        let policy = PolicyDocument {
            version: 2,
            grants: vec![],
        };
        let err = policy.validate().unwrap_err().to_string();
        assert!(err.contains("unsupported policy version"));
    }

    #[test]
    fn rejects_incomplete_http_grants() {
        let policy = PolicyDocument {
            version: 1,
            grants: vec![Grant {
                id: "broad".into(),
                agent: "demo".into(),
                capability: "http.request".into(),
                resource: "github".into(),
                allow: AllowRule::default(),
                require_approval: false,
            }],
        };
        let err = policy.validate().unwrap_err().to_string();
        assert!(err.contains("must specify methods, hosts, and path_prefixes"));
    }

    #[test]
    fn rejects_unsupported_grant_capabilities() {
        let policy = PolicyDocument {
            version: 1,
            grants: vec![Grant {
                id: "typo".into(),
                agent: "demo".into(),
                capability: "http.requset".into(),
                resource: "github".into(),
                allow: AllowRule {
                    methods: vec!["GET".into()],
                    hosts: vec!["api.github.com".into()],
                    path_prefixes: vec!["/safe".into()],
                    recipient_domains: vec![],
                },
                require_approval: false,
            }],
        };
        let err = policy.validate().unwrap_err().to_string();
        assert!(err.contains("unsupported capability"));
    }

    #[test]
    fn rejects_empty_http_path_prefix_entries() {
        let policy = PolicyDocument {
            version: 1,
            grants: vec![Grant {
                id: "broad".into(),
                agent: "demo".into(),
                capability: "http.request".into(),
                resource: "github".into(),
                allow: AllowRule {
                    methods: vec!["GET".into()],
                    hosts: vec!["api.github.com".into()],
                    path_prefixes: vec!["".into()],
                    recipient_domains: vec![],
                },
                require_approval: false,
            }],
        };
        let err = policy.validate().unwrap_err().to_string();
        assert!(err.contains("invalid path_prefix"));
    }

    #[test]
    fn rejects_trailing_slash_http_path_prefix_entries() {
        let policy = PolicyDocument {
            version: 1,
            grants: vec![Grant {
                id: "broad".into(),
                agent: "demo".into(),
                capability: "http.request".into(),
                resource: "github".into(),
                allow: AllowRule {
                    methods: vec!["GET".into()],
                    hosts: vec!["api.github.com".into()],
                    path_prefixes: vec!["/repos/example/repo/issues/".into()],
                    recipient_domains: vec![],
                },
                require_approval: false,
            }],
        };
        let err = policy.validate().unwrap_err().to_string();
        assert!(err.contains("invalid path_prefix"));
    }

    #[test]
    fn http_path_prefixes_match_segment_boundaries() {
        assert!(path_matches_prefix(
            "/repos/example/repo/issues",
            "/repos/example/repo/issues"
        ));
        assert!(path_matches_prefix(
            "/repos/example/repo/issues/1",
            "/repos/example/repo/issues"
        ));
        assert!(!path_matches_prefix(
            "/repos/example/repo/issues-admin",
            "/repos/example/repo/issues"
        ));
    }

    #[test]
    fn unsafe_http_paths_do_not_match_prefixes() {
        let prefix = "/repos/example/repo/issues";

        assert!(!path_matches_prefix(
            "/repos/example/repo/issues/../settings",
            prefix
        ));
        assert!(!path_matches_prefix(
            "/repos/example/repo/issues/%2e%2e/settings",
            prefix
        ));
        assert!(!path_matches_prefix(
            "/repos/example/repo/issues/%252e%252e/settings",
            prefix
        ));
        assert!(!path_matches_prefix(
            r"/repos/example/repo/issues\..\settings",
            prefix
        ));
        assert!(!path_matches_prefix(
            "/repos/example/repo/issues/1?admin=true",
            prefix
        ));
        assert!(!path_matches_prefix(
            "/repos/example/repo/issues/1%3fadmin=true",
            prefix
        ));
        assert!(!path_matches_prefix(
            "/repos/example/repo/issues/1#fragment",
            prefix
        ));
        assert!(!path_matches_prefix("repos/example/repo/issues/1", prefix));
    }

    #[test]
    fn rejects_unconstrained_email_grants() {
        let policy = PolicyDocument {
            version: 1,
            grants: vec![Grant {
                id: "mail".into(),
                agent: "demo".into(),
                capability: "email.send".into(),
                resource: "mail".into(),
                allow: AllowRule::default(),
                require_approval: false,
            }],
        };
        let err = policy.validate().unwrap_err().to_string();
        assert!(err.contains("recipient_domains"));
    }

    #[test]
    fn email_send_matches_recipient_domain() {
        let policy = PolicyDocument {
            version: 1,
            grants: vec![Grant {
                id: "mail".into(),
                agent: "demo".into(),
                capability: "email.send".into(),
                resource: "mail".into(),
                allow: AllowRule {
                    methods: vec![],
                    hosts: vec![],
                    path_prefixes: vec![],
                    recipient_domains: vec!["example.com".into()],
                },
                require_approval: false,
            }],
        };
        let matching = ActionRequest {
            id: "act_1".into(),
            agent_id: "demo".into(),
            task_id: None,
            capability: "email.send".into(),
            resource: "mail".into(),
            operation: json!({"to": "external@example.com"}),
            payload: json!({}),
            payload_hash: None,
            idempotency_key: None,
            requested_at: None,
        };
        let mut mismatched = matching.clone();
        mismatched.operation = json!({"to": "external@example.net"});
        let mut multi_recipient = matching.clone();
        multi_recipient.operation = json!({"to": "attacker@evil.test, external@example.com"});
        let mut cc_recipient = matching.clone();
        cc_recipient.operation = json!({"to": "external@example.com", "cc": "attacker@evil.test"});

        assert_eq!(
            policy.evaluate(&matching).unwrap().decision,
            PolicyDecisionKind::Allow
        );
        assert_eq!(
            policy.evaluate(&mismatched).unwrap().decision,
            PolicyDecisionKind::Deny
        );
        assert_eq!(
            policy.evaluate(&multi_recipient).unwrap().decision,
            PolicyDecisionKind::Deny
        );
        assert_eq!(
            policy.evaluate(&cc_recipient).unwrap().decision,
            PolicyDecisionKind::Deny
        );
    }
}
