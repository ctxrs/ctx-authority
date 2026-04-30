use crate::config::{
    canonical_host_port_for_scheme, GrantDelegationConfig, HttpGrantConfig, HttpResourceScheme,
    ProfileConfig,
};
use crate::policy::http_path_matches_prefix;
use crate::{AuthorityError, Result};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::{BTreeSet, HashMap, HashSet};

#[derive(Debug, Clone)]
pub struct GrantMatch {
    pub grant: HttpGrantConfig,
    pub chain: Vec<HttpGrantConfig>,
    pub root_secret_ref: String,
    pub chain_hash: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct GrantPolicyEnvelope<'a> {
    pub holder_profile: &'a str,
    pub holder_subject: &'a str,
    pub matched_grant_id: &'a str,
    pub chain_ids: Vec<&'a str>,
    pub chain: Vec<GrantPolicyChainEntry<'a>>,
    pub root_secret_ref_hash: &'a str,
}

#[derive(Debug, Clone, Serialize)]
pub struct GrantPolicyChainEntry<'a> {
    pub id: &'a str,
    pub parent: Option<&'a str>,
    pub profile: &'a str,
    pub subject: &'a str,
    pub scheme: &'a str,
    pub host: &'a str,
    pub methods: &'a [String],
    pub path_prefixes: &'a [String],
    pub delegation_allowed: bool,
    pub delegation_remaining_depth: u8,
}

pub fn profile_subject(profile: &ProfileConfig) -> String {
    profile.agent.clone().unwrap_or_else(|| profile.id.clone())
}

pub fn normalize_methods(methods: Vec<String>) -> Vec<String> {
    let mut seen = BTreeSet::new();
    for method in methods {
        seen.insert(method.to_ascii_uppercase());
    }
    seen.into_iter().collect()
}

pub fn grant_chain<'a>(
    grants: &'a [HttpGrantConfig],
    grant_id: &str,
) -> Result<Vec<&'a HttpGrantConfig>> {
    let index: HashMap<&str, &HttpGrantConfig> = grants
        .iter()
        .map(|grant| (grant.id.as_str(), grant))
        .collect();
    let mut chain = Vec::new();
    let mut seen = HashSet::new();
    let mut current_id = grant_id;
    loop {
        if !seen.insert(current_id.to_string()) {
            return Err(AuthorityError::Config(format!(
                "grant {grant_id} has a parent cycle"
            )));
        }
        let grant = index.get(current_id).copied().ok_or_else(|| {
            AuthorityError::Config(format!("grant {current_id} is not configured"))
        })?;
        chain.push(grant);
        let Some(parent) = &grant.parent else {
            break;
        };
        current_id = parent;
    }
    chain.reverse();
    Ok(chain)
}

pub fn matching_grant(
    profile: &ProfileConfig,
    grants: &[HttpGrantConfig],
    scheme: HttpResourceScheme,
    canonical_target_host: &str,
    method: &str,
    path: &str,
) -> Result<Option<GrantMatch>> {
    for grant in grants {
        if grant.profile != profile.id
            || grant.scheme != scheme
            || canonical_host_port_for_scheme(&grant.host, grant.scheme).as_deref()
                != Some(canonical_target_host)
            || !grant
                .allow
                .methods
                .iter()
                .any(|allowed| allowed.eq_ignore_ascii_case(method))
            || !grant
                .allow
                .path_prefixes
                .iter()
                .any(|prefix| http_path_matches_prefix(path, prefix))
        {
            continue;
        }
        let chain_refs = grant_chain(grants, &grant.id)?;
        let root = chain_refs
            .first()
            .ok_or_else(|| AuthorityError::Config(format!("grant {} has no root", grant.id)))?;
        let root_secret_ref = root.secret_ref.clone().ok_or_else(|| {
            AuthorityError::Config(format!("grant {} has no root secret", grant.id))
        })?;
        let chain: Vec<HttpGrantConfig> = chain_refs.into_iter().cloned().collect();
        let chain_hash = grant_chain_hash(&chain)?;
        return Ok(Some(GrantMatch {
            grant: grant.clone(),
            chain,
            root_secret_ref,
            chain_hash,
        }));
    }
    Ok(None)
}

pub fn validate_http_grants(profiles: &[ProfileConfig], grants: &[HttpGrantConfig]) -> Result<()> {
    let profile_index: HashMap<&str, &ProfileConfig> = profiles
        .iter()
        .map(|profile| (profile.id.as_str(), profile))
        .collect();
    let grant_index: HashMap<&str, &HttpGrantConfig> = grants
        .iter()
        .map(|grant| (grant.id.as_str(), grant))
        .collect();

    for grant in grants {
        let profile = profile_index.get(grant.profile.as_str()).ok_or_else(|| {
            AuthorityError::Config(format!(
                "grant {} references missing profile {}",
                grant.id, grant.profile
            ))
        })?;
        let expected_subject = profile_subject(profile);
        if grant.subject != expected_subject {
            return Err(AuthorityError::Config(format!(
                "grant {} subject {} does not match profile {} subject {}",
                grant.id, grant.subject, grant.profile, expected_subject
            )));
        }
        let methods = normalize_methods(grant.allow.methods.clone());
        if methods != grant.allow.methods {
            return Err(AuthorityError::Config(format!(
                "grant {} methods must be uppercase and deduplicated",
                grant.id
            )));
        }

        match &grant.parent {
            None => {
                if grant.secret_ref.is_none() {
                    return Err(AuthorityError::Config(format!(
                        "root grant {} must specify secret_ref",
                        grant.id
                    )));
                }
            }
            Some(parent_id) => {
                if grant.secret_ref.is_some() {
                    return Err(AuthorityError::Config(format!(
                        "child grant {} must not specify secret_ref",
                        grant.id
                    )));
                }
                let _ = grant_chain(grants, &grant.id)?;
                let parent = grant_index.get(parent_id.as_str()).ok_or_else(|| {
                    AuthorityError::Config(format!(
                        "grant {} references missing parent {}",
                        grant.id, parent_id
                    ))
                })?;
                validate_child_subset(parent, grant)?;
            }
        }
    }
    Ok(())
}

pub fn child_grant_is_subset(parent: &HttpGrantConfig, child: &HttpGrantConfig) -> Result<()> {
    validate_child_subset(parent, child)
}

pub fn grant_chain_hash(chain: &[HttpGrantConfig]) -> Result<String> {
    let mut hasher = Sha256::new();
    for grant in chain {
        hasher.update(grant.id.as_bytes());
        hasher.update([0]);
    }
    Ok(format!("sha256:{}", hex::encode(hasher.finalize())))
}

fn validate_child_subset(parent: &HttpGrantConfig, child: &HttpGrantConfig) -> Result<()> {
    if !parent.delegation.allowed {
        return Err(AuthorityError::Config(format!(
            "parent grant {} does not allow delegation",
            parent.id
        )));
    }
    if parent.delegation.remaining_depth == 0 {
        return Err(AuthorityError::Config(format!(
            "parent grant {} has no remaining delegation depth",
            parent.id
        )));
    }
    if child.delegation.remaining_depth >= parent.delegation.remaining_depth {
        return Err(AuthorityError::Config(format!(
            "child grant {} delegation depth must be less than parent {}",
            child.id, parent.id
        )));
    }
    if child.scheme != parent.scheme {
        return Err(AuthorityError::Config(format!(
            "child grant {} scheme must match parent {}",
            child.id, parent.id
        )));
    }
    if canonical_host_port_for_scheme(&child.host, child.scheme)
        != canonical_host_port_for_scheme(&parent.host, parent.scheme)
    {
        return Err(AuthorityError::Config(format!(
            "child grant {} host must match parent {}",
            child.id, parent.id
        )));
    }
    for method in &child.allow.methods {
        if !parent
            .allow
            .methods
            .iter()
            .any(|parent_method| parent_method == method)
        {
            return Err(AuthorityError::Config(format!(
                "child grant {} method {} is outside parent {}",
                child.id, method, parent.id
            )));
        }
    }
    for prefix in &child.allow.path_prefixes {
        if !parent
            .allow
            .path_prefixes
            .iter()
            .any(|parent_prefix| http_path_matches_prefix(prefix, parent_prefix))
        {
            return Err(AuthorityError::Config(format!(
                "child grant {} path_prefix {} is outside parent {}",
                child.id, prefix, parent.id
            )));
        }
    }
    Ok(())
}

pub fn delegation(allowed: bool, remaining_depth: u8) -> GrantDelegationConfig {
    GrantDelegationConfig {
        allowed,
        remaining_depth,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{AppConfig, HttpAllowConfig};

    fn profile(id: &str) -> ProfileConfig {
        ProfileConfig {
            id: id.into(),
            agent: Some(id.into()),
            env_vars: Default::default(),
            http_resources: Vec::new(),
        }
    }

    fn grant(
        id: &str,
        parent: Option<&str>,
        profile: &str,
        methods: Vec<&str>,
        prefixes: Vec<&str>,
        delegation: GrantDelegationConfig,
    ) -> HttpGrantConfig {
        HttpGrantConfig {
            id: id.into(),
            parent: parent.map(String::from),
            profile: profile.into(),
            subject: profile.into(),
            scheme: HttpResourceScheme::Https,
            host: "api.github.com".into(),
            secret_ref: parent.is_none().then(|| "github".into()),
            allow: HttpAllowConfig {
                methods: methods.into_iter().map(String::from).collect(),
                path_prefixes: prefixes.into_iter().map(String::from).collect(),
            },
            delegation,
        }
    }

    #[test]
    fn validates_attenuated_child_grants() {
        let config = AppConfig {
            profiles: vec![profile("main-agent"), profile("worker-agent")],
            grants: vec![
                grant(
                    "github-root",
                    None,
                    "main-agent",
                    vec!["GET", "POST"],
                    vec!["/repos/acme/app"],
                    delegation(true, 2),
                ),
                grant(
                    "github-issues",
                    Some("github-root"),
                    "worker-agent",
                    vec!["GET"],
                    vec!["/repos/acme/app/issues"],
                    delegation(false, 0),
                ),
            ],
            ..Default::default()
        };

        config.validate().unwrap();
    }

    #[test]
    fn rejects_broader_child_grants() {
        let mut config = AppConfig {
            profiles: vec![profile("main-agent"), profile("worker-agent")],
            grants: vec![
                grant(
                    "github-root",
                    None,
                    "main-agent",
                    vec!["GET"],
                    vec!["/repos/acme/app/issues"],
                    delegation(true, 2),
                ),
                grant(
                    "github-admin",
                    Some("github-root"),
                    "worker-agent",
                    vec!["POST"],
                    vec!["/repos/acme/app"],
                    delegation(false, 0),
                ),
            ],
            ..Default::default()
        };

        let err = config.validate().unwrap_err().to_string();
        assert!(err.contains("method POST"));

        config.grants[1].allow.methods = vec!["GET".into()];
        let err = config.validate().unwrap_err().to_string();
        assert!(err.contains("path_prefix"));
    }

    #[test]
    fn rejects_invalid_delegation_invariants() {
        let config = AppConfig {
            profiles: vec![profile("main-agent"), profile("worker-agent")],
            grants: vec![
                grant(
                    "github-root",
                    None,
                    "main-agent",
                    vec!["GET"],
                    vec!["/repos/acme/app"],
                    delegation(false, 0),
                ),
                grant(
                    "github-child",
                    Some("github-root"),
                    "worker-agent",
                    vec!["GET"],
                    vec!["/repos/acme/app/issues"],
                    delegation(false, 0),
                ),
            ],
            ..Default::default()
        };
        assert!(config
            .validate()
            .unwrap_err()
            .to_string()
            .contains("does not allow delegation"));
    }

    #[test]
    fn rejects_subject_drift_child_secret_and_cycles() {
        let mut drift = AppConfig {
            profiles: vec![profile("main-agent")],
            grants: vec![grant(
                "github-root",
                None,
                "main-agent",
                vec!["GET"],
                vec!["/repos/acme/app"],
                delegation(true, 2),
            )],
            ..Default::default()
        };
        drift.grants[0].subject = "old-agent".into();
        assert!(drift
            .validate()
            .unwrap_err()
            .to_string()
            .contains("subject"));

        let mut child_secret = AppConfig {
            profiles: vec![profile("main-agent"), profile("worker-agent")],
            grants: vec![
                grant(
                    "github-root",
                    None,
                    "main-agent",
                    vec!["GET"],
                    vec!["/repos/acme/app"],
                    delegation(true, 2),
                ),
                grant(
                    "github-child",
                    Some("github-root"),
                    "worker-agent",
                    vec!["GET"],
                    vec!["/repos/acme/app/issues"],
                    delegation(false, 0),
                ),
            ],
            ..Default::default()
        };
        child_secret.grants[1].secret_ref = Some("github".into());
        assert!(child_secret
            .validate()
            .unwrap_err()
            .to_string()
            .contains("must not specify secret_ref"));

        let cycle = AppConfig {
            profiles: vec![profile("main-agent")],
            grants: vec![
                HttpGrantConfig {
                    parent: Some("b".into()),
                    secret_ref: None,
                    ..grant(
                        "a",
                        None,
                        "main-agent",
                        vec!["GET"],
                        vec!["/repos/acme/app"],
                        delegation(true, 2),
                    )
                },
                HttpGrantConfig {
                    id: "b".into(),
                    parent: Some("a".into()),
                    secret_ref: None,
                    ..grant(
                        "b",
                        None,
                        "main-agent",
                        vec!["GET"],
                        vec!["/repos/acme/app"],
                        delegation(true, 1),
                    )
                },
            ],
            ..Default::default()
        };
        assert!(cycle.validate().unwrap_err().to_string().contains("cycle"));
    }
}
