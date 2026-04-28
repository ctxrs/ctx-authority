use crate::backends::SecretLease;
use crate::models::{ActionRequest, ProviderExecution};
use crate::{AuthorityError, Result};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use uuid::Uuid;

pub trait ProviderAdapter: Send + Sync {
    fn execute(
        &self,
        request: &ActionRequest,
        secret: Option<&SecretLease>,
    ) -> Result<ProviderExecution>;
}

#[derive(Debug, Clone)]
pub struct FakeProvider {
    name: String,
}

impl FakeProvider {
    pub fn new(name: impl Into<String>) -> Self {
        Self { name: name.into() }
    }
}

impl ProviderAdapter for FakeProvider {
    fn execute(
        &self,
        request: &ActionRequest,
        secret: Option<&SecretLease>,
    ) -> Result<ProviderExecution> {
        if request
            .operation
            .get("force_provider_error")
            .and_then(Value::as_bool)
            == Some(true)
        {
            return Err(AuthorityError::Provider(
                "forced fake provider error".into(),
            ));
        }
        let mut result = BTreeMap::new();
        result.insert("redacted".into(), json!(true));
        result.insert("used_secret".into(), json!(secret.is_some()));
        Ok(ProviderExecution {
            status: "succeeded".into(),
            provider: self.name.clone(),
            provider_request_id: Some(format!("fake_{}", Uuid::new_v4())),
            result,
        })
    }
}
