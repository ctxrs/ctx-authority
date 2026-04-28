use crate::canonical::canonical_json_bytes;
use crate::config::AppPaths;
use crate::models::{
    ActionRequest, ApprovalRecord, ProviderExecution, Receipt, ReceiptApproval, ReceiptSignature,
};
use crate::{AuthorityError, Result};
use base64::Engine;
use chrono::Utc;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand_core::OsRng;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::fs;

const RECEIPT_VERSION: &str = "authority.receipt.v1";

#[derive(Debug, Clone)]
pub struct ReceiptSigner {
    signing_key: SigningKey,
    key_id: String,
}

impl ReceiptSigner {
    pub fn load_or_create(paths: &AppPaths) -> Result<Self> {
        if let Some(parent) = paths.signing_key.parent() {
            fs::create_dir_all(parent)?;
        }
        let signing_key = if paths.signing_key.exists() {
            let encoded = fs::read_to_string(&paths.signing_key)?;
            let bytes = base64::engine::general_purpose::STANDARD
                .decode(encoded.trim())
                .map_err(|err| AuthorityError::Receipt(format!("invalid signing key: {err}")))?;
            let bytes: [u8; 32] = bytes
                .try_into()
                .map_err(|_| AuthorityError::Receipt("invalid signing key length".into()))?;
            SigningKey::from_bytes(&bytes)
        } else {
            let key = SigningKey::generate(&mut OsRng);
            fs::write(
                &paths.signing_key,
                base64::engine::general_purpose::STANDARD.encode(key.to_bytes()),
            )?;
            key
        };
        let key_id = key_id(&signing_key.verifying_key());
        Ok(Self {
            signing_key,
            key_id,
        })
    }

    pub fn deterministic_for_tests(seed: [u8; 32]) -> Self {
        let signing_key = SigningKey::from_bytes(&seed);
        let key_id = key_id(&signing_key.verifying_key());
        Self {
            signing_key,
            key_id,
        }
    }

    pub fn issue(
        &self,
        principal: String,
        request: &ActionRequest,
        payload_hash: String,
        policy_hash: String,
        approval: Option<&ApprovalRecord>,
        execution: ProviderExecution,
    ) -> Result<Receipt> {
        let approval = approval.map(|record| ReceiptApproval {
            required: true,
            approved_by: Some(record.approved_by.clone()),
            approved_at: Some(record.approved_at),
        });

        let mut receipt = Receipt {
            receipt_version: RECEIPT_VERSION.into(),
            receipt_id: format!("rcpt_{}", uuid::Uuid::new_v4()),
            principal,
            agent: request.agent_id.clone(),
            task: request.task_id.clone(),
            action: request.capability.clone(),
            resource: request.resource.clone(),
            payload_hash,
            policy_hash,
            approval,
            execution,
            issued_at: Utc::now(),
            signature: ReceiptSignature {
                alg: "ed25519".into(),
                kid: self.key_id.clone(),
                sig: String::new(),
            },
        };

        let signing_payload = receipt_signing_payload(&receipt)?;
        let signature = self.signing_key.sign(&signing_payload);
        receipt.signature.sig =
            base64::engine::general_purpose::STANDARD.encode(signature.to_bytes());
        Ok(receipt)
    }
}

pub fn verify_receipt(receipt: &Receipt, verifying_key: &VerifyingKey) -> Result<()> {
    let payload = receipt_signing_payload(receipt)?;
    let sig_bytes = base64::engine::general_purpose::STANDARD
        .decode(&receipt.signature.sig)
        .map_err(|err| AuthorityError::Receipt(format!("invalid signature encoding: {err}")))?;
    let sig_array: [u8; 64] = sig_bytes
        .try_into()
        .map_err(|_| AuthorityError::Receipt("invalid signature length".into()))?;
    let signature = Signature::from_bytes(&sig_array);
    verifying_key
        .verify(&payload, &signature)
        .map_err(|_| AuthorityError::Receipt("receipt signature verification failed".into()))
}

pub fn payload_hash<T: Serialize>(payload: &T) -> Result<String> {
    let bytes = canonical_json_bytes(payload)?;
    Ok(format!("sha256:{}", hex::encode(Sha256::digest(bytes))))
}

fn receipt_signing_payload(receipt: &Receipt) -> Result<Vec<u8>> {
    let mut unsigned = receipt.clone();
    unsigned.signature.sig = String::new();
    canonical_json_bytes(&unsigned)
}

fn key_id(key: &VerifyingKey) -> String {
    format!(
        "ed25519:{}",
        hex::encode(&Sha256::digest(key.as_bytes())[..8])
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::ActionRequest;
    use serde_json::json;
    use std::collections::BTreeMap;

    #[test]
    fn verifies_and_rejects_tampering() {
        let signer = ReceiptSigner::deterministic_for_tests([7; 32]);
        let request = ActionRequest {
            id: "act".into(),
            agent_id: "demo".into(),
            task_id: None,
            capability: "fake.action".into(),
            resource: "fake".into(),
            operation: json!({}),
            payload: json!({"x": 1}),
            payload_hash: None,
            idempotency_key: None,
            requested_at: None,
        };
        let receipt = signer
            .issue(
                "local".into(),
                &request,
                payload_hash(&request.payload).unwrap(),
                "sha256:policy".into(),
                None,
                ProviderExecution {
                    status: "succeeded".into(),
                    provider: "fake".into(),
                    provider_request_id: None,
                    result: BTreeMap::new(),
                },
            )
            .unwrap();
        verify_receipt(&receipt, &signer.signing_key.verifying_key()).unwrap();

        let mut tampered = receipt;
        tampered.execution.status = "failed".into();
        assert!(verify_receipt(&tampered, &signer.signing_key.verifying_key()).is_err());
    }
}
