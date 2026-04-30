use crate::boundary::json_value_from_str_no_duplicates;
use crate::capabilities::{
    capability_grant_chain, child_capability_grant_is_subset, execute_capability,
    normalize_capability_list, CapabilityExecuteRequest,
};
use crate::config::{AppConfig, AppPaths, CapabilityGrantConfig, GrantDelegationConfig};
use crate::grants::profile_subject;
use crate::models::Receipt;
use crate::receipts::ReceiptSigner;
use crate::receipts::{receipt_from_json_str_strict, receipt_from_json_value_strict};
use crate::{audit::AuditLog, Result};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::io::{BufRead, Write};

pub const MCP_SPEC_STATUS: &str = "implemented-minimal-stdio-json-rpc";

const JSONRPC_VERSION: &str = "2.0";
const MCP_PROTOCOL_VERSION: &str = "2025-11-25";

pub fn serve_stdio<R, W>(input: R, output: &mut W) -> Result<()>
where
    R: BufRead,
    W: Write,
{
    for line in input.lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }

        let response = match json_value_from_str_no_duplicates(&line) {
            Ok(message) => handle_message(message),
            Err(err) => Some(error_response(
                Value::Null,
                -32700,
                format!("parse error: {err}"),
            )),
        };

        if let Some(response) = response {
            serde_json::to_writer(&mut *output, &response)?;
            output.write_all(b"\n")?;
            output.flush()?;
        }
    }

    Ok(())
}

fn handle_message(message: Value) -> Option<Value> {
    let id = message.get("id").cloned()?;

    if message.get("jsonrpc").and_then(Value::as_str) != Some(JSONRPC_VERSION) {
        return Some(error_response(id, -32600, "invalid JSON-RPC version"));
    }

    let Some(method) = message.get("method").and_then(Value::as_str) else {
        return Some(error_response(id, -32600, "missing method"));
    };

    match method {
        "initialize" => Some(handle_initialize(id, &message)),
        "ping" => Some(success_response(id, json!({}))),
        "tools/list" => Some(success_response(id, json!({ "tools": tools() }))),
        "tools/call" => Some(handle_tool_call(id, message.get("params").cloned())),
        _ => Some(error_response(id, -32601, "method not found")),
    }
}

fn handle_initialize(id: Value, message: &Value) -> Value {
    let Some(requested_protocol_version) = message
        .get("params")
        .and_then(|params| params.get("protocolVersion"))
        .and_then(Value::as_str)
    else {
        return error_response(id, -32602, "missing MCP protocol version");
    };

    if requested_protocol_version != MCP_PROTOCOL_VERSION {
        return error_response(id, -32602, "unsupported MCP protocol version");
    }

    success_response(
        id,
        json!({
            "protocolVersion": MCP_PROTOCOL_VERSION,
            "capabilities": {
                "tools": {
                    "listChanged": false
                }
            },
            "serverInfo": {
                "name": "ctxa",
                "title": "ctx authority",
                "version": env!("CARGO_PKG_VERSION")
            },
            "instructions": "Request capabilities, not raw secrets. This server exposes only redacted broker metadata and receipt verification helpers."
        }),
    )
}

fn tools() -> Vec<Value> {
    vec![
        json!({
            "name": "capabilities.list",
            "title": "List ctx authority capabilities",
            "description": "List the MCP tools and broker action capabilities exposed by this local server.",
            "inputSchema": {
                "type": "object",
                "properties": {}
            },
            "outputSchema": {
                "type": "object",
                "properties": {
                    "mcp_tools": { "type": "array" },
                    "broker_capabilities": { "type": "array" }
                },
                "required": ["mcp_tools", "broker_capabilities"]
            }
        }),
        json!({
            "name": "receipts.verify",
            "title": "Verify Local Receipt",
            "description": "Cryptographically verifies a receipt signed by the local ctx authority key.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "receipt": {
                        "type": "object",
                        "description": "Receipt JSON object."
                    },
                    "receipt_json": {
                        "type": "string",
                        "description": "Receipt encoded as a JSON string."
                    }
                }
            },
            "outputSchema": {
                "type": "object",
                "properties": {
                    "valid": { "type": "boolean" },
                    "mode": { "type": "string" },
                    "receipt_id": { "type": "string" },
                    "key_id": { "type": "string" },
                    "checks": { "type": "array" }
                },
                "required": ["valid", "mode", "checks"]
            }
        }),
        json!({
            "name": "capability.grants.list",
            "title": "List Capability Grants",
            "description": "List configured provider capability grants held by the bound MCP profile without exposing provider credentials.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "profile": {
                        "type": "string",
                        "description": "Optional. When provided, it must match the MCP server's bound profile."
                    },
                    "provider": { "type": "string" }
                }
            },
            "outputSchema": {
                "type": "object",
                "properties": {
                    "grants": { "type": "array" }
                },
                "required": ["grants"]
            }
        }),
        json!({
            "name": "capability.grants.show",
            "title": "Show Capability Grant",
            "description": "Show one capability grant held by the bound MCP profile and its chain.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "id": { "type": "string" }
                },
                "required": ["id"]
            },
            "outputSchema": {
                "type": "object",
                "properties": {
                    "grant": { "type": "object" }
                },
                "required": ["grant"]
            }
        }),
        json!({
            "name": "capability.grants.delegate",
            "title": "Delegate Capability Grant",
            "description": "Create a mechanically narrower child capability grant.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "from": { "type": "string" },
                    "id": { "type": "string" },
                    "profile": { "type": "string" },
                    "capabilities": { "type": "array", "items": { "type": "string" } },
                    "resources": { "type": "array", "items": { "type": "string" } },
                    "operation_equals": { "type": "object" },
                    "payload_equals": { "type": "object" },
                    "delegable": { "type": "boolean" },
                    "max_depth": { "type": "integer" }
                },
                "required": ["from", "id", "profile", "capabilities", "resources"]
            },
            "outputSchema": {
                "type": "object",
                "properties": {
                    "grant": { "type": "object" }
                },
                "required": ["grant"]
            }
        }),
        json!({
            "name": "capability.execute",
            "title": "Execute Capability",
            "description": "Execute a granted provider capability and return provider response plus signed receipt.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "profile": { "type": "string" },
                    "provider": { "type": "string" },
                    "capability": { "type": "string" },
                    "resource": { "type": "string" },
                    "operation": { "type": "object" },
                    "payload": { "type": "object" }
                },
                "required": ["provider", "capability", "resource"]
            },
            "outputSchema": {
                "type": "object",
                "properties": {
                    "capability": { "type": "object" },
                    "provider_response": {}
                },
                "required": ["capability", "provider_response"]
            }
        }),
    ]
}

fn handle_tool_call(id: Value, params: Option<Value>) -> Value {
    let params = params.unwrap_or_else(|| json!({}));
    let Some(tool_name) = params.get("name").and_then(Value::as_str) else {
        return error_response(id, -32602, "tools/call params must include name");
    };
    let arguments = params
        .get("arguments")
        .cloned()
        .unwrap_or_else(|| json!({}));
    if !arguments.is_object() {
        return error_response(id, -32602, "tools/call arguments must be an object");
    }

    match tool_name {
        "capabilities.list" => success_response(id, tool_success(capabilities_list())),
        "receipts.verify" => success_response(id, receipts_verify(&arguments)),
        "capability.grants.list" => {
            success_response(id, mcp_result(capability_grants_list(&arguments)))
        }
        "capability.grants.show" => {
            success_response(id, mcp_result(capability_grants_show(&arguments)))
        }
        "capability.grants.delegate" => {
            success_response(id, mcp_result(capability_grants_delegate(&arguments)))
        }
        "capability.execute" => success_response(id, mcp_result(capability_execute(&arguments))),
        _ => error_response(id, -32602, format!("unknown tool: {tool_name}")),
    }
}

fn capabilities_list() -> Value {
    json!({
        "mcp_tools": [
            {
                "name": "capabilities.list",
                "status": "available"
            },
            {
                "name": "receipts.verify",
                "status": "available",
                "verification": "local-ed25519"
            },
            {
                "name": "capability.grants.list",
                "status": "available"
            },
            {
                "name": "capability.grants.show",
                "status": "available"
            },
            {
                "name": "capability.grants.delegate",
                "status": "available",
                "mutates_local_config": true
            },
            {
                "name": "capability.execute",
                "status": "available",
                "requires_local_grant": true
            }
        ],
        "broker_capabilities": [
            "github.issues.read",
            "github.issues.create",
            "github.issues.comment",
            "github.prs.read",
            "google.gmail.messages.read",
            "google.gmail.drafts.create",
            "google.gmail.drafts.send",
            "google.calendar.events.read",
            "google.calendar.events.create",
            "google.drive.files.read",
            "google.drive.files.update",
            "google.docs.documents.read",
            "google.docs.documents.update",
            "microsoft.outlook.messages.read",
            "microsoft.outlook.drafts.create",
            "microsoft.outlook.messages.send",
            "microsoft.calendar.events.read",
            "microsoft.calendar.events.create",
            "microsoft.drive.files.read",
            "microsoft.drive.files.update"
        ]
    })
}

fn receipts_verify(arguments: &Value) -> Value {
    match receipt_from_arguments(arguments).and_then(verify_local_receipt) {
        Ok(result) => tool_success(result),
        Err(message) => tool_error(message),
    }
}

fn mcp_result(result: std::result::Result<Value, String>) -> Value {
    match result {
        Ok(value) => tool_success(value),
        Err(message) => tool_error(message),
    }
}

fn capability_grants_list(arguments: &Value) -> std::result::Result<Value, String> {
    let bound_profile = bound_mcp_profile()?;
    let profile = optional_string(arguments, "profile")?.unwrap_or_else(|| bound_profile.clone());
    if profile != bound_profile {
        return Err(format!(
            "requested profile {profile} does not match bound MCP profile {bound_profile}"
        ));
    }
    let provider = optional_string(arguments, "provider")?;
    let paths = AppPaths::discover().map_err(redacted_error)?;
    let config = AppConfig::load(&paths.config_file).map_err(redacted_error)?;
    let grants: Vec<Value> = config
        .capability_grants
        .iter()
        .filter(|grant| {
            grant.profile == profile
                && provider
                    .as_deref()
                    .is_none_or(|provider| provider == grant.provider)
        })
        .map(capability_grant_value)
        .collect();
    Ok(json!({ "grants": grants }))
}

fn capability_grants_show(arguments: &Value) -> std::result::Result<Value, String> {
    let bound_profile = bound_mcp_profile()?;
    let id = required_string(arguments, "id")?;
    let paths = AppPaths::discover().map_err(redacted_error)?;
    let config = AppConfig::load(&paths.config_file).map_err(redacted_error)?;
    let grant = config
        .capability_grant(&id)
        .ok_or_else(|| format!("capability grant {id} is not configured"))?;
    if grant.profile != bound_profile {
        return Err(format!(
            "capability grant {id} is held by profile {}, not bound MCP profile {bound_profile}",
            grant.profile
        ));
    }
    let chain = capability_grant_chain(&config.capability_grants, &id).map_err(redacted_error)?;
    Ok(json!({
        "grant": capability_grant_value_with_chain(
            grant,
            chain.iter().map(|grant| grant.id.as_str()).collect(),
        )
    }))
}

fn capability_grants_delegate(arguments: &Value) -> std::result::Result<Value, String> {
    let holder_profile = bound_mcp_profile()?;
    let from = required_string(arguments, "from")?;
    let id = required_string(arguments, "id")?;
    let profile = required_string(arguments, "profile")?;
    let capabilities = required_string_array(arguments, "capabilities")?;
    let resources = required_string_array(arguments, "resources")?;
    let operation_equals = optional_value_map(arguments, "operation_equals")?;
    let payload_equals = optional_value_map(arguments, "payload_equals")?;
    let delegable = arguments
        .get("delegable")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let max_depth = arguments
        .get("max_depth")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let max_depth: u8 = max_depth
        .try_into()
        .map_err(|_| "max_depth is too large".to_string())?;
    if delegable && max_depth == 0 {
        return Err("delegable capability grants require max_depth greater than zero".into());
    }
    if !delegable && max_depth != 0 {
        return Err("max_depth requires delegable=true".into());
    }

    let paths = AppPaths::discover().map_err(redacted_error)?;
    paths.ensure().map_err(redacted_error)?;
    let mut config = AppConfig::load(&paths.config_file).map_err(redacted_error)?;
    if config.capability_grant(&id).is_some() {
        return Err(format!("capability grant {id} already exists"));
    }
    let parent = config
        .capability_grant(&from)
        .cloned()
        .ok_or_else(|| format!("capability grant {from} is not configured"))?;
    if parent.profile != holder_profile {
        return Err(format!(
            "capability grant {from} is held by profile {}, not bound MCP profile {holder_profile}",
            parent.profile
        ));
    }
    let child_profile = config
        .profile(&profile)
        .ok_or_else(|| format!("profile {profile} is not configured"))?;
    let child = CapabilityGrantConfig {
        id: id.clone(),
        parent: Some(parent.id.clone()),
        profile: profile.clone(),
        subject: profile_subject(child_profile),
        provider: parent.provider.clone(),
        capabilities: normalize_capability_list(capabilities),
        resources: normalize_capability_list(resources),
        constraints: crate::config::CapabilityGrantConstraints {
            operation_equals,
            payload_equals,
        },
        delegation: GrantDelegationConfig {
            allowed: delegable,
            remaining_depth: if delegable { max_depth } else { 0 },
        },
    };
    child_capability_grant_is_subset(&parent, &child).map_err(redacted_error)?;
    config.capability_grants.push(child.clone());
    config.save(&paths.config_file).map_err(redacted_error)?;
    AuditLog::open(&paths.audit_db)
        .and_then(|audit| {
            audit.record(
                "capability_grant_delegated",
                &json!({
                    "kind": "capability_grant_delegated",
                    "id": child.id,
                    "parent": child.parent,
                    "profile": child.profile,
                    "subject": child.subject,
                    "provider": child.provider,
                    "capabilities": child.capabilities,
                    "resources": child.resources,
                    "constraints": child.constraints,
                    "delegation": child.delegation,
                }),
            )
        })
        .map_err(redacted_error)?;
    Ok(json!({ "grant": capability_grant_value(&child) }))
}

fn capability_execute(arguments: &Value) -> std::result::Result<Value, String> {
    let bound_profile = bound_mcp_profile()?;
    let profile = optional_string(arguments, "profile")?.unwrap_or_else(|| bound_profile.clone());
    if profile != bound_profile {
        return Err(format!(
            "requested profile {profile} does not match bound MCP profile {bound_profile}"
        ));
    }
    let provider = required_string(arguments, "provider")?;
    let capability = required_string(arguments, "capability")?;
    let resource = required_string(arguments, "resource")?;
    let operation = arguments
        .get("operation")
        .cloned()
        .unwrap_or_else(|| json!({}));
    let payload = arguments
        .get("payload")
        .cloned()
        .unwrap_or_else(|| json!({}));
    if !operation.is_object() {
        return Err("operation must be an object".into());
    }
    if !payload.is_object() {
        return Err("payload must be an object".into());
    }

    let paths = AppPaths::discover().map_err(redacted_error)?;
    paths.ensure().map_err(redacted_error)?;
    let config = AppConfig::load(&paths.config_file).map_err(redacted_error)?;
    let provider_config = config
        .capability_provider(&provider)
        .cloned()
        .ok_or_else(|| format!("capability provider {provider} is not configured"))?;
    let backend = config
        .secret_backend
        .as_ref()
        .ok_or_else(|| "secret_backend is not configured".to_string())?
        .build()
        .map_err(redacted_error)?;
    let envelope = execute_capability(
        &config.profiles,
        &config.capability_grants,
        &provider_config,
        CapabilityExecuteRequest {
            profile,
            provider,
            capability,
            resource,
            operation,
            payload,
        },
        backend.as_ref(),
        &AuditLog::open(&paths.audit_db).map_err(redacted_error)?,
        &ReceiptSigner::load_or_create(&paths).map_err(redacted_error)?,
    )
    .map_err(redacted_error)?;
    serde_json::to_value(envelope).map_err(|_| "failed to encode capability result".into())
}

fn bound_mcp_profile() -> std::result::Result<String, String> {
    std::env::var("CTXA_MCP_PROFILE")
        .or_else(|_| std::env::var("CTXA_PROFILE"))
        .map_err(|_| {
            "MCP capability mutation and execution require CTXA_PROFILE or CTXA_MCP_PROFILE"
                .to_string()
        })
}

fn capability_grant_value(grant: &CapabilityGrantConfig) -> Value {
    capability_grant_value_with_chain(grant, Vec::new())
}

fn capability_grant_value_with_chain(grant: &CapabilityGrantConfig, chain: Vec<&str>) -> Value {
    json!({
        "id": grant.id,
        "parent": grant.parent,
        "profile": grant.profile,
        "subject": grant.subject,
        "provider": grant.provider,
        "capabilities": grant.capabilities,
        "resources": grant.resources,
        "constraints": grant.constraints,
        "delegation": grant.delegation,
        "chain": chain,
    })
}

fn required_string(arguments: &Value, key: &str) -> std::result::Result<String, String> {
    arguments
        .get(key)
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
        .ok_or_else(|| format!("missing {key}"))
}

fn optional_string(arguments: &Value, key: &str) -> std::result::Result<Option<String>, String> {
    match arguments.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(value)) => Ok(Some(value.clone())),
        Some(_) => Err(format!("{key} must be a string")),
    }
}

fn required_string_array(arguments: &Value, key: &str) -> std::result::Result<Vec<String>, String> {
    let values = arguments
        .get(key)
        .and_then(Value::as_array)
        .ok_or_else(|| format!("missing {key}"))?;
    let mut strings = Vec::new();
    for value in values {
        let Some(value) = value.as_str() else {
            return Err(format!("{key} must contain only strings"));
        };
        strings.push(value.to_string());
    }
    if strings.is_empty() {
        return Err(format!("{key} must not be empty"));
    }
    Ok(strings)
}

fn optional_value_map(
    arguments: &Value,
    key: &str,
) -> std::result::Result<BTreeMap<String, Value>, String> {
    let Some(value) = arguments.get(key) else {
        return Ok(BTreeMap::new());
    };
    if value.is_null() {
        return Ok(BTreeMap::new());
    }
    let object = value
        .as_object()
        .ok_or_else(|| format!("{key} must be an object"))?;
    Ok(object
        .iter()
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect())
}

fn redacted_error(error: impl std::fmt::Display) -> String {
    error.to_string()
}

fn receipt_from_arguments(arguments: &Value) -> std::result::Result<Receipt, String> {
    if let Some(receipt) = arguments.get("receipt") {
        return receipt_from_json_value_strict(receipt.clone())
            .map_err(|_| "receipt is not a valid receipt object".to_string());
    }

    if let Some(receipt_json) = arguments.get("receipt_json").and_then(Value::as_str) {
        return receipt_from_json_str_strict(receipt_json)
            .map_err(|_| "receipt_json is not a valid receipt".to_string());
    }

    Err("missing receipt or receipt_json argument".into())
}

fn verify_local_receipt(receipt: Receipt) -> std::result::Result<Value, String> {
    let paths = AppPaths::discover().map_err(redacted_error)?;
    let signer = ReceiptSigner::load(&paths).map_err(redacted_error)?;
    signer
        .verify_local_receipt(&receipt)
        .map_err(redacted_error)?;

    Ok(json!({
        "valid": true,
        "mode": "local-ed25519",
        "receipt_id": receipt.receipt_id,
        "key_id": receipt.signature.kid,
        "checks": [
            "receipt_json_deserialized",
            "ed25519_signature_verified",
            "local_key_id_matched"
        ]
    }))
}

fn tool_success(structured_content: Value) -> Value {
    json!({
        "content": [
            {
                "type": "text",
                "text": serde_json::to_string_pretty(&structured_content)
                    .unwrap_or_else(|_| "{}".into())
            }
        ],
        "structuredContent": structured_content,
        "isError": false
    })
}

fn tool_error(message: impl Into<String>) -> Value {
    let message = message.into();
    json!({
        "content": [
            {
                "type": "text",
                "text": message
            }
        ],
        "isError": true
    })
}

fn success_response(id: Value, result: Value) -> Value {
    json!({
        "jsonrpc": JSONRPC_VERSION,
        "id": id,
        "result": result
    })
}

fn error_response(id: Value, code: i64, message: impl Into<String>) -> Value {
    json!({
        "jsonrpc": JSONRPC_VERSION,
        "id": id,
        "error": {
            "code": code,
            "message": message.into()
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{ActionRequest, ProviderExecution};
    use crate::receipts::{action_hash, payload_hash};
    use serde_json::json;
    use std::collections::BTreeMap;
    use std::io::Cursor;
    use std::sync::Mutex;

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn initialize_advertises_tools_capability() {
        let response = handle_message(json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-11-25",
                "capabilities": {},
                "clientInfo": {
                    "name": "smoke",
                    "version": "0.0.0"
                }
            }
        }))
        .unwrap();

        assert_eq!(response["result"]["protocolVersion"], "2025-11-25");
        assert_eq!(
            response["result"]["capabilities"]["tools"]["listChanged"],
            false
        );
    }

    #[test]
    fn initialize_rejects_unsupported_protocol_versions() {
        let response = handle_message(json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2099-01-01",
                "capabilities": {},
                "clientInfo": {
                    "name": "smoke",
                    "version": "0.0.0"
                }
            }
        }))
        .unwrap();

        assert_eq!(response["error"]["code"], -32602);
        assert_eq!(
            response["error"]["message"],
            "unsupported MCP protocol version"
        );
    }

    #[test]
    fn initialize_rejects_missing_protocol_version() {
        let response = handle_message(json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "capabilities": {},
                "clientInfo": {
                    "name": "smoke",
                    "version": "0.0.0"
                }
            }
        }))
        .unwrap();

        assert_eq!(response["error"]["code"], -32602);
        assert_eq!(response["error"]["message"], "missing MCP protocol version");
    }

    #[test]
    fn lists_tools_in_deterministic_order() {
        let response = handle_message(json!({
            "jsonrpc": "2.0",
            "id": "list",
            "method": "tools/list"
        }))
        .unwrap();

        let tools = response["result"]["tools"].as_array().unwrap();
        assert_eq!(tools[0]["name"], "capabilities.list");
        assert_eq!(tools[1]["name"], "receipts.verify");
        assert_eq!(tools[2]["name"], "capability.grants.list");
    }

    #[test]
    fn calls_capabilities_list_tool() {
        let response = handle_message(json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {
                "name": "capabilities.list",
                "arguments": {}
            }
        }))
        .unwrap();

        assert_eq!(response["result"]["isError"], false);
        assert_eq!(
            response["result"]["structuredContent"]["mcp_tools"][0]["name"],
            "capabilities.list"
        );
    }

    #[test]
    fn verifies_locally_signed_receipt() {
        let _guard = ENV_LOCK.lock().unwrap();
        let home = tempfile::tempdir().unwrap();
        unsafe {
            std::env::set_var("CTXA_HOME", home.path());
        }
        let paths = AppPaths::discover().unwrap();
        paths.ensure().unwrap();
        let signer = ReceiptSigner::load_or_create(&paths).unwrap();
        let request = ActionRequest {
            id: "mcp-test-action".into(),
            agent_id: "demo".into(),
            task_id: None,
            capability: "fake.action".into(),
            resource: "fake".into(),
            operation: json!({}),
            payload: json!({}),
            payload_hash: None,
            idempotency_key: None,
            requested_at: None,
        };
        let receipt = signer
            .issue(
                "local".into(),
                &request,
                action_hash(&request).unwrap(),
                payload_hash(&json!({"policy": "test"})).unwrap(),
                None,
                ProviderExecution {
                    status: "succeeded".into(),
                    provider: "fake".into(),
                    provider_request_id: None,
                    result: BTreeMap::from([("redacted".into(), json!(true))]),
                },
            )
            .unwrap();
        let response = handle_message(json!({
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {
                "name": "receipts.verify",
                "arguments": {
                    "receipt": receipt
                }
            }
        }))
        .unwrap();

        assert_eq!(response["result"]["isError"], false);
        assert_eq!(response["result"]["structuredContent"]["valid"], true);
        assert_eq!(
            response["result"]["structuredContent"]["mode"],
            "local-ed25519"
        );

        unsafe {
            std::env::remove_var("CTXA_HOME");
        }
    }

    #[test]
    fn receipt_json_rejects_duplicate_keys() {
        let receipt = sample_receipt("ed25519", "not-empty");
        let receipt_json = serde_json::to_string_pretty(&receipt).unwrap();
        let duplicate = receipt_json.replacen(
            r#""redacted": true"#,
            r#""redacted": false,
          "redacted": true"#,
            1,
        );
        assert_ne!(duplicate, receipt_json);

        let response = handle_message(json!({
            "jsonrpc": "2.0",
            "id": 33,
            "method": "tools/call",
            "params": {
                "name": "receipts.verify",
                "arguments": {
                    "receipt_json": duplicate
                }
            }
        }))
        .unwrap();

        assert!(response.get("error").is_none());
        assert_eq!(response["result"]["isError"], true);
    }

    #[test]
    fn receipt_object_rejects_missing_signed_fields() {
        let mut receipt = sample_receipt("ed25519", "not-empty");
        receipt.as_object_mut().unwrap().remove("approval");

        let response = handle_message(json!({
            "jsonrpc": "2.0",
            "id": 34,
            "method": "tools/call",
            "params": {
                "name": "receipts.verify",
                "arguments": {
                    "receipt": receipt
                }
            }
        }))
        .unwrap();

        assert!(response.get("error").is_none());
        assert_eq!(response["result"]["isError"], true);
    }

    #[test]
    fn receipt_object_rejects_unsupported_versions() {
        let mut receipt = sample_receipt("ed25519", "not-empty");
        receipt["receipt_version"] = Value::String("authority.receipt.v999".into());

        let response = handle_message(json!({
            "jsonrpc": "2.0",
            "id": 35,
            "method": "tools/call",
            "params": {
                "name": "receipts.verify",
                "arguments": {
                    "receipt": receipt
                }
            }
        }))
        .unwrap();

        assert!(response.get("error").is_none());
        assert_eq!(response["result"]["isError"], true);
    }

    #[test]
    fn reports_receipt_verification_tool_errors_without_json_rpc_error() {
        let receipt = sample_receipt("ed25519", "");
        let response = handle_message(json!({
            "jsonrpc": "2.0",
            "id": 4,
            "method": "tools/call",
            "params": {
                "name": "receipts.verify",
                "arguments": {
                    "receipt": receipt
                }
            }
        }))
        .unwrap();

        assert!(response.get("error").is_none());
        assert_eq!(response["result"]["isError"], true);
    }

    #[test]
    fn capability_execute_requires_bound_mcp_profile() {
        let _guard = ENV_LOCK.lock().unwrap();
        unsafe {
            std::env::remove_var("CTXA_PROFILE");
            std::env::remove_var("CTXA_MCP_PROFILE");
        }
        let response = handle_message(json!({
            "jsonrpc": "2.0",
            "id": 41,
            "method": "tools/call",
            "params": {
                "name": "capability.execute",
                "arguments": {
                    "profile": "admin",
                    "provider": "github",
                    "capability": "github.issues.read",
                    "resource": "github:acme/app"
                }
            }
        }))
        .unwrap();

        assert!(response.get("error").is_none());
        assert_eq!(response["result"]["isError"], true);
        assert!(response["result"]["content"][0]["text"]
            .as_str()
            .unwrap()
            .contains("CTXA_PROFILE"));
    }

    #[test]
    fn capability_execute_rejects_profile_mismatch_before_loading_config() {
        let _guard = ENV_LOCK.lock().unwrap();
        unsafe {
            std::env::set_var("CTXA_PROFILE", "bound-profile");
            std::env::remove_var("CTXA_MCP_PROFILE");
        }
        let response = handle_message(json!({
            "jsonrpc": "2.0",
            "id": 42,
            "method": "tools/call",
            "params": {
                "name": "capability.execute",
                "arguments": {
                    "profile": "other-profile",
                    "provider": "github",
                    "capability": "github.issues.read",
                    "resource": "github:acme/app"
                }
            }
        }))
        .unwrap();
        unsafe {
            std::env::remove_var("CTXA_PROFILE");
        }

        assert!(response.get("error").is_none());
        assert_eq!(response["result"]["isError"], true);
        assert!(response["result"]["content"][0]["text"]
            .as_str()
            .unwrap()
            .contains("does not match bound MCP profile"));
    }

    #[test]
    fn capability_grant_inspection_is_bound_to_mcp_profile() {
        let _guard = ENV_LOCK.lock().unwrap();
        let home = tempfile::tempdir().unwrap();
        unsafe {
            std::env::set_var("CTXA_HOME", home.path());
            std::env::set_var("CTXA_PROFILE", "bound-profile");
            std::env::remove_var("CTXA_MCP_PROFILE");
        }
        let paths = AppPaths::for_home(home.path().to_path_buf());
        AppConfig {
            profiles: vec![
                crate::config::ProfileConfig {
                    id: "bound-profile".into(),
                    agent: Some("bound-profile".into()),
                    env_vars: Default::default(),
                    http_resources: Vec::new(),
                },
                crate::config::ProfileConfig {
                    id: "other-profile".into(),
                    agent: Some("other-profile".into()),
                    env_vars: Default::default(),
                    http_resources: Vec::new(),
                },
            ],
            capability_providers: vec![crate::config::CapabilityProviderConfig {
                id: "github".into(),
                kind: crate::config::CapabilityProviderKind::Github,
                api_base: "https://api.github.com".into(),
                auth: crate::config::CapabilityProviderAuthConfig::Bearer {
                    token_ref: "github-token".into(),
                },
            }],
            capability_grants: vec![
                CapabilityGrantConfig {
                    id: "bound-grant".into(),
                    parent: None,
                    profile: "bound-profile".into(),
                    subject: "bound-profile".into(),
                    provider: "github".into(),
                    capabilities: vec!["github.issues.read".into()],
                    resources: vec!["github:acme/app".into()],
                    constraints: Default::default(),
                    delegation: GrantDelegationConfig::default(),
                },
                CapabilityGrantConfig {
                    id: "other-grant".into(),
                    parent: None,
                    profile: "other-profile".into(),
                    subject: "other-profile".into(),
                    provider: "github".into(),
                    capabilities: vec!["github.issues.read".into()],
                    resources: vec!["github:acme/app".into()],
                    constraints: Default::default(),
                    delegation: GrantDelegationConfig::default(),
                },
            ],
            ..Default::default()
        }
        .save(&paths.config_file)
        .unwrap();

        let list = handle_message(json!({
            "jsonrpc": "2.0",
            "id": 43,
            "method": "tools/call",
            "params": {
                "name": "capability.grants.list",
                "arguments": {}
            }
        }))
        .unwrap();
        assert_eq!(list["result"]["isError"], false);
        let grants = list["result"]["structuredContent"]["grants"]
            .as_array()
            .unwrap();
        assert_eq!(grants.len(), 1);
        assert_eq!(grants[0]["id"], "bound-grant");

        let show = handle_message(json!({
            "jsonrpc": "2.0",
            "id": 44,
            "method": "tools/call",
            "params": {
                "name": "capability.grants.show",
                "arguments": {
                    "id": "other-grant"
                }
            }
        }))
        .unwrap();
        assert_eq!(show["result"]["isError"], true);
        assert!(show["result"]["content"][0]["text"]
            .as_str()
            .unwrap()
            .contains("not bound MCP profile"));

        unsafe {
            std::env::remove_var("CTXA_HOME");
            std::env::remove_var("CTXA_PROFILE");
        }
    }

    #[test]
    fn receipt_parse_errors_do_not_echo_input() {
        let response = handle_message(json!({
            "jsonrpc": "2.0",
            "id": 5,
            "method": "tools/call",
            "params": {
                "name": "receipts.verify",
                "arguments": {
                    "receipt": "super-secret-value"
                }
            }
        }))
        .unwrap();

        let text = response["result"]["content"][0]["text"].as_str().unwrap();
        assert!(response.get("error").is_none());
        assert_eq!(response["result"]["isError"], true);
        assert!(!text.contains("super-secret-value"), "{text}");
    }

    #[test]
    fn stdio_loop_writes_one_response_per_request_line() {
        let input = Cursor::new(
            r#"{"jsonrpc":"2.0","id":1,"method":"ping"}"#.to_owned()
                + "\n"
                + r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#
                + "\n",
        );
        let mut output = Vec::new();

        serve_stdio(input, &mut output).unwrap();

        let output = String::from_utf8(output).unwrap();
        let lines = output.lines().collect::<Vec<_>>();
        assert_eq!(lines.len(), 1);
        let response: Value = serde_json::from_str(lines[0]).unwrap();
        assert_eq!(response["result"], json!({}));
    }

    #[test]
    fn stdio_loop_rejects_duplicate_keys_before_dispatch() {
        let input = Cursor::new(
            r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"receipts.verify","arguments":{"receipt":{"receipt_version":"authority.receipt.v1","receipt_id":"bad","receipt_id":"rcpt_test","principal":"local","agent":"demo","task":null,"action":"fake.action","resource":"fake","payload_hash":"sha256:payload","policy_hash":"sha256:policy","approval":null,"execution":{"status":"succeeded","provider":"fake","provider_request_id":null,"result":{"redacted":true}},"issued_at":"2026-04-28T00:00:00Z","signature":{"alg":"ed25519","kid":"ed25519:test","sig":"not-empty"}}}}}"#,
        );
        let mut output = Vec::new();

        serve_stdio(input, &mut output).unwrap();

        let output = String::from_utf8(output).unwrap();
        let response: Value = serde_json::from_str(output.trim()).unwrap();
        assert_eq!(response["error"]["code"], -32700);
        assert!(response["error"]["message"]
            .as_str()
            .unwrap()
            .contains("duplicate JSON key"));
    }

    fn sample_receipt(alg: &str, sig: &str) -> Value {
        json!({
            "receipt_version": "authority.receipt.v1",
            "receipt_id": "rcpt_test",
            "principal": "local",
            "agent": "demo",
            "task": null,
            "action": "fake.action",
            "resource": "fake",
            "payload_hash": "sha256:payload",
            "policy_hash": "sha256:policy",
            "approval": null,
            "execution": {
                "status": "succeeded",
                "provider": "fake",
                "provider_request_id": null,
                "result": {
                    "redacted": true
                }
            },
            "issued_at": "2026-04-28T00:00:00Z",
            "signature": {
                "alg": alg,
                "kid": "ed25519:test",
                "sig": sig
            }
        })
    }
}
