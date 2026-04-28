use crate::models::Receipt;
use crate::Result;
use serde_json::{json, Value};
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

        let response = match serde_json::from_str::<Value>(&line) {
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
        "initialize" => Some(success_response(id, initialize_result(&message))),
        "ping" => Some(success_response(id, json!({}))),
        "tools/list" => Some(success_response(id, json!({ "tools": tools() }))),
        "tools/call" => Some(handle_tool_call(id, message.get("params").cloned())),
        _ => Some(error_response(id, -32601, "method not found")),
    }
}

fn initialize_result(message: &Value) -> Value {
    let requested_protocol_version = message
        .get("params")
        .and_then(|params| params.get("protocolVersion"))
        .and_then(Value::as_str)
        .unwrap_or(MCP_PROTOCOL_VERSION);

    json!({
        "protocolVersion": requested_protocol_version,
        "capabilities": {
            "tools": {
                "listChanged": false
            }
        },
        "serverInfo": {
            "name": "authority-broker",
            "title": "Authority Broker",
            "version": env!("CARGO_PKG_VERSION")
        },
        "instructions": "Request capabilities, not raw secrets. This server exposes only redacted broker metadata and receipt verification helpers."
    })
}

fn tools() -> Vec<Value> {
    vec![
        json!({
            "name": "capabilities.list",
            "title": "List Authority Broker Capabilities",
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
            "title": "Verify Receipt Structure",
            "description": "Check that a receipt is parseable and carries the supported ed25519 signature envelope. This minimal MCP surface does not yet perform key-based signature verification.",
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
                "verification": "structural"
            }
        ],
        "broker_capabilities": [
            {
                "name": "actions.request",
                "status": "planned"
            },
            {
                "name": "http.request",
                "status": "planned"
            },
            {
                "name": "approvals.status",
                "status": "planned"
            },
            {
                "name": "audit.search",
                "status": "planned"
            },
            {
                "name": "receipts.verify",
                "status": "available",
                "verification": "structural"
            }
        ]
    })
}

fn receipts_verify(arguments: &Value) -> Value {
    match receipt_from_arguments(arguments).and_then(verify_receipt_structure) {
        Ok(result) => tool_success(result),
        Err(message) => tool_error(message),
    }
}

fn receipt_from_arguments(arguments: &Value) -> std::result::Result<Receipt, String> {
    if let Some(receipt) = arguments.get("receipt") {
        return serde_json::from_value(receipt.clone())
            .map_err(|_| "receipt is not a valid receipt object".to_string());
    }

    if let Some(receipt_json) = arguments.get("receipt_json").and_then(Value::as_str) {
        return serde_json::from_str(receipt_json)
            .map_err(|_| "receipt_json is not a valid receipt".to_string());
    }

    Err("missing receipt or receipt_json argument".into())
}

fn verify_receipt_structure(receipt: Receipt) -> std::result::Result<Value, String> {
    if receipt.signature.alg != "ed25519" {
        return Err("receipt signature algorithm is not supported".into());
    }
    if receipt.signature.sig.trim().is_empty() {
        return Err("receipt signature is empty".into());
    }

    Ok(json!({
        "valid": true,
        "mode": "structural",
        "receipt_id": receipt.receipt_id,
        "key_id": receipt.signature.kid,
        "checks": [
            "receipt_json_deserialized",
            "ed25519_signature_envelope_present"
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
    use serde_json::json;
    use std::io::Cursor;

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
    fn verifies_structurally_signed_receipt() {
        let receipt = sample_receipt("ed25519", "not-empty");
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
            "structural"
        );
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
