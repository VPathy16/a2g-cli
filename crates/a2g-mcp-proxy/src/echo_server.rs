//! Trivial echo MCP server for demo and testing.
//!
//! Implements the minimum MCP server surface:
//!   - `initialize` → responds with server info.
//!   - `tools/list` → lists one tool: `echo`.
//!   - `tools/call` → echoes the arguments back as the result.
//!
//! Every call is logged to stderr so tests can verify (or deny) forwarding.

use std::io::{self, BufReader};

use serde_json::{json, Value};

mod mcp;

fn main() {
    let stdin = io::stdin();
    let stdout = io::stdout();
    let mut reader = BufReader::new(stdin.lock());
    let mut writer = stdout.lock();

    loop {
        let raw = match mcp::read_message(&mut reader) {
            Ok(Some(s)) => s,
            Ok(None) => break,
            Err(e) => {
                eprintln!("[echo-server] framing error: {e}");
                break;
            }
        };

        let req: Value = match serde_json::from_str(&raw) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("[echo-server] JSON parse error: {e}");
                continue;
            }
        };

        let id = req.get("id").cloned().unwrap_or(Value::Null);
        let method = req.get("method").and_then(|m| m.as_str()).unwrap_or("");

        let response = match method {
            "initialize" => {
                json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "result": {
                        "protocolVersion": "2024-11-05",
                        "serverInfo": {
                            "name": "a2g-echo-mcp-server",
                            "version": "0.2.0"
                        },
                        "capabilities": {
                            "tools": {}
                        }
                    }
                })
            }

            "tools/list" => {
                json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "result": {
                        "tools": [
                            {
                                "name": "echo",
                                "description": "Echo the input arguments back",
                                "inputSchema": {
                                    "type": "object",
                                    "properties": {
                                        "message": {
                                            "type": "string",
                                            "description": "Message to echo"
                                        }
                                    }
                                }
                            }
                        ]
                    }
                })
            }

            "tools/call" => {
                let params = req.get("params").cloned().unwrap_or(json!({}));
                let tool_name = params
                    .get("name")
                    .and_then(|n| n.as_str())
                    .unwrap_or("unknown");
                let arguments = params.get("arguments").cloned().unwrap_or(json!({}));

                // Log every call to stderr so e2e tests can check forwarding.
                eprintln!("[echo-server] TOOL_CALL tool={tool_name:?} arguments={arguments}");

                json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "result": {
                        "content": [
                            {
                                "type": "text",
                                "text": format!("echo: tool={tool_name} arguments={arguments}")
                            }
                        ]
                    }
                })
            }

            // Notifications: no response.
            "notifications/initialized" | "initialized" => continue,

            _ => {
                eprintln!("[echo-server] unknown method: {method}");
                json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "error": {
                        "code": -32601,
                        "message": format!("method not found: {method}")
                    }
                })
            }
        };

        let body = match serde_json::to_string(&response) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("[echo-server] JSON serialize error: {e}");
                continue;
            }
        };

        if let Err(e) = mcp::write_message(&mut writer, &body) {
            eprintln!("[echo-server] write error: {e}");
            break;
        }
    }
}
