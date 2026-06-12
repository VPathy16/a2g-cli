//! Minimal MCP (Model Context Protocol) JSON-RPC 2.0 stdio framing.
//!
//! Implements only the subset needed by the proxy:
//!   - Content-Length framed I/O (HTTP-like header + body).
//!   - `initialize` / `initialized` handshake.
//!   - `tools/list` passthrough.
//!   - `tools/call` with A2G governance gating.
//!
//! The framing is the Language Server Protocol (LSP) stdio variant:
//!
//! ```text
//! Content-Length: <N>\r\n
//! \r\n
//! <N bytes of UTF-8 JSON>
//! ```
//!
//! References:
//!   - https://spec.modelcontextprotocol.io/specification/
//!   - https://microsoft.github.io/language-server-protocol/specifications/base/0.9/specification/#baseProtocol

use std::io::{self, BufRead, Write};

use serde::{Deserialize, Serialize};
use serde_json::Value;

// ── Wire types ────────────────────────────────────────────────────────────────

/// A JSON-RPC 2.0 request message (id may be null for notifications).
#[allow(dead_code)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcRequest {
    pub jsonrpc: String,
    pub method: String,
    #[serde(default)]
    pub id: Option<Value>,
    #[serde(default)]
    pub params: Option<Value>,
}

/// A JSON-RPC 2.0 response message.
#[allow(dead_code)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcResponse {
    pub jsonrpc: String,
    pub id: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<JsonRpcError>,
}

/// A JSON-RPC 2.0 error object.
#[allow(dead_code)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcError {
    pub code: i64,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
}

// ── A2G-specific MCP error codes ──────────────────────────────────────────────

/// A2G governance DENY — call was refused before reaching the downstream server.
#[allow(dead_code)]
pub const ERR_A2G_DENIED: i64 = -32001;

/// A2G governance ESCALATE — HITL approval required.
/// The `data` object contains `binding_id` for retry.
#[allow(dead_code)]
pub const ERR_A2G_ESCALATE: i64 = -32002;

/// Gateway refused or errored after core ALLOW.
#[allow(dead_code)]
pub const ERR_A2G_GATEWAY: i64 = -32003;

/// Internal proxy error (mandate parse, key load, etc.).
#[allow(dead_code)]
pub const ERR_A2G_INTERNAL: i64 = -32004;

// ── Framing ───────────────────────────────────────────────────────────────────

/// Read one Content-Length–framed message from `reader`.
///
/// Returns `None` on clean EOF, `Err` on I/O or framing errors.
pub fn read_message<R: BufRead>(reader: &mut R) -> io::Result<Option<String>> {
    // Read headers (stop at blank line)
    let mut content_length: Option<usize> = None;

    loop {
        let mut line = String::new();
        let n = reader.read_line(&mut line)?;
        if n == 0 {
            // EOF
            return Ok(None);
        }
        let trimmed = line.trim();
        if trimmed.is_empty() {
            break;
        }
        if let Some(rest) = trimmed.strip_prefix("Content-Length:") {
            let len_str = rest.trim();
            content_length = Some(len_str.parse::<usize>().map_err(|e| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("invalid Content-Length: {e}"),
                )
            })?);
        }
        // Ignore unknown headers (e.g. Content-Type).
    }

    let len = content_length.ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidData, "missing Content-Length header")
    })?;

    let mut body = vec![0u8; len];
    reader.read_exact(&mut body)?;
    String::from_utf8(body).map(Some).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("message body is not valid UTF-8: {e}"),
        )
    })
}

/// Write one Content-Length–framed message to `writer`.
pub fn write_message<W: Write>(writer: &mut W, body: &str) -> io::Result<()> {
    let bytes = body.as_bytes();
    write!(writer, "Content-Length: {}\r\n\r\n", bytes.len())?;
    writer.write_all(bytes)?;
    writer.flush()
}

/// Serialise a `JsonRpcResponse` and write it as a framed message.
#[allow(dead_code)]
pub fn write_response<W: Write>(writer: &mut W, resp: &JsonRpcResponse) -> io::Result<()> {
    let body = serde_json::to_string(resp)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("JSON serialize: {e}")))?;
    write_message(writer, &body)
}

/// Build a success response.
#[allow(dead_code)]
pub fn ok_response(id: Value, result: Value) -> JsonRpcResponse {
    JsonRpcResponse {
        jsonrpc: "2.0".to_string(),
        id,
        result: Some(result),
        error: None,
    }
}

/// Build an error response.
#[allow(dead_code)]
pub fn err_response(id: Value, code: i64, message: String, data: Option<Value>) -> JsonRpcResponse {
    JsonRpcResponse {
        jsonrpc: "2.0".to_string(),
        id,
        result: None,
        error: Some(JsonRpcError {
            code,
            message,
            data,
        }),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;
    use std::io::{BufReader, Cursor};

    #[test]
    fn test_round_trip_framing() {
        let body = r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}"#;
        let mut buf = Vec::new();
        write_message(&mut buf, body).unwrap();

        let mut reader = BufReader::new(Cursor::new(buf));
        let result = read_message(&mut reader).unwrap().unwrap();
        assert_eq!(result, body);
    }

    #[test]
    fn test_eof_returns_none() {
        let buf: Vec<u8> = vec![];
        let mut reader = BufReader::new(Cursor::new(buf));
        assert!(read_message(&mut reader).unwrap().is_none());
    }

    #[test]
    fn test_missing_content_length_is_error() {
        let msg = "X-Custom: value\r\n\r\nhello";
        let mut reader = BufReader::new(Cursor::new(msg.as_bytes()));
        assert!(read_message(&mut reader).is_err());
    }
}
