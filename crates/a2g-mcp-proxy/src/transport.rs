//! Downstream MCP server transport trait seam.
//!
//! The `DownstreamTransport` trait abstracts the channel to the downstream
//! MCP server process.  Two implementations are provided:
//!
//! - `StdioTransport` — spawns a subprocess and communicates via stdin/stdout.
//!   This is the production implementation.
//! - `HttpSseTransport` — **not implemented** (ADR-0019 §Not changed).  The
//!   seam exists so a future implementation can be dropped in without changing
//!   the proxy dispatch loop.

use std::io::BufReader;
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};

use crate::mcp::{read_message, write_message, JsonRpcRequest, JsonRpcResponse};

/// Transport abstraction for the downstream MCP server.
///
/// Implementations must be able to:
/// - Send a raw JSON string to the downstream.
/// - Receive a raw JSON string from the downstream.
pub trait DownstreamTransport {
    /// Send a JSON-RPC message to the downstream server.
    fn send(&mut self, body: &str) -> Result<(), String>;

    /// Receive the next JSON-RPC message from the downstream server.
    ///
    /// Returns `Ok(None)` on clean EOF.
    fn recv(&mut self) -> Result<Option<String>, String>;
}

// ── Stdio transport ───────────────────────────────────────────────────────────

/// Stdio transport — wraps a spawned child process.
pub struct StdioTransport {
    _child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
}

impl StdioTransport {
    /// Spawn `command` with `args` and connect to its stdin/stdout.
    pub fn spawn(command: &str, args: &[String]) -> Result<Self, String> {
        let mut child = Command::new(command)
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .map_err(|e| format!("failed to spawn downstream '{command}': {e}"))?;

        let stdin = child.stdin.take().ok_or("no stdin on child process")?;
        let stdout = child
            .stdout
            .take()
            .map(BufReader::new)
            .ok_or("no stdout on child process")?;

        Ok(Self {
            _child: child,
            stdin,
            stdout,
        })
    }
}

impl DownstreamTransport for StdioTransport {
    fn send(&mut self, body: &str) -> Result<(), String> {
        write_message(&mut self.stdin, body).map_err(|e| format!("write to downstream stdin: {e}"))
    }

    fn recv(&mut self) -> Result<Option<String>, String> {
        read_message(&mut self.stdout).map_err(|e| format!("read from downstream stdout: {e}"))
    }
}

// ── HTTP/SSE transport (unimplemented seam) ───────────────────────────────────

/// HTTP/SSE transport — not implemented (ADR-0019 §Not changed).
///
/// This struct exists as a compile-time seam so that an HTTP/SSE implementation
/// can be added later without changing the proxy dispatch loop.  Any attempt to
/// construct or use it will panic with an informative message.
#[allow(dead_code)]
pub struct HttpSseTransport;

impl HttpSseTransport {
    /// Construct an HTTP/SSE transport.  Not implemented.
    #[allow(dead_code)]
    pub fn new(_url: &str) -> Self {
        unimplemented!(
            "HTTP/SSE transport is not implemented (ADR-0019 §Not changed); \
             use StdioTransport for the current release"
        )
    }
}

impl DownstreamTransport for HttpSseTransport {
    fn send(&mut self, _body: &str) -> Result<(), String> {
        unimplemented!("HTTP/SSE transport not implemented")
    }

    fn recv(&mut self) -> Result<Option<String>, String> {
        unimplemented!("HTTP/SSE transport not implemented")
    }
}

// ── Request/Response helpers (used by proxy.rs) ───────────────────────────────

/// Send a `JsonRpcRequest` and receive a `JsonRpcResponse` from the downstream.
///
/// Returns `Err` if the transport fails or the response cannot be parsed.
pub fn call_downstream(
    transport: &mut dyn DownstreamTransport,
    req: &JsonRpcRequest,
) -> Result<JsonRpcResponse, String> {
    let body = serde_json::to_string(req).map_err(|e| format!("request serialize error: {e}"))?;

    transport.send(&body)?;

    let response_body = transport
        .recv()?
        .ok_or_else(|| "downstream closed connection unexpectedly".to_string())?;

    serde_json::from_str::<JsonRpcResponse>(&response_body)
        .map_err(|e| format!("downstream response parse error: {e}"))
}
