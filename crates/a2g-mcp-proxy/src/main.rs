//! A2G MCP Proxy — binary entry point.
//!
//! Usage:
//!   a2g-mcp-proxy --config <path>
//!
//! The proxy reads an MCP JSON-RPC stream from stdin and writes responses to stdout,
//! interceding every `tools/call` through A2G governance.

use std::path::PathBuf;

mod config;
mod governance;
mod mcp;
mod proxy;
mod transport;

fn main() {
    // ── Argument parsing ───────────────────────────────────────────────────────
    let args: Vec<String> = std::env::args().collect();
    let config_path = parse_config_arg(&args).unwrap_or_else(|| {
        eprintln!("Usage: a2g-mcp-proxy --config <path>");
        std::process::exit(1);
    });

    // ── Load config ────────────────────────────────────────────────────────────
    let config = match config::ProxyConfig::load(&config_path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("[a2g-mcp-proxy] config error: {e}");
            std::process::exit(1);
        }
    };

    eprintln!(
        "[a2g-mcp-proxy] loaded config; downstream={} gateway={}",
        config.downstream.command,
        config.gateway_socket.display()
    );

    // ── Load governance context ────────────────────────────────────────────────
    let gov = match governance::GovernanceContext::load(&config) {
        Ok(g) => g,
        Err(e) => {
            eprintln!("[a2g-mcp-proxy] governance context error: {e}");
            std::process::exit(1);
        }
    };

    // ── Spawn downstream process ───────────────────────────────────────────────
    let mut downstream =
        match transport::StdioTransport::spawn(&config.downstream.command, &config.downstream.args)
        {
            Ok(t) => t,
            Err(e) => {
                eprintln!("[a2g-mcp-proxy] downstream spawn error: {e}");
                std::process::exit(1);
            }
        };

    // ── Run proxy loop ─────────────────────────────────────────────────────────
    let stdin = std::io::stdin();
    let mut stdout = std::io::stdout();

    proxy::run_proxy(stdin.lock(), &mut stdout, &mut downstream, &config, &gov);

    eprintln!("[a2g-mcp-proxy] upstream closed; shutting down");
}

fn parse_config_arg(args: &[String]) -> Option<PathBuf> {
    let mut iter = args.iter().peekable();
    while let Some(arg) = iter.next() {
        if arg == "--config" {
            return iter.next().map(PathBuf::from);
        }
        if let Some(rest) = arg.strip_prefix("--config=") {
            return Some(PathBuf::from(rest));
        }
    }
    None
}
