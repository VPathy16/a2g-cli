//! TOML configuration for the A2G MCP proxy.
//!
//! The config is authoring-side only — it is never signed or included in any
//! cryptographic payload.  It controls:
//!
//! - The downstream MCP server process to spawn.
//! - The A2G mandate file path.
//! - The gateway Unix socket path.
//! - TrustAnchor mode (self-sovereign for now; root key extension forthcoming).
//! - The tool-name → capability mapping table.
//!
//! **Default rule**: any tool NOT in the mapping table is treated as
//! `pay.unknown` (always-HITL, fail-closed).

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// Top-level proxy configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyConfig {
    /// Downstream MCP server process config.
    pub downstream: DownstreamConfig,

    /// Path to the A2G mandate CBOR file.
    pub mandate_path: PathBuf,

    /// Path to the gateway Unix socket.
    pub gateway_socket: PathBuf,

    /// Path to the demo key file written by the gateway on startup.
    /// The proxy reads `receipt_signing_key_hex` from this file to sign receipts.
    pub demo_key_file: PathBuf,

    /// Trust anchor configuration.
    #[serde(default)]
    pub trust_anchor: TrustAnchorConfig,

    /// Tool name → A2G capability mapping.
    ///
    /// Keys are MCP tool names (e.g. `"echo"`, `"read_file"`).
    /// Values are A2G capability names (e.g. `"vehicle.climate.set_temperature"`,
    /// `"comms.contacts.read"`, `"pay.checkout"`).
    ///
    /// Any tool NOT in this table is treated as `pay.unknown` (always-HITL,
    /// fail-closed per ADR-0019).
    #[serde(default)]
    pub tool_map: HashMap<String, String>,
}

/// Downstream MCP server process configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DownstreamConfig {
    /// Executable path or command name for the downstream MCP server.
    pub command: String,

    /// Arguments to pass to the downstream process.
    #[serde(default)]
    pub args: Vec<String>,
}

/// Trust anchor source for mandate validation.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(tag = "mode", rename_all = "snake_case")]
pub enum TrustAnchorConfig {
    /// Accept any self-consistent mandate without checking the issuer against
    /// a trusted key set.  Suitable for local dev and single-tenant deployments
    /// where key pinning is enforced elsewhere.  Requires an explicit opt-in so
    /// insecure mode is never the result of omission (ADR-0014).
    #[default]
    SelfSovereign,

    /// The mandate's issuer pubkey must match one of the listed hex-encoded
    /// 32-byte ed25519 public keys.
    Roots { pubkeys: Vec<String> },
}

impl ProxyConfig {
    /// Load and parse a TOML config file.
    pub fn load(path: &Path) -> Result<Self, String> {
        let raw = std::fs::read_to_string(path)
            .map_err(|e| format!("cannot read config {}: {e}", path.display()))?;
        toml::from_str(&raw).map_err(|e| format!("config parse error: {e}"))
    }

    /// Resolve the A2G capability for a given MCP tool name.
    ///
    /// Returns the mapped capability name if found; otherwise returns
    /// `"pay.unknown"` (always-HITL, fail-closed default per ADR-0019).
    pub fn resolve_capability<'a>(&'a self, tool_name: &str) -> &'a str {
        self.tool_map
            .get(tool_name)
            .map(|s| s.as_str())
            .unwrap_or("pay.unknown")
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use std::io::Write;

    #[test]
    fn test_unmapped_tool_resolves_to_pay_unknown() {
        let cfg = ProxyConfig {
            downstream: DownstreamConfig {
                command: "echo-server".to_string(),
                args: vec![],
            },
            mandate_path: PathBuf::from("/tmp/mandate.cbor"),
            gateway_socket: PathBuf::from("/tmp/gateway.sock"),
            demo_key_file: PathBuf::from("/tmp/demo-keys.json"),
            trust_anchor: TrustAnchorConfig::SelfSovereign,
            tool_map: {
                let mut m = HashMap::new();
                m.insert(
                    "echo".to_string(),
                    "vehicle.climate.set_temperature".to_string(),
                );
                m
            },
        };

        assert_eq!(
            cfg.resolve_capability("echo"),
            "vehicle.climate.set_temperature"
        );
        assert_eq!(cfg.resolve_capability("unknown_tool"), "pay.unknown");
        assert_eq!(cfg.resolve_capability(""), "pay.unknown");
    }

    #[test]
    fn test_load_toml_config() {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        write!(
            f,
            r#"
mandate_path = "/tmp/mandate.cbor"
gateway_socket = "/tmp/gw.sock"
demo_key_file = "/tmp/demo-keys.json"

[downstream]
command = "a2g-echo-mcp-server"
args = []

[trust_anchor]
mode = "self_sovereign"

[tool_map]
echo = "vehicle.climate.set_temperature"
read = "vehicle.infotainment.media_control"
"#
        )
        .unwrap();

        let cfg = ProxyConfig::load(f.path()).unwrap();
        assert_eq!(cfg.downstream.command, "a2g-echo-mcp-server");
        assert_eq!(
            cfg.resolve_capability("echo"),
            "vehicle.climate.set_temperature"
        );
        assert_eq!(cfg.resolve_capability("not_mapped"), "pay.unknown");
    }
}
