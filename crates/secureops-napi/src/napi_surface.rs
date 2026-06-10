//! `#[napi]` wrappers - the thin FFI seam the Node.js shim calls.
//!
//! Every wrapper delegates immediately to the plain Rust function in the crate
//! root or plugin module, keeping audit logic free of napi types
//! (PRODUCT.md A.2 / Part G Phase 1).

use napi_derive::napi;

// ---------------------------------------------------------------------------
// Core audit surface
// ---------------------------------------------------------------------------

/// Run a full read-only audit and return the report as pretty JSON.
/// JavaScript: `await secureops.auditToJson(stateDir, deep, fix)`
#[napi(js_name = "auditToJson")]
pub async fn audit_to_json_napi(state_dir: String, deep: bool, fix: bool) -> napi::Result<String> {
    Ok(crate::audit_to_json(state_dir, deep, fix).await)
}

/// Return JSON metadata about the bundled IOC database.
/// JavaScript: `secureops.iocDbInfo()`
#[napi(js_name = "iocDbInfo")]
pub fn ioc_db_info_napi() -> napi::Result<String> {
    Ok(crate::ioc_db_info())
}

/// Return the SecureOps version string.
/// JavaScript: `secureops.version()`
#[napi(js_name = "version")]
pub fn version_napi() -> napi::Result<String> {
    Ok(crate::SECUREOPS_VERSION.to_string())
}

// ---------------------------------------------------------------------------
// OpenClaw plugin lifecycle hooks
// ---------------------------------------------------------------------------

/// Plugin manifest (name, version, commands, MCP tools).
/// JavaScript: `secureops.pluginManifest()`
#[napi(js_name = "pluginManifest")]
pub fn plugin_manifest_napi() -> napi::Result<String> {
    Ok(crate::plugin::plugin_manifest())
}

/// `gateway_start` hook - kill-switch gate + startup audit.
/// JavaScript: `await secureops.onGatewayStart(stateDir)`
#[napi(js_name = "onGatewayStart")]
pub async fn on_gateway_start_napi(state_dir: String) -> napi::Result<String> {
    Ok(crate::plugin::on_gateway_start(&state_dir).await)
}

/// `gateway_stop` hook.
/// JavaScript: `secureops.onGatewayStop()`
#[napi(js_name = "onGatewayStop")]
pub fn on_gateway_stop_napi() -> napi::Result<String> {
    Ok(crate::plugin::on_gateway_stop())
}

// ---------------------------------------------------------------------------
// Command + MCP tool dispatch
// ---------------------------------------------------------------------------

/// Dispatch a `secureops <cmd>` command (audit/harden/status/kill/…).
/// JavaScript: `await secureops.dispatchCommand(cmd, args)`
#[napi(js_name = "dispatchCommand")]
pub async fn dispatch_command_napi(cmd: String, args: Vec<String>) -> napi::Result<String> {
    Ok(crate::plugin::dispatch_command(&cmd, &args).await)
}

/// Dispatch an MCP tool call (security_audit/skill_scan/kill_switch/…).
/// JavaScript: `await secureops.callTool(tool, args)`
#[napi(js_name = "callTool")]
pub async fn call_tool_napi(tool: String, args: Vec<String>) -> napi::Result<String> {
    Ok(crate::plugin::call_tool(&tool, &args).await)
}
