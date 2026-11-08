//! RET's plugin system.
//!
//! Plugins are self-contained executables written in any language. Each one
//! lives in its own directory with a tiny `plugin.toml` manifest and is found
//! in either:
//!
//!   ~/.ret/plugins/<name>/plugin.toml   (user-wide)
//!   ./.ret/plugins/<name>/plugin.toml   (project-local, shadows user)
//!
//! RET runs the plugin as a separate process with the artifact path as the
//! final argument. The plugin writes a JSON document to stdout — either
//! RET's `AnalysisReport` shape or the simpler `{ "findings": [...] }`
//! shape — which RET maps onto its own evidence model. Because plugins run
//! out-of-process, a crashing or badly-behaved plugin can never take down
//! RET; its output and exit are validated and bounded.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use serde::{Deserialize, Serialize};

use crate::core::error::{Error, Result};
use crate::core::evidence::{Confidence, Evidence, Finding, Location, Severity};

/// Upper bound on plugin stdout we are willing to parse (bytes).
const MAX_PLUGIN_OUTPUT: u64 = 4 * 1024 * 1024;

/// A `plugin.toml` manifest.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginManifest {
    pub name: String,
    #[serde(default)]
    pub version: String,
    #[serde(default)]
    pub description: String,
    /// Command as argv; the first element is resolved against PATH unless it is
    /// an absolute or relative path. The artifact path is appended as the final
    /// argument.
    pub entry: Vec<String>,
    /// Artifact kinds this plugin claims to understand. Empty means "any".
    #[serde(default)]
    pub formats: Vec<String>,
}

/// A discovered, loadable plugin.
#[derive(Debug, Clone)]
pub struct Plugin {
    pub manifest: PluginManifest,
    pub dir: PathBuf,
}

pub fn user_plugin_root() -> PathBuf {
    let home = std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .unwrap_or_else(|_| ".".into());
    Path::new(&home).join(".ret").join("plugins")
}

pub fn local_plugin_root() -> PathBuf {
    std::env::current_dir()
        .unwrap_or_else(|_| PathBuf::from("."))
        .join(".ret")
        .join("plugins")
}

/// Discover every installed plugin (project-local names shadow user ones).
pub fn discover() -> Vec<Plugin> {
    let mut seen = std::collections::BTreeSet::new();
    let mut out = Vec::new();
    for root in [user_plugin_root(), local_plugin_root()] {
        let Ok(entries) = std::fs::read_dir(&root) else { continue };
        for e in entries.flatten() {
            let dir = e.path();
            if !dir.is_dir() {
                continue;
            }
            let Some(name) = dir.file_name().and_then(|n| n.to_str()).map(String::from) else {
                continue;
            };
            if !seen.insert(name.clone()) {
                continue; // local shadows user
            }
            let manifest_path = dir.join("plugin.toml");
            let Ok(text) = std::fs::read_to_string(&manifest_path) else { continue };
            let manifest: PluginManifest = match toml::from_str(&text) {
                Ok(m) => m,
                Err(_) => continue, // skip broken manifests, keep the tool usable
            };
            out.push(Plugin {
                manifest,
                dir: dir.clone(),
            });
        }
    }
    out.sort_by(|a, b| a.manifest.name.cmp(&b.manifest.name));
    out
}

/// Look up a single plugin by name.
pub fn get(name: &str) -> Result<Plugin> {
    for root in [user_plugin_root(), local_plugin_root()] {
        let dir = root.join(name);
        let manifest_path = dir.join("plugin.toml");
        if manifest_path.exists() {
            let text = std::fs::read_to_string(&manifest_path)?;
            let manifest: PluginManifest = toml::from_str(&text)
                .map_err(|e| Error::malformed(format!("{}/plugin.toml: {e}", dir.display())))?;
            if manifest.name != name {
                return Err(Error::malformed(format!(
                    "plugin at {} declares name '{}' but was requested as '{name}'",
                    dir.display(),
                    manifest.name
                )));
            }
            return Ok(Plugin {
                manifest,
                dir,
            });
        }
    }
    Err(Error::not_found(format!(
        "plugin '{name}' is not installed in ~/.ret/plugins or ./.ret/plugins"
    )))
}

/// Run a plugin against an artifact and map its output onto RET findings.
pub fn run(plugin: &Plugin, artifact: &Path) -> Result<Vec<Finding>> {
    if plugin.manifest.entry.is_empty() {
        return Err(Error::invalid_arg(format!(
            "plugin '{}' declares no entry command",
            plugin.manifest.name
        )));
    }
    if !artifact.exists() {
        return Err(Error::not_found(format!(
            "artifact not found: {}",
            artifact.display()
        )));
    }
    // Plugins run with their own `current_dir`, so hand them an absolute path.
    let artifact_abs = if artifact.is_absolute() {
        artifact.to_path_buf()
    } else {
        std::path::absolute(artifact).unwrap_or_else(|_| artifact.to_path_buf())
    };
    let mut cmd = Command::new(&plugin.manifest.entry[0]);
    cmd.args(&plugin.manifest.entry[1..]);
    cmd.arg(&artifact_abs);
    cmd.current_dir(&plugin.dir);
    cmd.stdin(Stdio::null());
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());
    let out = cmd.output().map_err(|e| {
        Error::provider_missing(
            format!("plugin:{}", plugin.manifest.name),
            format!("failed to spawn '{}': {e}", plugin.manifest.entry.join(" ")),
        )
    })?;
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        return Err(Error::internal(format!(
            "plugin '{}' exited with {:?}: {}",
            plugin.manifest.name,
            out.status.code(),
            stderr.trim().chars().take(600).collect::<String>()
        )));
    }
    if out.stdout.len() > MAX_PLUGIN_OUTPUT as usize {
        return Err(Error::limit(format!(
            "plugin '{}' produced more than 4 MiB of output",
            plugin.manifest.name
        )));
    }
    let text = String::from_utf8_lossy(&out.stdout);
    let parsed: serde_json::Value = serde_json::from_str(text.trim()).map_err(|e| {
        Error::malformed(format!(
            "plugin '{}' printed non-JSON to stdout: {e}",
            plugin.manifest.name
        ))
    })?;
    Ok(plugin_findings(&parsed))
}

/// Accept RET's report shape, a plain `{ "findings": [...] }`, or a bare
/// array, and turn each element into a Finding.
fn plugin_findings(v: &serde_json::Value) -> Vec<Finding> {
    let items: &Vec<serde_json::Value> = match v {
        serde_json::Value::Array(a) => a,
        serde_json::Value::Object(map) => {
            if let Some(arr) = map.get("findings").and_then(|x| x.as_array()) {
                arr
            } else {
                return Vec::new();
            }
        }
        _ => return Vec::new(),
    };
    items.iter().filter_map(finding_from_json).collect()
}

fn finding_from_json(v: &serde_json::Value) -> Option<Finding> {
    let id = v.get("id").and_then(|x| x.as_str())?.to_string();
    let claim = v.get("claim").and_then(|x| x.as_str())?.to_string();
    let severity = parse_severity(
        v.get("severity").and_then(|x| x.as_str()).unwrap_or("note"),
    );
    let confidence = parse_confidence(
        v.get("confidence")
            .and_then(|x| x.as_str())
            .unwrap_or("inferred"),
    );
    let mut f = Finding::new(format!("plugin.{id}"), claim, severity, confidence);
    if let Some(ev) = v.get("evidence").and_then(|x| x.as_array()) {
        for e in ev {
            let Some(label) = e.get("label").and_then(|x| x.as_str()) else {
                continue;
            };
            let value = e.get("value").and_then(|x| x.as_str()).unwrap_or("").to_string();
            f.evidence.push(Evidence::new(
                label,
                value,
                location_from_json(e.get("location")),
            ));
        }
    }
    if let Some(lim) = v.get("limitations").and_then(|x| x.as_array()) {
        for l in lim {
            if let Some(s) = l.as_str() {
                f.limitations.push(s.to_string());
            }
        }
    }
    Some(f)
}

fn location_from_json(v: Option<&serde_json::Value>) -> Location {
    let Some(v) = v else { return Location::entity("artifact", "whole") };
    if let Some(start) = v.get("start").and_then(|x| x.as_u64()) {
        return Location::bytes(start, v.get("end").and_then(|x| x.as_u64()));
    }
    if let Some(path) = v.get("path").and_then(|x| x.as_str()) {
        return Location::route(path);
    }
    Location::entity(
        v.get("kind").and_then(|x| x.as_str()).unwrap_or("artifact"),
        v.get("name").and_then(|x| x.as_str()).unwrap_or("whole"),
    )
}

fn parse_severity(s: &str) -> Severity {
    match s {
        "info" | "Info" => Severity::Info,
        "warning" | "warn" => Severity::Warning,
        "critical" | "error" => Severity::Critical,
        _ => Severity::Note,
    }
}

fn parse_confidence(s: &str) -> Confidence {
    match s {
        "direct" => Confidence::Direct,
        "derived" => Confidence::Derived,
        _ => Confidence::Inferred,
    }
}
