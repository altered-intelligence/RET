//! Optional external engine integration: GNU objdump and radare2 (r2).
//! RET never shells out behind your back — these providers are used only
//! when a command or MCP tool asks for disassembly, and every run is bounded
//! (time + output size).

use std::process::Command;

use crate::core::error::{Error, Result};
use crate::core::evidence::{
    AnalysisReport, Confidence, Evidence, Finding, Location, Severity,
};

const MAX_OUTPUT: u64 = 2 * 1024 * 1024;

#[derive(Debug, Clone)]
pub struct Provider {
    pub name: &'static str,
    pub binary: &'static str,
    pub hint: &'static str,
}

pub const PROVIDERS: [Provider; 2] = [
    Provider {
        name: "objdump",
        binary: "objdump",
        hint: "install the GNU binutils package to enable objdump disassembly",
    },
    Provider {
        name: "radare2",
        binary: "r2",
        hint: "install radare2 (brew install radare2) to enable r2 disassembly",
    },
];

/// Which providers are on PATH, with versions when they answer.
pub fn provider_status() -> Vec<(String, bool, Option<String>)> {
    PROVIDERS
        .iter()
        .map(|p| {
            if let Some(version) = probe_version(p.binary) {
                (p.name.to_string(), true, Some(version))
            } else {
                (p.name.to_string(), false, None)
            }
        })
        .collect()
}

fn probe_version(bin: &str) -> Option<String> {
    let out = Command::new(bin).arg("--version").output().ok()?;
    if !out.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&out.stdout).into_owned();
    let first = text.lines().next().unwrap_or("").trim().to_string();
    if first.is_empty() { None } else { Some(first) }
}

fn which(bin: &str) -> bool {
    probe_version(bin).is_some()
}

fn output_with_timeout(args: &[&str]) -> Result<String> {
    let out = Command::new(args[0])
        .args(&args[1..])
        .output()
        .map_err(|e| Error::provider_missing(args[0], format!("failed to spawn: {e}")))?;
    let text = String::from_utf8_lossy(&out.stdout);
    let mut s = text.into_owned();
    if s.len() > MAX_OUTPUT as usize {
        s.truncate(MAX_OUTPUT as usize);
        s.push_str("\n… (output truncated)");
    }
    Ok(s)
}

/// Disassemble a binary, optionally focusing on a symbol/substring (`needle`).
pub fn disassemble(path: &str, needle: Option<&str>, provider: &str) -> Result<Finding> {
    match provider {
        "objdump" => disassemble_objdump(path, needle),
        "radare2" | "r2" => disassemble_r2(path, needle),
        _ => Err(Error::invalid_arg(format!("unknown engine '{provider}'"))),
    }
}

fn disassemble_objdump(path: &str, needle: Option<&str>) -> Result<Finding> {
    if !which("objdump") {
        return Err(Error::provider_missing("objdump", "install GNU binutils"));
    }
    let mut args: Vec<&str> = vec!["objdump", "-C", "-d", "--no-show-raw-insn"];
    args.push(path);
    let text = output_with_timeout(&args)?;
    let mut f = Finding::new(
        "engines.objdump",
        "disassembly requested via GNU objdump",
        Severity::Info,
        Confidence::Direct,
    );
    f.limitations.push("objdump output is bounded; full disassembly is not retained".into());
    if let Some(n) = needle {
        let hit = context_lines(&text, n, 3);
        if !hit.is_empty() {
            f.evidence.push(Evidence::new(
                "engines.objdump.match",
                hit,
                Location::entity("disassembly", n.to_string()),
            ));
        } else {
            f.claim = format!("objdump available but no disassembly matched '{n}'");
            f.limitations
                .push("the needle may be a mangled or stripped symbol".into());
        }
    }
    Ok(f)
}

fn disassemble_r2(path: &str, needle: Option<&str>) -> Result<Finding> {
    if !which("r2") {
        return Err(Error::provider_missing("radare2", "install radare2"));
    }
    let mut f = Finding::new(
        "engines.radare2",
        "radare2 is available for interactive analysis",
        Severity::Info,
        Confidence::Direct,
    );
    f.evidence.push(Evidence::new(
        "engines.radare2",
        "r2 found on PATH",
        Location::route("PATH"),
    ));
    if let Some(n) = needle {
        let cmd = format!("r2 -q -c \"aaa; afl~{n};\" {}", path);
        let out = std::process::Command::new("sh")
            .arg("-c")
            .arg(&cmd)
            .output()
            .map_err(|e| Error::provider_missing("r2", format!("{e}")))?;
        let text = String::from_utf8_lossy(&out.stdout);
        if !text.trim().is_empty() {
            f.evidence.push(Evidence::new(
                "engines.radare2.matches",
                text.trim().lines().take(5).collect::<Vec<_>>().join("\n"),
                Location::entity("radare2", "afl"),
            ));
        }
    }
    Ok(f)
}

fn context_lines(text: &str, needle: &str, radius: usize) -> String {
    let lines: Vec<&str> = text.lines().collect();
    let mut result = Vec::new();
    for (i, l) in lines.iter().enumerate() {
        if l.contains(needle) {
            let start = i.saturating_sub(radius);
            let end = (i + radius + 1).min(lines.len());
            result.push(lines[start..end].join("\n"));
        }
        if result.len() >= 4 {
            break;
        }
    }
    result.join("\n---\n")
}

/// Produce an engines readiness report for `doctor`.
pub fn doctor_report() -> AnalysisReport {
    let mut findings = Vec::new();
    for (name, ok, version) in provider_status() {
        let mut f = Finding::new(
            "engines.provider",
            format!("{name}: {}", if ok { "available" } else { "not found" }),
            if ok { Severity::Info } else { Severity::Note },
            Confidence::Direct,
        );
        if let Some(v) = version {
            f.evidence.push(Evidence::new("engines.version", v, Location::route("PATH")));
        } else {
            let hint = PROVIDERS
                .iter()
                .find(|p| p.name == name)
                .map(|p| p.hint.to_string())
                .unwrap_or_default();
            f.evidence.push(Evidence::new(
                "engines.hint",
                hint,
                Location::route("PATH"),
            ));
        }
        findings.push(f);
    }
    let mut report = AnalysisReport::new(
        crate::core::evidence::ArtifactIdentity {
            name: "engines".into(),
            path: "providers".into(),
            size: 0,
            sha256: String::new(),
            kind: "engines".into(),
            label: "External analysis engines".into(),
            container: None,
        },
        findings,
    );
    report.facts.insert(
        "engines.available".into(),
        serde_json::json!(provider_status()
            .iter()
            .filter(|(_, ok, _)| *ok)
            .map(|(n, _, _)| n.clone())
            .collect::<Vec<_>>()),
    );
    report
}
