pub mod apk;
pub mod binary;
pub mod detect;
pub mod dotnet;
pub mod engines;
pub mod entropy;
pub mod har;
pub mod iocs;
pub mod jsapp;
pub mod model;
pub mod png;
pub mod sqlite;
pub mod wasm;

use std::path::{Path, PathBuf};

use crate::core::error::Result;
use crate::core::evidence::{AnalysisReport, ArtifactIdentity, Confidence, Finding, Severity};

#[derive(Debug, Clone)]
pub struct Settings {
    pub max_strings: usize,
    pub max_string_len: usize,
    pub min_string_len: usize,
    pub max_findings: usize,
    pub allow_engines: bool,
    pub head_limit: u64,
    pub redact_credentials: bool,
}

impl Default for Settings {
    fn default() -> Self {
        Settings {
            max_strings: 40,
            max_string_len: 512,
            min_string_len: 4,
            max_findings: 256,
            allow_engines: true,
            head_limit: 64 * 1024 * 1024,
            redact_credentials: true,
        }
    }
}

#[derive(Debug, Clone)]
pub struct AnalysisContext {
    pub path: PathBuf,
    pub head: Vec<u8>,
    pub settings: Settings,
}

impl AnalysisContext {
    pub fn new(path: PathBuf, head: Vec<u8>, settings: Settings) -> Self {
        AnalysisContext { path, head, settings }
    }
}

pub fn identity_for(path: &Path, kind: &str, label: &str, _head: &[u8]) -> Result<ArtifactIdentity> {
    let meta = std::fs::metadata(path)?;
    // A directory has no single file hash; its identity is structural.
    let sha256 = if path.is_dir() {
        String::new()
    } else {
        crate::core::digests::hex(&crate::core::digests::hash_file(path)?)
    };
    Ok(ArtifactIdentity {
        name: path
            .file_name()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_else(|| path.display().to_string()),
        path: path.display().to_string(),
        size: meta.len(),
        sha256,
        kind: kind.to_string(),
        label: label.to_string(),
        container: None,
    })
}

pub fn analyze_path(path: &Path, settings: &Settings) -> Result<AnalysisReport> {
    let (kind, has_content) = detect::detect_path(path)?;
    if !has_content && !path.is_dir() {
        return Ok(analyzer_unrecognized(path, settings, "empty file"));
    }
    let head = if path.is_dir() {
        Vec::new()
    } else {
        detect::read_head(path).map_err(|e| e.ctx(format!("reading {}", path.display())))?
    };
    let ctx = AnalysisContext::new(path.to_path_buf(), head, settings.clone());
    let mut report = match kind {
        detect::Kind::Elf => binary::elf::analyze(&ctx),
        detect::Kind::Pe => match dotnet::try_dotnet(&ctx) {
            Some(report) => Ok(report),
            None => binary::pe::analyze(&ctx),
        },
        detect::Kind::MachO => binary::macho::analyze(&ctx),
        detect::Kind::Wasm => wasm::analyze(&ctx),
        detect::Kind::Png => png::analyze(&ctx),
        detect::Kind::Gguf => model::gguf::analyze(&ctx),
        detect::Kind::Safetensors => model::safetensors::analyze(&ctx),
        detect::Kind::Sqlite => sqlite::analyze(&ctx),
        detect::Kind::Zip => apk::analyze_zip(&ctx, false),
        detect::Kind::Apk => apk::analyze_zip(&ctx, true),
        detect::Kind::DelimitedText => Ok(har::try_har(&ctx).unwrap_or_else(|| {
            analyzer_unrecognized(path, settings, "unrecognized text artifact")
        })),
        detect::Kind::UnknownFile => Ok(analyzer_unrecognized(
            path,
            settings,
            "no analyzer matched",
        )),
        detect::Kind::JsDirectory | detect::Kind::Directory => jsapp::analyze_directory(&ctx),
    }?;
    // Global safety cap on finding volume; keep the summary consistent.
    if report.findings.len() > settings.max_findings {
        report.findings.truncate(settings.max_findings);
        report.summary = summarized_by_severity(&report.findings);
    }
    Ok(report)
}

/// Recompute the severity-count summary (used after capping finding volume).
fn summarized_by_severity(findings: &[Finding]) -> serde_json::Map<String, serde_json::Value> {
    let mut m = serde_json::Map::new();
    for sev in [
        crate::core::evidence::Severity::Info,
        crate::core::evidence::Severity::Note,
        crate::core::evidence::Severity::Warning,
        crate::core::evidence::Severity::Critical,
    ] {
        let n = findings.iter().filter(|f| f.severity == sev).count();
        m.insert(sev.label().into(), serde_json::json!(n));
    }
    m.insert("total".into(), serde_json::json!(findings.len()));
    m
}

pub fn analyzer_unrecognized(path: &Path, settings: &Settings, reason: &str) -> AnalysisReport {
    let identity = identity_for(path, "unknown", "unknown artifact", &[])
        .unwrap_or_else(|_| ArtifactIdentity {
            name: path.display().to_string(),
            path: path.display().to_string(),
            size: 0,
            sha256: String::new(),
            kind: "unknown".into(),
            label: "unknown".into(),
            container: None,
        });
    let mut finding = Finding::new(
        "core.unrecognized",
        format!("no analyzer matched this artifact: {reason}"),
        Severity::Note,
        Confidence::Inferred,
    );
    finding.limitations.push(
        "RET has no parser for this format. The artifact was not modified, run, or executed."
            .into(),
    );
    let mut report = AnalysisReport::new(identity, vec![finding]);
    report
        .facts
        .insert("core.recognized".into(), serde_json::json!(false));
    let _ = settings;
    report
}

pub fn read_bounded(path: &Path, limit: u64) -> Result<Vec<u8>> {
    let meta = std::fs::metadata(path)?;
    if meta.len() == 0 {
        return Ok(Vec::new());
    }
    use std::io::Read;
    let mut f = std::fs::File::open(path)?;
    let take = meta.len().min(limit) as usize;
    let mut buf = vec![0u8; take];
    let mut read = 0usize;
    while read < take {
        let n = f.read(&mut buf[read..])?;
        if n == 0 {
            break;
        }
        read += n;
    }
    buf.truncate(read);
    Ok(buf)
}
