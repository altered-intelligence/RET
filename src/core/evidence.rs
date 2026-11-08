//! RET's evidence model.
//!
//! Every conclusion RET produces is a `Finding` that carries *proof*
//! (evidence with byte-level locations), *confidence* (whether the claim was
//! observed directly, derived, or inferred), and *limitations* (what the
//! analysis could not establish). This keeps conclusions auditable: an agent
//! or human can always trace a claim back to the bytes that support it.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fmt;

/// How strongly a claim is supported by the observed bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Confidence {
    /// Directly observed in the artifact (a header field, a parsed entry).
    Direct,
    /// Derived through a documented transformation of observed facts.
    Derived,
    /// Inferred from patterns/heuristics; may be wrong.
    Inferred,
}

impl Confidence {
    pub fn label(self) -> &'static str {
        match self {
            Confidence::Direct => "direct",
            Confidence::Derived => "derived",
            Confidence::Inferred => "inferred",
        }
    }
}

/// Severity / informational weight of a finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Info,
    Note,
    Warning,
    Critical,
}

impl Severity {
    pub fn label(self) -> &'static str {
        match self {
            Severity::Info => "info",
            Severity::Note => "note",
            Severity::Warning => "warning",
            Severity::Critical => "critical",
        }
    }
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.label())
    }
}

/// Where in an artifact a piece of evidence lives.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "at", rename_all = "snake_case")]
pub enum Location {
    /// The whole artifact, or a path within a container/directory.
    Route { path: String },
    /// A byte range `[start, end)` inside the artifact file.
    Bytes {
        start: u64,
        end: Option<u64>,
        #[serde(skip_serializing_if = "Option::is_none")]
        note: Option<String>,
    },
    /// A parsed entity (table/stream/section) rather than raw bytes.
    Entity { kind: String, name: String },
}

impl Location {
    pub fn route(path: impl Into<String>) -> Self {
        Location::Route { path: path.into() }
    }
    pub fn bytes(start: u64, end: Option<u64>) -> Self {
        Location::Bytes {
            start,
            end,
            note: None,
        }
    }
    pub fn entity(kind: impl Into<String>, name: impl Into<String>) -> Self {
        Location::Entity {
            kind: kind.into(),
            name: name.into(),
        }
    }
}

/// One concrete, auditable fact that supports a claim.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Evidence {
    /// Short label for the fact, e.g. `program_headers.count`.
    pub label: String,
    /// The human/machine readable fact value.
    pub value: String,
    pub location: Location,
    /// How this fact was obtained.
    pub provenance: Confidence,
}

impl Evidence {
    pub fn new(label: impl Into<String>, value: impl Into<String>, location: Location) -> Self {
        Evidence {
            label: label.into(),
            value: value.into(),
            location,
            provenance: Confidence::Direct,
        }
    }
    pub fn derived(label: impl Into<String>, value: impl Into<String>, location: Location) -> Self {
        let mut e = Self::new(label, value, location);
        e.provenance = Confidence::Derived;
        e
    }
    pub fn inferred(label: impl Into<String>, value: impl Into<String>, location: Location) -> Self {
        let mut e = Self::new(label, value, location);
        e.provenance = Confidence::Inferred;
        e
    }
}

/// A claim about an artifact, with the evidence and limits that surround it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    /// Stable dotted identifier, e.g. `elf.program_headers`.
    pub id: String,
    /// The claim itself.
    pub claim: String,
    pub severity: Severity,
    pub confidence: Confidence,
    pub evidence: Vec<Evidence>,
    pub limitations: Vec<String>,
    /// Timestamp of when the finding was produced.
    pub produced_at: DateTime<Utc>,
    /// Findings are appended to an accumulating case; `run` tags the run.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub run: Option<u64>,
}

impl Finding {
    pub fn new(
        id: impl Into<String>,
        claim: impl Into<String>,
        severity: Severity,
        confidence: Confidence,
    ) -> Self {
        Finding {
            id: id.into(),
            claim: claim.into(),
            severity,
            confidence,
            evidence: Vec::new(),
            limitations: Vec::new(),
            produced_at: Utc::now(),
            run: None,
        }
    }
    /// Builder helpers: convenient for plugins and agents constructing
    /// findings programmatically (the built-in analyzers set fields directly).
    #[allow(dead_code)]
    pub fn with(mut self, evidence: impl IntoIterator<Item = Evidence>) -> Self {
        self.evidence.extend(evidence);
        self
    }
    #[allow(dead_code)]
    pub fn evidence(mut self, e: Evidence) -> Self {
        self.evidence.push(e);
        self
    }
    #[allow(dead_code)]
    pub fn limitation(mut self, l: impl Into<String>) -> Self {
        self.limitations.push(l.into());
        self
    }
    #[allow(dead_code)]
    pub fn facts(&self) -> Vec<(String, String)> {
        self.evidence
            .iter()
            .map(|e| (e.label.clone(), e.value.clone()))
            .collect()
    }
}

/// Identity and provenance of one analyzed artifact.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ArtifactIdentity {
    /// Base name used as the artifact handle.
    pub name: String,
    pub path: String,
    pub size: u64,
    pub sha256: String,
    /// Detected kind, e.g. `elf`, `pe`, `js_app`.
    pub kind: String,
    /// Human label, e.g. "ELF 64-bit LSB executable, x86-64".
    pub label: String,
    /// Sniffed mime-ish descriptor.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub container: Option<String>,
}

/// The full result of running one analyzer against one artifact.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisReport {
    pub artifact: ArtifactIdentity,
    pub findings: Vec<Finding>,
    /// Machine-oriented facts used for comparison & dashboards. Keys are
    /// flattened, sortable paths like `hardening.nx`.
    pub facts: serde_json::Map<String, serde_json::Value>,
    /// Free-form structured data an analyzer wants to expose beyond findings.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<serde_json::Value>,
    pub produced_at: DateTime<Utc>,
    /// Number of findings by severity.
    pub summary: serde_json::Map<String, serde_json::Value>,
}

impl AnalysisReport {
    pub fn new(artifact: ArtifactIdentity, findings: Vec<Finding>) -> Self {
        let mut summary = serde_json::Map::new();
        for sev in [Severity::Info, Severity::Note, Severity::Warning, Severity::Critical] {
            let n = findings.iter().filter(|f| f.severity == sev).count();
            summary.insert(sev.label().to_string(), serde_json::json!(n));
        }
        summary.insert("total".into(), serde_json::json!(findings.len()));
        AnalysisReport {
            artifact,
            findings,
            facts: serde_json::Map::new(),
            detail: None,
            produced_at: Utc::now(),
            summary,
        }
    }

    /// A canonical, comparison-stable digest of the report's structured facts.
    pub fn structural_digest(&self) -> String {
        let mut keys: Vec<&String> = self.facts.keys().collect();
        keys.sort();
        let mut canonical = String::new();
        for k in keys {
            canonical.push_str(&format!(
                "{}={};",
                k,
                serde_json::to_string(self.facts.get(k).unwrap())
                    .unwrap_or_else(|_| "null".into())
            ));
        }
        crate::core::digests::sha256_hex(canonical.as_bytes())
    }

    pub fn severity_counts(&self) -> (usize, usize, usize, usize) {
        let mut c = (0usize, 0usize, 0usize, 0usize);
        for f in &self.findings {
            match f.severity {
                Severity::Info => c.0 += 1,
                Severity::Note => c.1 += 1,
                Severity::Warning => c.2 += 1,
                Severity::Critical => c.3 += 1,
            }
        }
        c
    }
}
