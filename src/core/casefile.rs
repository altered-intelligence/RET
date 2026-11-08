//! The RET *case file*: an append-friendly, human-inspectable ledger that
//! accumulates every finding across runs, tracks the artifacts examined, and
//! keeps a hash history so later runs can report what changed.
//!
//! Layout on disk (a directory):
//!   case.json        — case metadata + artifact table + snapshots
//!   findings.jsonl   — one Finding per line, appended per run
//!   history.jsonl    — one Snapshot per recorded run (append-only)

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

use crate::core::error::{Error, Result};

pub const CASE_FILE: &str = "case.json";
pub const FINDINGS_FILE: &str = "findings.jsonl";
pub const HISTORY_FILE: &str = "history.jsonl";

fn now() -> DateTime<Utc> {
    chrono::Utc::now()
}

/// One recorded touch of an artifact (usually one `record`/`analyze` run).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Snapshot {
    pub timestamp: DateTime<Utc>,
    pub name: String,
    pub path: String,
    pub size: u64,
    pub sha256: String,
    /// Canonical digest of structured facts, when analysis ran.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub structural_digest: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
}

/// Per-artifact tracked state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrackedArtifact {
    pub name: String,
    pub path: String,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub size: u64,
    pub sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Case {
    pub id: String,
    pub created: DateTime<Utc>,
    pub updated: DateTime<Utc>,
    pub description: String,
    pub artifacts: Vec<TrackedArtifact>,
    pub findings: Vec<crate::core::evidence::Finding>,
    pub snapshots: Vec<Snapshot>,
}

impl Case {
    pub fn new(description: impl Into<String>) -> Self {
        let t = now();
        Case {
            id: format!("case-{}", t.format("%Y%m%d%H%M%S")),
            created: t,
            updated: t,
            description: description.into(),
            artifacts: Vec::new(),
            findings: Vec::new(),
            snapshots: Vec::new(),
        }
    }

    pub fn touch(&mut self, artifact: &crate::core::evidence::ArtifactIdentity) {
        if let Some(existing) = self
            .artifacts
            .iter_mut()
            .find(|a| a.path == artifact.path)
        {
            existing.last_seen = now();
            existing.size = artifact.size;
            existing.sha256 = artifact.sha256.clone();
        } else {
            let t = now();
            self.artifacts.push(TrackedArtifact {
                name: artifact.name.clone(),
                path: artifact.path.clone(),
                first_seen: t,
                last_seen: t,
                size: artifact.size,
                sha256: artifact.sha256.clone(),
            });
        }
        self.updated = now();
    }

    pub fn add_report(&mut self, report: &crate::core::evidence::AnalysisReport, run: u64) {
        self.touch(&report.artifact);
        for mut f in report.findings.clone() {
            f.run = Some(run);
            self.findings.push(f);
        }
        self.updated = now();
    }

    pub fn add_snapshot(&mut self, s: Snapshot) {
        self.snapshots.push(s);
        self.updated = now();
    }

    pub fn latest_snapshot(&self, path: &str) -> Option<&Snapshot> {
        self.snapshots
            .iter()
            .filter(|s| s.path == path)
            .next_back()
    }
}

/// Open (or create) a case inside `dir`.
pub fn open_or_create(dir: &Path, description: &str) -> Result<Case> {
    std::fs::create_dir_all(dir).map_err(|e| Error::new(crate::core::error::ErrorKind::Io, e.to_string()))?;
    let case_path = dir.join(CASE_FILE);
    let mut case = if case_path.exists() {
        let data = std::fs::read(&case_path)?;
        let mut c: Case = serde_json::from_slice(&data)?;
        // Re-hydrate findings from the append log.
        let findings_path = dir.join(FINDINGS_FILE);
        if findings_path.exists() {
            let log = std::fs::read_to_string(&findings_path)?;
            c.findings = log
                .lines()
                .filter(|l| !l.trim().is_empty())
                .map(|l| serde_json::from_str::<crate::core::evidence::Finding>(l))
                .collect::<std::result::Result<Vec<_>, _>>()?;
        }
        let history_path = dir.join(HISTORY_FILE);
        if history_path.exists() {
            let log = std::fs::read_to_string(&history_path)?;
            c.snapshots = log
                .lines()
                .filter(|l| !l.trim().is_empty())
                .map(|l| serde_json::from_str::<Snapshot>(l))
                .collect::<std::result::Result<Vec<_>, _>>()?;
        }
        c
    } else {
        Case::new(description)
    };
    case.description = description.to_string();
    save(&case, dir)?;
    Ok(case)
}

pub fn save(case: &Case, dir: &Path) -> Result<()> {
    std::fs::create_dir_all(dir)?;
    let case_json = serde_json::to_string_pretty(case)?;
    std::fs::write(dir.join(CASE_FILE), case_json)?;
    let findings_log: Vec<String> = case
        .findings
        .iter()
        .map(|f| serde_json::to_string(f).unwrap())
        .collect();
    std::fs::write(dir.join(FINDINGS_FILE), findings_log.join("\n"))?;
    let history_log: Vec<String> = case
        .snapshots
        .iter()
        .map(|s| serde_json::to_string(s).unwrap())
        .collect();
    std::fs::write(dir.join(HISTORY_FILE), history_log.join("\n"))?;
    Ok(())
}

/// Resolve `--case-dir` default (`.ret/case` under CWD) into a path.
pub fn default_case_dir() -> PathBuf {
    std::env::current_dir()
        .unwrap_or_else(|_| PathBuf::from("."))
        .join(".ret")
        .join("case")
}
