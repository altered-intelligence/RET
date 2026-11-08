//! Artifact comparison and change history.
//!
//! RET never asserts "identical" from hashes alone: it compares the
//! canonical structural digests of analysis facts and reports each difference
//! (added / removed / modified) so a human or agent can judge significance.

use serde::{Deserialize, Serialize};

use crate::analysis::Settings;
use crate::core::error::Result;
use crate::core::evidence::{AnalysisReport, Confidence, Finding, Severity};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChangeKind {
    Added,
    Removed,
    Modified,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FieldChange {
    pub key: String,
    pub kind: ChangeKind,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub before: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub after: Option<serde_json::Value>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    /// Byte-for-byte identical.
    IdenticalBytes,
    /// Same structural facts (same analysis output), even if bytes differ.
    StructurallyEqual,
    /// Structural facts differ.
    Changed,
    /// Comparison not possible without both analyses.
    NotComparable,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompareResult {
    pub verdict: Verdict,
    pub a: SideInfo,
    pub b: SideInfo,
    pub changes: Vec<FieldChange>,
    pub changed_field_count: usize,
    pub explanations: Vec<String>,
    pub findings: Vec<Finding>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SideInfo {
    pub name: String,
    pub path: String,
    pub kind: String,
    pub size: u64,
    pub sha256: String,
    pub structural_digest: String,
    pub finding_count: usize,
}

fn side_info(r: &AnalysisReport) -> SideInfo {
    SideInfo {
        name: r.artifact.name.clone(),
        path: r.artifact.path.clone(),
        kind: r.artifact.kind.clone(),
        size: r.artifact.size,
        sha256: r.artifact.sha256.clone(),
        structural_digest: r.structural_digest(),
        finding_count: r.findings.len(),
    }
}

fn changes_between(a: &AnalysisReport, b: &AnalysisReport) -> Vec<FieldChange> {
    let mut changes = Vec::new();
    let mut keys: std::collections::BTreeSet<&String> = a.facts.keys().collect();
    keys.extend(b.facts.keys());
    for k in keys {
        match (a.facts.get(k), b.facts.get(k)) {
            (Some(x), Some(y)) => {
                if x != y {
                    changes.push(FieldChange {
                        key: k.clone(),
                        kind: ChangeKind::Modified,
                        before: Some(x.clone()),
                        after: Some(y.clone()),
                    });
                }
            }
            (Some(x), None) => changes.push(FieldChange {
                key: k.clone(),
                kind: ChangeKind::Removed,
                before: Some(x.clone()),
                after: None,
            }),
            (None, Some(y)) => changes.push(FieldChange {
                key: k.clone(),
                kind: ChangeKind::Added,
                before: None,
                after: Some(y.clone()),
            }),
            (None, None) => {}
        }
    }
    changes
}

/// Compare two already-computed analysis reports.
pub fn compare_reports(a: &AnalysisReport, b: &AnalysisReport) -> CompareResult {
    let mut changes = changes_between(a, b);
    let changed_field_count = changes.len();
    // Only surface the most informative changes in the JSON payload
    changes.truncate(160);
    let mut explanations = Vec::new();

    let a_info = side_info(a);
    let b_info = side_info(b);

    let verdict = if a_info.sha256 == b_info.sha256 && a_info.size == b_info.size {
        Verdict::IdenticalBytes
    } else if a_info.structural_digest == b_info.structural_digest {
        Verdict::StructurallyEqual
    } else if a_info.kind != b_info.kind {
        explanations.push(format!(
            "different artifact kinds ({} vs {})",
            a_info.kind, b_info.kind
        ));
        Verdict::Changed
    } else {
        Verdict::Changed
    };

    let mut f = Finding::new(
        "compare.summary",
        format!(
            "{} vs {}: verdict={:?}, {} structural field(s) differ",
            a_info.name, b_info.name, verdict, changed_field_count
        ),
        Severity::Note,
        Confidence::Derived,
    );
    f.evidence.push(crate::core::evidence::Evidence::derived(
        "compare.verdict",
        format!("{verdict:?}"),
        crate::core::evidence::Location::entity("compare", "verdict"),
    ));

    CompareResult {
        verdict,
        a: a_info,
        b: b_info,
        changes,
        changed_field_count,
        explanations,
        findings: vec![f],
    }
}

/// Compare two artifacts on disk by running both through analysis.
pub fn compare_paths(
    p1: &std::path::Path,
    p2: &std::path::Path,
    settings: &Settings,
) -> Result<CompareResult> {
    let a = crate::analysis::analyze_path(p1, settings)?;
    let b = crate::analysis::analyze_path(p2, settings)?;
    Ok(compare_reports(&a, &b))
}

/// Compare the current state of a path against its last recorded snapshot.
pub fn compare_against_history(
    path: &std::path::Path,
    case_dir: &std::path::Path,
    settings: &Settings,
) -> Result<CompareResult> {
    let case = crate::core::casefile::open_or_create(case_dir, "history comparison")?;
    let current = crate::analysis::analyze_path(path, settings)?;
    let snapshot = case
        .latest_snapshot(&current.artifact.path)
        .cloned()
        .ok_or_else(|| crate::core::error::Error::not_found(format!(
            "no recorded snapshot for {}; use `ret record` first",
            path.display()
        )))?;

    let mut f = Finding::new(
        "compare.history",
        format!(
            "history: {} was {} on {} ({} → {})",
            current.artifact.name,
            if snapshot.sha256 == current.artifact.sha256 {
                "unchanged"
            } else if snapshot.structural_digest.is_some()
                && snapshot.structural_digest.as_deref() == Some(current.structural_digest().as_str())
            {
                "structurally unchanged"
            } else {
                "changed"
            },
            snapshot.timestamp.format("%Y-%m-%d %H:%M:%S %Z"),
            &snapshot.sha256[..8.min(snapshot.sha256.len())],
            &current.artifact.sha256[..8.min(current.artifact.sha256.len())],
        ),
        if snapshot.sha256 == current.artifact.sha256 {
            Severity::Info
        } else {
            Severity::Note
        },
        Confidence::Derived,
    );
    f.evidence.push(crate::core::evidence::Evidence::derived(
        "history.sha256.before",
        snapshot.sha256.clone(),
        crate::core::evidence::Location::entity("history", "before"),
    ));
    f.evidence.push(crate::core::evidence::Evidence::derived(
        "history.sha256.after",
        current.artifact.sha256.clone(),
        crate::core::evidence::Location::entity("history", "after"),
    ));

    // Build a pseudo "before" report from the snapshot so we can diff facts.
    let before = AnalysisReport {
        artifact: crate::core::evidence::ArtifactIdentity {
            name: snapshot.name.clone(),
            path: snapshot.path.clone(),
            size: snapshot.size,
            sha256: snapshot.sha256.clone(),
            kind: snapshot.kind.clone().unwrap_or_default(),
            label: "historical snapshot".into(),
            container: None,
        },
        findings: Vec::new(),
        facts: serde_json::Map::new(),
        detail: None,
        produced_at: snapshot.timestamp,
        summary: serde_json::Map::new(),
    };
    let mut result = compare_reports(&before, &current);
    // Snapshots store a hash + structural digest, not full facts, so when the
    // bytes are identical there is no meaningful field diff to show: suppress
    // the misleading "added" flood that a fact-less before-report would produce.
    if snapshot.sha256 == current.artifact.sha256 {
        result.changes.clear();
        result.changed_field_count = 0;
    }
    result.findings.insert(0, f);
    Ok(result)
}
