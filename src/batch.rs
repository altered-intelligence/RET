//! Batch / directory scans: analyze many artifacts at once, in parallel, and
//! roll the results into a case file with a readable summary.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use rayon::prelude::*;
use serde::{Deserialize, Serialize};

use crate::analysis::Settings;
use crate::core::error::Result;
use crate::core::evidence::AnalysisReport;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ItemSummary {
    pub path: String,
    pub kind: String,
    pub size: u64,
    pub sha256: String,
    pub findings: usize,
    pub structural_digest: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchResult {
    pub scanned: usize,
    pub analyzed: usize,
    pub failed: usize,
    pub by_kind: BTreeMap<String, usize>,
    pub findings_by_kind: BTreeMap<String, usize>,
    pub items: Vec<ItemSummary>,
    pub errors: Vec<(String, String)>,
    pub duration_ms: u64,
}

pub struct BatchOptions {
    pub root: PathBuf,
    pub depth: usize,
    pub max_items: usize,
    pub workers: usize,
    pub skip_hidden: bool,
    pub settings: Settings,
}

impl Default for BatchOptions {
    fn default() -> Self {
        BatchOptions {
            root: PathBuf::from("."),
            depth: 4,
            max_items: 2000,
            workers: 8,
            skip_hidden: true,
            settings: Settings::default(),
        }
    }
}

/// Discover candidate files under the root without analyzing them.
pub fn discover(root: &Path, depth: usize, max_items: usize, skip_hidden: bool) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut walk = walkdir::WalkDir::new(root)
        .max_depth(depth)
        .follow_links(false)
        .into_iter();
    while let Some(Ok(e)) = walk.next() {
        if out.len() >= max_items {
            break;
        }
        let p = e.path();
        if p.is_dir() {
            if skip_hidden && e.depth() == 1 {
                let name = p.file_name().map(|s| s.to_string_lossy().into_owned()).unwrap_or_default();
                if name.starts_with('.') {
                    walk.skip_current_dir();
                    continue;
                }
            }
            continue;
        }
        if skip_hidden {
            if let Some(name) = p.file_name().and_then(|s| s.to_str()) {
                if name.starts_with('.') {
                    continue;
                }
            }
        }
        out.push(p.to_path_buf());
    }
    out
}

pub fn run(opts: &BatchOptions) -> BatchResult {
    let started = std::time::Instant::now();
    let candidates = discover(&opts.root, opts.depth, opts.max_items, opts.skip_hidden);
    let scanned = candidates.len();

    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(opts.workers.max(1))
        .build()
        .unwrap_or_else(|_| rayon::ThreadPoolBuilder::new().build().unwrap());

    let (items, errors) = pool.install(|| {
        let results: Vec<(Option<AnalysisReport>, String, Option<String>)> = candidates
            .par_iter()
            .map(|p| {
                match crate::analysis::analyze_path(p, &opts.settings) {
                    Ok(report) => (Some(report), p.display().to_string(), None),
                    Err(e) => (None, p.display().to_string(), Some(e.to_string())),
                }
            })
            .collect();
        let mut errors = Vec::new();
        let mut items = Vec::new();
        for (report, path, err) in results {
            if let Some(err) = err {
                errors.push((path, err));
            } else if let Some(r) = report {
                items.push(ItemSummary {
                    path: r.artifact.path.clone(),
                    kind: r.artifact.kind.clone(),
                    size: r.artifact.size,
                    sha256: r.artifact.sha256.clone(),
                    findings: r.findings.len(),
                    structural_digest: r.structural_digest(),
                });
            }
        }
        (items, errors)
    });

    let mut by_kind = BTreeMap::new();
    let mut findings_by_kind = BTreeMap::new();
    for it in &items {
        *by_kind.entry(it.kind.clone()).or_insert(0usize) += 1;
        *findings_by_kind.entry(it.kind.clone()).or_insert(0usize) += it.findings;
    }

    BatchResult {
        scanned,
        analyzed: items.len(),
        failed: errors.len(),
        by_kind,
        findings_by_kind,
        items,
        errors,
        duration_ms: started.elapsed().as_millis() as u64,
    }
}

/// Run a batch and append every report into a case file directory.
pub fn run_and_record(opts: &BatchOptions, case_dir: &Path, description: &str) -> Result<BatchResult> {
    let result = run(opts);
    let mut case = crate::core::casefile::open_or_create(case_dir, description)?;
    let run = case.snapshots.len() as u64 + 1;
    for item in &result.items {
        // Re-run single analysis for case write (kept simple; item guardrails
        // already bounded discovery, so this stays bounded too).
        if let Ok(report) = crate::analysis::analyze_path(Path::new(&item.path), &opts.settings) {
            case.add_report(&report, run);
        }
    }
    crate::core::casefile::save(&case, case_dir)?;
    Ok(result)
}

pub fn human_summary(res: &BatchResult) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "scanned {} files, analyzed {}, failed {}\n",
        res.scanned, res.analyzed, res.failed
    ));
    for (kind, n) in &res.by_kind {
        let findings = res.findings_by_kind.get(kind).copied().unwrap_or(0);
        out.push_str(&format!("  {kind:<14} {n:>5} artifacts, {findings} findings\n"));
    }
    out.push_str(&format!("completed in {} ms\n", res.duration_ms));
    out
}
