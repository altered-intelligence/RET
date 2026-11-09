//! Shannon-entropy profiling with byte-addressable evidence.
//!
//! RET's contract is that every claim points at the bytes that support it.
//! Entropy findings therefore report the exact window ranges each value was
//! computed over, and every heuristic verdict (packed / encrypted-looking
//! content) is marked `inferred` with its limitation stated in the finding.

use std::path::Path;

use crate::analysis::{identity_for, Settings};
use crate::core::evidence::{AnalysisReport, Confidence, Evidence, Finding, Location, Severity};
use crate::core::error::{Error, Result};

/// Shannon entropy of a byte slice, in bits per byte (0.0 ..= 8.0).
pub fn shannon(bytes: &[u8]) -> f64 {
    if bytes.is_empty() {
        return 0.0;
    }
    let mut counts = [0u64; 256];
    for &b in bytes {
        counts[b as usize] += 1;
    }
    let n = bytes.len() as f64;
    let mut h = 0.0f64;
    for &c in &counts {
        if c == 0 {
            continue;
        }
        let p = c as f64 / n;
        h -= p * p.log2();
    }
    h
}

/// Entropy of one non-overlapping window.
#[derive(Debug, Clone, serde::Serialize)]
pub struct WindowEntropy {
    pub offset: u64,
    pub len: usize,
    pub entropy: f64,
}

/// Non-overlapping entropy windows across `bytes`.
pub fn window_map(bytes: &[u8], window: usize) -> Vec<WindowEntropy> {
    let window = window.max(64);
    let mut out = Vec::new();
    let mut off = 0usize;
    while off < bytes.len() {
        let end = (off + window).min(bytes.len());
        out.push(WindowEntropy {
            offset: off as u64,
            len: end - off,
            entropy: shannon(&bytes[off..end]),
        });
        off = end;
    }
    out
}

/// One contiguous high-entropy region (adjacent windows merged).
#[derive(Debug, Clone, serde::Serialize)]
pub struct HighRegion {
    pub start: u64,
    pub end: u64,
    pub max_entropy: f64,
}

/// Merge adjacent windows at or above `threshold` into contiguous regions.
pub fn high_regions(map: &[WindowEntropy], threshold: f64) -> Vec<HighRegion> {
    let mut out: Vec<HighRegion> = Vec::new();
    for w in map {
        if w.entropy < threshold {
            continue;
        }
        match out.last_mut() {
            Some(r) if r.end == w.offset => {
                r.end = w.offset + w.len as u64;
                if w.entropy > r.max_entropy {
                    r.max_entropy = w.entropy;
                }
            }
            _ => out.push(HighRegion {
                start: w.offset,
                end: w.offset + w.len as u64,
                max_entropy: w.entropy,
            }),
        }
    }
    out
}

/// Analyze one file and produce an entropy profile as an evidence-shaped report.
pub fn analyze(path: &Path, settings: &Settings, window: usize, threshold: f64) -> Result<AnalysisReport> {
    if path.is_dir() {
        return Err(Error::invalid_arg(
            "entropy analysis requires a single file (directories are not supported)",
        ));
    }
    let bytes = crate::analysis::read_bounded(path, settings.head_limit)?;
    let file_len = std::fs::metadata(path).map(|m| m.len()).unwrap_or(bytes.len() as u64);
    let truncated = (bytes.len() as u64) < file_len;

    let overall = shannon(&bytes);
    let map = window_map(&bytes, window);
    let regions = high_regions(&map, threshold);

    let identity = identity_for(path, "entropy_profile", "entropy profile", &bytes)?;
    let mut findings = Vec::new();

    let mut f = Finding::new(
        "entropy.overall",
        format!("overall Shannon entropy {overall:.3} bits/byte over {} bytes", bytes.len()),
        Severity::Info,
        Confidence::Direct,
    );
    f.evidence.push(Evidence::derived(
        "entropy.overall",
        format!("{overall:.3}"),
        Location::bytes(0, Some(bytes.len() as u64)),
    ));
    f.evidence.push(Evidence::derived(
        "entropy.window_bytes",
        window.to_string(),
        Location::route("settings"),
    ));
    if truncated {
        f.limitations
            .push(format!("only the first {} bytes were analyzed (head limit)", bytes.len()));
    }
    findings.push(f);

    if !regions.is_empty() {
        let mut f = Finding::new(
            "entropy.high_regions",
            format!(
                "{} high-entropy region(s) at or above {threshold:.2} bits/byte (window {window} bytes)",
                regions.len()
            ),
            Severity::Note,
            Confidence::Inferred,
        );
        for r in regions.iter().take(32) {
            let peak = format!("{:.3}", r.max_entropy);
            f.evidence.push(Evidence::derived(
                "entropy.high_region",
                format!("0x{:x}..0x{:x} peak {peak} bits/byte", r.start, r.end),
                Location::bytes(r.start, Some(r.end)),
            ));
        }
        if regions.len() > 32 {
            f.limitations
                .push(format!("{} additional regions not listed", regions.len() - 32));
        }
        f.limitations
            .push("high entropy suggests compressed, encrypted, or packed content; compressed resources, archives, and Authenticode signature blocks are also legitimately high-entropy".into());
        findings.push(f);
    }

    let mut report = AnalysisReport::new(identity, findings);
    report
        .facts
        .insert("entropy.overall".into(), serde_json::json!((overall * 1000.0).round() / 1000.0));
    report.facts.insert("entropy.window".into(), serde_json::json!(window));
    report
        .facts
        .insert("entropy.threshold".into(), serde_json::json!((threshold * 100.0).round() / 100.0));
    report.facts.insert("entropy.high_region_count".into(), serde_json::json!(regions.len()));
    if !regions.is_empty() {
        let tops: Vec<serde_json::Value> = regions
            .iter()
            .take(16)
            .map(|r| {
                serde_json::json!({
                    "start": r.start,
                    "end": r.end,
                    "peak_entropy": (r.max_entropy * 1000.0).round() / 1000.0,
                })
            })
            .collect();
        report.facts.insert("entropy.regions".into(), serde_json::json!(tops));
    }
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constant_bytes_have_zero_entropy() {
        assert_eq!(shannon(&[0x41u8; 1000]), 0.0);
        assert_eq!(shannon(&[]), 0.0);
    }

    #[test]
    fn uniform_distribution_reaches_eight_bits() {
        let mut buf = Vec::new();
        for i in 0..256u32 {
            buf.push(i as u8);
        }
        assert!((shannon(&buf) - 8.0).abs() < 1e-9);
    }

    #[test]
    fn half_half_split_is_one_bit() {
        let mut buf = vec![0x00u8; 512];
        buf.extend(std::iter::repeat(0xff).take(512));
        assert!((shannon(&buf) - 1.0).abs() < 1e-9);
    }

    #[test]
    fn windows_cover_the_file_exactly() {
        let bytes: Vec<u8> = (0..10_000u32).map(|i| (i % 251) as u8).collect();
        let map = window_map(&bytes, 4096);
        assert_eq!(map.first().unwrap().offset, 0);
        assert_eq!(map.last().unwrap().offset + map.last().unwrap().len as u64, bytes.len() as u64);
        assert_eq!(map.iter().map(|w| w.len as u64).sum::<u64>(), bytes.len() as u64);
    }

    #[test]
    fn adjacent_high_windows_merge_into_one_region() {
        let mut bytes = vec![0x00u8; 4096]; // zero entropy
        let high: Vec<u8> = (0..8192u32).map(|i| (i * 7 % 251) as u8).collect(); // ~high entropy
        bytes.extend(high.clone());
        bytes.extend(vec![0x00u8; 4096]);
        let map = window_map(&bytes, 4096);
        let regions = high_regions(&map, 7.0);
        assert_eq!(regions.len(), 1, "expected one merged region, got {regions:?}");
        assert_eq!(regions[0].start, 4096);
        assert_eq!(regions[0].end, 12_288);
    }

    #[test]
    fn analysis_report_shape() {
        let dir = std::env::temp_dir().join("ret-entropy-test");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("blob.bin");
        let high: Vec<u8> = (0..16_384u32).map(|i| (i * 13 % 251) as u8).collect();
        std::fs::write(&path, &high).unwrap();
        let settings = Settings::default();
        let ctx_report = analyze(&path, &settings, 4096, 7.0).unwrap();
        assert_eq!(ctx_report.artifact.kind, "entropy_profile");
        assert!(ctx_report
            .findings
            .iter()
            .any(|f| f.id == "entropy.high_regions"));
        assert!(ctx_report.facts.contains_key("entropy.overall"));
        std::fs::remove_dir_all(&dir).ok();
    }
}
