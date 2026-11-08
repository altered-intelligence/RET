//! Native binary analysis: format parsers plus cross-format helpers for
//! string extraction, hardening fingerprints, and managed-runtime markers
//! (Go / Rust) that are independent of the container format.

pub mod elf;
pub mod macho;
pub mod pe;

use crate::core::evidence::{Confidence, Finding, Severity};

/// One printable string found at a byte offset.
#[derive(Debug, Clone)]
pub struct StringHit {
    pub offset: u64,
    pub text: String,
}

/// Extract printable strings (ASCII and UTF-8 readable), 8-bit clean.
pub fn scan_strings(bytes: &[u8], min_len: usize) -> Vec<StringHit> {
    let mut out = Vec::new();
    let mut start = None;
    let mut buf: Vec<u8> = Vec::new();
    let flush = |start: &mut Option<usize>, buf: &mut Vec<u8>, out: &mut Vec<StringHit>| {
        if let Some(s) = start.take() {
            if buf.len() >= min_len {
                out.push(StringHit {
                    offset: s as u64,
                    text: String::from_utf8_lossy(buf).into_owned(),
                });
            }
            buf.clear();
        }
    };
    for (i, &b) in bytes.iter().enumerate() {
        if (0x20..=0x7E).contains(&b) || b >= 0x80 {
            if start.is_none() {
                start = Some(i);
            }
            buf.push(b);
        } else {
            flush(&mut start, &mut buf, &mut out);
        }
    }
    flush(&mut start, &mut buf, &mut out);
    out
}

/// Find a plausible embedded Go toolchain version such as `go1.22.4`.
pub fn find_go_version(bytes: &[u8]) -> Option<String> {
    let mut i = 0;
    while i + 5 < bytes.len() {
        if &bytes[i..i + 3] == b"go1" && bytes[i + 3] == b'.' {
            let mut j = i + 4;
            while j < bytes.len() && (bytes[j].is_ascii_digit() || bytes[j] == b'.') {
                j += 1;
            }
            let ver = String::from_utf8_lossy(&bytes[i..j]).into_owned();
            if ver.contains('.') && ver.split('.').count() <= 3 {
                return Some(ver);
            }
        }
        i += 1;
    }
    None
}

/// Look for the `Go build ID:` marker emitted by `-B=default` binaries.
pub fn find_go_buildid(bytes: &[u8]) -> Option<String> {
    const MARKER: &[u8] = b"Go build ID:";
    let pos = find_subslice(bytes, MARKER)?;
    let rest = &bytes[pos + MARKER.len()..];
    let rest = rest.splitn(2, |&b| b == 0).next().unwrap_or(rest);
    let s = String::from_utf8_lossy(rest).into_owned();
    let trimmed = s.trim_matches(|c: char| !c.is_ascii_alphanumeric()).to_string();
    if trimmed.len() >= 8 {
        Some(trimmed)
    } else {
        None
    }
}

/// Heuristics that a binary was produced by the Rust toolchain.
pub fn rust_markers(bytes: &[u8]) -> Vec<String> {
    const MARKERS: [&[u8]; 5] = [
        b"rust_begin_unwind",
        b"__rust_alloc",
        b"rust_eh_personality",
        b"panicked at",
        b"core::panicking::",
    ];
    MARKERS
        .iter()
        .filter(|m| find_subslice(bytes, m).is_some())
        .map(|m| String::from_utf8_lossy(m).into_owned())
        .collect()
}

pub fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack
        .windows(needle.len())
        .position(|w| w == needle)
}

/// Emit managed-runtime marker findings (Go / Rust) with evidence, if present.
/// `container_kind` is one of "elf" | "pe" | "macho"; `is_dotnet` handled by the PE analyzer.
pub fn managed_runtime_findings(
    bytes: &[u8],
    container_kind: &str,
    budget: &mut Vec<Finding>,
) {
    if let Some(ver) = find_go_version(bytes) {
        let mut f = Finding::new(
            format!("{container_kind}.runtime.go_version"),
            format!("binary embeds Go toolchain version {ver}"),
            Severity::Info,
            Confidence::Inferred,
        );
        f.limitations
            .push("version string located heuristically; a stripped binary may omit it".into());
        budget.push(f);
    }
    if let Some(bid) = find_go_buildid(bytes) {
        let mut f = Finding::new(
            format!("{container_kind}.runtime.go_buildid"),
            format!("Go build ID recorded from build cache: {bid}"),
            Severity::Note,
            Confidence::Direct,
        );
        f.limitations
            .push("present only when the binary was linked with default build ID settings".into());
        budget.push(f);
    }
    let rust = rust_markers(bytes);
    if !rust.is_empty() {
        let mut f = Finding::new(
            format!("{container_kind}.runtime.rust"),
            format!(
                "binary exhibits Rust runtime markers: {}",
                rust.join(", ")
            ),
            Severity::Info,
            Confidence::Inferred,
        );
        f.limitations.push(
            "markers indicate the Rust runtime is linked; they do not prove the app is written in Rust".into(),
        );
        budget.push(f);
    }
}

/// Collect the string inventory finding used by every binary analyzer.
pub fn string_inventory_finding(
    strings: &[StringHit],
    max_strings: usize,
    max_len: usize,
    settings_min: usize,
    settings_max_total: usize,
) -> Finding {
    let total = strings.len();
    let mut f = Finding::new(
        "strings.inventory",
        format!("extracted {total} printable strings"),
        Severity::Info,
        Confidence::Direct,
    );
    let mut samples = strings
        .iter()
        .take(settings_max_total)
        .cloned()
        .collect::<Vec<_>>();
    samples.sort_by(|a, b| b.text.len().cmp(&a.text.len()));
    for s in samples.iter().take(max_strings.min(samples.len())) {
        let mut t = s.text.clone();
        if t.len() > max_len {
            t.truncate(max_len);
            t.push('…');
        }
        f.evidence.push(crate::core::evidence::Evidence::new(
            "strings.sample",
            format!("@0x{:x} {}", s.offset, t),
            crate::core::evidence::Location::bytes(s.offset, None),
        ));
    }
    f.limitations.push(format!(
        "strings shorter than {} bytes are omitted; list capped at {settings_max_total} candidates",
        settings_min
    ));
    f
}
