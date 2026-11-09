//! Indicator-of-compromise (IOC) extraction with byte-addressable evidence.
//!
//! Hand-written detectors over ASCII/UTF-8 printable runs plus a UTF-16LE
//! pass (where Windows malware stores most of its strings). No regex engine:
//! every detector is a bounded scanner over the artifact bytes, and every
//! extracted indicator carries the byte offset it was found at.
//!
//! Confidence mapping follows RET's evidence model: literal byte patterns
//! (URLs, e-mails, hashes, registry keys, paths) are `direct` observations;
//! classification that depends on heuristics (domain-looking labels, IPv4
//! literals that may be version strings) is `inferred` and says so.

use std::collections::HashMap;
use std::path::Path;

use crate::analysis::{identity_for, Settings};
use crate::core::evidence::{AnalysisReport, Confidence, Evidence, Finding, Location, Severity};
use crate::core::error::{Error, Result};

/// Cap per indicator kind to keep reports bounded.
pub const MAX_PER_KIND: usize = 200;
/// Cap on total indicators in a report.
pub const MAX_TOTAL: usize = 1000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IocKind {
    Url,
    IpV4,
    Domain,
    Email,
    Md5,
    Sha1,
    Sha256,
    RegistryPath,
    FileSystemPath,
}

impl IocKind {
    pub fn label(self) -> &'static str {
        match self {
            IocKind::Url => "url",
            IocKind::IpV4 => "ipv4",
            IocKind::Domain => "domain",
            IocKind::Email => "email",
            IocKind::Md5 => "md5",
            IocKind::Sha1 => "sha1",
            IocKind::Sha256 => "sha256",
            IocKind::RegistryPath => "registry_path",
            IocKind::FileSystemPath => "file_path",
        }
    }
}

/// One extracted indicator with the byte range that proves it.
#[derive(Debug, Clone, serde::Serialize)]
pub struct Ioc {
    pub kind: IocKind,
    pub value: String,
    /// Byte offset of the first byte of the indicator in the artifact.
    pub offset: u64,
    /// Length in bytes of the raw match.
    pub len: usize,
    /// Character encoding of the containing run: "ascii" or "utf16le".
    pub encoding: &'static str,
}

/// A printable run in the artifact: either an ASCII/UTF-8 run or a decoded
/// UTF-16LE run. Detectors run over these.
struct Run {
    offset: u64,
    text: String,
    encoding: &'static str,
}

/// Collect printable ASCII/UTF-8 runs (offset of run start, text).
fn ascii_runs(bytes: &[u8], min_len: usize) -> Vec<Run> {
    let mut out = Vec::new();
    let mut start: Option<usize> = None;
    for (i, &b) in bytes.iter().enumerate() {
        let printable = (0x20..=0x7E).contains(&b) || b >= 0x80;
        if printable {
            if start.is_none() {
                start = Some(i);
            }
        } else if let Some(s) = start.take() {
            if i - s >= min_len {
                out.push(Run {
                    offset: s as u64,
                    text: String::from_utf8_lossy(&bytes[s..i]).into_owned(),
                    encoding: "ascii",
                });
            }
        }
    }
    if let Some(s) = start {
        if bytes.len() - s >= min_len {
            out.push(Run {
                offset: s as u64,
                text: String::from_utf8_lossy(&bytes[s..]).into_owned(),
                encoding: "ascii",
            });
        }
    }
    out
}

/// Collect UTF-16LE runs: sequences of (printable-ASCII, 0x00) pairs.
fn utf16le_runs(bytes: &[u8], min_chars: usize) -> Vec<Run> {
    let mut out = Vec::new();
    let mut i = 0usize;
    while i + 1 < bytes.len() {
        // Look for a run of pairs (lo printable ASCII, hi 0x00). The lookahead
        // on the next pair keeps pure-ASCII text from being misread.
        if bytes[i + 1] == 0
            && (0x20..=0x7E).contains(&bytes[i])
            && (i + 3 >= bytes.len() || bytes[i + 3] == 0)
        {
            let start = i;
            let mut chars: Vec<u8> = Vec::new();
            let mut j = i;
            while j + 1 < bytes.len() && bytes[j + 1] == 0 && (0x20..=0x7E).contains(&bytes[j]) {
                chars.push(bytes[j]);
                j += 2;
            }
            if chars.len() >= min_chars {
                out.push(Run {
                    offset: start as u64,
                    text: String::from_utf8_lossy(&chars).into_owned(),
                    encoding: "utf16le",
                });
            }
            i = j.max(i + 2);
        } else {
            i += 1;
        }
    }
    out
}

fn is_delim(b: u8) -> bool {
    b <= 0x20
        || matches!(
            b,
            b'"' | b'\'' | b'<' | b'>' | b')' | b'(' | b'[' | b']' | b'{' | b'}' | b'|' | b'`'
        )
}

/// Dedupe-and-cap one indicator into the result list.
fn push_ioc(ioc: Ioc, out: &mut Vec<Ioc>, seen: &mut HashMap<(IocKind, String), ()>) {
    let key = (ioc.kind, ioc.value.clone());
    if seen.contains_key(&key) {
        return;
    }
    if out.len() >= MAX_TOTAL {
        return;
    }
    let per_kind = out.iter().filter(|x| x.kind == ioc.kind).count();
    if per_kind >= MAX_PER_KIND {
        return;
    }
    seen.insert(key, ());
    out.push(ioc);
}

/// Extract indicators from raw artifact bytes.
pub fn extract(bytes: &[u8]) -> Vec<Ioc> {
    let mut out: Vec<Ioc> = Vec::new();
    let mut seen: HashMap<(IocKind, String), ()> = HashMap::new();

    let runs = ascii_runs(bytes, 3)
        .into_iter()
        .chain(utf16le_runs(bytes, 3))
        .collect::<Vec<Run>>();

    for run in &runs {
        let text = run.text.as_bytes();
        // Map a raw-run position back to an artifact byte offset.
        let base = |raw_pos: usize| -> u64 {
            if run.encoding == "utf16le" {
                run.offset + (raw_pos as u64) * 2
            } else {
                run.offset + raw_pos as u64
            }
        };
        // Length in artifact bytes of a raw-run span [a, b).
        let raw_len = |a: usize, b: usize| -> usize {
            if run.encoding == "utf16le" {
                (b - a) * 2
            } else {
                b - a
            }
        };

        extract_urls(run, text, &base, &raw_len, &mut out, &mut seen);
        extract_registry(run, text, &base, &raw_len, &mut out, &mut seen);
        extract_paths(run, text, &base, &raw_len, &mut out, &mut seen);
        extract_emails(run, text, &base, &raw_len, &mut out, &mut seen);
        extract_ipv4(run, text, &base, &raw_len, &mut out, &mut seen);
        extract_hashes(run, text, &base, &raw_len, &mut out, &mut seen);
        extract_domains(run, text, &base, &raw_len, &mut out, &mut seen);
    }
    out.sort_by(|a, b| a.offset.cmp(&b.offset).then_with(|| a.kind.label().cmp(b.kind.label())));
    out
}

fn extract_urls(
    run: &Run,
    text: &[u8],
    base: &impl Fn(usize) -> u64,
    raw_len: &impl Fn(usize, usize) -> usize,
    out: &mut Vec<Ioc>,
    seen: &mut HashMap<(IocKind, String), ()>,
) {
    const SCHEMES: [&[u8]; 3] = [b"https://", b"http://", b"ftp://"];
    let lower: Vec<u8> = text.to_ascii_lowercase();
    for scheme in SCHEMES {
        let mut from = 0usize;
        while let Some(rel) = find_subslice(&lower[from..], scheme) {
            let start = from + rel;
            let mut end = start + scheme.len();
            while end < text.len() && !is_delim(text[end]) {
                end += 1;
            }
            // Trim trailing punctuation that usually belongs to prose.
            while end > start + scheme.len()
                && matches!(text[end - 1], b'.' | b',' | b';' | b'!' | b'?')
            {
                end -= 1;
            }
            let raw = &text[start..end];
            let value = String::from_utf8_lossy(raw).into_owned();
            if value.len() <= 2048 && host_has_dot_or_localhost(&value[scheme.len()..]) {
                push_ioc(
                    Ioc {
                        kind: IocKind::Url,
                        value,
                        offset: base(start),
                        len: raw_len(start, end),
                        encoding: run.encoding,
                    },
                    out,
                    seen,
                );
            }
            from = end.max(start + scheme.len());
            if from >= text.len() {
                break;
            }
        }
    }
}

fn host_has_dot_or_localhost(host_and_rest: &str) -> bool {
    let host = host_and_rest
        .split(['/', ':', '?', '#'])
        .next()
        .unwrap_or("");
    !host.is_empty() && (host.contains('.') || host.eq_ignore_ascii_case("localhost"))
}

const REGISTRY_PREFIXES: [&[u8]; 6] = [
    b"HKEY_LOCAL_MACHINE",
    b"HKEY_CURRENT_USER",
    b"HKEY_CLASSES_ROOT",
    b"HKLM",
    b"HKCU",
    b"HKCR",
];

fn extract_registry(
    run: &Run,
    text: &[u8],
    base: &impl Fn(usize) -> u64,
    raw_len: &impl Fn(usize, usize) -> usize,
    out: &mut Vec<Ioc>,
    seen: &mut HashMap<(IocKind, String), ()>,
) {
    let upper: Vec<u8> = text.to_ascii_uppercase();
    for prefix in REGISTRY_PREFIXES {
        let mut from = 0usize;
        while let Some(rel) = find_subslice(&upper[from..], prefix) {
            let start = from + rel;
            // Require a separator after the hive: `\`.
            let sep = start + prefix.len();
            if sep >= text.len() || text[sep] != b'\\' {
                from = start + prefix.len();
                if from >= text.len() {
                    break;
                }
                continue;
            }
            let mut end = sep + 1;
            while end < text.len() && !is_delim(text[end]) {
                end += 1;
            }
            let value = String::from_utf8_lossy(&text[start..end]).into_owned();
            if value.len() >= 8 && value.len() <= 1024 {
                push_ioc(
                    Ioc {
                        kind: IocKind::RegistryPath,
                        value,
                        offset: base(start),
                        len: raw_len(start, end),
                        encoding: run.encoding,
                    },
                    out,
                    seen,
                );
            }
            from = end.max(start + prefix.len());
            if from >= text.len() {
                break;
            }
        }
    }
}

const UNIX_PATH_PREFIXES: [&[u8]; 10] = [
    b"/usr/", b"/etc/", b"/tmp/", b"/var/", b"/opt/", b"/home/", b"/root/",
    b"/Users/", b"/Applications/", b"/Library/",
];

fn extract_paths(
    run: &Run,
    text: &[u8],
    base: &impl Fn(usize) -> u64,
    raw_len: &impl Fn(usize, usize) -> usize,
    out: &mut Vec<Ioc>,
    seen: &mut HashMap<(IocKind, String), ()>,
) {
    let lower: Vec<u8> = text.to_ascii_lowercase();
    let mut hits: Vec<(usize, usize)> = Vec::new();
    for prefix in UNIX_PATH_PREFIXES {
        let mut from = 0usize;
        while let Some(rel) = find_subslice(&lower[from..], prefix) {
            let start = from + rel;
            let mut end = start + prefix.len();
            while end < text.len() && !is_delim(text[end]) {
                end += 1;
            }
            while end > start && matches!(text[end - 1], b'.' | b',' | b';') {
                end -= 1;
            }
            if end - start >= 5 {
                hits.push((start, end));
            }
            from = end.max(start + prefix.len());
            if from >= text.len() {
                break;
            }
        }
    }
    // Windows drive paths: letter ':' '\' ...
    if text.len() >= 3 {
        for i in 0..=text.len() - 3 {
            if text[i].is_ascii_alphabetic()
                && text[i + 1] == b':'
                && (text[i + 2] == b'\\' || text[i + 2] == b'/')
            {
                let start = i;
                let mut end = i + 3;
                while end < text.len() && !is_delim(text[end]) {
                    end += 1;
                }
                if end - start >= 6 {
                    hits.push((start, end));
                }
            }
        }
    }
    hits.sort_unstable();
    hits.dedup();
    for (start, end) in hits.into_iter().take(MAX_PER_KIND) {
        let value = String::from_utf8_lossy(&text[start..end]).into_owned();
        push_ioc(
            Ioc {
                kind: IocKind::FileSystemPath,
                value,
                offset: base(start),
                len: raw_len(start, end),
                encoding: run.encoding,
            },
            out,
            seen,
        );
    }
}

fn extract_emails(
    run: &Run,
    text: &[u8],
    base: &impl Fn(usize) -> u64,
    raw_len: &impl Fn(usize, usize) -> usize,
    out: &mut Vec<Ioc>,
    seen: &mut HashMap<(IocKind, String), ()>,
) {
    let mut i = 0usize;
    while i < text.len() {
        if text[i] != b'@' {
            i += 1;
            continue;
        }
        // Expand left to the start of the local part.
        let mut ls = i;
        while ls > 0 && is_email_word(text[ls - 1]) {
            ls -= 1;
        }
        // Expand right across the domain, then trim a trailing dot.
        let mut re = i + 1;
        while re < text.len() && (is_email_word(text[re]) || text[re] == b'.') {
            re += 1;
        }
        while re > i + 1 && text[re - 1] == b'.' {
            re -= 1;
        }
        if i > ls && re > i + 1 {
            let local = &text[ls..i];
            let domain = &text[i + 1..re];
            if valid_local(local) && valid_domain_labels(domain) {
                let value = String::from_utf8_lossy(&text[ls..re]).into_owned();
                push_ioc(
                    Ioc {
                        kind: IocKind::Email,
                        value,
                        offset: base(ls),
                        len: raw_len(ls, re),
                        encoding: run.encoding,
                    },
                    out,
                    seen,
                );
            }
        }
        i = re.max(i + 1);
    }
}

fn is_email_word(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'+' | b'.')
}

fn valid_local(local: &[u8]) -> bool {
    !local.is_empty()
        && local.len() <= 64
        && local[0].is_ascii_alphanumeric()
        && local[local.len() - 1].is_ascii_alphanumeric()
}

fn valid_domain_labels(domain: &[u8]) -> bool {
    let s = String::from_utf8_lossy(domain);
    let mut count = 0;
    for label in s.split('.') {
        count += 1;
        if label.is_empty() || label.len() > 63 {
            return false;
        }
        if !label.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-') {
            return false;
        }
        if label.starts_with('-') || label.ends_with('-') {
            return false;
        }
    }
    // Require a plausible alphabetic TLD on the last label.
    let tld = s.rsplit('.').next().unwrap_or("");
    (2..=24).contains(&tld.len())
        && tld.bytes().all(|b| b.is_ascii_alphabetic())
        && count >= 2
}

fn extract_ipv4(
    run: &Run,
    text: &[u8],
    base: &impl Fn(usize) -> u64,
    raw_len: &impl Fn(usize, usize) -> usize,
    out: &mut Vec<Ioc>,
    seen: &mut HashMap<(IocKind, String), ()>,
) {
    let mut i = 0usize;
    while i < text.len() {
        if !text[i].is_ascii_digit() {
            i += 1;
            continue;
        }
        // Parse up to four dot-separated octets.
        let start = i;
        let mut octets = [0u32; 4];
        let mut got = 0usize;
        let mut j = i;
        while got < 4 && j < text.len() {
            let mut val = 0u32;
            let mut digits = 0;
            while j < text.len() && text[j].is_ascii_digit() && digits < 3 {
                val = val * 10 + (text[j] - b'0') as u32;
                digits += 1;
                j += 1;
            }
            if digits == 0 {
                break;
            }
            octets[got] = val;
            got += 1;
            if got < 4 && j < text.len() && text[j] == b'.' {
                j += 1;
            } else {
                break;
            }
        }
        if got == 4
            && octets.iter().all(|o| *o <= 255)
            && (start == 0 || !matches!(text[start - 1], b'0'..=b'9' | b'.'))
            && (j >= text.len() || !matches!(text[j], b'0'..=b'9' | b'.'))
            && octets.iter().any(|o| *o > 0)
        {
            let value = format!("{}.{}.{}.{}", octets[0], octets[1], octets[2], octets[3]);
            push_ioc(
                Ioc {
                    kind: IocKind::IpV4,
                    value,
                    offset: base(start),
                    len: raw_len(start, j),
                    encoding: run.encoding,
                },
                out,
                seen,
            );
        }
        i = j.max(i + 1);
    }
}

fn is_hex_strict(s: &[u8]) -> bool {
    s.iter()
        .all(|&c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c.to_ascii_lowercase()))
}

fn extract_hashes(
    run: &Run,
    text: &[u8],
    base: &impl Fn(usize) -> u64,
    raw_len: &impl Fn(usize, usize) -> usize,
    out: &mut Vec<Ioc>,
    seen: &mut HashMap<(IocKind, String), ()>,
) {
    const TARGETS: [(usize, IocKind); 3] = [
        (32, IocKind::Md5),
        (40, IocKind::Sha1),
        (64, IocKind::Sha256),
    ];
    let mut i = 0usize;
    while i < text.len() {
        if !text[i].is_ascii_hexdigit() {
            i += 1;
            continue;
        }
        let mut j = i;
        while j < text.len() && text[j].is_ascii_hexdigit() {
            j += 1;
        }
        let run_len = j - i;
        for (want, kind) in TARGETS {
            if run_len == want
                && (i == 0 || !text[i - 1].is_ascii_hexdigit())
                && (j >= text.len() || !text[j].is_ascii_hexdigit())
                && is_hex_strict(&text[i..j])
            {
                let value = String::from_utf8_lossy(&text[i..j]).to_ascii_lowercase();
                push_ioc(
                    Ioc {
                        kind,
                        value,
                        offset: base(i),
                        len: raw_len(i, j),
                        encoding: run.encoding,
                    },
                    out,
                    seen,
                );
            }
        }
        i = j.max(i + 1);
    }
}

const FILE_EXT_BLOCKLIST: [&str; 31] = [
    "exe", "dll", "so", "dylib", "png", "jpg", "gif", "json", "xml", "html",
    "htm", "js", "ts", "py", "rb", "rs", "c", "h", "cpp", "txt", "md", "db",
    "asar", "har", "php", "asp", "aspx", "jsp", "cgi", "bin", "dat",
];

fn extract_domains(
    run: &Run,
    text: &[u8],
    base: &impl Fn(usize) -> u64,
    raw_len: &impl Fn(usize, usize) -> usize,
    out: &mut Vec<Ioc>,
    seen: &mut HashMap<(IocKind, String), ()>,
) {
    let mut i = 0usize;
    while i < text.len() {
        if !is_domain_char(text[i]) {
            i += 1;
            continue;
        }
        let start = i;
        while i < text.len() && (is_domain_char(text[i]) || text[i] == b'.') {
            i += 1;
        }
        let end = i;
        let tok = &text[start..end];
        if tok.len() < 4 || tok.len() > 253 {
            continue;
        }
        let s = String::from_utf8_lossy(tok).to_ascii_lowercase();
        if !s.contains('.') {
            continue;
        }
        let parts: Vec<&str> = s.split('.').collect();
        if parts.len() < 2 {
            continue;
        }
        let last = parts[parts.len() - 1];
        let looks_tld = (2..=24).contains(&last.len())
            && last.bytes().all(|b| b.is_ascii_alphabetic())
            && !FILE_EXT_BLOCKLIST.contains(&last);
        let all_labels_ok = parts.iter().all(|p| {
            !p.is_empty()
                && p.len() <= 63
                && p.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
                && !p.starts_with('-')
                && !p.ends_with('-')
        });
        let numeric = parts.iter().all(|p| p.bytes().all(|b| b.is_ascii_digit()));
        if looks_tld && all_labels_ok && !numeric {
            push_ioc(
                Ioc {
                    kind: IocKind::Domain,
                    value: s,
                    offset: base(start),
                    len: raw_len(start, end),
                    encoding: run.encoding,
                },
                out,
                seen,
            );
        }
    }
}

fn is_domain_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'-' || b == b'_'
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack
        .windows(needle.len())
        .position(|w| w == needle)
}

/// Analyze a file and produce an IOC report in RET's evidence model.
pub fn analyze(path: &Path, settings: &Settings) -> Result<AnalysisReport> {
    if path.is_dir() {
        return Err(Error::invalid_arg(
            "IOC extraction requires a single file (directories are not supported)",
        ));
    }
    let bytes = crate::analysis::read_bounded(path, settings.head_limit)?;
    let file_len = std::fs::metadata(path)
        .map(|m| m.len())
        .unwrap_or(bytes.len() as u64);
    let truncated = (bytes.len() as u64) < file_len;

    let iocs = extract(&bytes);
    let identity = identity_for(path, "ioc_report", "indicator extraction", &bytes)?;

    let mut findings = Vec::new();
    let mut by_kind: Vec<(IocKind, usize)> = Vec::new();
    for kind in [
        IocKind::Url,
        IocKind::IpV4,
        IocKind::Domain,
        IocKind::Email,
        IocKind::Md5,
        IocKind::Sha1,
        IocKind::Sha256,
        IocKind::RegistryPath,
        IocKind::FileSystemPath,
    ] {
        let n = iocs.iter().filter(|i| i.kind == kind).count();
        if n > 0 {
            by_kind.push((kind, n));
        }
    }

    let mut summary = Finding::new(
        "iocs.summary",
        format!(
            "{} indicator(s) extracted across {} kind(s)",
            iocs.len(),
            by_kind.len()
        ),
        Severity::Info,
        Confidence::Derived,
    );
    if truncated {
        summary
            .limitations
            .push(format!("only the first {} bytes were scanned (head limit)", bytes.len()));
    }
    summary.limitations.push(
        "detectors cover ASCII/UTF-8 and UTF-16LE patterns; encoded, defanged (e.g. hxxp, [.]), or encrypted indicators are not extracted"
            .into(),
    );
    summary
        .limitations
        .push("an extracted indicator is evidence that bytes matching its pattern exist at the cited offset, not proof of malicious use"
            .into());
    findings.push(summary);

    for (kind, _) in &by_kind {
        let items: Vec<&Ioc> = iocs.iter().filter(|i| i.kind == *kind).collect();
        let confidence = match kind {
            IocKind::Domain | IocKind::IpV4 => Confidence::Inferred,
            _ => Confidence::Direct,
        };
        let mut f = Finding::new(
            format!("iocs.{}", kind.label()),
            format!("{} {} indicator(s) extracted", items.len(), kind.label()),
            Severity::Note,
            confidence,
        );
        for item in items.iter().take(64) {
            f.evidence.push(Evidence {
                label: format!("ioc.{}", kind.label()),
                value: item.value.clone(),
                location: Location::bytes(item.offset, Some(item.offset + item.len as u64)),
                provenance: confidence,
            });
        }
        if items.len() > 64 {
            f.limitations
                .push(format!("{} additional indicators listed in report detail only", items.len() - 64));
        }
        if matches!(kind, IocKind::IpV4) {
            f.limitations
                .push("IPv4-looking strings may be version numbers or counters; verify the cited bytes before treating an address as a network indicator".into());
        }
        if matches!(kind, IocKind::Domain) {
            f.limitations
                .push("domain detection is heuristic (label/TLD shape); benign strings such as package names can match".into());
        }
        findings.push(f);
    }

    let mut report = AnalysisReport::new(identity, findings);
    for (kind, n) in &by_kind {
        report
            .facts
            .insert(format!("iocs.{}.count", kind.label()), serde_json::json!(n));
    }
    report
        .facts
        .insert("iocs.total".into(), serde_json::json!(iocs.len()));
    let detail = serde_json::to_value(&iocs).unwrap_or_else(|_| serde_json::json!([]));
    report.detail = Some(detail);
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn find<'a>(iocs: &'a [Ioc], kind: IocKind, value: &str) -> Option<&'a Ioc> {
        iocs.iter().find(|i| i.kind == kind && i.value == value)
    }

    #[test]
    fn extracts_url_ip_email_domain_and_hash() {
        let mut blob: Vec<u8> = b"Visit https://evil.example.net/payload?id=1 for details.\x00"[..].to_vec();
        blob.extend_from_slice(b"contact admin@fortinet.com\x00");
        blob.extend_from_slice(b"connect 185.199.108.153:443 and retry\x00");
        blob.extend_from_slice(b"digest 44d886e218ecdc45b56e5e1d1a2fbc4e is old md5\x00");
        blob.extend_from_slice(b"host evil-example.com\x00");
        let iocs = extract(&blob);
        assert!(
            find(&iocs, IocKind::Url, "https://evil.example.net/payload?id=1").is_some(),
            "urls: {iocs:?}"
        );
        assert!(find(&iocs, IocKind::Email, "admin@fortinet.com").is_some(), "emails: {iocs:?}");
        assert!(find(&iocs, IocKind::IpV4, "185.199.108.153").is_some(), "ips: {iocs:?}");
        assert!(
            find(&iocs, IocKind::Md5, "44d886e218ecdc45b56e5e1d1a2fbc4e").is_some(),
            "hashes: {iocs:?}"
        );
        assert!(find(&iocs, IocKind::Domain, "evil-example.com").is_some(), "domains: {iocs:?}");
    }

    #[test]
    fn extracts_registry_and_windows_path() {
        let blob = b"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run and C:\\Windows\\System32\\cmd.exe end\x00";
        let iocs = extract(blob);
        assert!(
            find(&iocs, IocKind::RegistryPath, "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run").is_some(),
            "reg: {iocs:?}"
        );
        assert!(
            find(&iocs, IocKind::FileSystemPath, "C:\\Windows\\System32\\cmd.exe").is_some(),
            "paths: {iocs:?}"
        );
    }

    #[test]
    fn extracts_from_utf16le_strings() {
        // "http://bad.example.com/x" encoded as UTF-16LE.
        let s = "http://bad.example.com/x";
        let mut blob = Vec::new();
        for ch in s.chars() {
            blob.push(ch as u8);
            blob.push(0x00);
        }
        blob.extend_from_slice(&[0x00, 0x00]);
        let iocs = extract(&blob);
        assert!(find(&iocs, IocKind::Url, s).is_some(), "utf16 urls: {iocs:?}");
        assert_eq!(iocs[0].encoding, "utf16le");
    }

    #[test]
    fn every_ioc_carries_a_byte_offset_inside_the_blob() {
        let blob = b"go to https://a.example.org/now\x00";
        let iocs = extract(blob);
        assert!(!iocs.is_empty());
        for i in &iocs {
            assert!(i.offset + i.len as u64 <= blob.len() as u64);
            let raw = &blob[i.offset as usize..(i.offset as usize + i.len)];
            assert_eq!(String::from_utf8_lossy(raw), i.value, "round-trip mismatch for {i:?}");
        }
    }

    #[test]
    fn rejects_bogus_ipv4_octets() {
        let blob = b"version 999.1.2.3 and 1.2.3.4.5 here\x00";
        let iocs = extract(blob);
        assert!(find(&iocs, IocKind::IpV4, "999.1.2.3").is_none());
        assert!(
            iocs.iter().filter(|i| i.kind == IocKind::IpV4).count() == 0,
            "{iocs:?}"
        );
    }

    #[test]
    fn email_with_trailing_dot_is_trimmed() {
        let blob = b"reply to ops@contoso.com. thanks\x00";
        let iocs = extract(blob);
        assert!(find(&iocs, IocKind::Email, "ops@contoso.com").is_some(), "{iocs:?}");
        assert!(find(&iocs, IocKind::Email, "ops@contoso.com.").is_none());
    }
}
