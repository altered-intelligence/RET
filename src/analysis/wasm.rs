//! WebAssembly module analysis: validation of the module skeleton, section
//! inventory, and exact import/export forms (WAT-style).

use crate::analysis::{AnalysisContext, identity_for};
use crate::core::error::{Error, Result};
use crate::core::evidence::{AnalysisReport, Confidence, Evidence, Finding, Location, Severity};

#[derive(Debug, Clone)]
struct Import {
    module: String,
    name: String,
    kind: String,
    detail: String,
}

#[derive(Debug, Clone)]
struct Export {
    name: String,
    kind: String,
    index: u32,
}

pub fn analyze(ctx: &AnalysisContext) -> Result<AnalysisReport> {
    let b = &ctx.head;
    if b.len() < 8 {
        return Err(Error::malformed("wasm too small"));
    }
    if &b[0..4] != b"\0asm" {
        return Err(Error::malformed("missing \\0asm magic"));
    }
    let version = u32::from_le_bytes([b[4], b[5], b[6], b[7]]);
    let label = format!("WebAssembly module, version {version}");

    let mut imports: Vec<Import> = Vec::new();
    let mut exports: Vec<Export> = Vec::new();
    let mut section_counts: Vec<(u8, usize)> = Vec::new();
    let mut pos = 8usize;
    let mut func_count: Option<u32> = None;
    let mut code_count: Option<u32> = None;
    while pos < b.len() {
        let Some(&sid) = b.get(pos) else { break };
        pos += 1;
        let Some(size) = leb_u32(b, &mut pos) else { break };
        let _start = pos;
        let end = pos.saturating_add(size as usize).min(b.len());
        match sid {
            1 => {
                if let Some(n) = leb_u32(b, &mut pos) {
                    func_count = Some(n);
                    section_counts.push((sid, n as usize));
                }
            }
            2 => {
                if let Some(n) = leb_u32(b, &mut pos) {
                    let count = n as usize;
                    let mut read = 0usize;
                    while read < count && pos < end {
                        let Some(module) = read_name(b, &mut pos) else { break };
                        let Some(name) = read_name(b, &mut pos) else { break };
                        let Some(kind) = b.get(pos).copied() else { break };
                        pos += 1;
                        let (kind_name, detail) = match kind {
                            0 => {
                                let t = leb_u32(b, &mut pos).unwrap_or(0);
                                ("func".to_string(), format!("type=0x{t:x}"))
                            }
                            1 => {
                                let et = leb_u32(b, &mut pos).unwrap_or(0);
                                let lim = read_limits(b, &mut pos);
                                ("table".to_string(), format!("elemtype=0x{et:x} {lim}"))
                            }
                            2 => {
                                let lim = read_limits(b, &mut pos);
                                ("memory".to_string(), lim)
                            }
                            3 => {
                                let gt = b.get(pos).copied().unwrap_or(0);
                                pos += 1;
                                ("global".to_string(), format!("type=0x{gt:x}"))
                            }
                            4 => ("tag".to_string(), String::new()),
                            _ => ("unknown".to_string(), String::new()),
                        };
                        imports.push(Import {
                            module,
                            name,
                            kind: kind_name,
                            detail,
                        });
                        read += 1;
                    }
                }
            }
            3 => {
                section_counts.push((sid, 0));
            }
            4 => {
                if let Some(n) = leb_u32(b, &mut pos) {
                    section_counts.push((sid, n as usize));
                }
            }
            5 => {
                if let Some(n) = leb_u32(b, &mut pos) {
                    section_counts.push((sid, n as usize));
                }
            }
            6 => {
                if let Some(n) = leb_u32(b, &mut pos) {
                    let mut i = 0usize;
                    while i < n as usize && pos < end {
                        let Some(name) = read_name(b, &mut pos) else { break };
                        let Some(kind) = b.get(pos).copied() else { break };
                        pos += 1;
                        let Some(index) = leb_u32(b, &mut pos) else { break };
                        exports.push(Export {
                            name,
                            kind: kind_name(kind).to_string(),
                            index,
                        });
                        i += 1;
                    }
                }
            }
            7 => {
                let f = leb_u32(b, &mut pos).unwrap_or(0);
                section_counts.push((7, f as usize));
            }
            8 | 9 | 10 | 11 | 12 => {
                let n = if sid == 10 {
                    leb_u32(b, &mut pos).unwrap_or(0)
                } else {
                    0
                };
                if sid == 10 {
                    code_count = Some(n);
                }
                section_counts.push((sid, n as usize));
            }
            _ => {
                section_counts.push((sid, 0));
            }
        }
        pos = end;
    }

    let mut findings: Vec<Finding> = Vec::new();
    let mut report = AnalysisReport::new(
        identity_for(&ctx.path, "wasm", &label, b)?,
        Vec::new(),
    );
    report
        .facts
        .insert("wasm.version".into(), serde_json::json!(version));

    // Hierarchy of section inventory
    let mut sf = Finding::new(
        "wasm.sections",
        format!("{} sections", section_counts.len()),
        Severity::Info,
        Confidence::Direct,
    );
    for (sid, n) in &section_counts {
        sf.evidence.push(Evidence::new(
            "wasm.section",
            format!("{} ({sid}) count={n}", section_name(*sid)),
            Location::entity("section", section_name(*sid).to_string()),
        ));
    }
    if let (Some(f), Some(c)) = (func_count, code_count) {
        report.facts.insert("wasm.functions".into(), serde_json::json!(f));
        report
            .facts
            .insert("wasm.code_entries".into(), serde_json::json!(c));
        // Declaration vs definition mismatch is a notable signal.
        if f != c {
            let mut mf = Finding::new(
                "wasm.func_code_mismatch",
                format!("function declarations ({f}) != code bodies ({c})"),
                Severity::Warning,
                Confidence::Direct,
            );
            mf.limitations.push("unresolved or truncated code section".into());
            findings.push(mf);
        }
    }
    findings.push(sf);

    if !imports.is_empty() {
        let mut impf = Finding::new(
            "wasm.imports",
            format!("{} imports", imports.len()),
            Severity::Info,
            Confidence::Direct,
        );
        for i in imports.iter().take(32) {
            impf.evidence.push(Evidence::new(
                "wasm.import",
                format!("(import \"{}\" \"{}\" ({} {}))", i.module, i.name, i.kind, i.detail),
                Location::entity("import", format!("{}::{}", i.module, i.name)),
            ));
        }
        report
            .facts
            .insert("wasm.import_count".into(), serde_json::json!(imports.len()));
        findings.push(impf);
    }

    if !exports.is_empty() {
        let mut exf = Finding::new(
            "wasm.exports",
            format!("{} exports", exports.len()),
            Severity::Info,
            Confidence::Direct,
        );
        for e in exports.iter().take(32) {
            exf.evidence.push(Evidence::new(
                "wasm.export",
                format!("(export \"{}\" ({} {}))", e.name, e.kind, e.index),
                Location::entity("export", e.name.clone()),
            ));
        }
        report
            .facts
            .insert("wasm.export_count".into(), serde_json::json!(exports.len()));
        findings.push(exf);
    }

    let strings = crate::analysis::binary::scan_strings(b, ctx.settings.min_string_len);
    findings.push(crate::analysis::binary::string_inventory_finding(
        &strings,
        ctx.settings.max_strings,
        ctx.settings.max_string_len,
        ctx.settings.min_string_len,
        200,
    ));

    report.findings = findings;
    report.summary = summary(&report.findings);
    Ok(report)
}

fn summary(findings: &[Finding]) -> serde_json::Map<String, serde_json::Value> {
    let mut m = serde_json::Map::new();
    for sev in [Severity::Info, Severity::Note, Severity::Warning, Severity::Critical] {
        let n = findings.iter().filter(|f| f.severity == sev).count();
        m.insert(sev.label().into(), serde_json::json!(n));
    }
    m.insert("total".into(), serde_json::json!(findings.len()));
    m
}

fn kind_name(k: u8) -> &'static str {
    match k {
        0 => "func",
        1 => "table",
        2 => "mem",
        3 => "global",
        4 => "tag",
        _ => "unknown",
    }
}

fn section_name(id: u8) -> &'static str {
    match id {
        0 => "custom",
        1 => "type",
        2 => "import",
        3 => "function",
        4 => "table",
        5 => "memory",
        6 => "global",
        7 => "export",
        8 => "start",
        9 => "element",
        10 => "code",
        11 => "data",
        12 => "data-count",
        13 => "tag",
        _ => "unknown",
    }
}

/// Decode an unsigned LEB128 u32 at `pos` (advances `pos`).
fn leb_u32(b: &[u8], pos: &mut usize) -> Option<u32> {
    let mut result: u32 = 0;
    let mut shift = 0u32;
    loop {
        let byte = *b.get(*pos)?;
        *pos += 1;
        result |= ((byte & 0x7f) as u32) << shift;
        if byte & 0x80 == 0 {
            break;
        }
        shift += 7;
        if shift >= 35 {
            return None;
        }
    }
    Some(result)
}

/// Read a WASM name: length-prefixed UTF-8 string.
fn read_name(b: &[u8], pos: &mut usize) -> Option<String> {
    let len = leb_u32(b, pos)? as usize;
    let s = b.get(*pos..*pos + len)?;
    *pos += len;
    Some(String::from_utf8_lossy(s).into_owned())
}

/// Read limits `(flags, min, max?)`.
fn read_limits(b: &[u8], pos: &mut usize) -> String {
    let Some(flags) = leb_u32(b, pos) else { return "limits".into() };
    let Some(min) = leb_u32(b, pos) else { return "limits".into() };
    if flags & 1 != 0 {
        let max = leb_u32(b, pos).unwrap_or(0);
        format!("min={min} max={max}")
    } else {
        format!("min={min}")
    }
}
