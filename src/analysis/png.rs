//! PNG metadata analysis: IHDR geometry, color model, text chunks, and
//! ancillary profile markers.

use crate::analysis::{AnalysisContext, identity_for};
use crate::core::error::{Error, Result};
use crate::core::evidence::{AnalysisReport, Confidence, Evidence, Finding, Location, Severity};

const SIGNATURE: [u8; 8] = [0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A];

pub fn analyze(ctx: &AnalysisContext) -> Result<AnalysisReport> {
    let b = &ctx.head;
    if b.len() < 24 || b[0..8] != SIGNATURE {
        return Err(Error::malformed("not a PNG"));
    }
    let mut findings: Vec<Finding> = Vec::new();
    let report = AnalysisReport::new(
        identity_for(&ctx.path, "png", "PNG image", b)?,
        Vec::new(),
    );
    let mut report = report;

    let mut pos = 8usize;
    let mut found_ihdr = false;
    let mut width = 0u32;
    let mut height = 0u32;
    let mut bit_depth = 0u8;
    let mut color_type = 0u8;
    let mut interlace = 0u8;
    let mut text: Vec<String> = Vec::new();
    let mut idat_count = 0u32;
    let mut chunks = 0usize;

    while pos + 12 <= b.len() {
        let len = u32::from_be_bytes([b[pos], b[pos + 1], b[pos + 2], b[pos + 3]]) as usize;
        let ctype = &b[pos + 4..pos + 8];
        let data = &b[pos + 8..(pos + 8 + len).min(b.len())];
        match ctype {
            b"IHDR" if data.len() >= 13 => {
                width = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
                height = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
                bit_depth = data[8];
                color_type = data[9];
                interlace = data[12];
                found_ihdr = true;
            }
            b"tEXt" => {
                if let Some(nul) = data.iter().position(|&x| x == 0) {
                    let key = String::from_utf8_lossy(&data[..nul]).into_owned();
                    let value = String::from_utf8_lossy(&data[nul + 1..]).trim().to_string();
                    text.push(format!("{key}: {value}"));
                }
            }
            b"iTXt" => {
                if let Some(nul) = data.iter().position(|&x| x == 0) {
                    let key = String::from_utf8_lossy(&data[..nul]).into_owned();
                    text.push(format!("{key}: <international text>"));
                }
            }
            b"zTXt" => {
                if let Some(nul) = data.iter().position(|&x| x == 0) {
                    let key = String::from_utf8_lossy(&data[..nul]).into_owned();
                    let comp = data.get(nul + 1).copied().unwrap_or(0);
                    if comp == 0 {
                        if let Some(payload) = data.get(nul + 2..) {
                            if let Ok(decoded) = inflate(payload) {
                                text.push(format!(
                                    "{key}: {}",
                                    String::from_utf8_lossy(&decoded).trim()
                                ));
                            } else {
                                text.push(format!("{key}: <compressed, undecodable>"));
                            }
                        }
                    }
                }
            }
            b"IDAT" => idat_count += 1,
            b"IEND" => {
                chunks += 1;
                break;
            }
            _ => {}
        }
        pos += 12 + len;
        chunks += 1;
    }

    if !found_ihdr {
        return Err(Error::malformed("PNG missing IHDR"));
    }

    let color_name = color_type_name(color_type);
    let mut hf = Finding::new(
        "png.ihdr",
        format!("{width}×{height} PNG, {bit_depth}-bit {color_name}, {} IDAT chunk(s)", idat_count),
        Severity::Info,
        Confidence::Direct,
    );
    hf.evidence.push(Evidence::new("png.ihdr.width", width.to_string(), Location::bytes(8 + 8, Some(8 + 12))));
    hf.evidence.push(Evidence::new("png.ihdr.height", height.to_string(), Location::bytes(8 + 12, Some(8 + 16))));
    hf.evidence.push(Evidence::new(
        "png.ihdr.color_type",
        format!("{color_name} ({color_type})"),
        Location::entity("chunk", "IHDR"),
    ));
    hf.evidence.push(Evidence::new(
        "png.ihdr.interlace",
        if interlace == 1 { "Adam7" } else { "none" }.to_string(),
        Location::entity("chunk", "IHDR"),
    ));
    report
        .facts
        .insert("png.width".into(), serde_json::json!(width));
    report
        .facts
        .insert("png.height".into(), serde_json::json!(height));
    report
        .facts
        .insert("png.color_type".into(), color_name.into());
    report
        .facts
        .insert("png.idat_chunks".into(), serde_json::json!(idat_count));
    findings.push(hf);

    if !text.is_empty() {
        let mut tf = Finding::new(
            "png.text",
            format!("{} text chunks", text.len()),
            Severity::Info,
            Confidence::Direct,
        );
        for t in text.iter().take(12) {
            tf.evidence.push(Evidence::new("png.text", t.clone(), Location::entity("chunk", "text")));
        }
        findings.push(tf);
    }

    let strings = crate::analysis::binary::scan_strings(b, 4);
    findings.push(crate::analysis::binary::string_inventory_finding(
        &strings,
        ctx.settings.max_strings,
        ctx.settings.max_string_len,
        4,
        100,
    ));

    let _ = chunks;
    report.findings = findings;
    report.summary = summary(&report.findings);
    Ok(report)
}

fn color_type_name(t: u8) -> &'static str {
    match t {
        0 => "grayscale",
        2 => "truecolor (RGB)",
        3 => "indexed-color",
        4 => "grayscale+alpha",
        6 => "truecolor+alpha (RGBA)",
        _ => "unknown",
    }
}

fn inflate(data: &[u8]) -> std::result::Result<Vec<u8>, String> {
    miniz_oxide::inflate::decompress_to_vec(data)
        .map_err(|e| format!("zlib: {e}"))
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
