//! GGUF (llama.cpp) header/metadata/tensor analysis.

use crate::analysis::{AnalysisContext, identity_for};
use crate::core::error::{Error, Result};
use crate::core::evidence::{AnalysisReport, Confidence, Evidence, Finding, Location, Severity};

pub fn analyze(ctx: &AnalysisContext) -> Result<AnalysisReport> {
    let b = &ctx.head;
    if b.len() < 24 || &b[0..4] != b"GGUF" {
        return Err(Error::malformed("not a GGUF file"));
    }
    let version = u32::from_le_bytes([b[4], b[5], b[6], b[7]]);
    let tensor_count = le64_at(b, 8);
    let kv_count = le64_at(b, 16);

    let mut pos = 24usize;
    let mut metadata: Vec<(String, String)> = Vec::new();
    for _ in 0..kv_count.min(4096) {
        let Some(key) = gguf_string(b, &mut pos) else { break };
        let Some((v, _t)) = gguf_value(b, &mut pos) else { break };
        metadata.push((key, v));
    }

    // Tensor info follows metadata.
    let mut tensor_info: Vec<(String, String, u128)> = Vec::new();
    let mut total_params: u128 = 0;
    for _ in 0..tensor_count.min(8192) {
        let Some(name) = gguf_string(b, &mut pos) else { break };
        let Some(n_dims) = read_u32(b, &mut pos) else { break };
        let mut dims = Vec::new();
        for _ in 0..n_dims.min(8) {
            let Some(d) = read_u64(b, &mut pos) else { break };
            dims.push(d);
        }
        let Some(qtype) = read_u32(b, &mut pos) else { break };
        let Some(_offset) = read_u64(b, &mut pos) else { break };
        let tname = gguf_type(qtype);
        let params: u128 = dims.iter().map(|d| *d as u128).product();
        total_params += params;
        if tensor_info.len() < 32 {
            tensor_info.push((
                name,
                format!("{tname} dims=[{}]", dims.iter().map(|d| d.to_string()).collect::<Vec<_>>().join(",")),
                params,
            ));
        }
    }

    let mut findings: Vec<Finding> = Vec::new();
    let report = AnalysisReport::new(
        identity_for(&ctx.path, "gguf", "GGUF model artifact", b)?,
        Vec::new(),
    );
    let mut report = report;
    report.facts.insert("gguf.version".into(), serde_json::json!(version));
    report.facts.insert("gguf.tensor_count".into(), serde_json::json!(tensor_count));
    report.facts.insert("gguf.total_params".into(), serde_json::json!(total_params));

    // Metadata finding
    let mut mf = Finding::new(
        "gguf.metadata",
        format!("GGUF v{version}: {kv_count} metadata keys"),
        Severity::Info,
        Confidence::Direct,
    );
    let interesting = |k: &str| {
        k == "general.architecture"
            || k == "general.name"
            || k == "general.file_type"
            || k.starts_with("llama.context_length")
            || k == "tokenizer.ggml.model"
            || k == "general.quantization_version"
    };
    for (k, v) in metadata.iter() {
        if interesting(k) {
            mf.evidence.push(Evidence::new("gguf.metadata", format!("{k} = {v}"), Location::entity("metadata", k.clone())));
            report.facts.insert(format!("gguf.metadata.{k}"), serde_json::json!(v));
        }
    }
    findings.push(mf);

    // Tensor inventory
    let mut tf = Finding::new(
        "gguf.tensors",
        format!("{tensor_count} tensors, ~{:.1}M total parameters", total_params as f64 / 1e6),
        Severity::Info,
        Confidence::Derived,
    );
    for (name, desc, params) in tensor_info.iter() {
        tf.evidence.push(Evidence::derived(
            "gguf.tensor",
            format!("{name} {desc} (~{:.2}M params)", *params as f64 / 1e6),
            Location::entity("tensor", name.clone()),
        ));
    }
    tf.limitations.push("only the first tensors are enumerated; counts are derived from the header".into());
    findings.push(tf);

    let strings = crate::analysis::binary::scan_strings(b, 4);
    findings.push(crate::analysis::binary::string_inventory_finding(
        &strings,
        ctx.settings.max_strings,
        ctx.settings.max_string_len,
        4,
        80,
    ));

    report.findings = findings;
    report.summary = summary(&report.findings);
    Ok(report)
}

fn le64_at(b: &[u8], off: usize) -> u64 {
    if off + 8 <= b.len() {
        u64::from_le_bytes(b[off..off + 8].try_into().unwrap())
    } else {
        0
    }
}

fn read_u32(b: &[u8], pos: &mut usize) -> Option<u32> {
    if *pos + 4 > b.len() {
        return None;
    }
    let v = u32::from_le_bytes([b[*pos], b[*pos + 1], b[*pos + 2], b[*pos + 3]]);
    *pos += 4;
    Some(v)
}

fn read_u64(b: &[u8], pos: &mut usize) -> Option<u64> {
    if *pos + 8 > b.len() {
        return None;
    }
    let mut arr = [0u8; 8];
    arr.copy_from_slice(&b[*pos..*pos + 8]);
    *pos += 8;
    Some(u64::from_le_bytes(arr))
}

fn gguf_string(b: &[u8], pos: &mut usize) -> Option<String> {
    let len = read_u64(b, pos)? as usize;
    if *pos + len > b.len() {
        return None;
    }
    let s = String::from_utf8_lossy(&b[*pos..*pos + len]).into_owned();
    *pos += len;
    Some(s)
}

/// Parse one GGUF value; returns (display string, type code).
fn gguf_value(b: &[u8], pos: &mut usize) -> Option<(String, u8)> {
    let t = read_u32(b, pos)? as u8;
    let v = match t {
        0 | 10 => read_u64(b, pos)?.to_string(),
        4 | 1 | 2 | 3 | 5 | 11 => read_u32(b, pos)?.to_string(),
        6 => {
            let v = read_u32(b, pos)?;
            format!("{}", f32::from_bits(v))
        }
        12 => {
            let v = read_u64(b, pos)?;
            format!("{}", f64::from_bits(v))
        }
        7 => {
            let bv = read_u32(b, pos)?;
            if bv == 1 { "true" } else { "false" }.to_string()
        }
        8 => gguf_string(b, pos)?,
        9 => {
            let elem_t = read_u32(b, pos)? as u8;
            let item_len = read_u64(b, pos)?;
            let mut items = Vec::new();
            for _ in 0..item_len.min(1024) {
                let Some((v, _)) = gguf_value(b, pos) else { break };
                items.push(v);
            }
            let _ = elem_t;
            format!("[{}]", items.join(", "))
        }
        _ => {
            // Unknown; can't safely skip without type semantics.
            return None;
        }
    };
    Some((v, t))
}

fn gguf_type(t: u32) -> &'static str {
    match t {
        0 => "F32",
        1 => "F16",
        2 => "Q4_0",
        3 => "Q4_1",
        6 => "Q5_0",
        7 => "Q5_1",
        8 => "Q8_0",
        9 => "Q8_1",
        10 => "Q2_K",
        11 => "Q3_K",
        12 => "Q4_K",
        13 => "Q5_K",
        14 => "Q6_K",
        15 => "Q8_K",
        16 => "IQ2_XXS",
        17 => "IQ2_XS",
        18 => "IQ3_XXS",
        19 => "IQ1_S",
        20 => "IQ4_NL",
        21 => "IQ3_S",
        22 => "IQ2_S",
        23 => "IQ4_XS",
        26 => "I8",
        27 => "I16",
        28 => "I32",
        29 => "I64",
        32 => "TQ1_0",
        33 => "TQ2_0",
        _ => "unknown",
    }
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
