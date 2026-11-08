//! safetensors (HuggingFace) metadata analysis.

use crate::analysis::{AnalysisContext, identity_for};
use crate::core::error::{Error, Result};
use crate::core::evidence::{AnalysisReport, Confidence, Evidence, Finding, Location, Severity};

pub fn analyze(ctx: &AnalysisContext) -> Result<AnalysisReport> {
    let b = &ctx.head;
    if b.len() < 8 {
        return Err(Error::malformed("safetensors file too small"));
    }
    let header_len = u64::from_le_bytes(b[0..8].try_into().unwrap());
    if header_len == 0 || (8 + header_len as usize) > b.len() {
        return Err(Error::malformed("safetensors header length out of range"));
    }
    let header_bytes = &b[8..8 + header_len as usize];
    let header: serde_json::Value = serde_json::from_slice(header_bytes)?;
    let Some(obj) = header.as_object() else {
        return Err(Error::malformed("safetensors header not an object"));
    };

    let mut metadata = Vec::new();
    let mut tensors: Vec<(String, String, u128)> = Vec::new();
    let mut total_tensors = 0usize;
    let mut total_elements: u128 = 0;
    let mut dtype_set = std::collections::BTreeSet::new();

    for (k, v) in obj {
        if k == "__metadata__" {
            if let Some(mo) = v.as_object() {
                for (mk, mv) in mo {
                    metadata.push((mk.clone(), mv.to_string()));
                }
            }
            continue;
        }
        let Some(t) = v.as_object() else { continue };
        total_tensors += 1;
        let dtype = t
            .get("dtype")
            .and_then(|d| d.as_str())
            .unwrap_or("unknown")
            .to_string();
        let shape: Vec<u64> = t
            .get("shape")
            .and_then(|s| s.as_array())
            .map(|a| a.iter().filter_map(|x| x.as_u64()).collect())
            .unwrap_or_default();
        let elements: u128 = shape.iter().map(|d| *d as u128).product();
        total_elements += elements;
        dtype_set.insert(dtype.clone());
        tensors.push((
            k.clone(),
            format!(
                "{dtype} [{}]",
                shape.iter().map(|d| d.to_string()).collect::<Vec<_>>().join(",")
            ),
            elements,
        ));
    }

    let mut findings: Vec<Finding> = Vec::new();
    let report = AnalysisReport::new(
        identity_for(&ctx.path, "safetensors", "safetensors model artifact", b)?,
        Vec::new(),
    );
    let mut report = report;
    report.facts.insert("st.tensor_count".into(), serde_json::json!(total_tensors));
    report.facts.insert("st.total_elements".into(), serde_json::json!(total_elements));
    report.facts.insert(
        "st.dtypes".into(),
        serde_json::json!(dtype_set.iter().collect::<Vec<_>>()),
    );

    let mut hf = Finding::new(
        "safetensors.header",
        format!(
            "{total_tensors} tensors across {} dtype(s), ~{:.1}M elements",
            dtype_set.len(),
            total_elements as f64 / 1e6
        ),
        Severity::Info,
        Confidence::Direct,
    );
    hf.evidence.push(Evidence::new(
        "safetensors.header_len",
        header_len.to_string(),
        Location::bytes(0, Some(8)),
    ));
    findings.push(hf);

    if !metadata.is_empty() {
        let mut mf = Finding::new(
            "safetensors.metadata",
            format!("{} metadata entries", metadata.len()),
            Severity::Info,
            Confidence::Direct,
        );
        for (k, v) in metadata.iter().take(12) {
            mf.evidence.push(Evidence::new("safetensors.metadata", format!("{k} = {v}"), Location::entity("metadata", k.clone())));
        }
        findings.push(mf);
    }

    let mut tf = Finding::new(
        "safetensors.tensors",
        format!("{total_tensors} tensors"),
        Severity::Info,
        Confidence::Direct,
    );
    for (name, desc, _el) in tensors.iter().take(24) {
        tf.evidence.push(Evidence::new("safetensors.tensor", format!("{name} {desc}"), Location::entity("tensor", name.clone())));
    }
    findings.push(tf);

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
