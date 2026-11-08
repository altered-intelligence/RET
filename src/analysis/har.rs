//! HAR / web capture analysis: endpoints, payload types, exposed data,
//! cookies, and credential redaction.

use crate::analysis::{AnalysisContext, identity_for};
use crate::core::evidence::{AnalysisReport, Confidence, Evidence, Finding, Location, Severity};

pub fn try_har(ctx: &AnalysisContext) -> Option<AnalysisReport> {
    let json: serde_json::Value = serde_json::from_slice(&ctx.head).ok()?;
    let log = json.get("log")?;
    if !log.get("entries").map(|e| e.is_array()).unwrap_or(false) {
        return None;
    }
    Some(analyze_har(ctx, &json, log))
}

fn analyze_har(ctx: &AnalysisContext, json: &serde_json::Value, log: &serde_json::Value) -> AnalysisReport {
    let creator = log.get("creator").and_then(|c| c.get("name")).and_then(|n| n.as_str()).unwrap_or("unknown");
    let entries: Vec<serde_json::Value> = log
        .get("entries")
        .and_then(|e| e.as_array())
        .cloned()
        .unwrap_or_default();

    let mut findings: Vec<Finding> = Vec::new();
    let mut report = AnalysisReport::new(
        identity_for(&ctx.path, "har", "HTTP Archive (HAR) capture", &ctx.head)
            .unwrap_or_else(|_| fallback_identity(ctx)),
        Vec::new(),
    );

    let mut endpoints: Vec<(String, String)> = Vec::new(); // (method, url)
    let mut mime_counts: std::collections::BTreeMap<String, usize> = std::collections::BTreeMap::new();
    let mut cookie_count = 0usize;
    let mut set_cookie_count = 0usize;
    let mut redacted_fields = 0usize;
    let mut status_codes: std::collections::BTreeMap<u16, usize> = std::collections::BTreeMap::new();

    for entry in entries.iter().take(2000) {
        // Request side (an entry may legitimately lack a response: in-flight, failed).
        if let Some(req) = entry.get("request") {
            let method = req
                .get("method")
                .and_then(|m| m.as_str())
                .unwrap_or("?")
                .to_string();
            let url = req
                .get("url")
                .and_then(|u| u.as_str())
                .unwrap_or("")
                .to_string();
            endpoints.push((method, url));
            if let Some(cookies) = req.get("cookies").and_then(|c| c.as_array()) {
                cookie_count += cookies.len();
            }
        }
        // Response side
        if let Some(res) = entry.get("response") {
            if let Some(status) = res.get("status").and_then(|s| s.as_u64()) {
                *status_codes.entry(status as u16).or_default() += 1;
            }
            if let Some(content) = res
                .get("content")
                .and_then(|c| c.get("mimeType"))
                .and_then(|m| m.as_str())
            {
                let base = content.split(';').next().unwrap_or(content).to_string();
                *mime_counts.entry(base).or_default() += 1;
            }
            if let Some(hdrs) = res.get("headers").and_then(|h| h.as_array()) {
                for h in hdrs {
                    let name = h.get("name").and_then(|n| n.as_str()).unwrap_or("");
                    if name.eq_ignore_ascii_case("set-cookie") {
                        set_cookie_count += 1;
                    }
                    if redact_match(name) {
                        redacted_fields += 1;
                    }
                }
            }
        }
    }

    report.facts.insert("har.creator".into(), serde_json::json!(creator));
    report.facts.insert("har.entries".into(), serde_json::json!(entries.len()));
    report.facts.insert("har.endpoints".into(), serde_json::json!(endpoints.len()));

    // Creator / overview
    let mut hf = Finding::new(
        "har.overview",
        format!(
            "HAR capture by {creator}: {} entries, {} endpoints, {} distinct content types",
            entries.len(),
            endpoints.len(),
            mime_counts.len()
        ),
        Severity::Info,
        Confidence::Direct,
    );
    hf.evidence.push(Evidence::new(
        "har.creator",
        creator.to_string(),
        Location::entity("har", "log.creator.name"),
    ));
    findings.push(hf);

    // Endpoints
    if !endpoints.is_empty() {
        let mut ef = Finding::new(
            "har.endpoints",
            format!("{} HTTP transactions observed", endpoints.len()),
            Severity::Info,
            Confidence::Direct,
        );
        let mut seen = std::collections::BTreeSet::new();
        for (method, url) in endpoints.iter().filter(|(m, _)| m != "OPTIONS") {
            let key = format!("{method} {url}");
            if !seen.insert(key.clone()) || ef.evidence.len() >= 40 {
                continue;
            }
            ef.evidence.push(Evidence::new(
                "har.endpoint",
                key,
                Location::entity("request", url.clone()),
            ));
        }
        findings.push(ef);
    }

    // Status / content-type distribution
    if !status_codes.is_empty() {
        let mut sf = Finding::new(
            "har.status",
            format!("{} response statuses", status_codes.len()),
            Severity::Info,
            Confidence::Derived,
        );
        for (code, n) in status_codes.iter() {
            sf.evidence.push(Evidence::derived(
                "har.status",
                format!("HTTP {code}: {n}"),
                Location::entity("response", format!("status={code}")),
            ));
        }
        findings.push(sf);
    }
    if !mime_counts.is_empty() {
        let mut mf = Finding::new(
            "har.mime",
            format!("{} content types", mime_counts.len()),
            Severity::Info,
            Confidence::Derived,
        );
        for (mime, n) in mime_counts.iter().take(20) {
            mf.evidence.push(Evidence::derived(
                "har.mime",
                format!("{mime}: {n}"),
                Location::entity("response", "mimeType"),
            ));
        }
        findings.push(mf);
    }

    // Exposed payloads (request bodies / response bodies)
    let exposed = collect_exposed(json, &entries, ctx.settings.redact_credentials);
    if !exposed.is_empty() {
        let mut xf = Finding::new(
            "har.exposed_payloads",
            format!("{} payload bodies captured with MIME types", exposed.len()),
            Severity::Note,
            Confidence::Direct,
        );
        for (method, url, mime, body) in exposed.iter().take(12) {
            let sample: String = body.chars().take(320).collect();
            xf.evidence.push(Evidence::new(
                "har.payload",
                format!("{method} {url} [{mime}] {sample}"),
                Location::entity("payload", url.clone()),
            ));
        }
        xf.limitations.push(format!(
            "bodies are sampled; {} candidate(s) found",
            exposed.len()
        ));
        findings.push(xf);
    }

    if cookie_count > 0 {
        let mut cf = Finding::new(
            "har.cookies",
            format!("{cookie_count} request cookies, {set_cookie_count} Set-Cookie responses"),
            Severity::Info,
            Confidence::Direct,
        );
        cf.evidence.push(Evidence::new(
            "har.cookies",
            format!("{cookie_count} request cookies"),
            Location::entity("request", "cookies"),
        ));
        findings.push(cf);
    }

    if redacted_fields > 0 {
        let mut rf = Finding::new(
            "har.redacted",
            format!("{redacted_fields} credential-like header values redacted"),
            Severity::Info,
            Confidence::Direct,
        );
        rf.limitations.push("redaction is name-based; a token in an unusual header is not guaranteed to be caught".into());
        findings.push(rf);
    }

    report.findings = findings;
    report.summary = summary(&report.findings);
    report
}

fn fallback_identity(ctx: &AnalysisContext) -> crate::core::evidence::ArtifactIdentity {
    crate::core::evidence::ArtifactIdentity {
        name: ctx
            .path
            .file_name()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_default(),
        path: ctx.path.display().to_string(),
        size: 0,
        sha256: String::new(),
        kind: "har".into(),
        label: "HAR capture".into(),
        container: None,
    }
}

fn redact_match(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    n.contains("authorization")
        || n.contains("token")
        || n.contains("secret")
        || n.contains("api-key")
        || n == "cookie"
}

/// Collect (method, url, mime, body) for small, text-ish request/response bodies,
/// redacting obvious credential patterns inside body text so secrets never leak
/// into a case file (unless the operator disabled redaction).
fn collect_exposed(
    _json: &serde_json::Value,
    entries: &[serde_json::Value],
    redact: bool,
) -> Vec<(String, String, String, String)> {
    let mut out = Vec::new();
    for entry in entries.iter().take(500) {
        if let Some(pd) = entry
            .pointer("/request/postData/text")
            .and_then(|t| t.as_str())
        {
            if !pd.is_empty() && pd.len() < 64 * 1024 {
                let method = entry.pointer("/request/method").and_then(|m| m.as_str()).unwrap_or("?").to_string();
                let url = entry.pointer("/request/url").and_then(|u| u.as_str()).unwrap_or("").to_string();
                let mime = entry
                    .pointer("/request/postData/mimeType")
                    .and_then(|m| m.as_str())
                    .unwrap_or("?")
                    .to_string();
                out.push((method, url, mime, redact_body(pd, redact)));
            }
        }
        if let Some(res_body) = entry
            .pointer("/response/content/text")
            .and_then(|t| t.as_str())
        {
            if !res_body.is_empty() && res_body.len() < 64 * 1024 && !res_body.starts_with('\u{fffd}') {
                let method = entry.pointer("/request/method").and_then(|m| m.as_str()).unwrap_or("?").to_string();
                let url = entry.pointer("/request/url").and_then(|u| u.as_str()).unwrap_or("").to_string();
                let mime = entry
                    .pointer("/response/content/mimeType")
                    .and_then(|m| m.as_str())
                    .unwrap_or("?")
                    .to_string();
                out.push((method, url, mime, redact_body(res_body, redact)));
            }
        }
    }
    out
}

/// Best-effort redaction of credential-looking substrings (JWT/bearer).
fn redact_body(body: &str, redact: bool) -> String {
    if !redact {
        return body.to_string();
    }
    let mut b = body.to_string();
    for prefix in ["Authorization: Bearer ", "authorization: Bearer "] {
        if let Some(pos) = b.find(prefix) {
            let rest = &b[pos + prefix.len()..];
            let end = rest
                .find(|c: char| c.is_whitespace() || c == '"' || c == '\'')
                .unwrap_or(rest.len());
            b.replace_range(pos + prefix.len()..pos + prefix.len() + end, "<REDACTED>");
        }
    }
    // JWT-format tokens: three+ dot-separated base64url segments. We require a
    // reasonable minimum total length so URLs like `cdn.jsdelivr.net` are not
    // mistaken for tokens.
    let mut result = String::with_capacity(b.len());
    let bytes = b.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if let Some(end) = jwt_end(&bytes, i) {
            result.push_str("<REDACTED>");
            i = end;
            continue;
        }
        result.push(bytes[i] as char);
        i += 1;
    }
    result
}

/// Is there a JWT-shaped token (2+ dots, base64url segments) starting at `start`?
/// Returns the exclusive end offset if one is found, otherwise `None`.
fn jwt_end(bytes: &[u8], start: usize) -> Option<usize> {
    let is_token_char = |c: u8| c.is_ascii_alphanumeric() || matches!(c, b'-' | b'_');
    if !is_token_char(bytes.get(start).copied()?) {
        return None;
    }
    let mut pos = start;
    let mut dots = 0usize;
    loop {
        let seg_start = pos;
        while pos < bytes.len() && is_token_char(bytes[pos]) && pos - seg_start < 4096 {
            pos += 1;
        }
        if pos == seg_start {
            return None;
        }
        if pos >= bytes.len() || bytes[pos] != b'.' {
            break;
        }
        dots += 1;
        pos += 1;
    }
    let len = pos - start;
    if dots >= 2 && len >= 24 {
        Some(pos)
    } else {
        None
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
