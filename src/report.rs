//! Case-file & artifact report export.
//!
//! `ret report --format markdown|html` turns a case into a readable,
//! portable document. HTML output is a fully standalone page (fonts, CSS and
//! a small search/filter script are embedded) so it can be archived, shared,
//! or attached to an incident follow-up without any external assets.

use crate::core::casefile::{Case, Snapshot};
use crate::core::evidence::{AnalysisReport, Finding, Location, Severity};

/// Render a whole case as Markdown.
pub fn markdown_case(case: &Case) -> String {
    let mut out = String::new();
    out.push_str(&format!("# RET case `{}`\n\n", case.id));
    out.push_str(&format!(
        "**{}**  \ncreated **{}** · updated **{}**\n\n",
        case.description,
        case.created.format("%Y-%m-%d %H:%M:%S UTC"),
        case.updated.format("%Y-%m-%d %H:%M:%S UTC")
    ));

    out.push_str("## Artifacts\n\n");
    if case.artifacts.is_empty() {
        out.push_str("_none recorded yet_\n\n");
    } else {
        out.push_str("| artifact | size | sha256 |\n|---|---|---|\n");
        for a in &case.artifacts {
            out.push_str(&format!(
                "| `{}` | {} | `{}` |\n",
                a.name, a.size, a.sha256
            ));
        }
    }

    out.push_str("\n## Snapshot history\n\n");
    if case.snapshots.is_empty() {
        out.push_str("_no snapshots yet_\n\n");
    } else {
        out.push_str("| when | artifact | size | sha256 |\n|---|---|---|---|\n");
        for s in case.snapshots.iter().rev().take(40) {
            out.push_str(&format!(
                "| {} | `{}` | {} | `{}` |\n",
                s.timestamp.format("%Y-%m-%d %H:%M:%S UTC"),
                s.name,
                s.size,
                s.sha256
            ));
        }
    }

    out.push_str(&format!("\n## Findings ({})\n\n", case.findings.len()));
    let mut by_sev: Vec<(Severity, Vec<&Finding>)> = Vec::new();
    let order = [
        Severity::Critical,
        Severity::Warning,
        Severity::Note,
        Severity::Info,
    ];
    for sev in order {
        let v: Vec<&Finding> = case
            .findings
            .iter()
            .filter(|f| f.severity == sev)
            .collect();
        if !v.is_empty() {
            by_sev.push((sev, v));
        }
    }
    for (sev, v) in by_sev {
        out.push_str(&format!("### {}\n\n", sev.label().to_uppercase()));
        for f in v {
            out.push_str(&format!(
                "- **`{}`** — {}  \n",
                f.id,
                f.claim.trim_end_matches('.')
            ));
            for e in &f.evidence {
                out.push_str(&format!(
                    "  - _{}_: `{}` — `{}`\n",
                    e.label,
                    e.value.replace('`', "'"),
                    loc_markdown(&e.location)
                ));
            }
            if !f.limitations.is_empty() {
                for l in &f.limitations {
                    out.push_str(&format!("  - ⚠ _limitation:_ {}\n", l.replace('`', "'")));
                }
            }
        }
        out.push('\n');
    }
    out
}

fn loc_markdown(loc: &Location) -> String {
    match loc {
        Location::Route { path } => format!("route {}", path),
        Location::Bytes { start, end, note } => {
            let rng = match end {
                Some(e) => format!("bytes 0x{start:x}-0x{e:x}"),
                None => format!("bytes 0x{start:x}"),
            };
            match note {
                Some(n) => format!("{rng} ({n})"),
                None => rng,
            }
        }
        Location::Entity { kind, name } => format!("entity {kind}:{name}"),
    }
}

/// Render a single analysis report as Markdown (used by `analyze --export`).
pub fn markdown_report(r: &AnalysisReport) -> String {
    let a = &r.artifact;
    let mut out = String::new();
    out.push_str(&format!("# RET report — {}\n\n", a.label));
    out.push_str(&format!("- **path**: `{}`\n", a.path));
    out.push_str(&format!("- **kind**: `{}`\n", a.kind));
    out.push_str(&format!("- **size**: {} bytes\n", a.size));
    out.push_str(&format!("- **sha256**: `{}`\n", a.sha256));
    if !r.facts.is_empty() {
        out.push_str(&format!("- **structural digest**: `{}`\n", r.structural_digest()));
    }
    out.push_str(&format!("\n## Findings ({})\n\n", r.findings.len()));
    for (sev, list) in group_by_severity(&r.findings) {
        out.push_str(&format!("### {}\n\n", sev.label().to_uppercase()));
        for f in list {
            out.push_str(&format!(
                "- **`{}`** — {}  \n",
                f.id,
                f.claim
            ));
            for e in &f.evidence {
                out.push_str(&format!(
                    "  - _{}_: `{}` — `{}`\n",
                    e.label,
                    e.value.replace('`', "'"),
                    loc_markdown(&e.location)
                ));
            }
            for l in &f.limitations {
                out.push_str(&format!("  - ⚠ _limitation:_ {}\n", l.replace('`', "'")));
            }
        }
        out.push('\n');
    }
    out
}

fn group_by_severity<'a>(findings: &'a [Finding]) -> Vec<(Severity, Vec<&'a Finding>)> {
    let order = [
        Severity::Critical,
        Severity::Warning,
        Severity::Note,
        Severity::Info,
    ];
    order
        .iter()
        .filter_map(|sev| {
            let v: Vec<&'a Finding> = findings
                .iter()
                .filter(|f| &f.severity == sev)
                .collect();
            if v.is_empty() {
                None
            } else {
                Some((*sev, v))
            }
        })
        .collect()
}

/// A tiny, dependency-free structural digest of a snapshot for display.
fn snapshot_badge(s: &Snapshot) -> String {
    match &s.kind {
        Some(k) => k.clone(),
        None => "unknown".into(),
    }
}

/// Render a whole case as a standalone HTML report with embedded CSS/JS.
pub fn html_case(case: &Case) -> String {
    let findings_json = serde_json::to_string(&case.findings).unwrap_or_else(|_| "[]".into());

    let mut findings_html = String::new();
    for f in &case.findings {
        findings_html.push_str(&format!(
            r#"<article class="finding sev-{sev}">
  <div class="head">
    <span class="badge sev-{sev}">{sev}</span>
    <code class="id">{id}</code>
    <span class="conf">{conf}</span>
  </div>
  <p class="claim"></p>
  <pre class="data">{data}</pre>
</article>"#,
            sev = f.severity.label(),
            id = html_escape(&f.id),
            conf = f.confidence.label(),
            data = html_escape(&serde_json::to_string_pretty(f).unwrap_or_default()),
        ));
    }
    if findings_html.is_empty() {
        findings_html.push_str("<p class=\"empty\">No findings recorded yet.</p>");
    }

    format!(
        r#"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>RET case {id}</title>
<style>
:root {{ --bg:#0f1420; --panel:#161d2e; --fg:#dbe4f3; --muted:#8fa0bc; --line:#26314a;
  --cri:#ff5c5c; --warn:#ffb454; --note:#56c2ff; --info:#5be08a; --accent:#7aa7ff; }}
* {{ box-sizing:border-box; }}
body {{ margin:0; background:var(--bg); color:var(--fg);
  font:15px/1.55 ui-sans-serif,system-ui,"Segoe UI",Roboto,Helvetica,Arial,sans-serif; }}
header {{ padding:28px 36px; border-bottom:1px solid var(--line);
  background:linear-gradient(180deg,#182238,#141a2a); }}
h1 {{ margin:0 0 6px; font-size:22px; letter-spacing:.2px; }}
code, pre {{ font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace; }}
.wrap {{ max-width:1080px; margin:0 auto; padding:0 24px; }}
.meta {{ color:var(--muted); font-size:13px; }}
.columns {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(220px,1fr));
  gap:14px; padding:20px 24px 6px; }}
.stat {{ background:var(--panel); border:1px solid var(--line); border-radius:10px;
  padding:14px 16px; }}
.stat b {{ display:block; font-size:26px; color:var(--accent); }}
.stat span {{ color:var(--muted); font-size:12px; text-transform:uppercase; letter-spacing:.6px; }}
section {{ padding:18px 24px; }}
section h2 {{ font-size:16px; color:var(--accent); margin:0 0 12px; text-transform:uppercase;
  letter-spacing:1px; font-size:13px; }}
.finding {{ background:var(--panel); border:1px solid var(--line); border-left-width:4px;
  border-radius:8px; padding:12px 16px; margin:0 0 14px; }}
.head {{ display:flex; gap:10px; align-items:center; margin-bottom:6px; }}
.badge {{ font-size:10px; padding:2px 8px; border-radius:20px; text-transform:uppercase;
  letter-spacing:.6px; }}
.sev-critical {{ border-left-color:var(--cri); }} .sev-critical .badge {{ background:var(--cri); color:#111; }}
.sev-warning {{ border-left-color:var(--warn); }} .sev-warning .badge {{ background:var(--warn); color:#111; }}
.sev-note {{ border-left-color:var(--note); }} .sev-note .badge {{ background:var(--note); color:#111; }}
.sev-info {{ border-left-color:var(--info); }} .sev-info .badge {{ background:var(--info); color:#111; }}
.id {{ color:var(--muted); font-size:12px; }}
.conf {{ margin-left:auto; color:var(--muted); font-size:11px; }}
.claim {{ margin:0 0 8px; }}
pre.data {{ background:#0b0f18; border:1px solid var(--line); border-radius:6px;
  padding:10px; overflow:auto; max-height:320px; font-size:12px; color:var(--muted); white-space:pre-wrap; }}
.toolbar {{ padding:0 24px 0; position:sticky; top:0; background:var(--bg); z-index:9;
  border-bottom:1px solid var(--line); display:flex; gap:10px; align-items:center; flex-wrap:wrap; }}
.toolbar input, .toolbar select {{ background:var(--panel); color:var(--fg);
  border:1px solid var(--line); border-radius:6px; padding:7px 10px; font-size:13px; }}
.toolbar label {{ color:var(--muted); font-size:12px; }}
.count {{ color:var(--muted); font-size:12px; margin-left:auto; }}
table {{ width:100%; border-collapse:collapse; font-size:13px; }}
th, td {{ text-align:left; padding:8px 10px; border-bottom:1px solid var(--line); }}
th {{ color:var(--muted); text-transform:uppercase; font-size:11px; letter-spacing:.5px; }}
footer {{ color:var(--muted); font-size:12px; padding:26px 24px; border-top:1px solid var(--line); }}
.empty {{ color:var(--muted); }}
</style>
</head>
<body>
<header><div class="wrap">
  <h1>RET case {id}</h1>
  <div class="meta">{desc} · created {created} · updated {updated}</div>
</div></header>

<div class="columns">
  <div class="stat"><b>{nart}</b><span>artifacts</span></div>
  <div class="stat"><b>{nfind}</b><span>findings</span></div>
  <div class="stat"><b>{nsnap}</b><span>snapshots</span></div>
  <div class="stat"><b>{nsev}</b><span>critical / warning</span></div>
</div>

<div class="toolbar">
  <label for="q">filter</label>
  <input id="q" type="text" placeholder="search id, claim, label…" style="min-width:260px">
  <label for="s">severity</label>
  <select id="s">
    <option value="">all</option><option>critical</option><option>warning</option>
    <option>note</option><option>info</option>
  </select>
  <span class="count" id="count"></span>
</div>

<section id="findings"><div class="wrap">
  <h2>Findings</h2>
  <div id="list">{findings_html}</div>
</div></section>

<section><div class="wrap"><h2>Artifacts</h2>
<table><thead><tr><th>artifact</th><th>size</th><th>sha256</th></tr></thead>
<tbody id="artifacts">{artifacts_rows}</tbody></table></div></section>

<section><div class="wrap"><h2>Snapshot history</h2>
<table><thead><tr><th>when</th><th>artifact</th><th>size</th><th>sha256</th></tr></thead>
<tbody id="snapshots">{snapshots_rows}</tbody></table></div></section>

<footer><div class="wrap">Generated by RET — Reverse Engineering Toolkit. Findings, evidence and limitations are
recorded as produced and are not claims of fact; byte locations let you verify every conclusion.</div></footer>

<script>
const DATA = {{
  findings: {findings_json},
}};
const list = document.getElementById('list');
const articles = Array.from(list.children).filter(e => e.classList && e.classList.contains('finding'));
const q = document.getElementById('q'), s = document.getElementById('s'), count = document.getElementById('count');
function apply() {{
  const needle = q.value.toLowerCase();
  const sev = s.value;
  let n = 0;
  for (let a of articles) {{
    const data = JSON.parse(a.querySelector('.data').textContent);
    const ok = (!sev || data.severity === sev) &&
      (!needle || (data.id + ' ' + data.claim + ' ' + data.evidence.map(e=>e.label+' '+e.value).join(' ')).toLowerCase().includes(needle));
    a.style.display = ok ? '' : 'none';
    if (ok) n++;
  }}
  count.textContent = n + ' of ' + articles.length;
}}
q.addEventListener('input', apply); s.addEventListener('change', apply); apply();
</script>
</body>
</html>"#,
        id = html_escape(&case.id),
        desc = html_escape(&case.description),
        created = case.created.format("%Y-%m-%d %H:%M:%S UTC"),
        updated = case.updated.format("%Y-%m-%d %H:%M:%S UTC"),
        nart = case.artifacts.len(),
        nfind = case.findings.len(),
        nsnap = case.snapshots.len(),
        nsev = case
            .findings
            .iter()
            .filter(|f| matches!(f.severity, Severity::Critical | Severity::Warning))
            .count(),
        findings_html = findings_html,
        artifacts_rows = case
            .artifacts
            .iter()
            .map(|a| {
                format!(
                    "<tr><td>{}</td><td>{}</td><td><code>{}</code></td></tr>",
                    html_escape(&a.name),
                    a.size,
                    a.sha256
                )
            })
            .collect::<Vec<_>>()
            .join("\n"),
        snapshots_rows = case
            .snapshots
            .iter()
            .rev()
            .take(60)
            .map(|s| {
                format!(
                    "<tr><td>{}</td><td>{} ({})</td><td>{}</td><td><code>{}</code></td></tr>",
                    s.timestamp.format("%Y-%m-%d %H:%M:%S UTC"),
                    html_escape(&s.name),
                    snapshot_badge(s),
                    s.size,
                    s.sha256
                )
            })
            .collect::<Vec<_>>()
            .join("\n"),
    )
}

/// Minimal HTML escaping (the data we embed is our own JSON, but be safe).
fn html_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(c),
        }
    }
    out
}
