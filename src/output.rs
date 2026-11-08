//! Renderers for the output formats RET supports end-to-end:
//! `human` (ANSI-colored terminal output), `json`, `jsonl`, and `yaml`.

use std::io::Write;

use crate::compare::CompareResult;
use crate::core::casefile::Case;
use crate::core::evidence::{AnalysisReport, Confidence, Finding, Location, Severity};

/// A stable output-format selector shared by every command that renders.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    Human,
    Json,
    Jsonl,
    Yaml,
}

impl Format {
    pub fn parse(s: &str) -> Result<Self, String> {
        match s.to_ascii_lowercase().as_str() {
            "human" | "text" | "pretty" | "table" => Ok(Format::Human),
            "json" => Ok(Format::Json),
            "jsonl" | "ndjson" => Ok(Format::Jsonl),
            "yaml" | "yml" => Ok(Format::Yaml),
            other => Err(format!(
                "unknown format '{other}' (expected human, json, jsonl, or yaml)"
            )),
        }
    }
}

/// The thing a command wants to render.
pub enum Output<'a> {
    Report(&'a AnalysisReport),
    Compare(&'a CompareResult),
    /// Full case rendering; CLI surfaces cases via `Value`/report exports today.
    #[allow(dead_code)]
    Case(&'a Case),
    Value(serde_json::Value),
    Text(String),
}

pub fn write_output(
    out: &Output,
    format: Format,
    color: bool,
    w: &mut dyn Write,
) -> std::io::Result<()> {
    match (out, format) {
        (Output::Report(r), Format::Human) => write!(w, "{}", report_human(r, color)),
        (Output::Report(r), Format::Json) => {
            write!(w, "{}\n", serde_json::to_string_pretty(r).map_err(io_err)?)
        }
        (Output::Report(r), Format::Jsonl) => {
            write!(w, "{}\n", serde_json::to_string(r).map_err(io_err)?)
        }
        (Output::Report(r), Format::Yaml) => write!(w, "{}", to_yaml(r)),

        (Output::Compare(c), Format::Human) => write!(w, "{}", compare_human(c)),
        (Output::Compare(c), Format::Json) => {
            write!(w, "{}\n", serde_json::to_string_pretty(c).map_err(io_err)?)
        }
        (Output::Compare(c), Format::Jsonl) => {
            write!(w, "{}\n", serde_json::to_string(c).map_err(io_err)?)
        }
        (Output::Compare(c), Format::Yaml) => write!(w, "{}", to_yaml(c)),

        (Output::Case(c), Format::Human) => write!(w, "{}", case_human(c)),
        (Output::Case(c), Format::Jsonl) => {
            // One Finding per line is the most useful JSONL form for a case.
            let base = serde_json::to_value(c).map_err(io_err)?;
            if let Some(map) = base.as_object() {
                let mut meta = map.clone();
                meta.remove("findings");
                write!(w, "{}\n", serde_json::to_string(&meta).map_err(io_err)?)?;
            }
            for f in &c.findings {
                write!(w, "{}\n", serde_json::to_string(f).map_err(io_err)?)?;
            }
            Ok(())
        }
        (Output::Case(c), fmt) => write_json_value(&serde_json::to_value(c).map_err(io_err)?, fmt, w),

        (Output::Value(v), fmt) => write_json_value(v, fmt, w),
        (Output::Text(t), _) => write!(w, "{t}"),
    }
}

fn write_json_value(
    v: &serde_json::Value,
    fmt: Format,
    w: &mut dyn Write,
) -> std::io::Result<()> {
    match fmt {
        Format::Json => write!(w, "{}\n", serde_json::to_string_pretty(v).map_err(io_err)?),
        Format::Jsonl => write!(w, "{}\n", serde_json::to_string(v).map_err(io_err)?),
        Format::Yaml => write!(w, "{}", to_yaml(v)),
        Format::Human => write!(w, "{}\n", serde_json::to_string_pretty(v).map_err(io_err)?),
    }
}

fn to_yaml<T: serde::Serialize>(t: &T) -> String {
    serde_yaml::to_string(t).unwrap_or_else(|e| format!("(yaml error: {e})\n"))
}

fn io_err(e: serde_json::Error) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::Other, e.to_string())
}

// ---------------------------------------------------------------------------
// ANSI helpers
// ---------------------------------------------------------------------------

pub const RESET: &str = "\x1b[0m";
pub const BOLD: &str = "\x1b[1m";
pub const DIM: &str = "\x1b[2m";

pub fn severity_color(sev: Severity) -> &'static str {
    match sev {
        Severity::Info => "\x1b[90m",
        Severity::Note => "\x1b[36m",
        Severity::Warning => "\x1b[33m",
        Severity::Critical => "\x1b[31m",
    }
}

pub fn confidence_color(c: Confidence) -> &'static str {
    match c {
        Confidence::Direct => "\x1b[32m",
        Confidence::Derived => "\x1b[36m",
        Confidence::Inferred => "\x1b[33m",
    }
}

fn human_size(n: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut v = n as f64;
    let mut u = 0;
    while v >= 1024.0 && u < UNITS.len() - 1 {
        v /= 1024.0;
        u += 1;
    }
    if u == 0 {
        format!("{n} B")
    } else {
        format!("{v:.1} {}", UNITS[u])
    }
}

// ---------------------------------------------------------------------------
// Human rendering
// ---------------------------------------------------------------------------

fn loc_human(loc: &Location) -> String {
    match loc {
        Location::Route { path } => format!("@ {path}"),
        Location::Bytes { start, end, note } => {
            let rng = match end {
                Some(e) => format!("0x{start:x}..0x{e:x}"),
                None => format!("0x{start:x}"),
            };
            match note {
                Some(n) => format!("@bytes {rng} ({n})"),
                None => format!("@bytes {rng}"),
            }
        }
        Location::Entity { kind, name } => format!("@{kind}:{name}"),
    }
}

pub fn report_human(r: &AnalysisReport, color: bool) -> String {
    use std::fmt::Write;
    let mut out = String::new();
    let a = &r.artifact;
    let _ = writeln!(out, "{BOLD}RET report — {}{RESET}", a.label);
    let _ = writeln!(out, "{DIM}name    {}{RESET}", a.name);
    let _ = writeln!(out, "{DIM}path    {}{RESET}", a.path);
    let _ = writeln!(out, "kind    {}", a.kind);
    let _ = writeln!(out, "size    {} ({} bytes)", human_size(a.size), a.size);
    let sha = if a.sha256.is_empty() {
        "<not hashed>".to_string()
    } else {
        a.sha256.clone()
    };
    let _ = writeln!(out, "sha256  {sha}");
    if !r.facts.is_empty() {
        let _ = writeln!(out, "digest  {}", r.structural_digest());
    }
    if let Some(c) = &a.container {
        let _ = writeln!(out, "shell   {c}");
    }
    let (i, n, w, c) = r.severity_counts();
    let _ = writeln!(
        out,
        "\nfindings {}{} = {}{c} critical{} + {w} warning + {n} note + {i} info",
        BOLD,
        i + n + w + c,
        severity_color(Severity::Critical),
        RESET
    );
    for f in &r.findings {
        write_finding(&mut out, f, color);
    }
    out
}

fn write_finding(out: &mut String, f: &Finding, color: bool) {
    use std::fmt::Write;
    let sev = f.severity.label();
    let cfg = f.confidence.label();
    if color {
        let _ = writeln!(
            out,
            "\n {}{sev}{RESET} {BOLD}{}{RESET}  {}{cfg}{RESET}",
            severity_color(f.severity),
            f.id,
            confidence_color(f.confidence)
        );
    } else {
        let _ = writeln!(out, "\n [{sev}] {}  ({cfg})", f.id);
    }
    let _ = writeln!(out, "   {BOLD}{}{RESET}", f.claim);
    for e in &f.evidence {
        let _ = writeln!(
            out,
            "     · {DIM}{}{RESET}  {}  {}",
            e.label,
            e.value,
            loc_human(&e.location)
        );
    }
    if let Some(run) = f.run {
        let _ = writeln!(out, "     · run {run}");
    }
    for l in &f.limitations {
        let _ = writeln!(out, "     ! {DIM}limitation: {l}{RESET}");
    }
}

pub fn compare_human(c: &CompareResult) -> String {
    use std::fmt::Write;
    let mut out = String::new();
    let verdict = format!("{:?}", c.verdict);
    let _ = writeln!(
        out,
        "{BOLD}compare: {}{RESET}",
        match c.verdict {
            crate::compare::Verdict::IdenticalBytes => "identical bytes",
            crate::compare::Verdict::StructurallyEqual => "structurally equal",
            crate::compare::Verdict::Changed => "changed",
            crate::compare::Verdict::NotComparable => "not comparable",
        }
    );
    let _ = writeln!(out, "  a  {}  ({} bytes, {})", c.a.name, c.a.size, c.a.sha256);
    let _ = writeln!(out, "  b  {}  ({} bytes, {})", c.b.name, c.b.size, c.b.sha256);
    let _ = writeln!(
        out,
        "  {} field(s) differ across {} structural facts",
        c.changed_field_count,
        verdict
    );
    for x in &c.explanations {
        let _ = writeln!(out, "  ! {x}");
    }
    for ch in &c.changes {
        let kind = match ch.kind {
            crate::compare::ChangeKind::Added => "added  ",
            crate::compare::ChangeKind::Removed => "removed",
            crate::compare::ChangeKind::Modified => "changed",
        };
        let _ = write!(out, "  {kind}  {}", ch.key);
        match (&ch.before, &ch.after) {
            (Some(b), Some(a)) => {
                let _ = writeln!(out, ": {:?} → {:?}", trunc(&b), trunc(&a));
            }
            (Some(b), None) => {
                let _ = writeln!(out, ": {:?} (was present)", trunc(&b));
            }
            (None, Some(a)) => {
                let _ = writeln!(out, ": {:?} (new)", trunc(&a));
            }
            (None, None) => {}
        }
    }
    out
}

fn trunc(v: &serde_json::Value) -> serde_json::Value {
    match v {
        serde_json::Value::String(s) if s.len() > 120 => {
            serde_json::Value::String(format!("{}…", &s[..120]))
        }
        other => other.clone(),
    }
}

pub fn case_human(c: &Case) -> String {
    use std::fmt::Write;
    let mut out = String::new();
    let _ = writeln!(out, "{BOLD}case {}{RESET} — {}", c.id, c.description);
    let _ = writeln!(out, "created {}", c.created.format("%Y-%m-%d %H:%M:%S %Z"));
    let _ = writeln!(out, "updated {}", c.updated.format("%Y-%m-%d %H:%M:%S %Z"));
    let _ = writeln!(out, "artifacts {}", c.artifacts.len());
    let _ = writeln!(out, "findings {}", c.findings.len());
    let _ = writeln!(out, "snapshots {}", c.snapshots.len());
    for a in c.artifacts.iter().take(30) {
        let _ = writeln!(out, "  {}  {} bytes  {}", a.name, a.size, a.sha256);
    }
    if c.artifacts.len() > 30 {
        let _ = writeln!(out, "  …and {} more", c.artifacts.len() - 30);
    }
    out
}
