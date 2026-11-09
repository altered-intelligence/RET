//! Command line interface for RET.
//!
//! Every command shares the evidence model: an `analyze` produces a report,
//! `record` archives it into the case file, `compare` explains how two
//! artifacts differ, and the rest are conveniences built on the same
//! primitives. All commands accept `--format human|json|jsonl|yaml`.

use std::io::{IsTerminal, Write};
use std::path::PathBuf;

use clap::{ArgAction, Parser, Subcommand};

use crate::analysis::Settings;
use crate::core::error::{Error, Result};
use crate::output::{Format, Output};

#[derive(Parser)]
#[command(
    name = "ret",
    version,
    about = "RET — Reverse Engineering Toolkit.",
    long_about = "RET — Reverse Engineering Toolkit: the local, evidence-first reverse \
        engineering workbench. RET analyzes binaries, apps, archives and captures locally, \
        records every conclusion with its evidence (byte locations, confidence, \
        limitations) into a case file, and exposes the same analysis to terminals, \
        agents (MCP), and a local web dashboard.",
    after_help = "Global options:\n  --format    output format: human, json, jsonl, yaml\n  --no-color  disable ANSI colors\n  --no-redact disable credential redaction in HAR payloads\n\nExamples:\n  ret analyze ./sample.elf\n  ret analyze ./app --record\n  ret iocs ./sample.bin\n  ret entropy ./sample.bin\n  ret batch ./vendor --record\n  ret compare app.v1 app.v2\n  ret report --out sarif --output case.sarif\n  ret serve --port 8100\n  ret mcp\n  ret doctor"
)]
struct Cli {
    #[arg(long, global = true, default_value = "human", value_name = "FMT",
          help = "Output format: human, json, jsonl, yaml")]
    format: String,

    #[arg(long, global = true, action = ArgAction::SetTrue,
          help = "Disable ANSI colors in human output")]
    no_color: bool,

    #[arg(long, global = true, action = ArgAction::SetTrue,
          help = "Disable credential redaction in HAR payload captures")]
    no_redact: bool,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Analyze a single file, directory, or archived app/web capture.
    Analyze(AnalyzeArgs),
    /// Scan a directory tree and analyze many artifacts in parallel.
    Batch(BatchArgs),
    /// Compare two artifacts (or a path against its recorded history).
    Compare(CompareArgs),
    /// Analyze an artifact and record it (findings + snapshot) into a case file.
    Record(RecordArgs),
    /// Show recorded snapshots for an artifact path.
    History(HistoryArgs),
    /// Export the case file as a Markdown, standalone HTML, or SARIF 2.1.0 report.
    Report(ReportArgs),
    /// List and run user plugins.
    #[command(subcommand)]
    Plugins(PluginsArgs),
    /// Environment & dependency readiness report.
    Doctor(DoctorArgs),
    /// Serve the embedded web dashboard.
    Serve(ServeArgs),
    /// Run the MCP server over stdio (for agents).
    Mcp,
    /// Disassemble a native binary via an external engine.
    Disassemble(DisassembleArgs),
    /// Extract printable strings from a file.
    Strings(StringsArgs),
    /// Extract indicators of compromise (URLs, IPs, hashes, paths...) with byte offsets.
    Iocs(IocsArgs),
    /// Profile Shannon entropy across an artifact and flag high-entropy regions.
    Entropy(EntropyArgs),
    /// Write the agent skill and MCP client registration to the current directory.
    Setup,
}

#[derive(clap::Args)]
struct AnalyzeArgs {
    /// File, directory, or archived app to analyze.
    #[arg(value_name = "PATH")]
    path: PathBuf,
    /// Record the report into the case file as a new run.
    #[arg(long, action = ArgAction::SetTrue)]
    record: bool,
    /// Case directory (defaults to ./.ret/case).
    #[arg(long, value_name = "DIR")]
    case_dir: Option<PathBuf>,
    /// Disable external engine usage.
    #[arg(long, action = ArgAction::SetTrue)]
    no_engines: bool,
    /// Also write the report to this file (markdown when it ends .md).
    #[arg(long, value_name = "FILE")]
    export: Option<PathBuf>,
}

#[derive(clap::Args)]
struct BatchArgs {
    /// Root directory to scan.
    #[arg(value_name = "ROOT")]
    root: PathBuf,
    /// Maximum directory depth.
    #[arg(long, default_value_t = 4, value_name = "N")]
    depth: usize,
    /// Number of worker threads.
    #[arg(long, default_value_t = 8, value_name = "N")]
    workers: usize,
    /// Maximum number of files to analyze.
    #[arg(long, default_value_t = 2000, value_name = "N")]
    max_items: usize,
    /// Include hidden files and directories.
    #[arg(long, action = ArgAction::SetTrue)]
    include_hidden: bool,
    /// Record every report into the case file.
    #[arg(long, action = ArgAction::SetTrue)]
    record: bool,
    /// Case directory (defaults to ./.ret/case).
    #[arg(long, value_name = "DIR")]
    case_dir: Option<PathBuf>,
}

#[derive(clap::Args)]
struct CompareArgs {
    /// First artifact (or `history:` to compare against recorded history).
    #[arg(value_name = "A")]
    a: PathBuf,
    /// Second artifact (omit when using `history:`).
    #[arg(value_name = "B", required_unless_present = "history")]
    b: Option<PathBuf>,
    /// Compare A against its latest recorded snapshot instead of a second file.
    #[arg(long, action = ArgAction::SetTrue)]
    history: bool,
    /// Case directory (defaults to ./.ret/case).
    #[arg(long, value_name = "DIR")]
    case_dir: Option<PathBuf>,
}

#[derive(clap::Args)]
struct RecordArgs {
    #[arg(value_name = "PATH")]
    path: PathBuf,
    #[arg(long, value_name = "DIR")]
    case_dir: Option<PathBuf>,
    #[arg(long, default_value = "manual record", value_name = "TEXT")]
    description: String,
    /// Do not archive findings, only the snapshot (name/size/hash).
    #[arg(long, action = ArgAction::SetTrue)]
    snapshot_only: bool,
}

#[derive(clap::Args)]
struct HistoryArgs {
    #[arg(value_name = "PATH")]
    path: PathBuf,
    #[arg(long, value_name = "DIR")]
    case_dir: Option<PathBuf>,
    #[arg(long, value_name = "N", help = "Show at most the last N snapshots")]
    last: Option<usize>,
}

#[derive(clap::Args)]
struct ReportArgs {
    #[arg(long, value_name = "DIR")]
    case_dir: Option<PathBuf>,
    /// Output format: markdown or html.
    #[arg(long, default_value = "markdown", value_name = "FMT")]
    out: String,
    /// Write to a file instead of stdout.
    #[arg(long, value_name = "FILE")]
    output: Option<PathBuf>,
}

#[derive(Subcommand)]
enum PluginsArgs {
    /// List installed plugins.
    #[command(name = "list")]
    List,
    /// Run a plugin against an artifact and merge its findings.
    #[command(name = "run")]
    Run {
        /// Plugin name (the directory in ~/.ret/plugins/<name>).
        name: String,
        /// Artifact to hand to the plugin.
        path: PathBuf,
    },
}

#[derive(clap::Args)]
struct DoctorArgs {}

#[derive(clap::Args)]
struct ServeArgs {
    /// Bind port.
    #[arg(long, default_value_t = 8100, value_name = "PORT")]
    port: u16,
    /// Bind address.
    #[arg(long, default_value = "127.0.0.1", value_name = "ADDR")]
    bind: String,
    #[arg(long, value_name = "DIR")]
    case_dir: Option<PathBuf>,
}

#[derive(clap::Args)]
struct DisassembleArgs {
    #[arg(value_name = "PATH")]
    path: PathBuf,
    /// Engine to use: objdump or radare2.
    #[arg(long, default_value = "objdump", value_name = "ENGINE")]
    engine: String,
    /// Restrict to context around this symbol/substring.
    #[arg(long, value_name = "NEEDLE")]
    needle: Option<String>,
}

#[derive(clap::Args)]
struct StringsArgs {
    #[arg(value_name = "PATH")]
    path: PathBuf,
    /// Minimum string length.
    #[arg(long, default_value_t = 4, value_name = "N")]
    min: usize,
    /// Maximum number of strings to report.
    #[arg(long, default_value_t = 200, value_name = "N")]
    max: usize,
}

#[derive(clap::Args)]
struct IocsArgs {
    /// File to extract indicators from.
    #[arg(value_name = "PATH")]
    path: PathBuf,
    /// Record the report into the case file as a new run.
    #[arg(long, action = ArgAction::SetTrue)]
    record: bool,
    /// Case directory (defaults to ./.ret/case).
    #[arg(long, value_name = "DIR")]
    case_dir: Option<PathBuf>,
}

#[derive(clap::Args)]
struct EntropyArgs {
    /// File to profile.
    #[arg(value_name = "PATH")]
    path: PathBuf,
    /// Window size in bytes for the entropy map.
    #[arg(long, default_value_t = 4096, value_name = "N")]
    window: usize,
    /// High-entropy threshold in bits/byte.
    #[arg(long, default_value_t = 7.0, value_name = "BITS")]
    threshold: f64,
    /// Record the report into the case file as a new run.
    #[arg(long, action = ArgAction::SetTrue)]
    record: bool,
    /// Case directory (defaults to ./.ret/case).
    #[arg(long, value_name = "DIR")]
    case_dir: Option<PathBuf>,
}

pub fn run() -> Result<()> {
    let cli = Cli::parse();
    let format = Format::parse(&cli.format).map_err(Error::invalid_arg)?;
    let color = !cli.no_color && std::io::stdout().is_terminal();
    let prefs = AnalysisPrefs {
        no_engines: false,
        no_redact: cli.no_redact,
    };

    match cli.command {
        Command::Analyze(a) => cmd_analyze(a, prefs, format, color),
        Command::Batch(b) => cmd_batch(b, prefs, format, color),
        Command::Compare(c) => cmd_compare(c, prefs, format, color),
        Command::Record(r) => cmd_record(r, prefs, format, color),
        Command::History(h) => cmd_history(h, format, color),
        Command::Report(r) => cmd_report(r, format, color),
        Command::Plugins(p) => cmd_plugins(p, prefs, format, color),
        Command::Doctor(_) => cmd_doctor(format, color),
        Command::Serve(s) => crate::web::serve(&s.bind, s.port, case_dir(&s.case_dir)),
        Command::Mcp => crate::mcp::serve_stdio(),
        Command::Disassemble(d) => cmd_disassemble(d, format, color),
        Command::Strings(s) => cmd_strings(s, prefs, format, color),
        Command::Iocs(i) => cmd_iocs(i, prefs, format, color),
        Command::Entropy(e) => cmd_entropy(e, prefs, format, color),
        Command::Setup => cmd_setup(),
    }
}

/// Toggleable analysis preferences from the command line.
#[derive(Clone, Copy)]
struct AnalysisPrefs {
    no_engines: bool,
    no_redact: bool,
}

impl AnalysisPrefs {
    fn settings(&self) -> Settings {
        let mut s = Settings::default();
        if self.no_engines {
            s.allow_engines = false;
        }
        if self.no_redact {
            s.redact_credentials = false;
        }
        s
    }
}

fn case_dir(opt: &Option<PathBuf>) -> PathBuf {
    opt.clone()
        .unwrap_or_else(crate::core::casefile::default_case_dir)
}

fn cmd_analyze(a: AnalyzeArgs, prefs: AnalysisPrefs, format: Format, color: bool) -> Result<()> {
    let mut p = prefs;
    p.no_engines = a.no_engines;
    let settings = p.settings();
    let report = crate::analysis::analyze_path(&a.path, &settings)?;

    if a.record {
        let dir = case_dir(&a.case_dir);
        let mut case = crate::core::casefile::open_or_create(&dir, "auto-analyze")?;
        let run = case.snapshots.len() as u64 + 1;
        case.add_report(&report, run);
        case.add_snapshot(snapshot_of(&report));
        crate::core::casefile::save(&case, &dir)?;
    }

    if let Some(export_path) = &a.export {
        let text = if export_path.extension().map(|e| e == "md").unwrap_or(false) {
            crate::report::markdown_report(&report)
        } else {
            format!("{}\n", serde_json::to_string_pretty(&report)?)
        };
        std::fs::write(export_path, text)?;
    }

    let mut out = std::io::stdout().lock();
    crate::output::write_output(&Output::Report(&report), format, color, &mut out)?;
    Ok(())
}

fn snapshot_of(report: &crate::core::evidence::AnalysisReport) -> crate::core::casefile::Snapshot {
    crate::core::casefile::Snapshot {
        timestamp: chrono::Utc::now(),
        name: report.artifact.name.clone(),
        path: report.artifact.path.clone(),
        size: report.artifact.size,
        sha256: report.artifact.sha256.clone(),
        structural_digest: (!report.facts.is_empty()).then(|| report.structural_digest()),
        kind: Some(report.artifact.kind.clone()),
    }
}

fn cmd_batch(b: BatchArgs, prefs: AnalysisPrefs, format: Format, color: bool) -> Result<()> {
    let opts = crate::batch::BatchOptions {
        root: b.root.clone(),
        depth: b.depth,
        max_items: b.max_items,
        workers: b.workers,
        skip_hidden: !b.include_hidden,
        settings: prefs.settings(),
    };
    let result = if b.record {
        let dir = case_dir(&b.case_dir);
        let desc = format!("batch scan of {}", b.root.display());
        crate::batch::run_and_record(&opts, &dir, &desc)?
    } else {
        crate::batch::run(&opts)
    };
    let mut out = std::io::stdout().lock();
    if format == Format::Human {
        let summary = crate::batch::human_summary(&result);
        crate::output::write_output(&Output::Text(summary), format, color, &mut out)?;
        for it in result.items.iter().take(40) {
            writeln!(
                out,
                "  {}  {}  {} findings  {}",
                it.kind,
                it.path,
                it.findings,
                &it.sha256[..12.min(it.sha256.len())]
            )?;
        }
        if result.items.len() > 40 {
            writeln!(out, "  …and {} more", result.items.len() - 40)?;
        }
    } else {
        crate::output::write_output(&Output::Value(serde_json::to_value(&result)?), format, color, &mut out)?;
    }
    Ok(())
}

fn cmd_compare(c: CompareArgs, prefs: AnalysisPrefs, format: Format, color: bool) -> Result<()> {
    let settings = prefs.settings();
    let result = if c.history {
        let dir = case_dir(&c.case_dir);
        crate::compare::compare_against_history(&c.a, &dir, &settings)?
    } else {
        let b = c.b.as_ref().ok_or_else(|| Error::invalid_arg("compare needs B unless --history"))?;
        crate::compare::compare_paths(&c.a, b, &settings)?
    };
    let mut out = std::io::stdout().lock();
    crate::output::write_output(&Output::Compare(&result), format, color, &mut out)?;
    Ok(())
}

fn cmd_record(r: RecordArgs, prefs: AnalysisPrefs, format: Format, color: bool) -> Result<()> {
    let settings = prefs.settings();
    let report = crate::analysis::analyze_path(&r.path, &settings)?;
    let dir = case_dir(&r.case_dir);
    let mut case = crate::core::casefile::open_or_create(&dir, &r.description)?;
    let run = case.snapshots.len() as u64 + 1;
    if !r.snapshot_only {
        case.add_report(&report, run);
    }
    case.add_snapshot(snapshot_of(&report));
    crate::core::casefile::save(&case, &dir)?;
    let summary = serde_json::json!({
        "recorded": report.artifact.path,
        "run": run,
        "kind": report.artifact.kind,
        "sha256": report.artifact.sha256,
        "case_dir": dir.display().to_string(),
        "snapshot_only": r.snapshot_only,
    });
    let mut out = std::io::stdout().lock();
    crate::output::write_output(&Output::Value(summary), format, color, &mut out)?;
    Ok(())
}

fn cmd_history(h: HistoryArgs, format: Format, color: bool) -> Result<()> {
    let dir = case_dir(&h.case_dir);
    let case = crate::core::casefile::open_or_create(&dir, "history view")?;
    let path_str = h.path.display().to_string();
    let mut snaps: Vec<_> = case
        .snapshots
        .iter()
        .filter(|s| s.path == path_str)
        .collect();
    snaps.reverse();
    if let Some(last) = h.last {
        snaps.truncate(last);
    }
    let names = {
        let artifact = case.artifacts.iter().find(|a| a.path == path_str);
        artifact.map(|a| a.name.clone())
    };
    let value = serde_json::json!({
        "path": path_str,
        "name": names,
        "snapshots": snaps.iter().map(|s| serde_json::json!({
            "timestamp": s.timestamp,
            "name": s.name,
            "size": s.size,
            "sha256": s.sha256,
            "kind": s.kind,
            "structural_digest": s.structural_digest,
        })).collect::<Vec<_>>(),
    });
    let mut out = std::io::stdout().lock();
    if format == Format::Human && snaps.is_empty() {
        crate::output::write_output(
            &Output::Text(format!(
                "no recorded history for {path_str} {} (use `ret record` first)\n",
                if names.is_some() { "(known artifact)" } else { "" }
            )),
            format,
            color,
            &mut out,
        )?;
    } else if format == Format::Human {
        for s in &snaps {
            writeln!(
                out,
                "{}  {}  {} bytes  {}",
                s.timestamp.format("%Y-%m-%d %H:%M:%S UTC"),
                s.sha256,
                s.size,
                s.kind.as_deref().unwrap_or("?"),
            )?;
        }
    } else {
        crate::output::write_output(&Output::Value(value), format, color, &mut out)?;
    }
    Ok(())
}

fn cmd_report(r: ReportArgs, format: Format, _color: bool) -> Result<()> {
    let dir = case_dir(&r.case_dir);
    let case = crate::core::casefile::open_or_create(&dir, "report export")?;
    let out_fmt = r.out.to_ascii_lowercase();
    let text = match out_fmt.as_str() {
        "html" => crate::report::html_case(&case),
        "markdown" | "md" => crate::report::markdown_case(&case),
        "sarif" => crate::report::sarif_case(&case),
        other => {
            return Err(Error::invalid_arg(format!(
                "report --out must be markdown, html, or sarif, got '{other}'"
            )))
        }
    };
    if let Some(path) = r.output {
        std::fs::write(&path, text)?;
        crate::output::write_output(
            &Output::Text(format!("wrote {} report to {}\n", out_fmt, path.display())),
            format,
            false,
            &mut std::io::stdout().lock(),
        )?;
    } else {
        crate::output::write_output(
            &Output::Text(text),
            Format::Human,
            false,
            &mut std::io::stdout().lock(),
        )?;
    }
    Ok(())
}

fn cmd_plugins(p: PluginsArgs, prefs: AnalysisPrefs, format: Format, color: bool) -> Result<()> {
    let mut out = std::io::stdout().lock();
    match p {
        PluginsArgs::List => {
            let plugins = crate::plugins::discover();
            let value = serde_json::json!({
                "user_dir": crate::plugins::user_plugin_root().display().to_string(),
                "local_dir": crate::plugins::local_plugin_root().display().to_string(),
                "plugins": plugins.iter().map(|pl| serde_json::json!({
                    "name": pl.manifest.name,
                    "version": pl.manifest.version,
                    "description": pl.manifest.description,
                    "formats": pl.manifest.formats,
                    "entry": pl.manifest.entry,
                    "dir": pl.dir.display().to_string(),
                })).collect::<Vec<_>>(),
            });
            if format == Format::Human {
                writeln!(out, "user plugins: {}", crate::plugins::user_plugin_root().display())?;
                writeln!(out, "local plugins: {}", crate::plugins::local_plugin_root().display())?;
                if plugins.is_empty() {
                    writeln!(out, "(no plugins installed)\nAdd one:\n  mkdir -p ~/.ret/plugins/my-plugin\n  # write plugin.toml + executable entry there")?;
                }
                for pl in &plugins {
                    writeln!(
                        out,
                        "\n{} v{}  — {}",
                        pl.manifest.name, pl.manifest.version, pl.manifest.description
                    )?;
                    writeln!(out, "    formats: {}", if pl.manifest.formats.is_empty() { "any".into() } else { pl.manifest.formats.join(", ") })?;
                    writeln!(out, "    entry:   {}", pl.manifest.entry.join(" "))?;
                }
            } else {
                crate::output::write_output(&Output::Value(value), format, color, &mut out)?;
            }
        }
        PluginsArgs::Run { name, path } => {
            let plugin = crate::plugins::get(&name)?;
            let findings = crate::plugins::run(&plugin, &path)?;
            // Attach plugin findings to an analyzer frame so they ride the same
            // evidence model and renderers.
            let mut report = crate::analysis::analyzer_unrecognized(&path, &prefs.settings(), "plugin analysis");
            report.artifact.kind = "plugin".into();
            report.artifact.label = format!("{} plugin output", plugin.manifest.name);
            report.findings = findings;
            crate::output::write_output(&Output::Report(&report), format, color, &mut out)?;
        }
    }
    Ok(())
}

fn cmd_doctor(format: Format, color: bool) -> Result<()> {
    let mut findings = Vec::new();
    let mut f = crate::core::evidence::Finding::new(
        "doctor.version",
        format!("ret {}", env!("CARGO_PKG_VERSION")),
        crate::core::evidence::Severity::Info,
        crate::core::evidence::Confidence::Direct,
    );
    findings.push(f);

    // rust toolchain
    f = crate::core::evidence::Finding::new(
        "doctor.rust",
        format!("rust {}", rustc_version()),
        crate::core::evidence::Severity::Info,
        crate::core::evidence::Confidence::Direct,
    );
    f.evidence.push(crate::core::evidence::Evidence::new(
        "doctor.rust.toolchain",
        rustc_version(),
        crate::core::evidence::Location::route("PATH"),
    ));
    findings.push(f);

    // engines
    let engines = crate::analysis::engines::doctor_report();
    findings.extend(engines.findings);

    // case dir writability
    let dir = crate::core::casefile::default_case_dir();
    let _ = std::fs::create_dir_all(&dir);
    if std::fs::metadata(&dir).map(|m| m.is_dir()).unwrap_or(false) {
        f = crate::core::evidence::Finding::new(
            "doctor.case_dir",
            format!("case dir writable at {}", dir.display()),
            crate::core::evidence::Severity::Info,
            crate::core::evidence::Confidence::Derived,
        );
        f.evidence.push(crate::core::evidence::Evidence::derived(
            "doctor.case_dir.path",
            dir.display().to_string(),
            crate::core::evidence::Location::route("cwd"),
        ));
    } else {
        f = crate::core::evidence::Finding::new(
            "doctor.case_dir",
            format!("cannot create case dir at {}", dir.display()),
            crate::core::evidence::Severity::Warning,
            crate::core::evidence::Confidence::Derived,
        );
    }
    findings.push(f);

    // plugins
    let plugins = crate::plugins::discover();
    f = crate::core::evidence::Finding::new(
        "doctor.plugins",
        format!("{} plugin(s) installed", plugins.len()),
        crate::core::evidence::Severity::Info,
        crate::core::evidence::Confidence::Direct,
    );
    findings.push(f);

    let mut report = crate::core::evidence::AnalysisReport::new(
        crate::core::evidence::ArtifactIdentity {
            name: "ret doctor".into(),
            path: "environment".into(),
            size: 0,
            sha256: String::new(),
            kind: "doctor".into(),
            label: "RET environment & dependencies".into(),
            container: None,
        },
        findings,
    );
    let available: Vec<String> = engines
        .facts
        .get("engines.available")
        .and_then(|v| v.as_array())
        .map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect())
        .unwrap_or_default();
    report
        .facts
        .insert("doctor.engines_available".into(), serde_json::json!(available));
    report
        .facts
        .insert("doctor.plugins".into(), serde_json::json!(plugins.len()));
    let mut out = std::io::stdout().lock();
    crate::output::write_output(&Output::Report(&report), format, color, &mut out)?;
    Ok(())
}

fn rustc_version() -> String {
    std::process::Command::new("rustc")
        .arg("--version")
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| "unknown".into())
}

fn cmd_disassemble(d: DisassembleArgs, format: Format, color: bool) -> Result<()> {
    let finding = crate::analysis::engines::disassemble(
        &d.path.display().to_string(),
        d.needle.as_deref(),
        &d.engine,
    )?;
    let report = crate::core::evidence::AnalysisReport::new(
        crate::core::evidence::ArtifactIdentity {
            name: d.path.display().to_string(),
            path: d.path.display().to_string(),
            size: std::fs::metadata(&d.path).map(|m| m.len()).unwrap_or(0),
            sha256: crate::core::digests::hex(&crate::core::digests::hash_file(&d.path)?),
            kind: "disassembly".into(),
            label: format!("{} disassembly", d.engine),
            container: None,
        },
        vec![finding],
    );
    let mut out = std::io::stdout().lock();
    crate::output::write_output(&Output::Report(&report), format, color, &mut out)?;
    Ok(())
}

fn cmd_strings(s: StringsArgs, prefs: AnalysisPrefs, format: Format, color: bool) -> Result<()> {
    let settings = prefs.settings();
    let bytes = crate::analysis::read_bounded(&s.path, settings.head_limit)?;
    let hits = crate::analysis::binary::scan_strings(&bytes, s.min);
    let mut out = std::io::stdout().lock();
    if format == Format::Human {
        let count = hits.len().min(s.max);
        writeln!(
            out,
            "{} printable strings (showing {} from {} total) in {}",
            hits.len(),
            count,
            hits.len(),
            s.path.display()
        )?;
        for h in hits.iter().take(s.max) {
            writeln!(out, "  0x{:08x}  {}", h.offset, h.text)?;
        }
    } else {
        let value = serde_json::json!({
            "path": s.path.display().to_string(),
            "min_len": s.min,
            "total": hits.len(),
            "strings": hits.iter().take(s.max).map(|h| serde_json::json!({
                "offset": h.offset,
                "text": h.text,
            })).collect::<Vec<_>>(),
        });
        crate::output::write_output(&Output::Value(value), format, color, &mut out)?;
    }
    Ok(())
}

fn cmd_iocs(i: IocsArgs, prefs: AnalysisPrefs, format: Format, color: bool) -> Result<()> {
    let settings = prefs.settings();
    let report = crate::analysis::iocs::analyze(&i.path, &settings)?;
    if i.record {
        let dir = case_dir(&i.case_dir);
        let mut case = crate::core::casefile::open_or_create(&dir, "ioc extraction")?;
        let run = case.snapshots.len() as u64 + 1;
        case.add_report(&report, run);
        case.add_snapshot(snapshot_of(&report));
        crate::core::casefile::save(&case, &dir)?;
    }
    let mut out = std::io::stdout().lock();
    crate::output::write_output(&Output::Report(&report), format, color, &mut out)?;
    Ok(())
}

fn cmd_entropy(e: EntropyArgs, prefs: AnalysisPrefs, format: Format, color: bool) -> Result<()> {
    let settings = prefs.settings();
    let report = crate::analysis::entropy::analyze(&e.path, &settings, e.window, e.threshold)?;
    if e.record {
        let dir = case_dir(&e.case_dir);
        let mut case = crate::core::casefile::open_or_create(&dir, "entropy profile")?;
        let run = case.snapshots.len() as u64 + 1;
        case.add_report(&report, run);
        case.add_snapshot(snapshot_of(&report));
        crate::core::casefile::save(&case, &dir)?;
    }
    let mut out = std::io::stdout().lock();
    crate::output::write_output(&Output::Report(&report), format, color, &mut out)?;
    Ok(())
}

const SKILL_TEXT: &str = r#"# RET — Agent Skill

You have access to RET (Reverse Engineering Toolkit), a local, evidence-first
reverse engineering workbench. Use these tools to understand any binary, app,
archive, or capture the user points you at. **Never** modify, execute, or
upload the artifact; all analysis is static and local.

## Available tools

- `analyze_artifact(path)` — full analysis. Use this first for any file or
  directory. Returns findings with evidence (byte locations), confidence and
  limitations.
- `inspect_native_binary(path)` — ELF/PE/Mach-O focus (headers, sections,
  hardening, runtime markers).
- `inspect_managed_assembly(path)` — help text for .NET / CLR assemblies.
- `inspect_javascript_application(path)` — JS app / Electron focus (package
  deps, module graph, ASAR, routes, boundaries, sourcemaps).
- `search_strings(path, min_len)` — printable strings with byte offsets.
- `extract_iocs(path)` — URLs, IPv4s, domains, e-mails, MD5/SHA1/SHA256
  literals, registry keys, and file paths with byte offsets (ASCII/UTF-8 and
  UTF-16LE). Evidence-first: every indicator cites the bytes it came from.
- `entropy_profile(path, window, threshold)` — Shannon-entropy map with
  high-entropy regions as byte ranges (packed/encrypted-looking content).
- `compare_artifacts(a, b)` — structural diff of two artifacts.
- `batch_inventory(root)` — directory scan: kinds, counts, findings.
- `provider_status()` — which native engines (objdump/r2) are on PATH.
- `list_plugins()` / `run_plugin(name, path)` — user plugins.
- `disassemble_binary(path, needle, engine)` — objdump/radare2 disassembly.

## How to read a finding

Every finding carries:

1. **claim** — what RET concluded.
2. **evidence** — the observed facts (labels + values + byte locations). Verify
   suspicious claims by re-reading the bytes at those offsets.
3. **confidence** — `direct` (observed), `derived` (computed from observations),
   or `inferred` (heuristic, may be wrong). Treat `inferred` conclusions as
   leads, not facts.
4. **limitations** — what the analysis could not establish.

## Good practice

- Start broad (`analyze_artifact`), then focus (`inspect_*`, `disassemble`).
- Corroborate `inferred` findings before stating them as fact.
- Never present string content as credentials or secrets to the user verbatim;
  redact and summarize. Do not echo private keys or tokens from strings.
- When reporting to the user, cite the analysis `id` and the strongest
  evidence/byte location that supports the conclusion.
- If analysis is not sufficient, say what *would* establish the claim and
  offer to run it.
"#;

fn cmd_setup() -> Result<()> {
    let cwd = std::env::current_dir().map_err(|e| Error::new(crate::core::error::ErrorKind::Io, e.to_string()))?;
    let skill_path = cwd.join("ret-agent-skill.md");
    std::fs::write(&skill_path, SKILL_TEXT)?;
    let mcp_cmd = std::env::current_exe()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|_| "ret".into());
    let snippet = format!(
        "{{\n  \"mcpServers\": {{\n    \"ret-mcp\": {{\n      \"command\": \"{mcp_cmd}\",\n      \"args\": [\"mcp\"],\n      \"type\": \"stdio\"\n    }}\n  }}\n}}\n"
    );
    let mcp_path = cwd.join("ret-mcp-client.json");
    std::fs::write(&mcp_path, &snippet)?;
    println!(
        "wrote agent skill to {}\nwrote MCP client registration to {}\n\nRegistration (merge into your client's MCP config):\n{}\nMCP server connects over stdio:\n  {mcp_cmd} mcp\n",
        skill_path.display(),
        mcp_path.display(),
        snippet.trim_end()
    );
    Ok(())
}
