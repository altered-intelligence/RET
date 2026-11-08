//! JavaScript / Electron application analysis: package metadata, ASAR
//! inventory, module/import graph, Electron main/preload/renderer boundaries,
//! source maps, and route heuristics. Runs only on the files supplied.

use std::path::Path;

use walkdir::WalkDir;

use crate::analysis::{AnalysisContext, identity_for};
use crate::core::error::{Error, Result};
use crate::core::evidence::{AnalysisReport, Confidence, Evidence, Finding, Location, Severity};

const MAX_JS_BYTES: u64 = 64 * 1024 * 1024;
const MAX_JS_FILES: usize = 4000;
const MAX_NODE_BYTES: usize = 256 * 1024;

pub fn analyze_directory(ctx: &AnalysisContext) -> Result<AnalysisReport> {
    let dir = &ctx.path;
    if !dir.is_dir() {
        return Err(Error::invalid_arg("expected a directory"));
    }
    let is_js_root = dir.join("package.json").is_file() || dir.join("app.asar").is_file();
    let label = if is_js_root {
        "JavaScript / Electron application directory"
    } else {
        "Directory"
    };

    let mut findings: Vec<Finding> = Vec::new();
    let mut report = AnalysisReport::new(
        identity_for(dir, if is_js_root { "js_app" } else { "directory" }, label, &[])?,
        Vec::new(),
    );

    if is_js_root {
        js_app_analysis(ctx, dir, &mut findings, &mut report);
    } else {
        directory_inventory(ctx, dir, &mut findings, &mut report);
    }

    report.findings = findings;
    report.summary = summary(&report.findings);
    Ok(report)
}

// ---------------------------------------------------------------------------
// Generic directory inventory
// ---------------------------------------------------------------------------

fn directory_inventory(
    ctx: &AnalysisContext,
    dir: &Path,
    findings: &mut Vec<Finding>,
    report: &mut AnalysisReport,
) {
    let mut total_files = 0usize;
    let mut total_bytes = 0u64;
    let mut by_ext = std::collections::BTreeMap::<String, usize>::new();
    let mut top: Vec<String> = Vec::new();
    let mut found_manifests: Vec<String> = Vec::new();

    let mut walk = WalkDir::new(dir).max_depth(6).follow_links(false).into_iter();
    let mut guard = 0usize;
    while let Some(Ok(e)) = walk.next() {
        guard += 1;
        if guard > 200_000 {
            break;
        }
        if e.depth() == 0 {
            continue;
        }
        let p = e.path();
        if p.is_dir() {
            if e.depth() == 1 {
                top.push(
                    p.file_name()
                        .map(|s| s.to_string_lossy().into_owned())
                        .unwrap_or_default(),
                );
            }
            continue;
        }
        total_files += 1;
        if let Ok(m) = e.metadata() {
            total_bytes += m.len();
        }
        let ext = p
            .extension()
            .map(|x| x.to_string_lossy().to_lowercase())
            .unwrap_or_default();
        *by_ext.entry(if ext.is_empty() { "(none)".to_string() } else { ext }).or_default() += 1;
        if p.file_name().map(|s| s == "package.json" || s == "Cargo.toml" || s == "pom.xml" || s == "go.mod").unwrap_or(false) {
            found_manifests.push(p.display().to_string());
        }
    }

    report.facts.insert("dir.files".into(), serde_json::json!(total_files));
    report.facts.insert("dir.bytes".into(), serde_json::json!(total_bytes));

    let mut inv = Finding::new(
        "directory.inventory",
        format!("{total_files} files, {}", crate::core::io::human_size(total_bytes)),
        Severity::Info,
        Confidence::Direct,
    );
    for t in top.iter().take(40) {
        inv.evidence.push(Evidence::new("directory.top", t.clone(), Location::route(t.clone())));
    }
    findings.push(inv);

    if !by_ext.is_empty() {
        let mut ef = Finding::new(
            "directory.file_types",
            format!("{} file extensions", by_ext.len()),
            Severity::Info,
            Confidence::Derived,
        );
        for (ext, n) in by_ext.iter().take(24) {
            ef.evidence.push(Evidence::derived(
                "directory.ext",
                format!(".{ext}: {n}"),
                Location::entity("extension", ext.clone()),
            ));
        }
        findings.push(ef);
    }

    if !found_manifests.is_empty() {
        let mut mf = Finding::new(
            "directory.manifests",
            format!("{} manifests found", found_manifests.len()),
            Severity::Info,
            Confidence::Direct,
        );
        for m in found_manifests.iter().take(10) {
            mf.evidence.push(Evidence::new("directory.manifest", m.clone(), Location::route(m.clone())));
        }
        findings.push(mf);
        // If it's not the root but has package.json, note the app is nested.
        let _ = ctx;
    }
}

// ---------------------------------------------------------------------------
// JS/Electron app analysis
// ---------------------------------------------------------------------------

fn js_app_analysis(
    ctx: &AnalysisContext,
    dir: &Path,
    findings: &mut Vec<Finding>,
    report: &mut AnalysisReport,
) {
    // ---- package.json ----
    let pkg_path = dir.join("package.json");
    let pkg = pkg_path.is_file().then(|| std::fs::read_to_string(&pkg_path).ok()).flatten();
    let pkg_json: Option<serde_json::Value> = pkg.as_ref().and_then(|s| serde_json::from_str(s).ok());
    let mut name = String::from("(unnamed)");
    let mut version = String::from("?");
    let mut main = String::from("?");
    let mut electron_version: Option<String> = None;
    let mut dependencies: Vec<String> = Vec::new();
    if let Some(j) = &pkg_json {
        name = j.get("name").and_then(|v| v.as_str()).unwrap_or("(unnamed)").to_string();
        version = j.get("version").and_then(|v| v.as_str()).unwrap_or("?").to_string();
        main = j.get("main").and_then(|v| v.as_str()).unwrap_or("index.js").to_string();
        if let Some(deps) = j.get("dependencies").and_then(|d| d.as_object()) {
            dependencies = deps.keys().cloned().collect();
        }
        if let Some(dev) = j.get("devDependencies").and_then(|d| d.as_object()) {
            dependencies.extend(dev.keys().cloned().collect::<Vec<_>>());
            electron_version = dev
                .get("electron")
                .and_then(|v| v.as_str())
                .map(|s| s.trim_start_matches(['^', '~', '>', '=']).to_string());
        }
    }

    report.facts.insert("js.name".into(), serde_json::json!(name.clone()));
    report.facts.insert("js.version".into(), serde_json::json!(version.clone()));

    let mut pf = Finding::new(
        "jsapp.package",
        format!("package '{name}' v{version}, main={main}, {} declared dependencies", dependencies.len()),
        Severity::Info,
        Confidence::Direct,
    );
    pf.evidence.push(Evidence::new("jsapp.package.name", name.clone(), Location::route("package.json")));
    pf.evidence.push(Evidence::new("jsapp.package.main", main.clone(), Location::route("package.json")));
    findings.push(pf);

    // ---- Electron detection ----
    let asar_paths: Vec<std::path::PathBuf> = [
        dir.join("app.asar"),
        dir.join("resources").join("app.asar"),
    ]
    .into_iter()
    .filter(|p| p.is_file())
    .collect();
    let electron_promise = electron_version.is_some() || !asar_paths.is_empty();

    let mut ef = Finding::new(
        "jsapp.electron",
        if electron_promise {
            "Electron application detected"
        } else {
            "no Electron markers found (plain Node.js project)"
        },
        Severity::Info,
        if electron_promise { Confidence::Direct } else { Confidence::Inferred },
    );
    if let Some(ev) = &electron_version {
        ef.evidence.push(Evidence::new("jsapp.electron.version", ev.clone(), Location::route("package.json")));
        report.facts.insert("js.electron_version".into(), serde_json::json!(ev));
    }
    for a in &asar_paths {
        ef.evidence.push(Evidence::new(
            "jsapp.electron.asar",
            format!("{} ({})", a.display(), human_file(a)),
            Location::route(a.display().to_string()),
        ));
    }
    ef.limitations.push("Electron detection is based on package metadata and ASAR presence".into());
    findings.push(ef);

    // ---- ASAR inventory ----
    for asar in &asar_paths {
        if let Ok(inv) = read_asar_inventory(asar) {
            let mut af = Finding::new(
                "jsapp.asar",
                format!(
                    "app.asar contains {} files ({})",
                    inv.count,
                    crate::core::io::human_size(inv.total_size)
                ),
                Severity::Info,
                Confidence::Direct,
            );
            for f in inv.notable.iter().take(16) {
                af.evidence.push(Evidence::new("jsapp.asar.file", f.clone(), Location::entity("asar", f.clone())));
            }
            findings.push(af);
        }
    }

    // ---- Walk JS sources ----
    let mut js_files = 0usize;
    let mut bytes_scanned: u64 = 0;
    let mut imports = std::collections::HashMap::<String, usize>::new();
    let mut local_imports = Vec::new();
    let mut ipc_main = 0usize;
    let mut ipc_renderer = 0usize;
    let mut browser_window = 0usize;
    let mut preload_refs = 0usize;
    let mut document_refs = 0usize;
    let mut map_files = 0usize;
    let mut source_map_comments = 0usize;
    let mut routes: Vec<String> = Vec::new();
    let mut all_js: Vec<std::path::PathBuf> = Vec::new();

    let mut walk = WalkDir::new(dir).max_depth(10).follow_links(false).into_iter();
    let mut guard = 0usize;
    while let Some(Ok(e)) = walk.next() {
        guard += 1;
        if guard > 100_000 || js_files >= MAX_JS_FILES || bytes_scanned >= MAX_JS_BYTES {
            break;
        }
        let p = e.path();
        if p.is_dir() {
            let name = p.file_name().map(|s| s.to_string_lossy().into_owned()).unwrap_or_default();
            if p != dir && matches!(name.as_str(), "node_modules" | ".git" | "dist" | "build" | "coverage") {
                walk.skip_current_dir();
            }
            continue;
        }
        let ext = p.extension().map(|x| x.to_string_lossy().to_lowercase()).unwrap_or_default();
        match ext.as_str() {
            "js" | "mjs" | "cjs" | "jsx" | "ts" | "tsx" => {
                js_files += 1;
                all_js.push(p.to_path_buf());
            }
            "map" => {
                if p.file_name().and_then(|s| s.to_str()).map(|s| s.ends_with(".map")).unwrap_or(false) {
                    map_files += 1;
                }
            }
            _ => {}
        }
    }

    for p in all_js.iter().take(MAX_JS_FILES) {
        let Ok(meta) = std::fs::metadata(p) else { continue };
        if meta.len() == 0 || meta.len() > MAX_NODE_BYTES as u64 {
            continue;
        }
        bytes_scanned += meta.len();
        let Ok(text) = std::fs::read_to_string(p) else { continue };
        scan_js_source(&text, &mut imports, &mut local_imports, &mut ipc_main, &mut ipc_renderer, &mut browser_window, &mut preload_refs, &mut document_refs, &mut source_map_comments, &mut routes);
    }

    report.facts.insert("js.files_scanned".into(), serde_json::json!(js_files));
    report.facts.insert("js.bytes_scanned".into(), serde_json::json!(bytes_scanned));

    // Import density
    let mut mf = Finding::new(
        "jsapp.modules",
        format!(
            "{} JS files scanned ({} bytes); {} module imports, {} local module references",
            js_files,
            bytes_scanned,
            imports.values().sum::<usize>(),
            local_imports.len()
        ),
        Severity::Info,
        Confidence::Derived,
    );
    let mut sorted: Vec<(&String, &usize)> = imports.iter().collect();
    sorted.sort_by(|a, b| b.1.cmp(a.1));
    for (modname, n) in sorted.iter().take(20) {
        mf.evidence.push(Evidence::derived(
            "jsapp.import",
            format!("{modname}: {n}"),
            Location::entity("import", (*modname).clone()),
        ));
    }
    mf.limitations.push("imports are detected by pattern; dynamic imports (import()) may be missed".into());
    findings.push(mf);

    // Electron boundaries
    if electron_promise {
        let preloading = main.to_string();
        let _ = preloading;
        let mut bf = Finding::new(
            "jsapp.electron_boundaries",
            format!(
                "main-process markers: ipcMain={ipc_main}, BrowserWindow={browser_window}; preload references={preload_refs}; renderer markers: ipcRenderer={ipc_renderer}, document={document_refs}"
            ),
            Severity::Info,
            Confidence::Derived,
        );
        bf.evidence.push(Evidence::derived(
            "jsapp.boundary.main",
            format!("ipcMain use={ipc_main}, BrowserWindow use={browser_window}"),
            Location::entity("electron", "main"),
        ));
        bf.evidence.push(Evidence::derived(
            "jsapp.boundary.renderer",
            format!("ipcRenderer use={ipc_renderer}, document/window use={document_refs}"),
            Location::entity("electron", "renderer"),
        ));
        if preload_refs > 0 {
            bf.evidence.push(Evidence::derived(
                "jsapp.boundary.preload",
                format!("preload script references={preload_refs}"),
                Location::entity("electron", "preload"),
            ));
        }
        findings.push(bf);
    }

    // Source maps
    if map_files > 0 || source_map_comments > 0 {
        let mut sf = Finding::new(
            "jsapp.sourcemaps",
            format!(
                "{map_files} .map file(s); {source_map_comments} sourceMappingURL comment(s)"
            ),
            Severity::Info,
            Confidence::Direct,
        );
        sf.evidence.push(Evidence::new(
            "jsapp.sourcemaps",
            format!("{map_files} .map file(s)"),
            Location::entity("sourcemap", ".map"),
        ));
        findings.push(sf);
    }

    // Routes
    if !routes.is_empty() {
        let mut rf = Finding::new(
            "jsapp.routes",
            format!("{} route-like patterns", routes.len()),
            Severity::Note,
            Confidence::Inferred,
        );
        let mut seen = std::collections::BTreeSet::new();
        for r in routes.iter().take(32) {
            if seen.insert(r.clone()) {
                rf.evidence.push(Evidence::inferred(
                    "jsapp.route",
                    r.clone(),
                    Location::entity("route", r.clone()),
                ));
            }
        }
        rf.limitations.push("route detection is heuristic (express-like patterns)".into());
        findings.push(rf);
    }

    let _ = ctx;
}

fn human_file(p: &Path) -> String {
    std::fs::metadata(p)
        .map(|m| crate::core::io::human_size(m.len()))
        .unwrap_or_else(|_| "?".into())
}

fn scan_js_source(
    text: &str,
    imports: &mut std::collections::HashMap<String, usize>,
    local_imports: &mut Vec<String>,
    ipc_main: &mut usize,
    ipc_renderer: &mut usize,
    browser_window: &mut usize,
    preload_refs: &mut usize,
    document_refs: &mut usize,
    source_map_comments: &mut usize,
    routes: &mut Vec<String>,
) {
    let bytes = text.as_bytes();
    let mut i = 0usize;
    while i < bytes.len() {
        // try to match require("x") / require('x') / from "x" / import "x"
        let window = text[i..].get(..256).unwrap_or(&text[i..]);
        let (module, consumed) = require_module(window);
        if consumed > 0 {
            if let Some(modname) = module {
                if modname.starts_with("./") || modname.starts_with("../") {
                    local_imports.push(modname.clone());
                }
                *imports.entry(modname).or_default() += 1;
            }
            i += consumed;
            continue;
        }

        // marker scanning
        if bytes[i..].starts_with(b"ipcMain") {
            *ipc_main += 1;
            i += 7;
        } else if bytes[i..].starts_with(b"ipcRenderer") {
            *ipc_renderer += 1;
            i += 11;
        } else if bytes[i..].starts_with(b"BrowserWindow") {
            *browser_window += 1;
            i += 13;
        } else if bytes[i..].starts_with(b"preload") {
            *preload_refs += 1;
            i += 7;
        } else if bytes[i..].starts_with(b"document.") {
            *document_refs += 1;
            i += 9;
        } else if bytes[i..].starts_with(b"sourceMappingURL=") {
            *source_map_comments += 1;
            i += 17;
        } else if let Some((method, path)) = route_pattern(window) {
            routes.push(format!("{method} {path}"));
            i += 1;
        } else {
            i += 1;
        }
    }
}

/// Detect `require("mod")`, `require('mod')`, `from "mod"`, `import "mod"`.
fn require_module(window: &str) -> (Option<String>, usize) {
    let b = window.as_bytes();
    for marker in [
        "require(\"",
        "require('",
        "from \"",
        "from '",
        "import \"",
        "import '",
    ] {
        if b.len() >= marker.len() && window.starts_with(marker) {
            let quote = marker.chars().last().unwrap();
            // Skip the whole marker so `rest` starts at the module name.
            let rest = &window[marker.len()..];
            let end = rest.find(quote).unwrap_or(rest.len());
            if end > 0 && end <= 512 {
                let name = rest[..end].to_string();
                return (Some(name), marker.len() + end + 1);
            }
        }
    }
    (None, 0)
}

/// Detect express-like route registrations.
fn route_pattern(window: &str) -> Option<(String, String)> {
    let b = window.as_bytes();
    for method in [".get(", ".post(", ".put(", ".delete(", ".patch(", ".use(", ".all("] {
        if b.len() >= method.len() && window.starts_with(method) {
            let rest = &window[method.len()..];
            let t = rest.trim_start();
            if t.starts_with('"') || t.starts_with('\'') {
                let quote = t.as_bytes()[0] as char;
                let inner = &t[1..];
                if let Some(end) = inner.find(quote) {
                    let path = inner[..end].to_string();
                    if !path.is_empty() && path.len() < 200 {
                        return Some((method.trim_matches(['(', '.']).to_uppercase(), path));
                    }
                }
            }
        }
    }
    None
}

// ---------------------------------------------------------------------------
// ASAR (Electron archive) parsing
// ---------------------------------------------------------------------------

struct AsarInventory {
    count: usize,
    total_size: u64,
    notable: Vec<String>,
}

fn read_asar_inventory(path: &Path) -> Result<AsarInventory> {
    let bytes = crate::analysis::read_bounded(path, 128 * 1024 * 1024)?;
    if bytes.len() < 16 || &bytes[0..4] != b"\x04\x00\x00\x00" {
        // ASAR starts with u32le size then u32le type (4 = pickle dict). The
        // type field itself is 4 => signature bytes are 04 00 00 00.
        return Err(Error::malformed("not an ASAR (missing pickle signature)"));
    }
    // Layout: size u32, header pickle size u32, type u32(=4) ...
    // Standard header parse:
    //   [0..4)    header_size (size of the rest)
    //   [4..8)    header pickle size
    //   [8..12)   pickle type (4)
    //   [12..16)  header JSON length
    let header_json_len = u32::from_le_bytes([bytes[12], bytes[13], bytes[14], bytes[15]]) as usize;
    let json_off = 16;
    if json_off + header_json_len > bytes.len() {
        return Err(Error::malformed("ASAR header JSON out of bounds"));
    }
    let header: serde_json::Value = serde_json::from_slice(&bytes[json_off..json_off + header_json_len])?;
    let mut inv = AsarInventory {
        count: 0,
        total_size: 0,
        notable: Vec::new(),
    };
    if let Some(files) = header.get("files").and_then(|f| f.as_object()) {
        walk_asar_files(files, "", &mut inv, 0);
    }
    Ok(inv)
}

fn walk_asar_files(
    files: &serde_json::Map<String, serde_json::Value>,
    prefix: &str,
    inv: &mut AsarInventory,
    depth: usize,
) {
    if depth > 12 {
        return;
    }
    for (name, v) in files {
        let full = if prefix.is_empty() {
            name.clone()
        } else {
            format!("{prefix}/{name}")
        };
        if let Some(sub) = v.get("files").and_then(|f| f.as_object()) {
            walk_asar_files(sub, &full, inv, depth + 1);
        } else {
            inv.count += 1;
            if let Some(size) = v.get("size").and_then(|s| s.as_u64()) {
                inv.total_size += size;
            }
            let lower = full.to_lowercase();
            if lower.ends_with(".js")
                || lower.contains("main")
                || lower.contains("preload")
                || lower.contains("package.json")
                || lower.ends_with(".node")
            {
                inv.notable.push(full);
            }
        }
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
