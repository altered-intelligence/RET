//! MCP (Model Context Protocol) server over stdio.
//!
//! A hand-rolled, line-delimited JSON-RPC 2.0 endpoint implementing the small
//! slice of MCP that agents actually need: `initialize`, `ping`, `tools/list`
//! and `tools/call`. Every tool returns RET's evidence-shaped findings as
//! structured JSON so an agent can reason about confidence and byte locations
//! instead of trusting a text blob.

use std::io::{BufRead, Write};
use std::path::{Path, PathBuf};

use serde_json::{json, Value};

use crate::analysis::Settings;
use crate::core::error::Result;
use crate::core::evidence::AnalysisReport;

const PROTOCOL_VERSION: &str = "2024-11-05";

struct Tool {
    name: &'static str,
    description: &'static str,
    input_schema: Value,
    call: fn(&Value) -> std::result::Result<String, String>,
}

/// Run the server until stdin closes.
pub fn serve_stdio() -> Result<()> {
    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    for line in stdin.lock().lines() {
        let line = match line {
            Ok(l) => l,
            Err(_) => break,
        };
        if line.trim().is_empty() {
            continue;
        }
        if let Some(resp) = handle_line(&line) {
            let mut text = serde_json::to_string(&resp).unwrap_or_else(|_| "{}".into());
            text.push('\n');
            if out.write_all(text.as_bytes()).is_err() {
                break;
            }
            let _ = out.flush();
        }
    }
    Ok(())
}

fn handle_line(raw: &str) -> Option<Value> {
    let v: Value = match serde_json::from_str(raw) {
        Ok(v) => v,
        Err(e) => {
            return Some(error_json(None, -32700, &format!("parse error: {e}")));
        }
    };
    let id = v.get("id").cloned();
    let method = match v.get("method").and_then(|m| m.as_str()) {
        Some(m) => m,
        None => return id.map(|i| error_json(Some(i), -32600, "invalid request")),
    };
    let params = v.get("params").cloned().unwrap_or_else(|| json!({}));
    if method == "tools/call" {
        return match tools_call(&params) {
            Ok(result) => Some(json!({
                "jsonrpc": "2.0",
                "id": id.unwrap_or(Value::Null),
                "result": result,
            })),
            Err((code, msg)) => Some(error_json(id, code, &msg)),
        };
    }
    let result = match method {
        "initialize" => Some(json!({
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": { "tools": {} },
            "serverInfo": { "name": "ret-mcp", "version": env!("CARGO_PKG_VERSION") },
        })),
        "ping" => Some(json!({})),
        "tools/list" => Some(json!({ "tools": schemas() })),
        // Notifications we knowingly ignore.
        "notifications/initialized" | "notifications/cancelled" | "notifications/roots/list_changed" => {
            None
        }
        "tools/unregister" | "prompts/list" | "resources/list" => Some(json!({})),
        other => {
            let id = id.clone();
            return Some(error_json(id, -32601, &format!("method not found: {other}")));
        }
    };
    match (id, result) {
        (Some(id), Some(result)) => Some(json!({
            "jsonrpc": "2.0", "id": id, "result": result,
        })),
        (Some(id), None) => Some(json!({
            "jsonrpc": "2.0", "id": id, "result": {},
        })),
        (None, _) => None, // notification, no reply
    }
}

fn error_json(id: Option<Value>, code: i64, message: &str) -> Value {
    let mut obj = serde_json::Map::new();
    obj.insert("jsonrpc".into(), json!("2.0"));
    match id {
        Some(i) => {
            obj.insert("id".into(), i);
        }
        None => {
            obj.insert("id".into(), Value::Null);
        }
    }
    obj.insert(
        "error".into(),
        json!({
            "code": code,
            "message": message,
        }),
    );
    Value::Object(obj)
}

fn schemas() -> Vec<Value> {
    tools().iter().map(|t| {
        json!({
            "name": t.name,
            "description": t.description,
            "inputSchema": t.input_schema,
        })
    }).collect()
}

fn str_arg(args: &Value, name: &str) -> std::result::Result<String, String> {
    args.get(name)
        .and_then(|v| v.as_str())
        .map(String::from)
        .ok_or_else(|| format!("tool requires string argument '{name}'"))
}

fn num_arg(args: &Value, name: &str, default: u64) -> u64 {
    args.get(name).and_then(|v| v.as_u64()).unwrap_or(default)
}

fn tools_call(params: &Value) -> std::result::Result<Value, (i64, String)> {
    let name = match params.get("name").and_then(|n| n.as_str()) {
        Some(n) => n,
        None => return Err((-32602, "tools/call requires 'name'".into())),
    };
    let args = params.get("arguments").cloned().unwrap_or_else(|| json!({}));
    let tool = tools()
        .into_iter()
        .find(|t| t.name == name)
        .ok_or_else(|| (-32602, format!("unknown tool '{name}'")))?;
    (tool.call)(&args)
        .map(|text| {
            json!({
                "content": [{"type": "text", "text": text}],
                "isError": false,
            })
        })
        .map_err(|msg| (-32000, msg))
}

// ---------------------------------------------------------------------------
// Tool implementations
// ---------------------------------------------------------------------------

fn report_json(r: &AnalysisReport) -> Value {
    json!({
        "artifact": r.artifact,
        "findings": r.findings,
        "facts": r.facts,
        "detail": r.detail,
        "produced_at": r.produced_at,
        "summary": r.summary,
        "structural_digest": r.structural_digest(),
    })
}

fn tool_analyze(args: &Value) -> std::result::Result<String, String> {
    let path = PathBuf::from(str_arg(args, "path")?);
    let settings = Settings::default();
    let report = crate::analysis::analyze_path(&path, &settings).map_err(|e| e.to_string())?;
    let mut v = report_json(&report);
    v["_tool"] = json!("analyze_artifact");
    serde_json::to_string_pretty(&v).map_err(|e| e.to_string())
}

fn tool_inspect_native(args: &Value) -> std::result::Result<String, String> {
    let path = PathBuf::from(str_arg(args, "path")?);
    let settings = Settings::default();
    let report = crate::analysis::analyze_path(&path, &settings).map_err(|e| e.to_string())?;
    let native = matches!(report.artifact.kind.as_str(), "elf" | "pe" | "macho");
    let mut v = report_json(&report);
    v["_tool"] = json!("inspect_native_binary");
    v["_is_native"] = json!(native);
    if !native {
        v["_note"] = json!("artifact is not an ELF/PE/Mach-O native binary; full analysis shown anyway");
    }
    serde_json::to_string_pretty(&v).map_err(|e| e.to_string())
}

fn tool_inspect_managed(args: &Value) -> std::result::Result<String, String> {
    let path = PathBuf::from(str_arg(args, "path")?);
    let settings = Settings::default();
    let report = crate::analysis::analyze_path(&path, &settings).map_err(|e| e.to_string())?;
    let is_managed = report.artifact.kind == "dotnet"
        || report
            .facts
            .get("dotnet.present")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
    let mut v = report_json(&report);
    v["_tool"] = json!("inspect_managed_assembly");
    v["_is_managed_assembly"] = json!(is_managed);
    if !is_managed {
        v["_note"] = json!("artifact does not look like a .NET/CLR managed assembly");
    }
    serde_json::to_string_pretty(&v).map_err(|e| e.to_string())
}

fn tool_inspect_js(args: &Value) -> std::result::Result<String, String> {
    let path = PathBuf::from(str_arg(args, "path")?);
    let settings = Settings::default();
    let report = crate::analysis::analyze_path(&path, &settings).map_err(|e| e.to_string())?;
    let mut v = report_json(&report);
    v["_tool"] = json!("inspect_javascript_application");
    let js_like = report.artifact.kind == "js_app" || path.is_dir();
    v["_looks_like_app"] = json!(js_like);
    serde_json::to_string_pretty(&v).map_err(|e| e.to_string())
}

fn tool_search_strings(args: &Value) -> std::result::Result<String, String> {
    let path = PathBuf::from(str_arg(args, "path")?);
    let settings = Settings::default();
    let min = num_arg(args, "min_len", 4) as usize;
    let max = num_arg(args, "max", 120) as usize;
    let bytes = crate::analysis::read_bounded(&path, settings.head_limit).map_err(|e| e.to_string())?;
    let hits = crate::analysis::binary::scan_strings(&bytes, min);
    let shown: Vec<Value> = hits
        .iter()
        .take(max)
        .map(|h| json!({ "offset": h.offset, "offset_hex": format!("0x{:x}", h.offset), "text": h.text }))
        .collect();
    serde_json::to_string_pretty(&json!({
        "path": path.display().to_string(),
        "min_len": min,
        "requested": max,
        "total_found": hits.len(),
        "strings": shown,
        "_note": "strings may include secrets; do not quote verbatim to the user",
    })).map_err(|e| e.to_string())
}

fn tool_extract_iocs(args: &Value) -> std::result::Result<String, String> {
    let path = PathBuf::from(str_arg(args, "path")?);
    let settings = Settings::default();
    let max = num_arg(args, "max", 100) as usize;
    let report = crate::analysis::iocs::analyze(&path, &settings).map_err(|e| e.to_string())?;
    let mut items = report.detail.clone().unwrap_or_else(|| json!([]));
    if let Some(arr) = items.as_array_mut() {
        arr.truncate(max);
    }
    let counts: Vec<Value> = report
        .facts
        .iter()
        .filter(|(k, _)| k.starts_with("iocs.") && k.ends_with(".count"))
        .map(|(k, v)| {
            json!({
                "kind": k.trim_start_matches("iocs.").trim_end_matches(".count"),
                "count": v,
            })
        })
        .collect();
    serde_json::to_string_pretty(&json!({
        "path": path.display().to_string(),
        "total": report.facts.get("iocs.total").cloned().unwrap_or(json!(0)),
        "counts": counts,
        "indicators": items,
        "_note": "every indicator carries offset/len/encoding citing its bytes; a match is evidence a pattern exists, not proof of malicious use",
    }))
    .map_err(|e| e.to_string())
}

fn tool_entropy_profile(args: &Value) -> std::result::Result<String, String> {
    let path = PathBuf::from(str_arg(args, "path")?);
    let settings = Settings::default();
    let window = num_arg(args, "window", 4096) as usize;
    let threshold = args.get("threshold").and_then(|v| v.as_f64()).unwrap_or(7.0);
    let report =
        crate::analysis::entropy::analyze(&path, &settings, window, threshold).map_err(|e| e.to_string())?;
    serde_json::to_string_pretty(&json!({
        "path": path.display().to_string(),
        "overall_entropy": report.facts.get("entropy.overall").cloned().unwrap_or(json!(null)),
        "window_bytes": window,
        "threshold": threshold,
        "high_region_count": report.facts.get("entropy.high_region_count").cloned().unwrap_or(json!(0)),
        "regions": report.facts.get("entropy.regions").cloned().unwrap_or(json!([])),
        "findings": report.findings,
        "_note": "high entropy suggests compressed/encrypted/packed content; compressed resources and signature blocks also score high — verify before concluding",
    }))
    .map_err(|e| e.to_string())
}

fn tool_compare(args: &Value) -> std::result::Result<String, String> {
    let a = PathBuf::from(str_arg(args, "a")?);
    let b = PathBuf::from(str_arg(args, "b")?);
    let settings = Settings::default();
    let result = crate::compare::compare_paths(&a, &b, &settings).map_err(|e| e.to_string())?;
    serde_json::to_string_pretty(&result).map_err(|e| e.to_string())
}

fn tool_batch(args: &Value) -> std::result::Result<String, String> {
    let root_str = str_arg(args, "root")?;
    let root = Path::new(&root_str);
    let opts = crate::batch::BatchOptions {
        root: root.to_path_buf(),
        depth: num_arg(args, "depth", 4) as usize,
        max_items: num_arg(args, "max_items", 1500) as usize,
        workers: 8,
        skip_hidden: true,
        settings: Settings::default(),
    };
    let result = crate::batch::run(&opts);
    serde_json::to_string_pretty(&result).map_err(|e| e.to_string())
}

fn tool_provider_status(_args: &Value) -> std::result::Result<String, String> {
    let status = crate::analysis::engines::provider_status();
    let value: Vec<Value> = status
        .iter()
        .map(|(name, ok, version)| {
            json!({ "provider": name, "available": ok, "version": version })
        })
        .collect();
    serde_json::to_string_pretty(&value).map_err(|e| e.to_string())
}

fn tool_list_plugins(_args: &Value) -> std::result::Result<String, String> {
    let plugins = crate::plugins::discover();
    let value: Vec<Value> = plugins
        .iter()
        .map(|p| {
            json!({
                "name": p.manifest.name,
                "version": p.manifest.version,
                "description": p.manifest.description,
                "formats": p.manifest.formats,
                "entry": p.manifest.entry,
                "dir": p.dir.display().to_string(),
            })
        })
        .collect();
    serde_json::to_string_pretty(&json!({ "plugins": value })).map_err(|e| e.to_string())
}

fn tool_run_plugin(args: &Value) -> std::result::Result<String, String> {
    let name = str_arg(args, "name")?;
    let path = PathBuf::from(str_arg(args, "path")?);
    let plugin = crate::plugins::get(&name).map_err(|e| e.to_string())?;
    let findings = crate::plugins::run(&plugin, &path).map_err(|e| e.to_string())?;
    serde_json::to_string_pretty(&json!({
        "_tool": "run_plugin",
        "plugin": name,
        "path": path.display().to_string(),
        "finding_count": findings.len(),
        "findings": findings,
    })).map_err(|e| e.to_string())
}

fn tool_disassemble(args: &Value) -> std::result::Result<String, String> {
    let path = str_arg(args, "path")?;
    let engine = args
        .get("engine")
        .and_then(|v| v.as_str())
        .unwrap_or("objdump");
    let needle = args.get("needle").and_then(|v| v.as_str());
    let finding =
        crate::analysis::engines::disassemble(&path, needle, engine).map_err(|e| e.to_string())?;
    serde_json::to_string_pretty(&json!({
        "_tool": "disassemble_binary",
        "engine": engine,
        "path": path,
        "finding": finding,
    })).map_err(|e| e.to_string())
}

fn tools() -> Vec<Tool> {
    vec![
    Tool {
        name: "analyze_artifact",
        description: "Full static analysis of any artifact (binary, archive, capture, directory). Returns findings with evidence, confidence, and limitations.",
        input_schema: json!({
            "type": "object",
            "properties": { "path": { "type": "string" } },
            "required": ["path"],
        }),
        call: tool_analyze,
    },
    Tool {
        name: "inspect_native_binary",
        description: "Analyze an ELF/PE/Mach-O native binary: headers, sections, imports, hardening, runtime markers.",
        input_schema: json!({
            "type": "object",
            "properties": { "path": { "type": "string" } },
            "required": ["path"],
        }),
        call: tool_inspect_native,
    },
    Tool {
        name: "inspect_managed_assembly",
        description: "Analyze a .NET / CLR managed assembly: metadata streams, tables, assembly refs, types, methods.",
        input_schema: json!({
            "type": "object",
            "properties": { "path": { "type": "string" } },
            "required": ["path"],
        }),
        call: tool_inspect_managed,
    },
    Tool {
        name: "inspect_javascript_application",
        description: "Analyze a JavaScript app or directory: package deps, module graph, boundaries, routes, sourcemaps, ASAR.",
        input_schema: json!({
            "type": "object",
            "properties": { "path": { "type": "string" } },
            "required": ["path"],
        }),
        call: tool_inspect_js,
    },
    Tool {
        name: "search_strings",
        description: "Extract printable strings with byte offsets. Strings may contain secrets; redact them when reporting.",
        input_schema: json!({
            "type": "object",
            "properties": {
                "path": { "type": "string" },
                "min_len": { "type": "integer", "minimum": 2, "default": 4 },
                "max": { "type": "integer", "default": 120 },
            },
            "required": ["path"],
        }),
        call: tool_search_strings,
    },
    Tool {
        name: "extract_iocs",
        description: "Extract indicators of compromise — URLs, IPv4s, domains, e-mails, MD5/SHA1/SHA256 literals, registry keys, file paths — with byte offsets, from ASCII/UTF-8 and UTF-16LE strings. Pattern match, not a verdict.",
        input_schema: json!({
            "type": "object",
            "properties": {
                "path": { "type": "string" },
                "max": { "type": "integer", "default": 100 },
            },
            "required": ["path"],
        }),
        call: tool_extract_iocs,
    },
    Tool {
        name: "entropy_profile",
        description: "Shannon-entropy profile of a file: overall entropy plus high-entropy regions as byte ranges (packed/encrypted-looking content).",
        input_schema: json!({
            "type": "object",
            "properties": {
                "path": { "type": "string" },
                "window": { "type": "integer", "default": 4096 },
                "threshold": { "type": "number", "default": 7.0 },
            },
            "required": ["path"],
        }),
        call: tool_entropy_profile,
    },
    Tool {
        name: "compare_artifacts",
        description: "Structurally compare two artifacts: byte hash, structural digest, and field-level differences.",
        input_schema: json!({
            "type": "object",
            "properties": {
                "a": { "type": "string" },
                "b": { "type": "string" },
            },
            "required": ["a", "b"],
        }),
        call: tool_compare,
    },
    Tool {
        name: "batch_inventory",
        description: "Scan a directory tree and summarize artifact kinds, counts, and findings without recording.",
        input_schema: json!({
            "type": "object",
            "properties": {
                "root": { "type": "string" },
                "depth": { "type": "integer", "default": 4 },
                "max_items": { "type": "integer", "default": 1500 },
            },
            "required": ["root"],
        }),
        call: tool_batch,
    },
    Tool {
        name: "provider_status",
        description: "Report which external engines (objdump, radare2) are available on PATH.",
        input_schema: json!({ "type": "object", "properties": {} }),
        call: tool_provider_status,
    },
    Tool {
        name: "list_plugins",
        description: "List installed RET plugins from ~/.ret/plugins and ./.ret/plugins.",
        input_schema: json!({ "type": "object", "properties": {} }),
        call: tool_list_plugins,
    },
    Tool {
        name: "run_plugin",
        description: "Run an installed plugin against an artifact and return its findings in RET's evidence model.",
        input_schema: json!({
            "type": "object",
            "properties": {
                "name": { "type": "string" },
                "path": { "type": "string" },
            },
            "required": ["name", "path"],
        }),
        call: tool_run_plugin,
    },
    Tool {
        name: "disassemble_binary",
        description: "Disassemble a native binary via an external engine (objdump or radare2). Optional 'needle' focuses on a symbol/substring.",
        input_schema: json!({
            "type": "object",
            "properties": {
                "path": { "type": "string" },
                "engine": { "type": "string", "enum": ["objdump", "radare2"], "default": "objdump" },
                "needle": { "type": "string" },
            },
            "required": ["path"],
        }),
        call: tool_disassemble,
    },
    ]
}
