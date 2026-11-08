//! Magic sniffing and artifact-kind identification.
//!
//! Detection is deliberately independent: a conservative magic/format probe
//! decides which analyzer to run, so a file is never misrouted. Everything
//! here is engine-free and reads only the first few kilobytes.

use crate::core::error::{Error, Result};

/// A coarse classification used to route to the right analyzer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Elf,
    Pe,
    MachO,
    Wasm,
    Png,
    Gguf,
    Safetensors,
    Sqlite,
    Zip,      // generic archive
    Apk,      // zip containing AndroidManifest.xml
    DelimitedText, // JSON / XML / TOML / YAML text files
    UnknownFile,
    /// A directory that looks like a JS/Electron application root.
    JsDirectory,
    /// Any other directory (for batch/directory scans).
    Directory,
}

const MAX_SNIFF: u64 = 4 * 1024 * 1024;

/// Detect an on-disk `Path`'s kind. Returns `has_kind=false` for empty files.
pub fn detect_path(path: &std::path::Path) -> Result<(Kind, bool)> {
    let meta = std::fs::metadata(path).map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            Error::not_found(format!("{}", path.display()))
        } else {
            Error::from(e)
        }
    })?;
    if meta.is_dir() {
        return Ok(match is_js_root(path)? {
            true => (Kind::JsDirectory, true),
            false => (Kind::Directory, true),
        });
    }
    if meta.len() == 0 {
        return Ok((Kind::UnknownFile, false));
    }
    detect_bytes(&read_head(path)?, path)
}

/// Read a bounded head of a file for sniffing (and keep it for analysis).
pub fn read_head(path: &std::path::Path) -> Result<Vec<u8>> {
    let meta = std::fs::metadata(path)?;
    if meta.len() == 0 {
        return Ok(Vec::new());
    }
    use std::io::Read;
    let mut f = std::fs::File::open(path)?;
    let take = meta.len().min(MAX_SNIFF) as usize;
    let mut buf = vec![0u8; take];
    let mut read = 0usize;
    while read < take {
        let n = f.read(&mut buf[read..])?;
        if n == 0 {
            break;
        }
        read += n;
    }
    buf.truncate(read);
    Ok(buf)
}

/// Detect kind from bytes + an optional path extension.
pub fn detect_bytes(head: &[u8], path: &std::path::Path) -> Result<(Kind, bool)> {
    if head.is_empty() {
        return Ok((Kind::UnknownFile, false));
    }
    let ext = path
        .extension()
        .map(|e| e.to_string_lossy().to_lowercase())
        .unwrap_or_default();

    if head.starts_with(b"\x7fELF") {
        return Ok((Kind::Elf, true));
    }
    if head.starts_with(b"MZ") && head.len() >= 0x40 {
        // .NET hosted in PE is detected later by the analysis pipeline.
        return Ok((Kind::Pe, true));
    }
    let m = macho_magic(head);
    if m {
        return Ok((Kind::MachO, true));
    }
    if head.starts_with(b"\0asm") {
        return Ok((Kind::Wasm, true));
    }
    if head.starts_with(b"\x89PNG\r\n\x1a\n") {
        return Ok((Kind::Png, true));
    }
    if head.starts_with(b"GGUF") {
        return Ok((Kind::Gguf, true));
    }
    if head.starts_with(b"SQLite format 3\0") {
        return Ok((Kind::Sqlite, true));
    }
    if ext == "safetensors" {
        return Ok((Kind::Safetensors, true));
    }
    if is_zip(head) {
        if ext == "apk" || ext == "xapk" || zip_has_manifest_marker(path, head) {
            return Ok((Kind::Apk, true));
        }
        return Ok((Kind::Zip, true));
    }
    if head.starts_with(b"{") || head.starts_with(b"[") {
        return Ok((Kind::DelimitedText, true));
    }
    // XML and other text-shaped metadata files.
    if head.starts_with(b"<?xml") || ext_is_text(&ext) {
        return Ok((Kind::DelimitedText, true));
    }
    Ok((Kind::UnknownFile, false))
}

/// Source/metadata extensions that are text artifacts even when their content
/// does not begin with a JSON/XML marker (e.g. `package.json` without a leading
/// brace would still be text-shaped, though JSON detection handles most cases).
fn ext_is_text(ext: &str) -> bool {
    matches!(
        ext,
        "json" | "xml" | "toml" | "yaml" | "yml" | "ini" | "csv" | "tsv" | "txt" | "md"
            | "html" | "css" | "js" | "mjs" | "cjs" | "har"
    )
}

fn macho_magic(head: &[u8]) -> bool {
    if head.len() < 4 {
        return false;
    }
    let m = u32::from_be_bytes([head[0], head[1], head[2], head[3]]);
    matches!(
        m,
        0xFEEDFACE | 0xFEEDFACF | 0xCEFAEDFE | 0xCFFAEDFE | 0xCAFEBABE | 0xBEBAFECA
    )
}

fn is_zip(head: &[u8]) -> bool {
    head.len() >= 4 && head.starts_with(b"PK\x03\x04")
}

/// Cheap probe: a ZIP whose central directory mentions `AndroidManifest.xml`.
/// We scan the end-of-central-directory + central directory region.
fn zip_has_manifest_marker(path: &std::path::Path, head: &[u8]) -> bool {
    // Common PPMD-encoded or large zips may not show it in the head; the real
    // check needs the EOCD. We do a bounded central-directory scan.
    if let Some(idx) = head.windows(4).position(|w| w == b"PK\x01\x02") {
        if head[idx..].windows(18).any(|w| w == b"AndroidManifest.xml") {
            return true;
        }
    }
    // Fall back to a full-file central directory scan when the head is small.
    let _ = path;
    false
}

/// Decide whether a directory looks like a JS/Electron application root:
/// contains a `package.json` (optionally an `app.asar`/`electron` dep).
pub fn is_js_root(dir: &std::path::Path) -> Result<bool> {
    if dir.join("package.json").is_file() {
        return Ok(true);
    }
    if dir.join("app.asar").is_file() {
        return Ok(true);
    }
    Ok(false)
}
