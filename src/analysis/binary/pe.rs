//! Portable Executable analysis: DOS/COFF/optional headers, sections,
//! import/export tables, Authenticode certificate directory, and hardening.

use crate::analysis::{AnalysisContext, identity_for};
use crate::core::error::{Error, Result};
use crate::core::evidence::{AnalysisReport, Confidence, Evidence, Finding, Location, Severity};
use crate::core::io::Reader;

// Some optional-header fields are parsed for completeness but not surfaced in
// findings today; they remain part of the parser's model for future use.
#[allow(dead_code)]
struct Pe {
    little: bool,
    is_64: bool,
    machine: u16,
    time_date_stamp: u32,
    characteristics: u16,
    entry: u64,
    image_base: u64,
    subsystem: u16,
    dll_chars: u16,
    section_align: u32,
    file_align: u32,
    data_dirs: Vec<(u32, u32)>, // (rva, size)
    sections: Vec<Section>,
}

struct Section {
    name: String,
    virtual_size: u32,
    virtual_addr: u32,
    raw_size: u32,
    raw_ptr: u32,
    chars: u32,
}

const DIR_EXPORT: usize = 0;
const DIR_IMPORT: usize = 1;
const DIR_CERTIFICATE: usize = 4;
const DIR_COM: usize = 14;

const DYN_BASE: u16 = 0x0040;
const NX_COMPAT: u16 = 0x0100;
const SAFE_SEH: u16 = 0x0400;
const HIGH_ENTROPY: u16 = 0x0020;
const GUARD_CF: u16 = 0x4000;

pub fn analyze(ctx: &AnalysisContext) -> Result<AnalysisReport> {
    let pe = parse(&ctx.head)?;
    let mut findings: Vec<Finding> = Vec::new();
    let machine = machine_name(pe.machine);
    let arch = if pe.is_64 { "64-bit" } else { "32-bit" };
    let subsys = subsystem_name(pe.subsystem);
    let label = format!("PE {arch} {machine}, subsystem={subsys}");

    let identity = identity_for(&ctx.path, "pe", &label, &ctx.head)?;
    let mut report = AnalysisReport::new(identity, Vec::new());
    report.facts.insert(
        "pe.arch".into(),
        serde_json::json!(format!("{arch} {machine}")),
    );
    report.facts.insert(
        "pe.machine".into(),
        serde_json::json!(format!("0x{:04x}", pe.machine)),
    );
    report.facts.insert(
        "pe.subsystem".into(),
        serde_json::json!(format!("{subsys} ({})", pe.subsystem)),
    );
    report.facts.insert(
        "pe.entry".into(),
        serde_json::json!(format!("0x{:x}", pe.entry)),
    );

    // Header finding
    let stamp = timestamp(pe.time_date_stamp);
    let mut hf = Finding::new("pe.header", label, Severity::Info, Confidence::Direct);
    hf.evidence.push(Evidence::new(
        "pe.header.machine",
        format!("{} (0x{:04x})", machine, pe.machine),
        Location::bytes(0 - 0, Some(0)),
    ));
    // COFF header starts at e_lfanew+4.
    let coff = pe_coff_off(&ctx.head)?;
    hf.evidence.push(Evidence::new(
        "pe.header.timestamp",
        stamp.clone(),
        Location::bytes(coff as u64 + 4, Some(coff as u64 + 8)),
    ));
    hf.evidence.push(Evidence::new(
        "pe.header.subsystem",
        format!("{subsys} ({})", pe.subsystem),
        Location::entity("optional_header", "Subsystem"),
    ));
    hf.evidence.push(Evidence::new(
        "pe.header.entry",
        format!("0x{:x}", pe.entry),
        Location::entity("optional_header", "AddressOfEntryPoint"),
    ));
    findings.push(hf);

    // Sections
    let mut sf = Finding::new(
        "pe.sections",
        format!("{} sections", pe.sections.len()),
        Severity::Info,
        Confidence::Direct,
    );
    for s in &pe.sections {
        let exec = if s.chars & 0x20_00_00_00 != 0 { "x" } else { "-" };
        let write = if s.chars & 0x80_00_00_00 != 0 { "w" } else { "-" };
        sf.evidence.push(Evidence::new(
            "pe.section",
            format!(
                "{} vsize={:#x} rva={:#x} rawsize={:#x} {exec}{write}",
                s.name, s.virtual_size, s.virtual_addr, s.raw_size
            ),
            Location::bytes(s.raw_ptr as u64, Some(s.raw_ptr as u64 + s.raw_size as u64)),
        ));
    }
    findings.push(sf);

    // Imports
    if let Some(imp) = imports(&ctx.head, &pe) {
        let mut imf = Finding::new(
            "pe.imports",
            format!("imports from {} DLLs", imp.len()),
            Severity::Info,
            Confidence::Direct,
        );
        for (dll, fns) in imp.iter().take(20) {
            let sample: Vec<String> = fns.iter().take(6).cloned().collect();
            let more = if fns.len() > 6 { format!(" (+{} more)", fns.len() - 6) } else { String::new() };
            imf.evidence.push(Evidence::new(
                "pe.import.dll",
                format!("{dll}: {}{}", sample.join(", "), more),
                Location::entity("import", dll.clone()),
            ));
        }
        report.facts.insert("pe.imports".into(), serde_json::json!(imp));
        findings.push(imf);
    }

    // Exports
    if let Some(exports) = exports(&ctx.head, &pe) {
        let mut exf = Finding::new(
            "pe.exports",
            format!("{} exported functions", exports.len()),
            Severity::Info,
            Confidence::Direct,
        );
        for (name, addr) in exports.iter().take(14) {
            exf.evidence.push(Evidence::new(
                "pe.export",
                format!("{name} @ 0x{addr:x}"),
                Location::entity("export", name.clone()),
            ));
        }
        report
            .facts
            .insert("pe.export_count".into(), serde_json::json!(exports.len()));
        findings.push(exf);
    }

    // Certificates
    if let Some(dir) = pe.data_dirs.get(DIR_CERTIFICATE) {
        if dir.0 != 0 && dir.1 != 0 {
            let certs = certificates(&ctx.head, &pe);
            let mut cf = Finding::new(
                "pe.certificates",
                format!("Authenticode certificate directory: {} blob(s)", certs.len()),
                Severity::Info,
                Confidence::Direct,
            );
            for c in certs.iter().take(8) {
                cf.evidence.push(Evidence::new(
                    "pe.certificate",
                    format!(
                        "revision={} type=0x{:x} len={} sha256={}",
                        c.revision, c.kind, c.length, c.sha256
                    ),
                    Location::bytes(c.offset, Some(c.offset + c.length as u64)),
                ));
            }
            findings.push(cf);
        }
    }

    // Hardening
    let t = [
        ("hardening.aslr", pe.dll_chars & DYN_BASE != 0, "ASLR (DYNAMIC_BASE)", 0x0040),
        ("hardening.nx", pe.dll_chars & NX_COMPAT != 0, "NX (NX_COMPAT / DEP)", 0x0100),
        ("hardening.high_entropy_va", pe.dll_chars & HIGH_ENTROPY != 0, "high-entropy 64-bit ASLR", 0x0020),
        ("hardening.cfg", pe.dll_chars & GUARD_CF != 0, "Control Flow Guard", 0x4000),
        ("hardening.seh", pe.dll_chars & SAFE_SEH != 0, "safe exception handlers (SEH)", 0x0400),
        ("hardening.large_address_aware", pe.characteristics & 0x0020 != 0, "large address aware", 0x0020),
    ];
    for (key, val, claim, bit) in t {
        let sev = if val { Severity::Info } else { Severity::Note };
        let mut f = Finding::new(
            format!("pe.hardening.{}", key.split('.').last().unwrap_or(key)),
            format!("{claim}: {val}"),
            sev,
            Confidence::Direct,
        );
        f.evidence.push(Evidence::new(
            "pe.hardening",
            format!("DllCharacteristics bit 0x{bit:04x} {}", if val { "set" } else { "not set" }),
            Location::entity("optional_header", "DllCharacteristics"),
        ));
        report.facts.insert(key.into(), serde_json::json!(val));
        findings.push(f);
    }

    // Stack canary via __security_cookie references
    if let Some(imp) = imports(&ctx.head, &pe) {
        let has_cookie = imp
            .iter()
            .flat_map(|(_, fns)| fns.iter())
            .any(|f| f == "__security_check_cookie" || f == "__security_cookie");
        let mut f = Finding::new(
            "pe.hardening.stack_canary",
            format!("stack canary (/GS): {has_cookie}"),
            if has_cookie { Severity::Info } else { Severity::Note },
            Confidence::Direct,
        );
        f.evidence.push(Evidence::new(
            "pe.hardening.canary",
            if has_cookie {
                "__security_check_cookie imported".to_string()
            } else {
                "no __security_check_cookie import found".to_string()
            },
            Location::entity("import", "__security_check_cookie"),
        ));
        report
            .facts
            .insert("hardening.stack_canary".into(), serde_json::json!(has_cookie));
        findings.push(f);
    }

    // .NET note when dispatch fell through
    if let Some(dir) = pe.data_dirs.get(DIR_COM) {
        if dir.0 != 0 {
            let mut f = Finding::new(
                "pe.dotnet_present",
                "PE hosts a .NET CLR header (managed assembly)",
                Severity::Info,
                Confidence::Direct,
            );
            f.evidence.push(Evidence::new(
                "pe.dotnet_present",
                format!("COM descriptor RVA=0x{:x} size={}", dir.0, dir.1),
                Location::entity("data_directory", "CLRRuntimeHeader"),
            ));
            findings.push(f);
        }
    }

    // Strings
    let strings = crate::analysis::binary::scan_strings(&ctx.head, ctx.settings.min_string_len);
    findings.push(crate::analysis::binary::string_inventory_finding(
        &strings,
        ctx.settings.max_strings,
        ctx.settings.max_string_len,
        ctx.settings.min_string_len,
        200,
    ));
    report
        .facts
        .insert("strings.count".into(), serde_json::json!(strings.len()));

    // Go / Rust markers
    let full = crate::analysis::read_bounded(&ctx.path, ctx.settings.head_limit)?;
    crate::analysis::binary::managed_runtime_findings(&full, "pe", &mut findings);

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

// ---------------------------------------------------------------------------
// Parsing
// ---------------------------------------------------------------------------

fn pe_coff_off(b: &[u8]) -> Result<usize> {
    if b.len() < 0x40 {
        return Err(Error::malformed("too small to be PE"));
    }
    if &b[0..2] != b"MZ" {
        return Err(Error::malformed("missing MZ magic"));
    }
    let e_lfanew = u32::from_le_bytes([b[0x3C], b[0x3D], b[0x3E], b[0x3F]]) as usize;
    if e_lfanew + 4 > b.len() || &b[e_lfanew..e_lfanew + 4] != b"PE\0\0" {
        return Err(Error::malformed("missing PE signature"));
    }
    Ok(e_lfanew + 4)
}

fn parse(b: &[u8]) -> Result<Pe> {
    let coff = pe_coff_off(b)?;
    if coff + 20 > b.len() {
        return Err(Error::malformed("COFF header truncated"));
    }
    let r = Reader::new(b, true); // PE is always little-endian
    let machine = r.u16(coff)?;
    let n_sections = r.u16(coff + 2)? as usize;
    let time_date_stamp = r.u32(coff + 4)?;
    let characteristics = r.u16(coff + 18)?;
    let size_of_optional = r.u16(coff + 16)? as usize;
    let opt = coff + 20;
    if opt + size_of_optional > b.len() {
        return Err(Error::malformed("optional header truncated"));
    }
    let magic = r.u16(opt)?;
    let (is_64, entry, image_base, section_align, file_align, subsystem, dll_chars, dirs_off, n_dirs) =
        match magic {
            0x10B => (
                false,
                r.u32(opt + 16)? as u64,
                r.u32(opt + 28)? as u64,
                r.u32(opt + 32)?,
                r.u32(opt + 36)?,
                r.u16(opt + 68)?,
                r.u16(opt + 70)?,
                opt + 96,
                r.u32(opt + 92)? as usize,
            ),
            0x20B => (
                true,
                r.u32(opt + 16)? as u64,
                r.u64(opt + 24)?,
                r.u32(opt + 32)?,
                r.u32(opt + 36)?,
                r.u16(opt + 68)?,
                r.u16(opt + 70)?,
                opt + 112,
                r.u32(opt + 108)? as usize,
            ),
            _ => return Err(Error::malformed("unsupported optional header magic")),
        };
    let n_dirs = n_dirs.min(16);
    let mut data_dirs = Vec::with_capacity(n_dirs);
    for i in 0..n_dirs {
        let o = dirs_off + i * 8;
        let rva = r.u32(o)?;
        let size = r.u32(o + 4)?;
        data_dirs.push((rva, size));
    }

    // Sections headers immediately after optional header.
    let sec_off = opt + size_of_optional;
    let mut sections = Vec::with_capacity(n_sections.min(96));
    for i in 0..n_sections {
        let o = sec_off + i * 40;
        if o + 40 > b.len() {
            break;
        }
        let name_raw: Vec<u8> = b[o..o + 8].to_vec();
        let name = String::from_utf8_lossy(trim_nul(&name_raw)).into_owned();
        let virtual_size = r.u32(o + 8)?;
        let virtual_addr = r.u32(o + 12)?;
        let raw_size = r.u32(o + 16)?;
        let raw_ptr = r.u32(o + 20)?;
        let chars = r.u32(o + 36)?;
        sections.push(Section {
            name,
            virtual_size,
            virtual_addr,
            raw_size,
            raw_ptr,
            chars,
        });
    }

    Ok(Pe {
        little: true,
        is_64,
        machine,
        time_date_stamp,
        characteristics,
        entry,
        image_base,
        subsystem,
        dll_chars,
        section_align,
        file_align,
        data_dirs,
        sections,
    })
}

fn trim_nul(b: &[u8]) -> &[u8] {
    let end = b.iter().position(|&x| x == 0).unwrap_or(b.len());
    &b[..end]
}

/// Translate an RVA to a file offset via the section table.
fn rva_to_offset(pe: &Pe, rva: u32) -> Option<u64> {
    for s in &pe.sections {
        let start = s.virtual_addr;
        let end = s.virtual_addr + s.virtual_size.max(s.raw_size);
        if rva >= start && rva < end {
            if rva - start < s.raw_size {
                return Some(s.raw_ptr as u64 + (rva - start) as u64);
            }
        }
    }
    None
}

fn cstr_at(b: &[u8], off: u64, max: usize) -> Option<String> {
    let off = off as usize;
    if off >= b.len() {
        return None;
    }
    let end = (off + max).min(b.len());
    let s = b.get(off..end)?;
    let nul = s.iter().position(|&x| x == 0).unwrap_or(s.len());
    let s = &s[..nul];
    (!s.is_empty()).then(|| String::from_utf8_lossy(s).into_owned())
}

fn imports(b: &[u8], pe: &Pe) -> Option<Vec<(String, Vec<String>)>> {
    let dir = pe.data_dirs.get(DIR_IMPORT)?;
    if dir.0 == 0 {
        return None;
    }
    let base = rva_to_offset(pe, dir.0)?;
    let r = Reader::new(b, true);
    let mut out = Vec::new();
    let max_dlls = 256;
    for i in 0..max_dlls {
        let o = base as usize + i * 20;
        if o + 20 > b.len() {
            break;
        }
        let orig_thunk = r.u32(o).ok()?;
        let name_rva = r.u32(o + 12).ok()?;
        let first_thunk = r.u32(o + 16).ok()?;
        if orig_thunk == 0 && name_rva == 0 && first_thunk == 0 {
            break;
        }
        let name_off = rva_to_offset(pe, name_rva)?;
        let Some(dll) = cstr_at(b, name_off, 4096) else {
            continue;
        };
        let thunk_rva = if orig_thunk != 0 { orig_thunk } else { first_thunk };
        let mut fns = Vec::new();
        let thunk_base = rva_to_offset(pe, thunk_rva)?;
        let ordinal_flag = if pe.is_64 { 0x8000_0000_0000_0000u64 } else { 0x8000_0000 };
        for j in 0..4096 {
            let to = thunk_base as usize + j * if pe.is_64 { 8 } else { 4 };
            if to + if pe.is_64 { 8 } else { 4 } > b.len() {
                break;
            }
            let val = if pe.is_64 {
                r.u64(to).ok()?
            } else {
                r.u32(to).ok()? as u64
            };
            if val == 0 {
                break;
            }
            if val & ordinal_flag != 0 {
                fns.push(format!("ordinal#{}", val & 0xffff));
            } else {
                let hin = rva_to_offset(pe, val as u32)?;
                if let Some(name) = cstr_at(b, hin + 2, 4096) {
                    fns.push(name);
                }
            }
        }
        out.push((dll, fns));
    }
    (!out.is_empty()).then_some(out)
}

fn exports(b: &[u8], pe: &Pe) -> Option<Vec<(String, u64)>> {
    let dir = pe.data_dirs.get(DIR_EXPORT)?;
    if dir.0 == 0 || dir.1 == 0 {
        return None;
    }
    let base = rva_to_offset(pe, dir.0)? as usize;
    let r = Reader::new(b, true);
    if base + 40 > b.len() {
        return None;
    }
    let n_names = r.u32(base + 24).ok()? as usize;
    let addr_of_names = r.u32(base + 32).ok()?;
    let addr_of_ordinals = r.u32(base + 36).ok()?;
    let addr_of_funcs = r.u32(base + 28).ok()?;
    let name_off = rva_to_offset(pe, addr_of_names)? as usize;
    let ord_off = rva_to_offset(pe, addr_of_ordinals)? as usize;
    let func_off = rva_to_offset(pe, addr_of_funcs)? as usize;
    let mut out = Vec::new();
    let n = n_names.min(4096);
    for i in 0..n {
        let np = name_off + i * 4;
        let op = ord_off + i * 2;
        if np + 4 > b.len() || op + 2 > b.len() {
            break;
        }
        let name_rva = r.u32(np).ok()?;
        let ord = r.u16(op).ok()? as usize;
        let Some(name) = cstr_at(b, rva_to_offset(pe, name_rva)?, 4096) else {
            continue;
        };
        let fp = func_off + ord * if pe.is_64 { 8 } else { 4 };
        if fp + if pe.is_64 { 8 } else { 4 } > b.len() {
            continue;
        }
        let addr = if pe.is_64 { r.u64(fp).unwrap_or(0) } else { r.u32(fp).unwrap_or(0) as u64 };
        out.push((name, addr));
    }
    (!out.is_empty()).then_some(out)
}

struct CertDesc {
    offset: u64,
    length: u32,
    revision: u16,
    kind: u16,
    sha256: String,
}

fn certificates(b: &[u8], pe: &Pe) -> Vec<CertDesc> {
    let mut out = Vec::new();
    let Some(dir) = pe.data_dirs.get(DIR_CERTIFICATE) else {
        return out;
    };
    let mut off = dir.0 as u64;
    let end = dir.0 as u64 + dir.1 as u64;
    while off + 8 <= end && off + 8 <= b.len() as u64 {
        let o = off as usize;
        let length = u32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]]);
        let revision = u16::from_le_bytes([b[o + 4], b[o + 5]]);
        let kind = u16::from_le_bytes([b[o + 6], b[o + 7]]);
        if length < 8 {
            break;
        }
        let payload = &b.get(o + 8..(o + length as usize).min(b.len())).unwrap_or(&[]);
        let sha = crate::core::digests::sha256_hex(payload);
        out.push(CertDesc {
            offset: off,
            length,
            revision,
            kind,
            sha256: sha,
        });
        off += ((length + 7) & !7) as u64;
    }
    out
}

// ---------------------------------------------------------------------------

fn timestamp(t: u32) -> String {
    // PE timestamps count seconds since 1970 (UTC).
    use chrono::TimeZone;
    let dt = chrono::Utc.timestamp_opt(t as i64, 0).single();
    match dt {
        Some(d) => d.format("%Y-%m-%d %H:%M:%S UTC").to_string(),
        None => format!("0x{t:x}"),
    }
}

fn machine_name(m: u16) -> &'static str {
    match m {
        0x014c => "i386",
        0x8664 => "x86-64",
        0x01c0 => "ARM",
        0x01c4 => "ARMv7",
        0xaa64 => "ARM64",
        0x0200 => "IA-64",
        0x0166 => "MIPS16",
        0x0284 => "ALPHA64",
        0x0500 => "SH3",
        0x01f0 => "PowerPC",
        0xffff => "unknown",
        _ => "machine-unknown",
    }
}

fn subsystem_name(s: u16) -> &'static str {
    match s {
        1 => "NATIVE",
        2 => "WINDOWS_GUI",
        3 => "WINDOWS_CUI",
        5 => "OS2_CUI",
        7 => "POSIX_CUI",
        9 => "WINDOWS_CE",
        10 => "EFI_APPLICATION",
        14 => "XBOX",
        16 => "WINDOWS_BOOT_APPLICATION",
        _ => "other",
    }
}
