//! Mach-O analysis: 32/64-bit thin binaries and universal (fat) binaries,
//! load commands, segments/sections, symbols, UUID, encryption, hardening.

use crate::analysis::{AnalysisContext, identity_for};
use crate::core::error::{Error, Result};
use crate::core::evidence::{AnalysisReport, Confidence, Evidence, Finding, Location, Severity};
use crate::core::io::Reader;

const MH_MAGIC_64: u32 = 0xFEEDFACF;
const MH_MAGIC: u32 = 0xFEEDFACE;
const MH_CIGAM_64: u32 = 0xCFFAEDFE;
const MH_CIGAM: u32 = 0xCEFAEDFE;
const FAT_MAGIC: u32 = 0xCAFEBABE;
const FAT_CIGAM: u32 = 0xBEBAFECA;
const FAT_MAGIC_64: u32 = 0xCAFEBABF;
const FAT_CIGAM_64: u32 = 0xBFBAFECA;

const LC_SEGMENT: u32 = 0x1;
const LC_SYMTAB: u32 = 0x2;
const LC_LOAD_DYLIB: u32 = 0xc;
const LC_LOAD_DYLINKER: u32 = 0xe;
const LC_SEGMENT_64: u32 = 0x19;
const LC_UUID: u32 = 0x1b;
const LC_CODE_SIGNATURE: u32 = 0x1d;
const LC_ENCRYPTION_INFO: u32 = 0x21;
const LC_ENCRYPTION_INFO_64: u32 = 0x2c;
const LC_VERSION_MIN_MACOSX: u32 = 0x24;
const LC_VERSION_MIN_IPHONEOS: u32 = 0x25;
const LC_VERSION_MIN_WATCHOS: u32 = 0x30;
const LC_BUILD_VERSION: u32 = 0x32;
const LC_LOAD_WEAK_DYLIB: u32 = 0x8000_0018;
const LC_MAIN: u32 = 0x8000_0028;
const LC_RPATH: u32 = 0x8000_001c;

const MH_PIE: u32 = 0x0020_0000;
const MH_NO_HEAP_EXECUTION: u32 = 0x0400_0000;
const MH_APP_EXTENSION_SAFE: u32 = 0x0200_0000;

const MH_EXECUTE: u32 = 2;
const MH_DYLIB: u32 = 6;
const MH_BUNDLE: u32 = 8;
const MH_OBJECT: u32 = 1;

struct MachSlice {
    little: bool,
    is_64: bool,
    cputype: i32,
    filetype: u32,
    flags: u32,
    /// (cmd, cmdsize, offset) for each load command.
    commands: Vec<(u32, u32, usize)>,
}

struct Segment {
    name: String,
    fileoff: u64,
    filesize: u64,
}

struct Dylib {
    name: String,
    weak: bool,
}

pub fn analyze(ctx: &AnalysisContext) -> Result<AnalysisReport> {
    let b = &ctx.head;
    let magic = u32::from_be_bytes([b[0], b[1], b[2], b[3]]);
    if matches!(magic, FAT_MAGIC | FAT_CIGAM | FAT_MAGIC_64 | FAT_CIGAM_64) {
        return analyze_fat(ctx);
    }

    let slice = thin(ctx)?;
    let arch_name = cputype_name(slice.cputype);
    let filetype_name = filetype_name(slice.filetype);
    let label = format!(
        "Mach-O {} {} [{}]",
        if slice.is_64 { "64-bit" } else { "32-bit" },
        arch_name,
        filetype_name
    );

    // Parse commands
    let mut segments: Vec<Segment> = Vec::new();
    let mut dylibs: Vec<Dylib> = Vec::new();
    let mut uuid: Option<String> = None;
    let mut symtab: Option<(u32, u32, u32, u32)> = None;
    let mut entry: Option<u64> = None;
    let mut encrypted: Option<(u32, u32, u32)> = None;
    let mut code_signature: Option<(u32, u32)> = None;
    let mut min_os: Option<String> = None;
    let mut rpaths: Vec<String> = Vec::new();
    let mut dylinker: Option<String> = None;

    let r = Reader::new(b, slice.little);
    for &(cmd, cmdsize, off) in &slice.commands {
        match cmd {
            LC_SEGMENT | LC_SEGMENT_64 => {
                if cmdsize < 56 {
                    continue;
                }
                let name = r.cstr_bounded(off + 8).unwrap_or(b"");
                let seg = if slice.is_64 {
                    let fileoff = r.u64(off + 24).unwrap_or(0);
                    let filesize = r.u64(off + 32).unwrap_or(0);
                    Segment { name: String::from_utf8_lossy(name).into_owned(), fileoff, filesize }
                } else {
                    let fileoff = r.u32(off + 20).unwrap_or(0) as u64;
                    let filesize = r.u32(off + 24).unwrap_or(0) as u64;
                    Segment { name: String::from_utf8_lossy(name).into_owned(), fileoff, filesize }
                };
                segments.push(seg);
            }
            LC_SYMTAB => {
                let symoff = r.u32(off + 8).unwrap_or(0);
                let nsyms = r.u32(off + 12).unwrap_or(0);
                let stroff = r.u32(off + 16).unwrap_or(0);
                let strsize = r.u32(off + 20).unwrap_or(0);
                symtab = Some((symoff, nsyms, stroff, strsize));
            }
            LC_LOAD_DYLIB | LC_LOAD_WEAK_DYLIB => {
                if cmdsize < 12 {
                    continue;
                }
                let nameoff = r.u32(off + 8).unwrap_or(0) as usize;
                let base = off + nameoff;
                if let Ok(s) = r.cstr_bounded(base) {
                    dylibs.push(Dylib {
                        name: String::from_utf8_lossy(s).into_owned(),
                        weak: cmd == LC_LOAD_WEAK_DYLIB,
                    });
                }
            }
            LC_LOAD_DYLINKER => {
                if cmdsize >= 12 {
                    let nameoff = r.u32(off + 8).unwrap_or(0) as usize;
                    if let Ok(s) = r.cstr_bounded(off + nameoff) {
                        dylinker = Some(String::from_utf8_lossy(s).into_owned());
                    }
                }
            }
            LC_RPATH => {
                if cmdsize >= 12 {
                    let nameoff = r.u32(off + 8).unwrap_or(0) as usize;
                    if let Ok(s) = r.cstr_bounded(off + nameoff) {
                        rpaths.push(String::from_utf8_lossy(s).into_owned());
                    }
                }
            }
            LC_UUID => {
                if cmdsize >= 24 {
                    let bytes = b.get(off + 8..off + 24).unwrap_or(&[]);
                    uuid = Some(format_uuid(bytes));
                }
            }
            LC_MAIN => {
                entry = r.u64(off + 8).ok();
            }
            LC_ENCRYPTION_INFO | LC_ENCRYPTION_INFO_64 => {
                let cryptid = r.u32(off + 16).unwrap_or(0);
                encrypted = Some((r.u32(off + 8).unwrap_or(0), r.u32(off + 12).unwrap_or(0), cryptid));
            }
            LC_CODE_SIGNATURE => {
                code_signature = Some((r.u32(off + 8).unwrap_or(0), r.u32(off + 12).unwrap_or(0)));
            }
            LC_VERSION_MIN_MACOSX | LC_VERSION_MIN_IPHONEOS | LC_VERSION_MIN_WATCHOS => {
                let min = r.u32(off + 8).unwrap_or(0);
                min_os = Some(format_version(min));
            }
            LC_BUILD_VERSION => {
                if cmdsize >= 12 {
                    let plat = r.u32(off + 8).unwrap_or(0);
                    let min = r.u32(off + 12).unwrap_or(0);
                    let _ = plat;
                    min_os = Some(format_version(min));
                }
            }
            _ => {}
        }
    }

    let mut findings: Vec<Finding> = Vec::new();
    let mut report = AnalysisReport::new(
        identity_for(&ctx.path, "macho", &label, b)?,
        Vec::new(),
    );
    report
        .facts
        .insert("macho.arch".into(), arch_name.into());
    report.facts.insert("macho.filetype".into(), filetype_name.into());
    report
        .facts
        .insert("macho.little_endian".into(), serde_json::json!(slice.little));

    // Header finding
    let mut hf = Finding::new("macho.header", label, Severity::Info, Confidence::Direct);
    hf.evidence.push(Evidence::new(
        "macho.header.cputype",
        format!("{arch_name} (0x{:x})", slice.cputype),
        Location::bytes(4, Some(8)),
    ));
    hf.evidence.push(Evidence::new(
        "macho.header.filetype",
        format!("{filetype_name} ({})", slice.filetype),
        Location::bytes(12, Some(16)),
    ));
    hf.evidence.push(Evidence::new(
        "macho.header.ncmds",
        slice.commands.len().to_string(),
        Location::bytes(if slice.is_64 { 16 } else { 16 }, Some(20)),
    ));
    if let Some(u) = &uuid {
        hf.evidence.push(Evidence::new("macho.uuid", u.clone(), Location::entity("load_command", "LC_UUID")));
    }
    report.facts.insert(
        "macho.uuid".into(),
        serde_json::json!(uuid.clone().unwrap_or_default()),
    );
    findings.push(hf);

    // Segments
    let mut sf = Finding::new(
        "macho.segments",
        format!("{} segments", segments.len()),
        Severity::Info,
        Confidence::Direct,
    );
    for seg in &segments {
        sf.evidence.push(Evidence::new(
            "macho.segment",
            format!("{} off={:#x} size={}", seg.name, seg.fileoff, seg.filesize),
            Location::bytes(seg.fileoff, Some(seg.fileoff + seg.filesize)),
        ));
    }
    findings.push(sf);

    // Dylibs / dependencies
    if !dylibs.is_empty() {
        let mut df = Finding::new(
            "macho.dependencies",
            format!("linked against {} dylibs", dylibs.len()),
            Severity::Info,
            Confidence::Direct,
        );
        for d in dylibs.iter().take(24) {
            df.evidence.push(Evidence::new(
                "macho.dylib",
                format!("{}{}", d.name, if d.weak { " (weak)" } else { "" }),
                Location::entity("load_command", "LC_LOAD_DYLIB"),
            ));
        }
        report.facts.insert(
            "macho.dylibs".into(),
            serde_json::json!(dylibs.iter().map(|d| d.name.clone()).collect::<Vec<_>>()),
        );
        findings.push(df);
    }
    if let Some(dyld) = &dylinker {
        let mut dkf = Finding::new(
            "macho.dylinker",
            format!("dynamic linker: {dyld}"),
            Severity::Info,
            Confidence::Direct,
        );
        dkf.evidence.push(Evidence::new(
            "macho.dylinker.path",
            dyld.clone(),
            Location::entity("load_command", "LC_LOAD_DYLINKER"),
        ));
        report
            .facts
            .insert("macho.dylinker".into(), serde_json::json!(dyld));
        findings.push(dkf);
    }
    if !rpaths.is_empty() {
        let mut rf = Finding::new(
            "macho.rpaths",
            format!("{} rpath entries", rpaths.len()),
            Severity::Note,
            Confidence::Direct,
        );
        for rp in &rpaths {
            rf.evidence.push(Evidence::new("macho.rpath", rp.clone(), Location::entity("load_command", "LC_RPATH")));
        }
        findings.push(rf);
    }
    if let Some(e) = entry {
        let mut ef = Finding::new(
            "macho.entry",
            format!("entry point offset 0x{e:x}"),
            Severity::Info,
            Confidence::Direct,
        );
        ef.evidence.push(Evidence::new(
            "macho.entry",
            format!("0x{e:x}"),
            Location::entity("load_command", "LC_MAIN"),
        ));
        findings.push(ef);
    }
    if let Some((_off, _size, cryptid)) = encrypted {
        if cryptid != 0 {
            let mut cf = Finding::new(
                "macho.encrypted",
                format!("segment encryption: cryptid={cryptid}"),
                Severity::Warning,
                Confidence::Direct,
            );
            cf.evidence.push(Evidence::new(
                "macho.encryption",
                format!("cryptid={cryptid} (non-zero => encrypted)"),
                Location::entity("load_command", "LC_ENCRYPTION_INFO"),
            ));
            report.facts.insert("macho.encrypted".into(), serde_json::json!(true));
            findings.push(cf);
        }
    }
    if let Some((_off, _size)) = code_signature {
        let mut cf = Finding::new(
            "macho.code_signature",
            "code signature (LC_CODE_SIGNATURE) present",
            Severity::Info,
            Confidence::Direct,
        );
        cf.evidence.push(Evidence::new(
            "macho.code_signature",
            format!("data at 0x{:x}", code_signature.unwrap().0),
            Location::entity("load_command", "LC_CODE_SIGNATURE"),
        ));
        report.facts.insert("macho.codesigned".into(), serde_json::json!(true));
        findings.push(cf);
    }
    if let Some(min) = min_os {
        let mut mf = Finding::new(
            "macho.min_os",
            format!("minimum OS version: {min}"),
            Severity::Info,
            Confidence::Direct,
        );
        mf.evidence.push(Evidence::new("macho.min_os", min.clone(), Location::entity("load_command", "LC_BUILD_VERSION/LC_VERSION_MIN")));
        findings.push(mf);
    }

    // Symbols
    if let Some((symoff, nsyms, stroff, strsize)) = symtab {
        let syms = symbols(b, slice.little, slice.is_64, symoff, nsyms, stroff, strsize);
        let mut xf = Finding::new(
            "macho.symbols",
            format!("{} symbols in symtab", nsyms),
            Severity::Info,
            Confidence::Direct,
        );
        let mut exported: Vec<(String, u64)> = Vec::new();
        for s in syms.iter().take(2000) {
            if s.0 {
                exported.push((s.1.clone(), s.2));
            }
        }
        for (name, addr) in exported.iter().take(14) {
            xf.evidence.push(Evidence::new(
                "macho.symbol.exported",
                format!("{name} @ 0x{addr:x}"),
                Location::entity("symbol", name.clone()),
            ));
        }
        report
            .facts
            .insert("macho.export_count".into(), serde_json::json!(exported.len()));
        findings.push(xf);
    }

    // Hardening
    let pie = slice.flags & MH_PIE != 0;
    let no_heap = slice.flags & MH_NO_HEAP_EXECUTION != 0;
    let app_ext = slice.flags & MH_APP_EXTENSION_SAFE != 0;
    let mut push_h = |key: &str, claimt: &str, val: bool, ev: String| {
        report.facts.insert(key.into(), serde_json::json!(val));
        let sev = if val { Severity::Info } else { Severity::Note };
        let mut f = Finding::new(
            format!("macho.hardening.{}", key.split('.').last().unwrap_or(key)),
            format!("{claimt}: {val}"),
            sev,
            Confidence::Direct,
        );
        f.evidence.push(Evidence::new(
            format!("macho.hardening.{key}"),
            ev,
            Location::entity("mach_header", "flags"),
        ));
        findings.push(f);
    };
    push_h(
        "hardening.pie",
        "PIE (MH_PIE)",
        pie,
        format!("header flags=0x{:x}", slice.flags),
    );
    push_h(
        "hardening.nx",
        "non-executable heap (MH_NO_HEAP_EXECUTION)",
        no_heap,
        format!("header flags=0x{:x}", slice.flags),
    );
    push_h(
        "hardening.app_extension_safe",
        "app-extension safe (MH_APP_EXTENSION_SAFE)",
        app_ext,
        format!("header flags=0x{:x}", slice.flags),
    );

    // Managed runtime markers
    let full = crate::analysis::read_bounded(&ctx.path, ctx.settings.head_limit)?;
    crate::analysis::binary::managed_runtime_findings(&full, "macho", &mut findings);

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

    report.findings = findings;
    report.summary = summary(&report.findings);
    Ok(report)
}

fn analyze_fat(ctx: &AnalysisContext) -> Result<AnalysisReport> {    let b = &ctx.head;
    let magic = u32::from_be_bytes([b[0], b[1], b[2], b[3]]);
    let little = matches!(magic, FAT_CIGAM | FAT_CIGAM_64);
    let is64 = matches!(magic, FAT_MAGIC_64 | FAT_CIGAM_64);
    let r = Reader::new(b, little);
    let n = r.u32(4)? as usize;
    let mut slices = Vec::new();
    let mut off = 8usize;
    for _ in 0..n.min(24) {
        if is64 {
            let cputype = r.u32(off)? as i32;
            let offset = r.u64(off + 8)?;
            let size = r.u64(off + 16)?;
            slices.push((cputype, offset, size));
            off += 32;
        } else {
            let cputype = r.u32(off)? as i32;
            let offset = r.u32(off + 8)? as u64;
            let size = r.u32(off + 12)? as u64;
            slices.push((cputype, offset, size));
            off += 20;
        }
    }
    let mut findings: Vec<Finding> = Vec::new();
    let report = AnalysisReport::new(
        identity_for(&ctx.path, "macho", "Mach-O universal (fat) binary", b)?,
        Vec::new(),
    );
    let mut sf = Finding::new(
        "macho.fat",
        format!("universal binary with {} architecture slices", slices.len()),
        Severity::Info,
        Confidence::Direct,
    );
    for (cpu, offset, size) in slices.iter().take(12) {
        sf.evidence.push(Evidence::new(
            "macho.fat.slice",
            format!("{} offset={:#x} size={}", cputype_name(*cpu), offset, size),
            Location::bytes(*offset, Some(offset + size)),
        ));
    }
    findings.push(sf);
    let mut report = report;
    report.findings = findings;
    report.summary = summary(&report.findings);
    Ok(report)
}

fn thin(ctx: &AnalysisContext) -> Result<MachSlice> {
    let b = &ctx.head;
    if b.len() < 28 {
        return Err(Error::malformed("Mach-O too small"));
    }
    let magic = u32::from_be_bytes([b[0], b[1], b[2], b[3]]);
    let (little_marker, is_64) = match magic {
        MH_MAGIC_64 => (false, true),
        MH_CIGAM_64 => (true, true),
        MH_MAGIC => (false, false),
        MH_CIGAM => (true, false),
        _ => return Err(Error::malformed("not a thin Mach-O header")),
    };
    // Resolve actual byte order by checking which magic reads consistently.
    // Both MH_CIGAM variants mean the file is little-endian.
    let little = little_marker;
    let r = Reader::new(b, little);
    let cputype = r.u32(4)? as i32;
    let _cpusubtype = r.u32(8)?;
    let filetype = r.u32(12)?;
    let ncmds = r.u32(16)? as usize;
    let sizeofcmds = r.u32(20)? as usize;
    let flags = r.u32(24)?;
    let header_len = if is_64 { 32 } else { 28 };
    if header_len + sizeofcmds > b.len() {
        return Err(Error::malformed("load commands truncated"));
    }
    let mut commands = Vec::with_capacity(ncmds.min(256));
    let mut off = header_len;
    for _ in 0..ncmds.min(256) {
        if off + 8 > b.len() {
            break;
        }
        let cmd = r.u32(off)?;
        let cmdsize = r.u32(off + 4)? as u32;
        if cmdsize < 8 || off + cmdsize as usize > b.len() {
            break;
        }
        commands.push((cmd, cmdsize, off));
        off += cmdsize as usize;
    }
    Ok(MachSlice {
        little,
        is_64,
        cputype,
        filetype,
        flags,
        commands,
    })
}

/// (is_defined_external, name, value)
fn symbols(
    b: &[u8],
    little: bool,
    is_64: bool,
    symoff: u32,
    nsyms: u32,
    stroff: u32,
    strsize: u32,
) -> Vec<(bool, String, u64)> {
    let r = Reader::new(b, little);
    let entsize = if is_64 { 16 } else { 12 };
    let mut out = Vec::new();
    let count = nsyms.min(50_000) as usize;
    for i in 0..count {
        let base = symoff as usize + i * entsize;
        if base + entsize > b.len() {
            break;
        }
        let n_strx = r.u32(base).unwrap_or(0);
        let n_type = b.get(base + 4).copied().unwrap_or(0);
        let n_value = if is_64 {
            r.u64(base + 8).unwrap_or(0)
        } else {
            r.u32(base + 8).unwrap_or(0) as u64
        };
        let is_ext = n_type & 0x01 != 0;
        let is_type_sect = n_type & 0x0e == 0x0e;
        if !(is_ext && is_type_sect) {
            continue;
        }
        if n_strx as usize >= strsize as usize {
            continue;
        }
        let so = stroff as usize + n_strx as usize;
        if so >= b.len() {
            continue;
        }
        let end = (so + 512).min(b.len());
        let raw = &b[so..end];
        let nul = raw.iter().position(|&x| x == 0).unwrap_or(raw.len());
        let name = String::from_utf8_lossy(&raw[..nul]).into_owned();
        out.push((true, name, n_value));
    }
    out
}

fn format_uuid(bytes: &[u8]) -> String {
    if bytes.len() < 16 {
        return String::new();
    }
    let hex = crate::core::io::hex(&bytes[..16]);
    format!(
        "{}-{}-{}-{}-{}",
        &hex[0..8], &hex[8..12], &hex[12..16], &hex[16..20], &hex[20..32]
    )
}

fn format_version(v: u32) -> String {
    let major = (v >> 16) & 0xffff;
    let minor = (v >> 8) & 0xff;
    let patch = v & 0xff;
    format!("{major}.{minor}.{patch}")
}

fn filetype_name(t: u32) -> &'static str {
    match t {
        MH_OBJECT => "OBJECT",
        MH_EXECUTE => "EXECUTE",
        3 => "FVMLIB",
        4 => "CORE",
        5 => "PRELOAD",
        MH_DYLIB => "DYLIB",
        MH_BUNDLE => "BUNDLE",
        9 => "DYLIB_STUB",
        10 => "DSYM",
        11 => "KEXT_BUNDLE",
        _ => "other",
    }
}

fn cputype_name(t: i32) -> &'static str {
    match t {
        7 => "i386",
        0x0100_0007 => "x86-64",
        12 => "arm",
        0x0100_000c => "arm64",
        0x0200_000c => "arm64e",
        18 => "ppc",
        0x0100_0012 => "ppc64",
        0x0a00_000c => "arm64_32",
        _ => "cpu-unknown",
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
