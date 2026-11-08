//! ELF header, program/section tables, dynamic, symbols, hardening, and
//! kernel-module analysis. Supports ELF32/ELF64 in either byte order.

use crate::analysis::{AnalysisContext, identity_for};
use crate::core::error::{Error, Result};
use crate::core::evidence::{AnalysisReport, Confidence, Evidence, Finding, Location, Severity};
use crate::core::io::Reader;

#[derive(Debug, Clone)]
struct Ehdr {
    is_64: bool,
    little: bool,
    e_type: u16,
    machine: u16,
    entry: u64,
    phoff: u64,
    shoff: u64,
    phnum: usize,
    phentsize: usize,
    shnum: usize,
    shentsize: usize,
    shstrndx: usize,
}

#[derive(Debug, Clone)]
struct Phdr {
    p_type: u32,
    p_flags: u32,
    p_offset: u64,
    p_filesz: u64,
    p_memsz: u64,
}

#[derive(Debug, Clone)]
struct Shdr {
    name_off: u32,
    sh_type: u32,
    offset: u64,
    size: u64,
    link: u32,
    info: u32,
    entsize: u64,
}

struct DynamicImports {
    needed: Vec<String>,
    soname: Option<String>,
    rpath: Option<String>,
    runpath: Option<String>,
    bind_now: bool,
}

struct SymSet {
    dynsym: usize,
    defined: Vec<DefinedSym>,
}

struct DefinedSym {
    name: String,
    addr: u64,
}

const PT_LOAD: u32 = 1;
const PT_DYNAMIC: u32 = 2;
const PT_INTERP: u32 = 3;
const PT_NOTE: u32 = 4;
const PT_GNU_STACK: u32 = 0x6474_e551;
const PT_GNU_RELRO: u32 = 0x6474_e552;
const PF_X: u32 = 1;

const SHT_PROGBITS: u32 = 1;
const SHT_STRTAB: u32 = 3;
const SHT_NOTE: u32 = 7;
const SHT_DYNSYM: u32 = 11;
const SHT_DYNAMIC: u32 = 6;
const SHT_SYMTAB: u32 = 2;

pub fn analyze(ctx: &AnalysisContext) -> Result<AnalysisReport> {
    let p = match ehdr(ctx) {
        Ok(p) => p,
        Err(_) => return fail_report(ctx, "ELF header could not be interpreted"),
    };

    let mut findings: Vec<Finding> = Vec::new();
    let type_name = et_name(p.e_type);
    let label = format!(
        "ELF {} ({}) machine {} ({})",
        if p.is_64 { 64 } else { 32 },
        if p.little { "LSB" } else { "MSB" },
        machine_name(p.machine),
        p.machine,
    );

    let identity = identity_for(&ctx.path, "elf", &label, &ctx.head)?;
    let mut report = AnalysisReport::new(identity, Vec::new());
    report.facts.insert("elf.class".into(), serde_json::json!(if p.is_64 { 64 } else { 32 }));
    report
        .facts
        .insert("elf.endian".into(), serde_json::json!(if p.little { "little" } else { "big" }));
    report.facts.insert(
        "elf.machine".into(),
        serde_json::json!(format!("{} ({})", machine_name(p.machine), p.machine)),
    );
    report.facts.insert(
        "elf.type".into(),
        serde_json::json!(format!("{type_name} ({})", p.e_type)),
    );
    report.facts.insert(
        "elf.entry".into(),
        serde_json::json!(format!("0x{:x}", p.entry)),
    );

    // ---- Header finding ----
    let mut hf = Finding::new("elf.header", label.clone(), Severity::Info, Confidence::Direct);
    hf.evidence
        .push(Evidence::new("elf.header.e_type", format!("{type_name} (0x{:x})", p.e_type), Location::bytes(0x10, Some(0x12))));
    hf.evidence.push(Evidence::new(
        "elf.header.machine",
        format!("{} (0x{:x})", machine_name(p.machine), p.machine),
        Location::bytes(0x12, Some(0x14)),
    ));
    hf.evidence.push(Evidence::new(
        "elf.header.entry",
        format!("0x{:x}", p.entry),
        Location::bytes(entry_off(&p) as u64, Some(entry_off(&p) as u64 + p.bits_width())),
    ));
    hf.evidence.push(Evidence::new(
        "elf.header.phnum",
        p.phnum.to_string(),
        Location::bytes(phnum_off(&p) as u64, Some(phnum_off(&p) as u64 + 2)),
    ));
    hf.evidence.push(Evidence::new(
        "elf.header.shnum",
        p.shnum.to_string(),
        Location::bytes(shnum_off(&p) as u64, Some(shnum_off(&p) as u64 + 2)),
    ));
    findings.push(hf);

    // ---- Program headers ----
    let phdrs = phdrs(&ctx.head, &p)?;
    let load_count = phdrs.iter().filter(|h| h.p_type == PT_LOAD).count();
    let mut pf = Finding::new(
        "elf.program_headers",
        format!("{} program headers, {load_count} loadable segments", phdrs.len()),
        Severity::Info,
        Confidence::Direct,
    );
    for ph in &phdrs {
        pf.evidence.push(Evidence::new(
            "elf.phdr",
            format!(
                "{} off={:#x} filesz={} memsz={} flags={:#x}",
                pt_name(ph.p_type), ph.p_offset, ph.p_filesz, ph.p_memsz, ph.p_flags
            ),
            Location::bytes(ph.p_offset, Some(ph.p_offset + ph.p_filesz)),
        ));
    }
    findings.push(pf);

    // ---- Sections ----
    let shdrs = shdrs(&ctx.head, &p)?;
    let section_name = |idx: usize| -> String { section_name_at(&ctx.head, &p, &shdrs, idx) };
    let mut sf = Finding::new(
        "elf.sections",
        format!("{} section headers", shdrs.len()),
        Severity::Info,
        Confidence::Direct,
    );
    for (i, s) in shdrs.iter().enumerate() {
        if s.sh_type == 0 {
            continue;
        }
        let name = section_name(i);
        sf.evidence.push(Evidence::new(
            "elf.section",
            format!("{name}[{i}] {} size={}", st_name(s.sh_type), s.size),
            Location::bytes(s.offset, Some(s.offset + s.size)),
        ));
    }
    findings.push(sf);

    // ---- Dynamic ---- 
    if let Some(dynm) = dynamic_imports(&ctx.head, &p, &shdrs) {
        let needed_display = if dynm.needed.is_empty() {
            "(none)".to_string()
        } else {
            dynm.needed.join(", ")
        };
        let mut df = Finding::new(
            "elf.dynamic",
            format!("dynamic dependencies: {needed_display}"),
            Severity::Info,
            Confidence::Direct,
        );
        if let Some(s) = &dynm.soname {
            df.evidence.push(Evidence::new("elf.dynamic.soname", s.clone(), Location::entity("dynamic", "DT_SONAME")));
        }
        for n in &dynm.needed {
            df.evidence.push(Evidence::new("elf.dynamic.needed", n.clone(), Location::entity("dynamic", "DT_NEEDED")));
        }
        if let Some(s) = &dynm.rpath {
            df.evidence.push(Evidence::new("elf.dynamic.rpath", s.clone(), Location::entity("dynamic", "DT_RPATH")));
        }
        if let Some(s) = &dynm.runpath {
            df.evidence.push(Evidence::new("elf.dynamic.runpath", s.clone(), Location::entity("dynamic", "DT_RUNPATH")));
        }
        report.facts.insert("elf.needed".into(), serde_json::json!(dynm.needed));
        if dynm.bind_now {
            report.facts.insert("elf.bind_now".into(), serde_json::json!(true));
        }
        findings.push(df);
    }

    // ---- Symbols ----
    let syms = symbols(&ctx.head, &p, &shdrs);
    if let Some(sym) = &syms {
        let mut xf = Finding::new(
            "elf.symbols",
            format!("{} dynamic symbols; {} defined external symbols", sym.dynsym, sym.defined.len()),
            Severity::Info,
            Confidence::Direct,
        );
        for d in sym.defined.iter().take(14) {
            xf.evidence.push(Evidence::new(
                "elf.symbol.defined",
                format!("{} @ 0x{:x}", d.name, d.addr),
                Location::entity("symbol", d.name.clone()),
            ));
        }
        findings.push(xf);
    }

    // ---- Hardening ----
    for h in hardening(&ctx.head, &p, &phdrs, &shdrs, &syms) {
        report.facts.insert(h.0.into(), serde_json::json!(h.1));
        let mut f = Finding::new(
            format!("elf.hardening.{}", h.2),
            format!("{}: {}", h.2, h.1),
            h.3,
            Confidence::Direct,
        );
        f.evidence.push(h.4);
        findings.push(f);
    }

    // ---- Kernel module markers ----
    kernel_module_findings(&ctx.head, &p, &shdrs, &mut findings);

    // ---- Managed runtime markers (Go / Rust) ----
    let full = crate::analysis::read_bounded(&ctx.path, ctx.settings.head_limit)?;
    crate::analysis::binary::managed_runtime_findings(&full, "elf", &mut findings);

    // ---- Strings ----
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
    report.summary = severity_summary(&report.findings);
    Ok(report)
}

impl Ehdr {
    fn bits_width(&self) -> u64 {
        if self.is_64 {
            8
        } else {
            4
        }
    }
}

// ---------------------------------------------------------------------------
// Parsers
// ---------------------------------------------------------------------------

fn ehdr(ctx: &AnalysisContext) -> Result<Ehdr> {
    let b = &ctx.head;
    if b.len() < 52 {
        return Err(Error::malformed("ELF too small"));
    }
    let is_64 = b[4] == 2;
    let little = b[5] == 1;
    let r = Reader::new(b, little);
    if is_64 {
        Ok(Ehdr {
            is_64: true,
            little,
            e_type: r.u16(16)?,
            machine: r.u16(18)?,
            entry: r.u64(24)?,
            phoff: r.u64(32)?,
            shoff: r.u64(40)?,
            phnum: r.u16(56)? as usize,
            phentsize: (r.u16(54)? as usize).max(1),
            shnum: r.u16(60)? as usize,
            shentsize: (r.u16(58)? as usize).max(1),
            shstrndx: r.u16(62)? as usize,
        })
    } else {
        Ok(Ehdr {
            is_64: false,
            little,
            e_type: r.u16(16)?,
            machine: r.u16(18)?,
            entry: r.u32(24)? as u64,
            phoff: r.u32(28)? as u64,
            shoff: r.u32(32)? as u64,
            phnum: r.u16(44)? as usize,
            phentsize: (r.u16(42)? as usize).max(1),
            shnum: r.u16(48)? as usize,
            shentsize: (r.u16(46)? as usize).max(1),
            shstrndx: r.u16(50)? as usize,
        })
    }
}

fn phdrs(b: &[u8], p: &Ehdr) -> Result<Vec<Phdr>> {
    let r = Reader::new(b, p.little);
    let mut out = Vec::with_capacity(p.phnum.min(256));
    for i in 0..p.phnum {
        let off = (p
            .phoff as usize)
            .checked_add(i * p.phentsize)
            .ok_or_else(|| Error::limit("phdr offset"))?;
        let ph = if p.is_64 {
            Phdr {
                p_type: r.u32(off)?,
                p_flags: r.u32(off + 4)?,
                p_offset: r.u64(off + 8)?,
                p_filesz: r.u64(off + 32)?,
                p_memsz: r.u64(off + 40)?,
            }
        } else {
            Phdr {
                p_type: r.u32(off)?,
                p_flags: r.u32(off + 24)?,
                p_offset: r.u32(off + 4)? as u64,
                p_filesz: r.u32(off + 16)? as u64,
                p_memsz: r.u32(off + 20)? as u64,
            }
        };
        out.push(ph);
    }
    Ok(out)
}

fn shdrs(b: &[u8], p: &Ehdr) -> Result<Vec<Shdr>> {
    if p.shoff == 0 || p.shnum == 0 {
        return Ok(Vec::new());
    }
    let r = Reader::new(b, p.little);
    let mut out = Vec::with_capacity(p.shnum.min(512));
    for i in 0..p.shnum {
        let off = (p
            .shoff as usize)
            .checked_add(i * p.shentsize)
            .ok_or_else(|| Error::limit("shdr offset"))?;
        let sh = if p.is_64 {
            Shdr {
                name_off: r.u32(off)?,
                sh_type: r.u32(off + 4)?,
                offset: r.u64(off + 24)?,
                size: r.u64(off + 32)?,
                link: r.u32(off + 40)?,
                info: r.u32(off + 44)?,
                entsize: r.u64(off + 56)?,
            }
        } else {
            Shdr {
                name_off: r.u32(off)?,
                sh_type: r.u32(off + 4)?,
                offset: r.u32(off + 16)? as u64,
                size: r.u32(off + 20)? as u64,
                link: r.u32(off + 24)?,
                info: r.u32(off + 28)?,
                entsize: r.u32(off + 36)? as u64,
            }
        };
        out.push(sh);
    }
    Ok(out)
}

/// Section name for index `idx`, resolved through `.shstrtab`.
fn section_name_at(b: &[u8], p: &Ehdr, shdrs: &[Shdr], idx: usize) -> String {
    let Some(sh) = shdrs.get(idx) else {
        return String::new();
    };
    let Some(strtab) = shdrs.get(p.shstrndx) else {
        return format!("#{idx}");
    };
    if strtab.sh_type != SHT_STRTAB {
        return format!("#{idx}");
    }
    let r = Reader::new(b, p.little);
    let off = (strtab.offset as usize).saturating_add(sh.name_off as usize);
    match r.cstr_bounded(off) {
        Ok(s) if s.len() <= 4096 => String::from_utf8_lossy(s).into_owned(),
        _ => format!("#{}", sh.name_off),
    }
}

fn strtab_at(b: &[u8], p: &Ehdr, link: u32) -> Option<(u64, u64)> {
    // Returns (offset, size) of the string table section linked by `link`.
    let shdrs = shdrs(b, p).ok()?;
    let st = shdrs.get(link as usize)?;
    (st.sh_type == SHT_STRTAB).then_some((st.offset, st.size))
}

fn read_str(b: &[u8], p: &Ehdr, st: (u64, u64), off: u32) -> Option<String> {
    if off as u64 >= st.1 {
        return None;
    }
    let base = st.0 as usize;
    let r = Reader::new(b, p.little);
    let s = r.cstr(base + off as usize, 4096).ok()?;
    Some(String::from_utf8_lossy(s).into_owned())
}

fn dynamic_imports(b: &[u8], p: &Ehdr, shdrs: &[Shdr]) -> Option<DynamicImports> {
    let dyn_sec = shdrs.iter().find(|s| s.sh_type == SHT_DYNAMIC)?;
    if dyn_sec.entsize == 0 && !p.is_64 {
        // 32-bit dynamic entries are 8 bytes.
    }
    let entsize = if dyn_sec.entsize == 0 {
        if p.is_64 {
            16
        } else {
            8
        }
    } else {
        dyn_sec.entsize as usize
    };
    let count = (dyn_sec.size / entsize as u64).min(16384) as usize;
    let (st_off, st_size) = strtab_at(b, p, dyn_sec.link)?;
    let r = Reader::new(b, p.little);
    let start = dyn_sec.offset as usize;
    const DT_NULL: u64 = 0;
    const DT_NEEDED: u64 = 1;
    const DT_SONAME: u64 = 14;
    const DT_RPATH: u64 = 15;
    const DT_BIND_NOW: u64 = 24;
    const DT_RUNPATH: u64 = 29;
    const DT_FLAGS: u64 = 30;
    const DT_FLAGS_1: u64 = 0x6fff_fffb;
    const DF_BIND_NOW: u64 = 0x8;
    const DF_1_NOW: u64 = 0x1;
    let mut out = DynamicImports {
        needed: Vec::new(),
        soname: None,
        rpath: None,
        runpath: None,
        bind_now: false,
    };
    for i in 0..count {
        let off = start + i * entsize;
        if off + entsize > b.len() {
            break;
        }
        let (tag, val) = if p.is_64 {
            (r.u64(off).ok()?, r.u64(off + 8).ok()?)
        } else {
            (r.u32(off).ok()? as u64, r.u32(off + 4).ok()? as u64)
        };
        match tag {
            DT_NULL => break,
            DT_NEEDED => {
                if let Some(s) = read_str(b, p, (st_off, st_size), val as u32) {
                    out.needed.push(s);
                }
            }
            DT_SONAME => out.soname = read_str(b, p, (st_off, st_size), val as u32),
            DT_RPATH => out.rpath = read_str(b, p, (st_off, st_size), val as u32),
            DT_RUNPATH => out.runpath = read_str(b, p, (st_off, st_size), val as u32),
            DT_BIND_NOW => out.bind_now = true,
            DT_FLAGS => {
                if val & DF_BIND_NOW != 0 {
                    out.bind_now = true;
                }
            }
            DT_FLAGS_1 => {
                if val & DF_1_NOW != 0 {
                    out.bind_now = true;
                }
            }
            _ => {}
        }
    }
    Some(out)
}

fn symbols(b: &[u8], p: &Ehdr, shdrs: &[Shdr]) -> Option<SymSet> {
    let sym_sec = shdrs
        .iter()
        .find(|s| s.sh_type == SHT_DYNSYM)
        .or_else(|| shdrs.iter().find(|s| s.sh_type == SHT_SYMTAB))?;
    let (st_off, st_size) = strtab_at(b, p, sym_sec.link)?;
    let entsize = if sym_sec.entsize == 0 {
        if p.is_64 {
            24
        } else {
            16
        }
    } else {
        sym_sec.entsize as usize
    };
    let count = (sym_sec.size / entsize as u64).min(200_000) as usize;
    let r = Reader::new(b, p.little);
    let start = sym_sec.offset as usize;
    let mut dynsym = 0usize;
    let mut defined = Vec::new();
    for i in 0..count {
        let off = start + i * entsize;
        if i >= sym_sec.info as usize {
            dynsym += 1;
        }
        let need = if p.is_64 { 24 } else { 16 };
        if off + need > b.len() {
            break;
        }
        let (name_off, value, st_info) = if p.is_64 {
            (r.u32(off).ok()?, r.u64(off + 8).ok()?, b[off + 4])
        } else {
            (r.u32(off).ok()?, r.u32(off + 4).ok()? as u64, b[off + 12])
        };
        let bind = st_info >> 4;
        let ty = st_info & 0xf;
        if bind == 1 && (ty == 2 || ty == 1) && name_off != 0 && value != 0 {
            if let Some(name) = read_str(b, p, (st_off, st_size), name_off) {
                defined.push(DefinedSym { name, addr: value });
            }
        }
    }
    Some(SymSet { dynsym, defined })
}

/// True when `needle` appears anywhere in the dynamic/static symbol table.
fn any_symbol(b: &[u8], p: &Ehdr, shdrs: &[Shdr], needle: &str) -> bool {
    let Some(sym) = symbols(b, p, shdrs) else {
        return false;
    };
    sym.defined.iter().any(|d| d.name == needle)
}

// ---------------------------------------------------------------------------
// Hardening
// ---------------------------------------------------------------------------

fn hardening(
    b: &[u8],
    p: &Ehdr,
    phdrs: &[Phdr],
    shdrs: &[Shdr],
    syms: &Option<SymSet>,
) -> Vec<(String, bool, &'static str, Severity, Evidence)> {
    let mut out = Vec::new();
    let has_symbol = |needle: &str| -> bool {
        syms.as_ref()
            .map(|s| s.defined.iter().any(|d| d.name == needle))
            .unwrap_or(false)
    };

    // PIE
    let interp = phdrs.iter().any(|ph| ph.p_type == PT_INTERP);
    let pie = p.e_type == 3 && interp;
    if pie {
        out.push((
            "hardening.pie".into(),
            true,
            "PIE",
            Severity::Info,
            Evidence::new(
                "elf.hardening.pie",
                "e_type=ET_DYN (3) with PT_INTERP",
                Location::bytes(0x10, Some(0x12)),
            ),
        ));
    } else if p.e_type == 2 {
        out.push((
            "hardening.pie".into(),
            false,
            "PIE",
            Severity::Note,
            Evidence::new(
                "elf.hardening.pie",
                "e_type=ET_EXEC (2), fixed load address",
                Location::bytes(0x10, Some(0x12)),
            ),
        ));
    }

    // NX stack
    let stack = phdrs.iter().find(|ph| ph.p_type == PT_GNU_STACK);
    let nx = stack.map(|s| s.p_flags & PF_X == 0).unwrap_or(false);
    out.push((
        "hardening.nx".into(),
        nx,
        "NX",
        if nx { Severity::Info } else { Severity::Note },
        Evidence::new(
            "elf.hardening.nx",
            match stack {
                Some(s) => format!("PT_GNU_STACK flags={:#x}", s.p_flags),
                None => "no PT_GNU_STACK (legacy executable-stack assumption)".into(),
            },
            Location::entity("program_header", "PT_GNU_STACK"),
        ),
    ));

    // RELRO
    let relro = phdrs.iter().any(|ph| ph.p_type == PT_GNU_RELRO);
    let bind_now = dynamic_imports(b, p, shdrs)
        .map(|d| d.bind_now)
        .unwrap_or(false);
    if relro && bind_now {
        out.push((
            "hardening.relro".into(),
            true,
            "RELRO",
            Severity::Info,
            Evidence::new(
                "elf.hardening.relro",
                "PT_GNU_RELRO present and BIND_NOW set (full RELRO)",
                Location::entity("program_header", "PT_GNU_RELRO"),
            ),
        ));
    } else if relro {
        out.push((
            "hardening.relro".into(),
            true,
            "RELRO",
            Severity::Note,
            Evidence::new(
                "elf.hardening.relro",
                "PT_GNU_RELRO present without BIND_NOW (partial RELRO)",
                Location::entity("program_header", "PT_GNU_RELRO"),
            ),
        ));
    } else {
        out.push((
            "hardening.relro".into(),
            false,
            "RELRO",
            Severity::Note,
            Evidence::new(
                "elf.hardening.relro",
                "no PT_GNU_RELRO segment",
                Location::entity("program_header", "PT_GNU_RELRO"),
            ),
        ));
    }

    // Stack canary
    let canary = has_symbol("__stack_chk_fail") || any_symbol(b, p, shdrs, "__stack_chk_fail");
    out.push((
        "hardening.stack_canary".into(),
        canary,
        "stack canary",
        if canary { Severity::Info } else { Severity::Note },
        Evidence::new(
            "elf.hardening.canary",
            if canary {
                "__stack_chk_fail present in symbol table".to_string()
            } else {
                "no __stack_chk_fail symbol".to_string()
            },
            Location::entity("symbol", "__stack_chk_fail"),
        ),
    ));

    // Fortify
    let fortify = has_symbol("__memcpy_chk")
        || any_symbol(b, p, shdrs, "__memcpy_chk")
        || syms
            .as_ref()
            .map(|s| s.defined.iter().any(|d| d.name.ends_with("_chk")))
            .unwrap_or(false);
    if fortify {
        out.push((
            "hardening.fortify".into(),
            true,
            "FORTIFY",
            Severity::Info,
            Evidence::new(
                "elf.hardening.fortify",
                "_chk function symbols present",
                Location::entity("symbol", "*_chk"),
            ),
        ));
    }

    // GNU build-id
    if let Some(bid) = gnu_build_id(b, p, phdrs, shdrs) {
        out.push((
            "hardening.build_id".into(),
            true,
            "GNU build-id",
            Severity::Info,
            Evidence::new(
                "elf.hardening.build_id",
                bid,
                Location::entity("note", "NT_GNU_BUILD_ID"),
            ),
        ));
    }

    out
}

fn gnu_build_id(b: &[u8], p: &Ehdr, phdrs: &[Phdr], shdrs: &[Shdr]) -> Option<String> {
    // Prefer a dedicated section.
    for (i, s) in shdrs.iter().enumerate() {
        let name = section_name_at(b, p, shdrs, i);
        if name.contains("build-id") {
            if let Some(id) = note_build_id(b, s.offset as usize) {
                return Some(id);
            }
        }
    }
    for ph in phdrs.iter().filter(|ph| ph.p_type == PT_NOTE) {
        if let Some(id) = note_build_id(b, ph.p_offset as usize) {
            return Some(id);
        }
    }
    None
}

/// Parse a note at `off`; return the build-id as hex when type==NT_GNU_BUILD_ID.
fn note_build_id(b: &[u8], off: usize) -> Option<String> {
    let r = Reader::new(b, true);
    let namesz = r.u32(off).ok()? as usize;
    let descsz = r.u32(off + 4).ok()? as usize;
    let ntype = r.u32(off + 8).ok()?;
    let mut pos = off + 12;
    let name = r.slice(pos, namesz).ok()?;
    pos += (namesz + 3) & !3;
    let desc = r.slice(pos, descsz).ok()?;
    if ntype == 3 && (name.starts_with(b"GNU") || name.starts_with(b"Go")) && descsz <= 64 {
        let mut s = String::with_capacity(descsz * 2);
        for byte in desc {
            s.push_str(&format!("{byte:02x}"));
        }
        return Some(s);
    }
    None
}

// ---------------------------------------------------------------------------
// Kernel modules
// ---------------------------------------------------------------------------

fn kernel_module_findings(b: &[u8], p: &Ehdr, shdrs: &[Shdr], out: &mut Vec<Finding>) {
    let Some(mi) = shdrs.iter().position(|s| section_name_at(b, p, shdrs, index_of(s, shdrs)) == ".modinfo") else {
        return;
    };
    let sec = &shdrs[mi];
    if sec.sh_type != SHT_PROGBITS {
        return;
    }
    let end = (sec.offset + sec.size).min(b.len() as u64) as usize;
    let data = &b[sec.offset as usize..end];
    let text = String::from_utf8_lossy(data).into_owned();
    let mut interesting = Vec::new();
    for l in text.split('\0') {
        if l.starts_with("vermagic=")
            || l.starts_with("name=")
            || l.starts_with("srcversion=")
            || l.starts_with("depends=")
            || l.starts_with("alias=")
        {
            interesting.push(l.to_string());
        }
    }
    if interesting.is_empty() {
        return;
    }
    let mut f = Finding::new(
        "elf.kernel_module",
        "ELF is a Linux kernel module: .modinfo present",
        Severity::Info,
        Confidence::Direct,
    );
    for l in interesting.iter().take(6) {
        f.evidence
            .push(Evidence::new("elf.modinfo", l.clone(), Location::entity("section", ".modinfo")));
    }
    out.push(f);
}

fn index_of<'a>(target: &Shdr, shdrs: &[Shdr]) -> usize {
    shdrs
        .iter()
        .position(|s| std::ptr::eq(s, target))
        .unwrap_or(0)
}

// ---------------------------------------------------------------------------
// Label helpers
// ---------------------------------------------------------------------------

fn et_name(t: u16) -> &'static str {
    match t {
        0 => "NONE",
        1 => "REL (relocatable)",
        2 => "EXEC (executable)",
        3 => "DYN (shared object / PIE)",
        4 => "CORE",
        _ => "unknown",
    }
}

pub fn machine_name(m: u16) -> &'static str {
    match m {
        0 => "no machine",
        2 => "SPARC",
        3 => "x86 (i386)",
        8 => "MIPS",
        20 => "PowerPC",
        21 => "PowerPC64",
        22 => "S390",
        40 => "ARM",
        42 => "SuperH",
        43 => "SPARC v9",
        50 => "IA-64",
        62 => "x86-64",
        183 => "AArch64",
        243 => "RISC-V",
        247 => "CUDA",
        _ => "machine-unknown",
    }
}

fn pt_name(t: u32) -> &'static str {
    match t {
        PT_LOAD => "LOAD",
        PT_DYNAMIC => "DYNAMIC",
        PT_INTERP => "INTERP",
        PT_NOTE => "NOTE",
        PT_GNU_STACK => "GNU_STACK",
        PT_GNU_RELRO => "GNU_RELRO",
        0x6ffffffb => "PAX_FLAGS",
        _ => "other",
    }
}

fn st_name(t: u32) -> &'static str {
    match t {
        0 => "NULL",
        SHT_PROGBITS => "PROGBITS",
        SHT_SYMTAB => "SYMTAB",
        SHT_STRTAB => "STRTAB",
        SHT_NOTE => "NOTE",
        8 => "NOBITS",
        SHT_DYNAMIC => "DYNAMIC",
        SHT_DYNSYM => "DYNSYM",
        5 => "HASH",
        0x6fff_fff5 => "GNU_HASH",
        0x6fff_fffb => "GNU_versym",
        0x6fff_ffe0 => "GNU_versym",
        0x6fffffff => "GNU_LIBLIST",
        _ => "other",
    }
}

fn fail_report(ctx: &AnalysisContext, reason: &str) -> Result<AnalysisReport> {
    let identity = identity_for(&ctx.path, "elf", "ELF (header unreadable)", &ctx.head)?;
    let mut f = Finding::new("elf.header.failed", reason, Severity::Note, Confidence::Inferred);
    f.limitations.push("header parse failed; deeper analysis skipped".into());
    let mut r = AnalysisReport::new(identity, vec![f]);
    r.facts.insert("elf.recognized".into(), serde_json::json!(false));
    Ok(r)
}

fn severity_summary(findings: &[Finding]) -> serde_json::Map<String, serde_json::Value> {
    let mut m = serde_json::Map::new();
    for sev in [Severity::Info, Severity::Note, Severity::Warning, Severity::Critical] {
        let n = findings.iter().filter(|f| f.severity == sev).count();
        m.insert(sev.label().into(), serde_json::json!(n));
    }
    m.insert("total".into(), serde_json::json!(findings.len()));
    m
}

fn entry_off(p: &Ehdr) -> usize {
    let _ = p;
    24
}

fn phnum_off(p: &Ehdr) -> usize {
    if p.is_64 {
        56
    } else {
        44
    }
}

fn shnum_off(p: &Ehdr) -> usize {
    if p.is_64 {
        60
    } else {
        48
    }
}
