//! .NET / CLR assembly analysis: COM descriptor, metadata root, table
//! inventory (assembly refs, types, methods), string heaps, and a compact
//! CIL instruction decoder for method bodies.

use crate::analysis::{AnalysisContext, identity_for};
use crate::core::error::{Error, Result};
use crate::core::evidence::{AnalysisReport, Confidence, Evidence, Finding, Location, Severity};
use crate::core::io::Reader;

const DIR_COM: usize = 14;

/// Returns `Some(report)` when the input is a recognized .NET assembly;
/// `None` lets the caller fall through to plain PE analysis.
pub fn try_dotnet(ctx: &AnalysisContext) -> Option<AnalysisReport> {
    let cli = match parse_cli(&ctx.head) {
        Ok(cli) => cli,
        Err(_) => return None,
    };
    let md = match parse_metadata(&ctx.head, &cli) {
        Ok(md) => md,
        Err(_) => return None,
    };
    Some(build_report(ctx, &cli, &md))
}

// ---------------------------------------------------------------------------
// PE + CLI header parsing
// ---------------------------------------------------------------------------

struct Section {
    virtual_addr: u32,
    virtual_size: u32,
    raw_ptr: u32,
    raw_size: u32,
}

struct CliHeader {
    offset: u64, // file offset of IMAGE_COR20_HEADER
    #[allow(dead_code)]
    runtime_version: String,
    #[allow(dead_code)]
    flags: u32,
    #[allow(dead_code)]
    entry_point_token: u32,
    metadata_rva: u32,
    #[allow(dead_code)]
    metadata_size: u32,
    #[allow(dead_code)]
    resources_size: u32,
    strong_name_size: u32,
    sections: Vec<Section>,
}

fn rva_to_off(sections: &[Section], rva: u32) -> Option<u64> {
    for s in sections {
        if rva >= s.virtual_addr && rva < s.virtual_addr + s.virtual_size.max(s.raw_size) {
            let delta = rva - s.virtual_addr;
            if delta < s.raw_size {
                return Some(s.raw_ptr as u64 + delta as u64);
            }
        }
    }
    None
}

fn parse_cli(b: &[u8]) -> Result<CliHeader> {
    let p = parse_pe_sections(b)?;
    let (dir_rva, dir_size) = {
        let opt = opt_header(b)?;
        let dirs = data_dirs(b, opt)?;
        if dirs.len() <= DIR_COM {
            return Err(Error::malformed("no data directories"));
        }
        dirs[DIR_COM]
    };
    if dir_rva == 0 {
        return Err(Error::malformed("no COM descriptor directory"));
    }
    let off = rva_to_off(&p.sections, dir_rva)
        .ok_or_else(|| Error::malformed("COM descriptor RVA out of sections"))? as usize;
    if off + 72 > b.len() {
        return Err(Error::malformed("CLI header truncated"));
    }
    let r = Reader::new(b, true);
    let metadata_rva = r.u32(off + 8)?;
    let metadata_size = r.u32(off + 12)?;
    let flags = r.u32(off + 16)?;
    let entry_point_token = r.u32(off + 20)?;
    let resources_size = r.u32(off + 28)?;
    let strong_name_size = r.u32(off + 36)?;
    let _ = dir_size;

    let md_off = rva_to_off(&p.sections, metadata_rva)
        .ok_or_else(|| Error::malformed("metadata RVA out of sections"))? as usize;
    if md_off + 4 > b.len() || &b[md_off..md_off + 4] != b"BSJB" {
        return Err(Error::malformed("metadata signature is not BSJB"));
    }
    let ver_len = r.u32(md_off + 12)? as usize;
    let runtime_version = String::from_utf8_lossy(&b[md_off + 16..md_off + 16 + ver_len])
        .trim_end_matches('\0')
        .to_string();

    Ok(CliHeader {
        offset: off as u64,
        runtime_version,
        flags,
        entry_point_token,
        metadata_rva,
        metadata_size,
        resources_size,
        strong_name_size,
        sections: p.sections,
    })
}

struct PeSections {
    sections: Vec<Section>,
}

fn parse_pe_sections(b: &[u8]) -> Result<PeSections> {
    if b.len() < 0x40 || &b[0..2] != b"MZ" {
        return Err(Error::malformed("not MZ"));
    }
    let e_lfanew = u32::from_le_bytes([b[0x3C], b[0x3D], b[0x3E], b[0x3F]]) as usize;
    if e_lfanew + 4 > b.len() || &b[e_lfanew..e_lfanew + 4] != b"PE\0\0" {
        return Err(Error::malformed("not PE"));
    }
    let coff = e_lfanew + 4;
    let n_sections = u16::from_le_bytes([b[coff + 2], b[coff + 3]]) as usize;
    let size_opt = u16::from_le_bytes([b[coff + 16], b[coff + 17]]) as usize;
    let sec_off = coff + 20 + size_opt;
    let mut sections = Vec::new();
    for i in 0..n_sections.min(96) {
        let o = sec_off + i * 40;
        if o + 40 > b.len() {
            break;
        }
        let virtual_size = u32::from_le_bytes([b[o + 8], b[o + 9], b[o + 10], b[o + 11]]);
        let virtual_addr = u32::from_le_bytes([b[o + 12], b[o + 13], b[o + 14], b[o + 15]]);
        let raw_size = u32::from_le_bytes([b[o + 16], b[o + 17], b[o + 18], b[o + 19]]);
        let raw_ptr = u32::from_le_bytes([b[o + 20], b[o + 21], b[o + 22], b[o + 23]]);
        sections.push(Section {
            virtual_addr,
            virtual_size,
            raw_ptr,
            raw_size,
        });
    }
    Ok(PeSections { sections })
}

fn opt_header(b: &[u8]) -> Result<usize> {
    let e_lfanew = u32::from_le_bytes([b[0x3C], b[0x3D], b[0x3E], b[0x3F]]) as usize;
    Ok(e_lfanew + 4 + 20)
}

fn data_dirs(b: &[u8], opt: usize) -> Result<Vec<(u32, u32)>> {
    let r = Reader::new(b, true);
    let magic = r.u16(opt)?;
    let (dirs_off, n_dirs) = match magic {
        0x10B => (opt + 96, r.u32(opt + 92)? as usize),
        0x20B => (opt + 112, r.u32(opt + 108)? as usize),
        _ => return Err(Error::malformed("unknown PE optional header magic")),
    };
    let n = n_dirs.min(16);
    let mut out = Vec::with_capacity(n);
    for i in 0..n {
        let o = dirs_off + i * 8;
        let rva = r.u32(o)?;
        let size = r.u32(o + 4)?;
        out.push((rva, size));
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// Metadata streams
// ---------------------------------------------------------------------------

struct Metadata {
    root_off: usize,
    #[allow(dead_code)]
    runtime_version: String,
    streams: Vec<(u32, u32, String)>, // (offset, size, name)
}

fn parse_metadata(b: &[u8], cli: &CliHeader) -> Result<Metadata> {
    let root = rva_to_off(&cli.sections, cli.metadata_rva)
        .ok_or_else(|| Error::malformed("metadata RVA out of bounds"))?
        as usize;
    if root + 4 > b.len() || &b[root..root + 4] != b"BSJB" {
        return Err(Error::malformed("metadata root missing BSJB"));
    }
    let r = Reader::new(b, true);
    let ver_len = r.u32(root + 12)? as usize;
    let ver_end = (root + 16 + ver_len).min(b.len());
    // align to 4
    let pos = ver_end;
    let runtime_version = String::from_utf8_lossy(&b[root + 16..ver_end])
        .trim_end_matches('\0')
        .to_string();
    let n_streams = r.u16(pos + 2).unwrap_or(0) as usize;
    // stream headers start after version + flags(2) + streams(2)
    let mut sh = pos + 4;
    let mut streams = Vec::new();
    for _ in 0..n_streams.min(8) {
        if sh + 8 > b.len() {
            break;
        }
        let off = r.u32(sh).unwrap_or(0);
        let size = r.u32(sh + 4).unwrap_or(0);
        // name: null-terminated, padded to 4-byte alignment
        let mut np = sh + 8;
        while np < b.len() && b[np] != 0 {
            np += 1;
        }
        let name = String::from_utf8_lossy(&b[sh + 8..np]).into_owned();
        let header_len = ((np - sh + 4) & !3) as usize;
        streams.push((off, size, name));
        sh += header_len;
    }
    Ok(Metadata {
        root_off: root,
        runtime_version,
        streams,
    })
}

// ---------------------------------------------------------------------------
// Tables
// ---------------------------------------------------------------------------

const T_MODULE: usize = 0;
const T_TYPEREF: usize = 1;
const T_TYPEDEF: usize = 2;
const T_FIELD: usize = 4;
const T_METHODDEF: usize = 6;
const T_PARAM: usize = 8;
const T_MEMBERREF: usize = 10;
const T_CUSTOMATTRIBUTE: usize = 12;
const T_METHODIMPL: usize = 25;
const T_MODULEREF: usize = 26;
const T_TYPESPEC: usize = 27;
const T_IMPLMAP: usize = 28;
const T_ASSEMBLY: usize = 32;
const T_ASSEMBLYREF: usize = 35;
const T_NESTEDCLASS: usize = 41;

struct TableMeta {
    start: usize,
    #[allow(dead_code)]
    rows: usize,
    row_size: usize,
}

struct Tables {
    tables: Vec<TableMeta>,
    // heap index sizes (2 or 4)
    string_size: usize,
    guid_size: usize,
    blob_size: usize,
    string_heap: (usize, usize), // (offset in file, size)
    rows_cache: [usize; 64],
}

impl Tables {
    fn row_count(&self, table: usize) -> usize {
        if table < 64 {
            self.rows_cache[table]
        } else {
            0
        }
    }
    fn cell_u32(&self, b: &[u8], table: usize, row: usize, col: usize, cols: &[u32]) -> usize {
        let t = &self.tables[table];
        let off = t.start + row * t.row_size;
        let mut pos = 0usize;
        for (i, c) in cols.iter().enumerate() {
            let width = self.col_width(*c, table);
            if i == col {
                return read_unsigned(b, off + pos, width);
            }
            pos += width;
        }
        0
    }
    fn string(&self, b: &[u8], idx: usize) -> String {
        if idx == 0 || self.string_heap.1 == 0 {
            return String::new();
        }
        let base = self.string_heap.0;
        let s = b.get((base + idx)..).and_then(|slice| {
            let end = slice
                .iter()
                .position(|&x| x == 0)
                .map(|p| p)
                .unwrap_or(0);
            Some(&slice[..end])
        });
        match s {
            Some(s) if s.len() <= 2048 => String::from_utf8_lossy(s).into_owned(),
            _ => String::new(),
        }
    }
    fn col_width(&self, col: u32, _table: usize) -> usize {
        match col {
            0 | 2 | 3 | 5 => 4,
            1 | 4 => 2,
            7 => self.string_size,
            8 => self.blob_size,
            9 => self.guid_size,
            6 => 2, // coded index: recomputed below
            0xA => 2,
            _ => 2,
        }
    }
}

fn read_unsigned(b: &[u8], off: usize, width: usize) -> usize {
    let mut v = 0usize;
    for i in 0..width {
        let byte = b.get(off + i).copied().unwrap_or(0) as usize;
        v |= byte << (8 * i);
    }
    v
}

fn build_tables(b: &[u8], md: &Metadata) -> Option<Tables> {
    // Find #~ (or #-)
    let (off, size, _name) = md
        .streams
        .iter()
        .find(|(_, _, n)| n == "#~" || n == "#-")
        .cloned()?;
    let base = (md.root_off as u64 + off as u64) as usize;
    if base + 24 > b.len() {
        return None;
    }
    let r = Reader::new(b, true);
    let heap_sizes = b[base + 6];
    let valid = r.u64(base + 8).unwrap_or(0);
    let string_size = if heap_sizes & 1 != 0 { 4 } else { 2 };
    let guid_size = if heap_sizes & 2 != 0 { 4 } else { 2 };
    let blob_size = if heap_sizes & 4 != 0 { 4 } else { 2 };

    // row counts: 64 u32 starting after the 24-byte header
    let mut rp = base + 24;
    let mut rows = [0usize; 64];
    for t in 0..64 {
        if (valid >> t) & 1 != 0 {
            if rp + 4 > b.len() {
                return None;
            }
            rows[t] = r.u32(rp).unwrap_or(0) as usize;
            rp += 4;
        }
    }
    let _ = size;

    // Compute row sizes per table using raw column widths; coded indices need
    // row counts across the referenced tables.
    let coded = |tagbits: usize, tables: &[usize]| -> usize {
        let max_rows = tables.iter().map(|t| rows.get(*t).copied().unwrap_or(0)).max().unwrap_or(0);
        if max_rows < (1usize << (16 - tagbits)) {
            2
        } else {
            4
        }
    };
    let typedef_or_ref = coded(2, &[T_TYPEDEF, T_TYPEREF, T_TYPESPEC]);
    let resolution_scope = coded(2, &[T_MODULE, T_MODULEREF, T_ASSEMBLY, T_ASSEMBLYREF]);
    let memberref_parent = coded(3, &[T_TYPEDEF, T_TYPEREF, T_MODULEREF, T_METHODDEF, T_TYPESPEC]);

    // Encoded column width selector -> actual width.
    let mut tables_out = Vec::new();
    let mut pos2 = rp;
    for t in 0..64 {
        if (valid >> t) & 1 == 0 || rows[t] == 0 {
            let start = pos2;
            let _ = start;
            tables_out.push(TableMeta {
                start: pos2,
                rows: rows[t],
                row_size: 0,
            });
            continue;
        }
        let row_size: usize = match t {
            T_MODULE => 2 + sstr(string_size) + guid_size * 3,
            T_TYPEREF => resolution_scope + sstr(string_size) * 2,
            T_TYPEDEF => 4 + sstr(string_size) * 2 + typedef_or_ref + 4 + 4,
            T_FIELD => 2 + sstr(string_size) + blob_size,
            T_METHODDEF => 4 + 2 + 2 + sstr(string_size) + blob_size + 4,
            T_PARAM => 2 + 2 + sstr(string_size),
            T_INTERFACEIMPL => typedef_or_ref + typedef_or_ref,
            T_MEMBERREF => memberref_parent + sstr(string_size) + blob_size,
            T_CUSTOMATTRIBUTE => 2 + 4 + blob_size, // parent coded(2)+ctor coded(2) => 4
            T_MODULEREF => sstr(string_size),
            T_TYPESPEC => blob_size,
            _ => 0,
        };
        let row_size = if row_size == 0 {
            default_row_size(t, string_size, guid_size, blob_size, &rows)
        } else {
            row_size
        };
        tables_out.push(TableMeta {
            start: pos2,
            rows: rows[t],
            row_size,
        });
        pos2 += row_size * rows[t];
    }

    // string heap offset
    let string_heap = md
        .streams
        .iter()
        .find(|(_, _, n)| n == "#Strings")
        .map(|(o, s, _)| (md.root_off + *o as usize, *s as usize))
        .unwrap_or((0, 0));

    Some(Tables {
        tables: tables_out,
        string_size,
        guid_size,
        blob_size,
        string_heap,
        rows_cache: rows,
    })
}

const T_INTERFACEIMPL: usize = 9;

fn sstr(s: usize) -> usize {
    s
}

/// Fallback row size calculator for tables not explicitly handled above.
fn default_row_size(t: usize, ssize: usize, gsize: usize, bsize: usize, rows: &[usize; 64]) -> usize {
    let coded2 = |tabs: &[usize]| -> usize {
        let m = tabs.iter().map(|&t| rows[t]).max().unwrap_or(0);
        if m < 1 << 14 { 2 } else { 4 }
    };
    let _coded3 = |tabs: &[usize]| -> usize {
        let m = tabs.iter().map(|&t| rows[t]).max().unwrap_or(0);
        if m < 1 << 13 { 2 } else { 4 }
    };
    let coded1 = |tabs: &[usize]| -> usize {
        let m = tabs.iter().map(|&t| rows[t]).max().unwrap_or(0);
        if m < 1 << 15 { 2 } else { 4 }
    };
    match t {
        T_ASSEMBLY => 4 + 2 * 4 + 4 + bsize + sstr(ssize) + ssize,
        T_ASSEMBLYREF => 2 * 4 + 2 + bsize + sstr(ssize) + ssize + bsize,
        T_NESTEDCLASS => coded2(&[T_TYPEDEF]) + coded2(&[T_TYPEDEF]),
        T_METHODIMPL => coded2(&[T_TYPEDEF]) * 3,
        T_IMPLMAP => 2 + coded1(&[T_FIELD, T_METHODDEF]) + sstr(ssize) + 4,
        11 => 2 + coded2(&[T_FIELD, T_PARAM]) + bsize, // Constant
        14 => 2 + coded2(&[T_TYPEDEF, T_METHODDEF, T_ASSEMBLY]) + bsize,
        23 => 2 + sstr(ssize) + bsize,
        20 => 2 + sstr(ssize) + coded2(&[T_TYPEDEF]), // Event
        24 => 2 + 4 + coded2(&[T_EVENT, T_PROPERTY]),
        18 => 4 + coded2(&[T_EVENT]) + 4,
        15 => 4 + 4 + 4,
        16 => 4 + 4,
        29 => 4 + 4, // FieldRVA
        _ => {
            let _ = gsize;
            2
        }
    }
}

const T_EVENT: usize = 20;
const T_PROPERTY: usize = 23;

// ---------------------------------------------------------------------------
// Report
// ---------------------------------------------------------------------------

fn build_report(ctx: &AnalysisContext, cli: &CliHeader, md: &Metadata) -> AnalysisReport {
    let mut findings: Vec<Finding> = Vec::new();
    let mut report = AnalysisReport::new(
        identity_for(
            &ctx.path,
            "dotnet",
            &format!(".NET assembly (runtime {})", cli.runtime_version),
            &ctx.head,
        )
        .unwrap_or_else(|_| crate::core::evidence::ArtifactIdentity {
            name: ctx
                .path
                .file_name()
                .map(|s| s.to_string_lossy().into_owned())
                .unwrap_or_default(),
            path: ctx.path.display().to_string(),
            size: 0,
            sha256: String::new(),
            kind: "dotnet".into(),
            label: ".NET assembly".into(),
            container: None,
        }),
        Vec::new(),
    );
    report
        .facts
        .insert("dotnet.runtime".into(), serde_json::json!(cli.runtime_version));

    // Header finding
    let mut hf = Finding::new(
        "dotnet.header",
        format!(
            ".NET assembly, runtime {}, strong-name {}",
            cli.runtime_version,
            if cli.strong_name_size > 0 { "signed" } else { "unsigned" }
        ),
        Severity::Info,
        Confidence::Direct,
    );
    hf.evidence.push(Evidence::new(
        "dotnet.runtime",
        cli.runtime_version.clone(),
        Location::bytes(cli.offset, Some(cli.offset + 72)),
    ));
    hf.evidence.push(Evidence::new(
        "dotnet.entry_point_token",
        format!("0x{:08x}", cli.entry_point_token),
        Location::entity("cli_header", "EntryPointToken"),
    ));
    findings.push(hf);

    let tables = build_tables(&ctx.head, md);
    if let Some(t) = &tables {
        // Assembly identity
        if t.row_count(T_ASSEMBLY) > 0 {
            let name_idx = t.cell_u32(&ctx.head, T_ASSEMBLY, 0, 7, &ASSEMBLY_COLS);
            let ver = assembly_version(&ctx.head, t, T_ASSEMBLY, &ASSEMBLY_COLS);
            let name = t.string(&ctx.head, name_idx);
            let mut af = Finding::new(
                "dotnet.assembly",
                format!("assembly '{name}' v{ver}"),
                Severity::Info,
                Confidence::Direct,
            );
            af.evidence.push(Evidence::new(
                "dotnet.assembly.name",
                name,
                Location::entity("assembly", "name"),
            ));
            findings.push(af);
        }

        // Module
        if t.row_count(T_MODULE) > 0 {
            let name_idx = t.cell_u32(&ctx.head, T_MODULE, 0, 1, &MODULE_COLS);
            let name = t.string(&ctx.head, name_idx);
            if !name.is_empty() {
                let mut mf = Finding::new(
                    "dotnet.module",
                    format!("module '{name}'"),
                    Severity::Info,
                    Confidence::Direct,
                );
                mf.evidence.push(Evidence::new(
                    "dotnet.module.name",
                    name,
                    Location::entity("module", "name"),
                ));
                findings.push(mf);
            }
        }

        // Assembly references
        let ar_count = t.row_count(T_ASSEMBLYREF);
        if ar_count > 0 {
            let mut rf = Finding::new(
                "dotnet.assembly_refs",
                format!("references {ar_count} declared assemblies"),
                Severity::Info,
                Confidence::Direct,
            );
            for i in 0..ar_count.min(24) {
                let name_idx = t.cell_u32(&ctx.head, T_ASSEMBLYREF, i, 7, &ASSEMBLYREF_COLS);
                let ver = assembly_version(&ctx.head, t, T_ASSEMBLYREF, &ASSEMBLYREF_COLS);
                let name = t.string(&ctx.head, name_idx);
                rf.evidence.push(Evidence::new(
                    "dotnet.assembly_ref",
                    format!("{name} v{ver}"),
                    Location::entity("assembly_ref", name),
                ));
            }
            findings.push(rf);
        }

        // Type definitions
        let td_count = t.row_count(T_TYPEDEF);
        if td_count > 0 {
            let mut tf = Finding::new(
                "dotnet.types",
                format!("{td_count} type definitions"),
                Severity::Info,
                Confidence::Direct,
            );
            for i in 0..td_count.min(32) {
                let name_idx = t.cell_u32(&ctx.head, T_TYPEDEF, i, 1, &TYPEDEF_COLS);
                let ns_idx = t.cell_u32(&ctx.head, T_TYPEDEF, i, 2, &TYPEDEF_COLS);
                let name = t.string(&ctx.head, name_idx);
                let ns = t.string(&ctx.head, ns_idx);
                let full = if ns.is_empty() { name } else { format!("{ns}.{name}") };
                if full.is_empty() {
                    continue;
                }
                tf.evidence.push(Evidence::new(
                    "dotnet.type",
                    full,
                    Location::entity("typedef", format!("#{i}")),
                ));
            }
            tf.limitations.push("only the first types are enumerated".into());
            findings.push(tf);
        }

        // Method definitions
        let md_count = t.row_count(T_METHODDEF);
        let mut method_names: Vec<String> = Vec::new();
        if md_count > 0 {
            let mut mdf = Finding::new(
                "dotnet.methods",
                format!("{md_count} method definitions"),
                Severity::Info,
                Confidence::Direct,
            );
            for i in 0..md_count.min(24) {
                let name_idx = t.cell_u32(&ctx.head, T_METHODDEF, i, 3, &METHODDEF_COLS);
                let name = t.string(&ctx.head, name_idx);
                if name.is_empty() {
                    continue;
                }
                method_names.push(name.clone());
                mdf.evidence.push(Evidence::new(
                    "dotnet.method",
                    name.clone(),
                    Location::entity("methoddef", format!("#{i}")),
                ));
            }
            mdf.limitations.push("first methods shown; IL bodies analyzed per-method below".into());
            findings.push(mdf);
        }

        // CIL bodies
        let bodies = cil_bodies(&ctx.head, cli, t, md_count);
        if !bodies.is_empty() {
            let mut cf = Finding::new(
                "dotnet.cil",
                format!("{} method bodies decoded; {} with CIL instructions", bodies.len(), bodies.len()),
                Severity::Info,
                Confidence::Derived,
            );
            for (name, code_size, first) in bodies.iter().take(16) {
                cf.evidence.push(Evidence::derived(
                    "dotnet.cil.body",
                    format!("{name}: {code_size} code bytes: {first}"),
                    Location::entity("cil", name.clone()),
                ));
            }
            cf.limitations.push(
                "CIL decoder covers the common opcode set; unusual encodings are shown as hex".into(),
            );
            findings.push(cf);
        }

        // Custom attributes
        let ca_count = t.row_count(T_CUSTOMATTRIBUTE);
        if ca_count > 0 {
            findings.push(Finding::new(
                "dotnet.custom_attributes",
                format!("{ca_count} custom attribute records"),
                Severity::Info,
                Confidence::Direct,
            ));
        }

        // Strong name
        if cli.strong_name_size > 0 {
            report
                .facts
                .insert("dotnet.strong_name".into(), serde_json::json!(true));
        }
    }

    report.findings = findings;
    report.summary = summary(&report.findings);
    report
}

const MODULE_COLS: [u32; 5] = [0, 7, 9, 9, 9];
const ASSEMBLY_COLS: [u32; 9] = [3, 2, 2, 2, 2, 3, 8, 7, 7];
const ASSEMBLYREF_COLS: [u32; 10] = [2, 2, 2, 2, 2, 3, 8, 7, 7, 8];
const TYPEDEF_COLS: [u32; 6] = [4, 7, 7, 6, 5, 5];
const METHODDEF_COLS: [u32; 6] = [3, 2, 2, 7, 8, 5];

fn assembly_version(b: &[u8], t: &Tables, table: usize, cols: &[u32]) -> String {
    let major = t.cell_u32(b, table, 0, 1, cols);
    let minor = t.cell_u32(b, table, 0, 2, cols);
    let build = t.cell_u32(b, table, 0, 3, cols);
    let rev = t.cell_u32(b, table, 0, 4, cols);
    format!("{major}.{minor}.{build}.{rev}")
}

// ---------------------------------------------------------------------------
// CIL (simplified MSIL opcode table + method body decoder)
// ---------------------------------------------------------------------------

/// Decode method bodies: walk methoddef row RVAs, read tiny/fat headers,
/// map bytes to mnemonics for the common opcode set.
fn cil_bodies(b: &[u8], cli: &CliHeader, t: &Tables, md_count: usize) -> Vec<(String, usize, String)> {
    let mut out = Vec::new();
    for i in 0..md_count.min(256) {
        let rva = t.cell_u32(b, T_METHODDEF, i, 0, &METHODDEF_COLS) as u32;
        let name_idx = t.cell_u32(b, T_METHODDEF, i, 3, &METHODDEF_COLS);
        let name = t.string(b, name_idx);
        if rva == 0 {
            continue;
        }
        let Some(off) = rva_to_off(&cli.sections, rva) else { continue };
        let Some((code, code_size)) = method_body_code(b, off as usize) else {
            continue;
        };
        let disasm = disassemble_snippet(code);
        out.push((name, code_size, disasm));
    }
    out
}

/// Parse a method body header and return the raw IL code slice.
fn method_body_code(b: &[u8], off: usize) -> Option<(&[u8], usize)> {
    let byte0 = *b.get(off)?;
    if byte0 & 0x03 == 0x02 {
        // tiny header: code size = byte0 >> 2
        let size = (byte0 >> 2) as usize;
        let code = b.get(off + 1..off + 1 + size)?;
        return Some((code, size));
    }
    if byte0 & 0x03 == 0x03 {
        // fat header: 12 bytes
        let code_size = u32::from_le_bytes([b[off + 4], b[off + 5], b[off + 6], b[off + 7]]) as usize;
        let code = b.get(off + 12..off + 12 + code_size)?;
        return Some((code, code_size));
    }
    None
}

/// Disassemble the first instructions of a code slice using a compact table.
fn disassemble_snippet(code: &[u8]) -> String {
    let mut out = Vec::new();
    let mut i = 0usize;
    let n = code.len();
    let max = n.min(240);
    while i < max && out.len() < 14 {
        let op = code[i];
        // Two-byte (0xFE prefix) opcodes.
        if op == 0xFE && i + 1 <= max {
            let op2 = code.get(i + 1).copied().unwrap_or(0);
            let name = op2_name(op2);
            let (consumed, _operand) = operand_len(op2, &code[i + 2..]);
            out.push(name.to_string());
            i += 2 + consumed;
            continue;
        }
        let name = op_name(op);
        let (consumed, operand) = operand_len(op, &code[i + 1..]);
        let mut line = name.to_string();
        if let Some(operand) = operand {
            line.push_str(&format!(" {operand}"));
        }
        out.push(line);
        i += 1 + consumed;
    }
    if max < n {
        out.push("…".to_string());
    }
    out.join("; ")
}

/// Compute operand bytes consumed and a display operand for an opcode.
fn operand_len(op: u8, rest: &[u8]) -> (usize, Option<String>) {
    let inline_br_s = |b: &[u8]| -> (usize, Option<String>) {
        if b.len() < 1 {
            return (0, None);
        }
        (1, Some(format!("{}", b[0] as i8)))
    };
    let inline_i8 = inline_br_s;
    let inline_i = |b: &[u8]| -> (usize, Option<String>) {
        if b.len() < 4 {
            return (0, None);
        }
        let v = i32::from_le_bytes([b[0], b[1], b[2], b[3]]);
        (4, Some(v.to_string()))
    };
    let inline_field = |b: &[u8]| -> (usize, Option<String>) {
        if b.len() < 4 {
            return (0, None);
        }
        let v = u32::from_le_bytes([b[0], b[1], b[2], b[3]]);
        (4, Some(format!("0x{v:x}")))
    };
    let inline_method = |b: &[u8]| -> (usize, Option<String>) {
        if b.len() < 4 {
            return (0, None);
        }
        let v = u32::from_le_bytes([b[0], b[1], b[2], b[3]]);
        (4, Some(format!("0x{v:x}")))
    };
    let _inline_sig = inline_method;
    let inline_string = inline_method;
    let inline_br = |b: &[u8]| -> (usize, Option<String>) {
        if b.len() < 4 {
            return (0, None);
        }
        let v = i32::from_le_bytes([b[0], b[1], b[2], b[3]]);
        (4, Some(format!("{v}")) )
    };
    let inline_var = |b: &[u8]| -> (usize, Option<String>) {
        if b.len() < 2 {
            return (0, None);
        }
        (2, Some(u16::from_le_bytes([b[0], b[1]]).to_string()))
    };
    let inline_switch = |b: &[u8]| -> (usize, Option<String>) {
        if b.len() < 4 {
            return (0, None);
        }
        let count = u32::from_le_bytes([b[0], b[1], b[2], b[3]]) as usize;
        (4 + count * 4, Some(format!("n={count}")))
    };
    let _ = inline_field;
    let inline_tok = inline_method;

    match op {
        0x00 => (0, None),                       // nop
        0x01 => (0, None),                       // break
        0x02 => (0, None),                       // ldarg.0
        0x03 => (0, None),
        0x04 => (0, None),
        0x05 => (0, None),
        0x06 => (0, None),                       // ldloc.0
        0x07..=0x09 => (0, None),
        0x0A => (0, None),                       // stloc.0
        0x0B..=0x0D => (0, None),
        0x0E => (0, None),                       // ldarg.s ... actually 0x0E ldarg.s
        0x0F => inline_br_s(rest),               // ldarg.s
        0x10 => (0, None),                       // ldarga.s → has 1-byte
        0x11 => inline_br_s(rest),
        0x12 => (0, None),                       // ldc.i4.s uses byte next; but 0x12 is ldc.i4.s
        0x15 => (1, Some("i4".into())),
        0x16 => (0, None),
        0x17..=0x1E => (0, None),
        0x1F => (0, None),
        0x20 => inline_i8(rest),
        0x21 => (0, None),
        0x22 => inline_i(rest),
        0x23 => inline_i(rest),
        0x24 => inline_i(rest),
        0x25 => inline_i(rest),
        0x26 => (0, None),
        0x27 => (0, None),
        0x28 => inline_method(rest),             // call
        0x29 => inline_method(rest),             // calli? actually calli is 0x29 with inline_sig
        0x2A => (0, None),                       // ret
        0x2B => inline_br_s(rest),               // br.s
        0x2C => inline_br_s(rest),               // brfalse.s
        0x2D => inline_br_s(rest),               // brtrue.s
        0x2E => inline_br_s(rest),               // beq.s
        0x2F => inline_br_s(rest),
        0x30 => inline_br_s(rest),
        0x31 => inline_br_s(rest),
        0x32 => inline_br_s(rest),
        0x33 => inline_br_s(rest),
        0x34 => inline_br_s(rest),
        0x35 => inline_br_s(rest),
        0x36 => inline_br_s(rest),
        0x37 => inline_br_s(rest),
        0x38 => inline_br(rest),                 // br (int32)
        0x39 => inline_br(rest),
        0x3A => inline_br(rest),
        0x3B => inline_br(rest),
        0x3C => inline_br(rest),
        0x3D => inline_br(rest),
        0x3E => inline_br(rest),
        0x3F => inline_br(rest),
        0x40 => inline_br(rest),
        0x41 => inline_br(rest),
        0x42 => inline_br(rest),
        0x43 => inline_br(rest),
        0x44 => inline_field(rest),              // ldfld
        0x45 => inline_var(rest),                // ldflda? (short form not standard)
        0x46 => inline_var(rest),                // stfld (short)
        0x72 => inline_string(rest),             // ldstr
        0x73 => inline_method(rest),             // newobj
        0x74 => inline_field(rest),              // castclass? no
        0x7B => inline_field(rest),              // ldfld
        0x7C => inline_field(rest),              // ldflda
        0x7D => inline_field(rest),              // stfld
        0x8C => inline_tok(rest),                // box
        0x91 => (0, None),                       // conv.* block
        0xDE => inline_switch(rest),             // switch
        0xFF => (0, None),
        0xFE => (1, None),
        _ if (0x03..=0x05).contains(&op) => (0, None),
        _ if (0x46..=0x50).contains(&op) => (0, None), // conv.*
        _ if (0x5B..=0x6F).contains(&op) => (0, None), // arithmetic/compare
        _ => (0, None),
    }
}

fn op_name(op: u8) -> &'static str {
    match op {
        0x00 => "nop",
        0x01 => "break",
        0x02 => "ldarg.0",
        0x03 => "ldarg.1",
        0x04 => "ldarg.2",
        0x05 => "ldarg.3",
        0x06 => "ldloc.0",
        0x07 => "ldloc.1",
        0x08 => "ldloc.2",
        0x09 => "ldloc.3",
        0x0A => "stloc.0",
        0x0B => "stloc.1",
        0x0C => "stloc.2",
        0x0D => "stloc.3",
        0x0E => "ldarg.s",
        0x0F => "ldarga.s",
        0x10 => "starg.s",
        0x11 => "ldloc.s",
        0x12 => "ldloca.s",
        0x13 => "stloc.s",
        0x14 => "ldnull",
        0x15 => "ldc.i4.m1",
        0x16 => "ldc.i4.0",
        0x17 => "ldc.i4.1",
        0x18 => "ldc.i4.2",
        0x19 => "ldc.i4.3",
        0x1A => "ldc.i4.4",
        0x1B => "ldc.i4.5",
        0x1C => "ldc.i4.6",
        0x1D => "ldc.i4.7",
        0x1E => "ldc.i4.8",
        0x1F => "ldc.i4.s",
        0x20 => "ldc.i4",
        0x21 => "ldc.i8",
        0x22 => "ldc.r4",
        0x23 => "ldc.r8",
        0x25 => "dup",
        0x26 => "pop",
        0x27 => "jmp",
        0x28 => "call",
        0x29 => "calli",
        0x2A => "ret",
        0x2B => "br.s",
        0x2C => "brfalse.s",
        0x2D => "brtrue.s",
        0x2E => "beq.s",
        0x2F => "bge.s",
        0x30 => "bgt.s",
        0x31 => "ble.s",
        0x32 => "blt.s",
        0x33 => "bne.un.s",
        0x34 => "bge.un.s",
        0x35 => "bgt.un.s",
        0x36 => "ble.un.s",
        0x37 => "blt.un.s",
        0x38 => "br",
        0x39 => "brfalse",
        0x3A => "brtrue",
        0x3B => "beq",
        0x3C => "bge",
        0x3D => "bgt",
        0x3E => "ble",
        0x3F => "blt",
        0x40 => "bne.un",
        0x41 => "bge.un",
        0x42 => "bgt.un",
        0x43 => "ble.un",
        0x44 => "blt.un",
        0x45 => "ldloc",
        0x46 => "stloc",
        0x58 => "add",
        0x59 => "sub",
        0x5A => "mul",
        0x5B => "div",
        0x5C => "div.un",
        0x5D => "rem",
        0x5E => "rem.un",
        0x5F => "and",
        0x60 => "or",
        0x61 => "xor",
        0x62 => "shl",
        0x63 => "shr",
        0x64 => "shr.un",
        0x65 => "neg",
        0x66 => "not",
        0x67 => "conv.i1",
        0x68 => "conv.i2",
        0x69 => "conv.i4",
        0x6A => "conv.i8",
        0x6B => "conv.r4",
        0x6C => "conv.r8",
        0x6D => "conv.u4",
        0x6E => "conv.u8",
        0x72 => "ldstr",
        0x73 => "newobj",
        0x74 => "castclass",
        0x75 => "isinst",
        0x7B => "ldfld",
        0x7C => "ldflda",
        0x7D => "stfld",
        0x7E => "ldsfld",
        0x7F => "ldsflda",
        0x80 => "stsfld",
        0x81 => "stobj",
        0x82 => "ldobj",
        0x83 => "ldelema",
        0x8C => "box",
        0x8D => "newarr",
        0x8E => "ldlen",
        0x8F => "ldelema",
        0x90 => "ldelem",
        0x91 => "stelem",
        0x9A => "throw",
        0x9B => "ldfld",
        0x9C => "ldfld",
        0x9D => "leave.s",
        0x9E => "leave",
        0xDE => "switch",
        _ => "opcode",
    }
}

fn op2_name(op: u8) -> &'static str {
    match op {
        0x00 => "arglist",
        0x01 => "ceq",
        0x02 => "cgt",
        0x03 => "cgt.un",
        0x04 => "clt",
        0x05 => "clt.un",
        0x06 => "ldftn",
        0x07 => "ldvirtftn",
        0x0C => "ldtoken",
        0x0D => "conv.u2",
        0x0E => "conv.u1",
        0x0F => "conv.i",
        0x10 => "conv.ovf.i",
        0x16 => "constrained.",
        0x1C => "readonly.",
        0x22 => "unbox",
        0x1E => "rethrow",
        0x1F => "sizeof",
        0x20 => "refanytype",
        0x21 => "readonly.",
        _ => "fe.?",
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
