//! SQLite database analysis: header facts, schema/table/column/index/view/
//! trigger inventory, read from the b-tree pages directly (no SQLite binary).

use crate::analysis::{AnalysisContext, identity_for};
use crate::core::error::{Error, Result};
use crate::core::evidence::{AnalysisReport, Confidence, Evidence, Finding, Location, Severity};

const HEADER: &[u8] = b"SQLite format 3\0";

// Header fields are parsed for completeness; a few are not surfaced in
// findings today but stay part of the parser's model.
#[allow(dead_code)]
struct DbHeader {
    page_size: u32,
    write_version: u8,
    read_version: u8,
    page_count: u64,
    freelist: u64,
    schema_cookie: u64,
    schema_format: u64,
    text_encoding: u64,
    user_version: u64,
    application_id: Option<u64>,
}

#[allow(dead_code)]
struct SchemaRow {
    kind: String,
    name: String,
    tbl_name: String,
    rootpage: i64,
    sql: String,
}

pub fn analyze(ctx: &AnalysisContext) -> Result<AnalysisReport> {
    let b = &ctx.head;
    if b.len() < 100 {
        return Err(Error::malformed("sqlite header truncated"));
    }
    if &b[0..16] != HEADER {
        return Err(Error::malformed("missing SQLite magic"));
    }
    let header = parse_header(b)?;
    let encoding = encoding_name(header.text_encoding);

    let label = format!(
        "SQLite database, {} pages of {} ({}), schema format {}",
        header.page_count, human(header.page_size), encoding, header.schema_format
    );

    let schema = read_schema(b, &header);

    let mut findings: Vec<Finding> = Vec::new();
    let report = AnalysisReport::new(
        identity_for(&ctx.path, "sqlite", &label, b)?,
        Vec::new(),
    );
    let mut report = report;
    report.facts.insert("sqlite.page_size".into(), serde_json::json!(header.page_size));
    report.facts.insert("sqlite.page_count".into(), serde_json::json!(header.page_count));
    report.facts.insert("sqlite.encoding".into(), encoding.into());
    report.facts.insert("sqlite.user_version".into(), serde_json::json!(header.user_version));

    let mut hf = Finding::new("sqlite.header", label, Severity::Info, Confidence::Direct);
    hf.evidence.push(Evidence::new(
        "sqlite.header.page_size",
        header.page_size.to_string(),
        Location::bytes(16, Some(18)),
    ));
    hf.evidence.push(Evidence::new(
        "sqlite.header.text_encoding",
        format!("{} ({})", encoding, header.text_encoding),
        Location::bytes(56, Some(60)),
    ));
    hf.evidence.push(Evidence::new(
        "sqlite.header.user_version",
        header.user_version.to_string(),
        Location::bytes(60, Some(64)),
    ));
    if let Some(app) = header.application_id {
        hf.evidence.push(Evidence::new(
            "sqlite.header.application_id",
            format!("0x{app:08x}"),
            Location::bytes(68, Some(72)),
        ));
    }
    findings.push(hf);

    // Schema inventory
    let tables: Vec<&SchemaRow> = schema.iter().filter(|r| r.kind == "table").collect();
    let indexes: Vec<&SchemaRow> = schema.iter().filter(|r| r.kind == "index").collect();
    let views: Vec<&SchemaRow> = schema.iter().filter(|r| r.kind == "view").collect();
    let triggers: Vec<&SchemaRow> = schema.iter().filter(|r| r.kind == "trigger").collect();

    report.facts.insert("sqlite.tables".into(), serde_json::json!(tables.len()));
    report.facts.insert("sqlite.indexes".into(), serde_json::json!(indexes.len()));
    report.facts.insert("sqlite.views".into(), serde_json::json!(views.len()));
    report.facts.insert("sqlite.triggers".into(), serde_json::json!(triggers.len()));

    if !tables.is_empty() {
        let mut tf = Finding::new(
            "sqlite.tables",
            format!("{} tables", tables.len()),
            Severity::Info,
            Confidence::Direct,
        );
        for t in tables.iter().take(32) {
            let cols = columns_of(&t.sql);
            tf.evidence.push(Evidence::new(
                "sqlite.table",
                format!("{}.{} ({} column(s))", t.tbl_name, t.name, cols.len()),
                Location::entity("table", t.name.clone()),
            ));
            for c in cols.iter().take(24) {
                tf.evidence.push(Evidence::new(
                    "sqlite.column",
                    c.clone(),
                    Location::entity("column", format!("{}.{}", t.name, c)),
                ));
            }
        }
        tf.limitations.push("columns are extracted from the declaring SQL with a lightweight parser".into());
        findings.push(tf);
    }

    if !indexes.is_empty() {
        let mut xf = Finding::new(
            "sqlite.indexes",
            format!("{} indexes", indexes.len()),
            Severity::Info,
            Confidence::Direct,
        );
        let mut has_internal = false;
        for i in indexes.iter().take(24) {
            if i.name.starts_with("sqlite_autoindex_") {
                has_internal = true;
                continue;
            }
            xf.evidence.push(Evidence::new(
                "sqlite.index",
                format!("{}.{}", i.tbl_name, i.name),
                Location::entity("index", i.name.clone()),
            ));
        }
        if has_internal {
            xf.limitations.push("sqlite_autoindex_* entries omitted".into());
        }
        findings.push(xf);
    }

    if !views.is_empty() {
        let mut vf = Finding::new(
            "sqlite.views",
            format!("{} views", views.len()),
            Severity::Info,
            Confidence::Direct,
        );
        for v in views.iter().take(16) {
            vf.evidence.push(Evidence::new(
                "sqlite.view",
                format!("{}.{}", v.tbl_name, v.name),
                Location::entity("view", v.name.clone()),
            ));
        }
        findings.push(vf);
    }

    if !triggers.is_empty() {
        let mut gf = Finding::new(
            "sqlite.triggers",
            format!("{} triggers", triggers.len()),
            Severity::Info,
            Confidence::Direct,
        );
        for g in triggers.iter().take(16) {
            gf.evidence.push(Evidence::new(
                "sqlite.trigger",
                format!("{}.{}", g.tbl_name, g.name),
                Location::entity("trigger", g.name.clone()),
            ));
        }
        findings.push(gf);
    }

    if schema.is_empty() {
        let mut ef = Finding::new(
            "sqlite.schema_unreadable",
            "no schema rows could be decoded from page 1",
            Severity::Note,
            Confidence::Inferred,
        );
        ef.limitations.push(
            "the schema b-tree may overflow pages beyond the bounded head, or use a page size > head".into(),
        );
        findings.push(ef);
    }

    let strings = crate::analysis::binary::scan_strings(b, 4);
    findings.push(crate::analysis::binary::string_inventory_finding(
        &strings,
        ctx.settings.max_strings,
        ctx.settings.max_string_len,
        4,
        60,
    ));

    report.findings = findings;
    report.summary = summary(&report.findings);
    Ok(report)
}

fn parse_header(b: &[u8]) -> Result<DbHeader> {
    let page_size_raw = u16::from_be_bytes([b[16], b[17]]);
    let page_size = if page_size_raw == 1 { 65536 } else { page_size_raw as u32 };
    Ok(DbHeader {
        page_size,
        write_version: b[18],
        read_version: b[19],
        page_count: u32::from_be_bytes([b[28], b[29], b[30], b[31]]) as u64,
        freelist: u32::from_be_bytes([b[32], b[33], b[34], b[35]]) as u64,
        schema_cookie: u32::from_be_bytes([b[40], b[41], b[42], b[43]]) as u64,
        schema_format: u32::from_be_bytes([b[44], b[45], b[46], b[47]]) as u64,
        text_encoding: u32::from_be_bytes([b[56], b[57], b[58], b[59]]) as u64,
        user_version: u32::from_be_bytes([b[60], b[61], b[62], b[63]]) as u64,
        application_id: Some(u32::from_be_bytes([b[68], b[69], b[70], b[71]]) as u64).filter(|v| *v != 0),
    })
}

fn encoding_name(e: u64) -> &'static str {
    match e {
        1 => "UTF-8",
        2 => "UTF-16le",
        3 => "UTF-16be",
        _ => "unknown",
    }
}

// ---------------------------------------------------------------------------
// B-tree / record decoding
// ---------------------------------------------------------------------------

fn read_schema(b: &[u8], h: &DbHeader) -> Vec<SchemaRow> {
    if (h.page_size as usize) > b.len() {
        return Vec::new();
    }
    let mut rows = Vec::new();
    let mut visited = std::collections::HashSet::new();
    collect_schema_pages(b, h, 1, &mut visited, &mut rows, 0);
    rows
}

fn collect_schema_pages(
    b: &[u8],
    h: &DbHeader,
    page: u64,
    visited: &mut std::collections::HashSet<u64>,
    rows: &mut Vec<SchemaRow>,
    depth: usize,
) {
    if depth > 8 || !visited.insert(page) {
        return;
    }
    let page_size = h.page_size as usize;
    let off = (page - 1) as usize * page_size;
    let Some(slice) = b.get(off..off.saturating_add(page_size)) else {
        return;
    };
    // B-tree header (table page): 8 bytes; page 1 prepends a 100-byte db header.
    let base = if page == 1 { 100 } else { 0 };
    if base + 8 > slice.len() {
        return;
    }
    let page_type = slice[base];
    let cell_count = u16::from_be_bytes([slice[base + 3], slice[base + 4]]) as usize;
    // The cell pointer array begins immediately after the b-tree header: at
    // header+8 for leaf pages, header+12 for interior pages. Pointers are
    // relative to the start of the *page* (for page 1 that start includes the
    // 100-byte database header), so a cell lives at `slice[ptr]`.
    let (ptr_array, right) = match page_type {
        0x0d => (base + 8, None),
        0x05 => {
            if base + 12 <= slice.len() {
                let r = Some(u32::from_be_bytes([
                    slice[base + 8],
                    slice[base + 9],
                    slice[base + 10],
                    slice[base + 11],
                ]) as u64);
                (base + 12, r)
            } else {
                return;
            }
        }
        _ => return, // not a table b-tree page
    };
    for i in 0..cell_count {
        let po = ptr_array + i * 2;
        if po + 2 > slice.len() {
            break;
        }
        let ptr = u16::from_be_bytes([slice[po], slice[po + 1]]) as usize;
        match page_type {
            0x0d => {
                if let Some(row) = decode_table_cell(slice, ptr) {
                    rows.push(row);
                }
            }
            0x05 => {
                if let Some(child) = decode_interior_cell(slice, ptr) {
                    collect_schema_pages(b, h, child, visited, rows, depth + 1);
                }
            }
            _ => {}
        }
    }
    if let Some(child) = right {
        collect_schema_pages(b, h, child, visited, rows, depth + 1);
    }
}

/// Decode a table leaf cell *within the page*; returns the record fields.
fn decode_table_cell(page: &[u8], cell: usize) -> Option<SchemaRow> {
    let mut pos = cell;
    let payload_len = varint(page, &mut pos)?;
    let _rowid = varint(page, &mut pos)?;
    // The payload may continue on overflow pages; schema rows fit inline.
    let available = page.len().saturating_sub(pos);
    if (payload_len as usize) > available || payload_len as usize > 1024 * 1024 {
        return None;
    }
    decode_record(&page[pos..pos + payload_len as usize])
}

fn decode_interior_cell(page: &[u8], cell: usize) -> Option<u64> {
    if cell + 4 > page.len() {
        return None;
    }
    Some(u32::from_be_bytes([
        page[cell],
        page[cell + 1],
        page[cell + 2],
        page[cell + 3],
    ]) as u64)
}

/// Decode a record (header + serial types + values) into schema fields.
fn decode_record(payload: &[u8]) -> Option<SchemaRow> {
    let mut pos = 0usize;
    let header_len = varint(payload, &mut pos)? as usize;
    if header_len == 0 || header_len > payload.len() || header_len < pos {
        return None;
    }
    let header_end = pos - 1 + header_len; // pos already consumed the length varint
    if header_end > payload.len() {
        return None;
    }
    let mut serials = Vec::new();
    while pos < header_end {
        let st = varint(payload, &mut pos)?;
        serials.push(st);
    }
    // Value area starts right after the header.
    let mut vpos = header_end;
    let mut values: Vec<Option<String>> = Vec::new();
    for st in serials {
        let (val, consumed) = serial_value(payload, vpos, st);
        vpos += consumed;
        values.push(val);
    }
    if values.len() < 4 {
        return None;
    }
    let s = |i: usize| values.get(i).cloned().flatten().unwrap_or_default();
    Some(SchemaRow {
        kind: s(0),
        name: s(1),
        tbl_name: s(2),
        rootpage: 0,
        sql: s(4),
    })
}

/// Return (decoded string value if text/int, bytes consumed).
fn serial_value(payload: &[u8], pos: usize, st: i64) -> (Option<String>, usize) {
    let (len, kind) = match st {
        0 => (0, "null"),
        1 => (1, "i8"),
        2 => (2, "i16"),
        3 => (3, "i24"),
        4 => (4, "i32"),
        5 => (6, "i48"),
        6 => (8, "i64"),
        7 => (8, "f64"),
        8 => (0, "i0"),
        9 => (0, "i1"),
        n if n >= 12 && n % 2 == 0 => (((n - 12) / 2) as usize, "blob"),
        n if n >= 13 => (((n - 13) / 2) as usize, "text"),
        _ => return (None, 0),
    };
    let end = pos.saturating_add(len);
    let Some(bytes) = payload.get(pos..end.min(payload.len())) else {
        return (None, len);
    };
    match kind {
        "text" => (Some(String::from_utf8_lossy(bytes).into_owned()), len),
        "i8" | "i16" | "i24" | "i32" | "i48" | "i64" => {
            let v = decode_int(bytes, len);
            (Some(v.to_string()), len)
        }
        "f64" if len == 8 => {
            let mut arr = [0u8; 8];
            arr.copy_from_slice(&bytes[..8]);
            let f = f64::from_be_bytes(arr);
            (Some(f.to_string()), len)
        }
        "blob" => (Some(format!("<blob {}B>", len)), len),
        "null" => (None, 0),
        _ => (Some("<value>".into()), len),
    }
}

fn decode_int(bytes: &[u8], len: usize) -> i64 {
    let mut v: i64 = 0;
    for &b in bytes.iter().take(len) {
        v = (v << 8) | b as i64;
    }
    // sign extend if the top bit of the first byte is set
    if !bytes.is_empty() && bytes[0] & 0x80 != 0 {
        v -= 1i64 << (8 * len);
    }
    v
}

/// Decode a SQLite varint (big-endian 7-bit groups, up to 9 bytes).
fn varint(b: &[u8], pos: &mut usize) -> Option<i64> {
    let mut result: i64 = 0;
    for _ in 0..8 {
        let byte = *b.get(*pos)?;
        *pos += 1;
        result = (result << 7) | (byte & 0x7f) as i64;
        if byte & 0x80 == 0 {
            return Some(result);
        }
    }
    // 9th byte contributes 8 bits
    let byte = *b.get(*pos)?;
    *pos += 1;
    Some((result << 8) | byte as i64)
}

// ---------------------------------------------------------------------------
// Column extraction from SQL
// ---------------------------------------------------------------------------

fn columns_of(sql: &str) -> Vec<String> {
    let upper = sql.to_ascii_uppercase();
    let Some(open) = upper.find('(') else {
        return Vec::new();
    };
    // Find the closing paren respecting nesting & quotes.
    let bytes = sql.as_bytes();
    let mut depth = 0usize;
    let mut close = None;
    let mut i = open;
    let mut quote: Option<u8> = None;
    while i < bytes.len() {
        let c = bytes[i];
        if let Some(q) = quote {
            if c == q {
                quote = None;
            } else if c == b'\\' && q == b'\'' {
                i += 1;
            }
        } else {
            match c {
                b'\'' | b'"' | b'`' => quote = Some(c),
                b'(' => depth += 1,
                b')' => {
                    depth -= 1;
                    if depth == 0 {
                        close = Some(i);
                        break;
                    }
                }
                _ => {}
            }
        }
        i += 1;
    }
    let Some(close) = close else {
        return Vec::new();
    };
    let inner = &sql[open + 1..close];
    let mut cols = Vec::new();
    depth = 0;
    quote = None;
    let mut start = 0usize;
    let check = |c: &[u8]| -> bool {
        let s = String::from_utf8_lossy(c).to_ascii_uppercase();
        s.starts_with("PRIMARY")
            || s.starts_with("UNIQUE")
            || s.starts_with("CHECK")
            || s.starts_with("FOREIGN")
            || s.starts_with("CONSTRAINT")
            || s.starts_with("REFERENCES")
    };
    for (idx, c) in inner.as_bytes().iter().enumerate() {
        if let Some(q) = quote {
            if *c == q {
                quote = None;
            }
            continue;
        }
        match c {
            b'\'' | b'"' | b'`' => quote = Some(*c),
            b'(' => depth += 1,
            b')' => depth -= 1,
            b',' if depth == 0 => {
                let part = inner[start..idx].trim();
                if !part.is_empty() && !check(part.as_bytes()) {
                    let name = part
                        .split_whitespace()
                        .next()
                        .map(|n| n.trim_matches(|ch| ch == '"' || ch == '`' || ch == '\''))
                        .unwrap_or(part)
                        .to_string();
                    cols.push(name);
                }
                start = idx + 1;
            }
            _ => {}
        }
    }
    let remaining = inner[start..].trim();
    if !remaining.is_empty() && !check(remaining.as_bytes()) {
        if let Some(first) = remaining.split_whitespace().next() {
            cols.push(first.trim_matches(|ch| ch == '"' || ch == '`' || ch == '\'').to_string());
        }
    }
    cols
}

fn human(n: u32) -> String {
    crate::core::io::human_size(n as u64)
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
