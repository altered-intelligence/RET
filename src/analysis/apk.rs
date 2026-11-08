//! ZIP / APK analysis: central-directory inventory, Android binary XML
//! manifest decoding, and v1/v2/v3 signature detection.

use crate::analysis::{AnalysisContext, identity_for};
use crate::core::error::{Error, Result};
use crate::core::evidence::{AnalysisReport, Confidence, Evidence, Finding, Location, Severity};

const MAX_ZIP_READ: u64 = 192 * 1024 * 1024; // bounded read for archives

#[derive(Debug, Clone)]
struct ZipEntry {
    name: String,
    method: u16,
    compressed_size: u32,
    uncompressed_size: u32,
    local_off: u32,
}

#[derive(Default)]
struct Zip {
    entries: Vec<ZipEntry>,
}

pub fn analyze_zip(ctx: &AnalysisContext, as_apk: bool) -> Result<AnalysisReport> {
    let bytes = crate::analysis::read_bounded(&ctx.path, MAX_ZIP_READ)?;
    let zip = parse_central_directory(&bytes)?;
    let kind = if as_apk { "apk" } else { "zip" };
    let label = format!(
        "{} archive, {} entries",
        if as_apk { "Android application package (APK)" } else { "ZIP" },
        zip.entries.len()
    );

    let mut findings: Vec<Finding> = Vec::new();
    let mut report = AnalysisReport::new(
        identity_for(&ctx.path, kind, &label, &ctx.head)?,
        Vec::new(),
    );
    report
        .facts
        .insert("zip.entry_count".into(), serde_json::json!(zip.entries.len()));

    let mut inf = Finding::new(
        "zip.inventory",
        format!("{} archive entries", zip.entries.len()),
        Severity::Info,
        Confidence::Direct,
    );
    for e in zip.entries.iter().take(32) {
        inf.evidence.push(Evidence::new(
            "zip.entry",
            format!(
                "{} ({}→{} B, {})",
                e.name,
                e.compressed_size,
                e.uncompressed_size,
                if e.method == 0 { "stored" } else { "deflate" }
            ),
            Location::bytes(e.local_off as u64, Some(e.local_off as u64 + 30)),
        ));
    }
    findings.push(inf);

    if as_apk {
        apk_analysis(&zip, &bytes, &mut findings, &mut report);
    }

    report.findings = findings;
    report.summary = summary(&report.findings);
    Ok(report)
}

// ---------------------------------------------------------------------------
// APK specifics
// ---------------------------------------------------------------------------

fn apk_analysis(
    zip: &Zip,
    bytes: &[u8],
    findings: &mut Vec<Finding>,
    report: &mut AnalysisReport,
) {
    // classes.dex inventory
    let dexes: Vec<String> = zip
        .entries
        .iter()
        .filter(|e| e.name.to_lowercase().starts_with("classes") && e.name.ends_with(".dex"))
        .map(|e| e.name.clone())
        .collect();
    if !dexes.is_empty() {
        let mut df = Finding::new(
            "apk.dex",
            format!("{} Dalvik bytecode file(s)", dexes.len()),
            Severity::Info,
            Confidence::Direct,
        );
        for d in dexes.iter().take(16) {
            df.evidence.push(Evidence::new("apk.dex", d.clone(), Location::entity("dex", d.clone())));
        }
        findings.push(df);
    }

    // Native libraries
    let so_count = zip
        .entries
        .iter()
        .filter(|e| e.name.starts_with("lib/") && e.name.ends_with(".so"))
        .count();
    if so_count > 0 {
        let mut nf = Finding::new(
            "apk.native_libs",
            format!("{so_count} native libraries under lib/"),
            Severity::Info,
            Confidence::Direct,
        );
        let mut abis = std::collections::BTreeSet::new();
        for e in zip
            .entries
            .iter()
            .filter(|e| e.name.starts_with("lib/") && e.name.ends_with(".so"))
        {
            if let Some(abi) = e.name.split('/').nth(1) {
                abis.insert(abi.to_string());
            }
        }
        for abi in abis {
            nf.evidence.push(Evidence::new("apk.native_abi", abi.clone(), Location::entity("lib", abi.clone())));
        }
        findings.push(nf);
    }

    // v1 signature
    let v1_files: Vec<String> = zip
        .entries
        .iter()
        .filter(|e| {
            let n = e.name.to_uppercase();
            n.starts_with("META-INF/")
                && (n.ends_with(".RSA") || n.ends_with(".DSA") || n.ends_with(".EC") || n.ends_with(".SF"))
        })
        .map(|e| e.name.clone())
        .collect();
    if !v1_files.is_empty() {
        let mut v1 = Finding::new(
            "apk.signature.v1",
            format!("v1 (JAR) signature present: {}", v1_files.join(", ")),
            Severity::Info,
            Confidence::Direct,
        );
        for f in v1_files.iter().take(8) {
            v1.evidence.push(Evidence::new("apk.signature.v1.file", f.clone(), Location::entity("meta-inf", f.clone())));
        }
        findings.push(v1);
    }

    // v2/v3 signing block
    if let Some(sb) = parse_signing_block(bytes) {
        if let Some(v2) = &sb.v2 {
            let mut sig = Finding::new(
                "apk.signature.v2",
                format!("APK Signature Scheme v2: {} signer(s)", v2.signers.len()),
                Severity::Info,
                Confidence::Direct,
            );
            for (i, s) in v2.signers.iter().enumerate() {
                sig.evidence.push(Evidence::new(
                    "apk.signer.v2",
                    format!(
                        "signer#{i}: {} cert(s) first-cert sha256={} algs={:?}",
                        s.cert_count, s.first_cert_sha256, s.algorithms
                    ),
                    Location::entity("signer", format!("#{i}")),
                ));
            }
            findings.push(sig);
        }
        if let Some(v3) = &sb.v3 {
            let mut sig = Finding::new(
                "apk.signature.v3",
                format!("APK Signature Scheme v3: {} signer(s)", v3.signers.len()),
                Severity::Info,
                Confidence::Direct,
            );
            for (i, s) in v3.signers.iter().enumerate() {
                sig.evidence.push(Evidence::new(
                    "apk.signer.v3",
                    format!("signer#{i}: {} cert(s)", s.cert_count),
                    Location::entity("signer", format!("#{i}")),
                ));
            }
            findings.push(sig);
        }
        if sb.v2.is_none() && sb.v3.is_none() {
            let mut note = Finding::new(
                "apk.signature.block",
                "APK Signing Block present but no v2/v3 payload found",
                Severity::Note,
                Confidence::Direct,
            );
            note.limitations.push("the block may carry v4 or custom entries".into());
            findings.push(note);
        }
    }

    // Manifest
    if let Some(entry) = zip.entries.iter().find(|e| e.name == "AndroidManifest.xml") {
        match read_entry_uncompressed(bytes, &zip, entry) {
            Ok(data) => match decode_manifest(&data) {
                Ok(m) => manifest_into_findings(&m, findings, report),
                Err(e) => {
                    let mut mf = Finding::new(
                        "apk.manifest",
                        format!("AndroidManifest.xml could not be decoded: {e}"),
                        Severity::Note,
                        Confidence::Inferred,
                    );
                    mf.limitations.push("binary XML decoder stopped early".into());
                    findings.push(mf);
                }
            },
            Err(e) => {
                let mf = Finding::new(
                    "apk.manifest",
                    format!("AndroidManifest.xml could not be read: {e}"),
                    Severity::Note,
                    Confidence::Inferred,
                );
                findings.push(mf);
            }
        }
    }
}

struct Signer {
    cert_count: usize,
    first_cert_sha256: String,
    algorithms: Vec<u32>,
}

struct SigningBlock {
    v2: Option<Block>,
    v3: Option<Block>,
}
struct Block {
    signers: Vec<Signer>,
}

/// A tiny cursor over a byte slice for the v2/v3 block format.
struct Cursor<'a> {
    b: &'a [u8],
    p: usize,
}
impl<'a> Cursor<'a> {
    fn new(b: &'a [u8]) -> Self {
        Cursor { b, p: 0 }
    }
    fn u32(&mut self) -> Option<u32> {
        if self.p + 4 > self.b.len() {
            return None;
        }
        let v = u32::from_le_bytes(self.b[self.p..self.p + 4].try_into().unwrap());
        self.p += 4;
        Some(v)
    }
    fn u64(&mut self) -> Option<u64> {
        if self.p + 8 > self.b.len() {
            return None;
        }
        let v = u64::from_le_bytes(self.b[self.p..self.p + 8].try_into().unwrap());
        self.p += 8;
        Some(v)
    }
    fn take(&mut self, len: usize) -> Option<&'a [u8]> {
        if self.p + len > self.b.len() {
            return None;
        }
        let s = &self.b[self.p..self.p + len];
        self.p += len;
        Some(s)
    }
    fn skip_u32_prefixed(&mut self) {
        let len = self.u32().unwrap_or(0) as usize;
        self.p = self.p.saturating_add(len).min(self.b.len());
    }
}

/// Locate and parse the APK Signing Block (v2 id 0x7109871a, v3 id 0xf05368c0).
fn parse_signing_block(bytes: &[u8]) -> Option<SigningBlock> {
    let magic = b"APK Sig Block 42";
    let idx = rfind_subslice(bytes, magic)?;
    if idx < 16 {
        return None;
    }
    let block_size = u64::from_be_bytes(bytes[idx - 8..idx].try_into().ok()?) as usize;
    if block_size < 24 {
        return None;
    }
    let block_start = idx + 16 - block_size;
    let mut c = Cursor::new(&bytes[block_start..idx - 8]);
    let mut v2 = None;
    let mut v3 = None;
    loop {
        let len = c.u64()? as usize;
        let id = c.u32()?;
        let payload = c.take(len)?;
        match id {
            0x7109871a => v2 = parse_block(payload),
            0xf05368c0 => v3 = parse_block(payload),
            _ => {}
        }
        if len == 0 {
            break;
        }
    }
    Some(SigningBlock { v2, v3 })
}

fn parse_block(payload: &[u8]) -> Option<Block> {
    let mut c = Cursor::new(payload);
    let signer_count = c.u32()? as usize;
    let mut signers = Vec::new();
    for _ in 0..signer_count.min(32) {
        // signed data
        let sd_len = c.u64()? as usize;
        let sd = c.take(sd_len)?;
        let mut sc = Cursor::new(sd);
        sc.skip_u32_prefixed(); // digests
        let certs_len = sc.u32()? as usize;
        let certs = sc.take(certs_len)?;
        let (cert_count, first_sha) = parse_certificates(certs)?;
        // signatures
        let sigs_len = c.u64()? as usize;
        let sigs = c.take(sigs_len)?;
        let algorithms = parse_algorithms(sigs);
        // public key + attributes
        let pk_len = c.u64()? as usize;
        c.take(pk_len)?;
        let attrs_len = c.u64()? as usize;
        c.take(attrs_len)?;
        signers.push(Signer {
            cert_count,
            first_cert_sha256: first_sha,
            algorithms,
        });
    }
    Some(Block { signers })
}

/// certs content: count u32, then (len u64 + DER bytes)* .
fn parse_certificates(certs: &[u8]) -> Option<(usize, String)> {
    let mut c = Cursor::new(certs);
    let count = c.u32()? as usize;
    let mut first = String::new();
    for i in 0..count.min(16) {
        let len = c.u64()? as usize;
        let der = c.take(len)?;
        if i == 0 {
            first = crate::core::digests::sha256_hex(der);
        }
    }
    Some((count, first))
}

/// signatures content: count u32, then (alg u32, len u64, bytes)*.
fn parse_algorithms(sigs: &[u8]) -> Vec<u32> {
    let mut c = Cursor::new(sigs);
    let Some(count) = c.u32() else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for _ in 0..count.min(32) {
        let Some(alg) = c.u32() else { break };
        let Some(len) = c.u64() else { break };
        if c.take(len as usize).is_none() {
            break;
        }
        out.push(alg);
    }
    out
}

fn rfind_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .rposition(|w| w == needle)
}

// ---------------------------------------------------------------------------
// ZIP central directory
// ---------------------------------------------------------------------------

fn parse_central_directory(bytes: &[u8]) -> Result<Zip> {
    const EOCD: &[u8] = b"PK\x05\x06";
    let Some(eocd) = rfind_subslice(bytes, EOCD) else {
        return Err(Error::malformed("no end-of-central-directory record"));
    };
    if eocd + 22 > bytes.len() {
        return Err(Error::malformed("truncated EOCD"));
    }
    let entry_count = u16::from_le_bytes([bytes[eocd + 10], bytes[eocd + 11]]) as usize;
    let cd_size = u32::from_le_bytes([bytes[eocd + 12], bytes[eocd + 13], bytes[eocd + 14], bytes[eocd + 15]]) as usize;
    let cd_off = u32::from_le_bytes([bytes[eocd + 16], bytes[eocd + 17], bytes[eocd + 18], bytes[eocd + 19]]) as usize;
    if cd_off.saturating_add(cd_size) > bytes.len() {
        return Err(Error::malformed("central directory out of bounds"));
    }
    let mut zip = Zip::default();
    let mut pos = cd_off;
    // When the archive has a Zip64 EOCD the 0xffff count is a sentinel; we
    // still attempt a bounded read from the actual central directory.
    let max = if entry_count == 0xffff { 4096 } else { entry_count };
    for _ in 0..max.min(4096) {
        if pos + 46 > bytes.len() || &bytes[pos..pos + 4] != b"PK\x01\x02" {
            break;
        }
        let method = u16::from_le_bytes([bytes[pos + 10], bytes[pos + 11]]);
        let compressed_size = u32::from_le_bytes([bytes[pos + 20], bytes[pos + 21], bytes[pos + 22], bytes[pos + 23]]);
        let uncompressed_size = u32::from_le_bytes([bytes[pos + 24], bytes[pos + 25], bytes[pos + 26], bytes[pos + 27]]);
        let name_len = u16::from_le_bytes([bytes[pos + 28], bytes[pos + 29]]) as usize;
        let extra_len = u16::from_le_bytes([bytes[pos + 30], bytes[pos + 31]]) as usize;
        let comment_len = u16::from_le_bytes([bytes[pos + 32], bytes[pos + 33]]) as usize;
        let local_off = u32::from_le_bytes([bytes[pos + 42], bytes[pos + 43], bytes[pos + 44], bytes[pos + 45]]);
        let name = String::from_utf8_lossy(&bytes[pos + 46..pos + 46 + name_len]).into_owned();
        zip.entries.push(ZipEntry {
            name,
            method,
            compressed_size,
            uncompressed_size,
            local_off,
        });
        pos += 46 + name_len + extra_len + comment_len;
    }
    Ok(zip)
}

fn read_entry_uncompressed(bytes: &[u8], _zip: &Zip, entry: &ZipEntry) -> Result<Vec<u8>> {
    let lf = entry.local_off as usize;
    if lf + 30 > bytes.len() || &bytes[lf..lf + 4] != b"PK\x03\x04" {
        return Err(Error::malformed("missing local file header"));
    }
    let name_len = u16::from_le_bytes([bytes[lf + 26], bytes[lf + 27]]) as usize;
    let extra_len = u16::from_le_bytes([bytes[lf + 28], bytes[lf + 29]]) as usize;
    let data_off = lf + 30 + name_len + extra_len;
    let data_end = data_off + entry.compressed_size as usize;
    if data_end > bytes.len() {
        return Err(Error::malformed("entry data out of bounds"));
    }
    let raw = &bytes[data_off..data_end];
    if entry.method == 0 {
        return Ok(raw.to_vec());
    }
    miniz_oxide::inflate::decompress_to_vec_zlib(raw)
        .or_else(|_| miniz_oxide::inflate::decompress_to_vec(raw))
        .map_err(|e| Error::malformed(format!("inflate: {e}")))
}

// ---------------------------------------------------------------------------
// Android binary XML (AXML)
// ---------------------------------------------------------------------------

#[derive(Default)]
struct ManifestInfo {
    package: Option<String>,
    version_name: Option<String>,
    version_code: Option<String>,
    min_sdk: Option<String>,
    target_sdk: Option<String>,
    permissions: Vec<String>,
    components: Vec<(String, String)>,
    application: Vec<(String, String)>,
}

fn decode_manifest(data: &[u8]) -> Result<ManifestInfo> {
    let mut out = ManifestInfo::default();
    let mut pos = 0usize;
    let mut strings: Vec<String> = Vec::new();
    while pos + 8 <= data.len() {
        let chunk_type = u16::from_le_bytes([data[pos], data[pos + 1]]);
        let _header_size = u16::from_le_bytes([data[pos + 2], data[pos + 3]]) as usize;
        let chunk_size = u32::from_le_bytes([data[pos + 4], data[pos + 5], data[pos + 6], data[pos + 7]]) as usize;
        if chunk_size < 8 || pos + chunk_size > data.len() {
            break;
        }
        let body = &data[pos..pos + chunk_size];
        match chunk_type {
            0x0001 => {
                if let Some(s) = parse_string_pool(body) {
                    strings = s;
                }
            }
            0x0102 => {
                if body.len() < 21 {
                    break;
                }
                let name_idx = u32::from_le_bytes([body[8], body[9], body[10], body[11]]) as usize;
                let attr_start = u16::from_le_bytes([body[16], body[17]]) as usize;
                let attr_size = u16::from_le_bytes([body[18], body[19]]) as usize;
                let attr_count = u16::from_le_bytes([body[20], body[21]]) as usize;
                let tag = strings.get(name_idx).cloned().unwrap_or_default();
                let mut attrs = Vec::new();
                let mut apos = (20usize).max(attr_start);
                for _ in 0..attr_count.min(64) {
                    if apos + 20 > body.len() {
                        break;
                    }
                    let aname_idx = u32::from_le_bytes([body[apos + 4], body[apos + 5], body[apos + 6], body[apos + 7]]) as usize;
                    let raw_idx = u32::from_le_bytes([body[apos + 8], body[apos + 9], body[apos + 10], body[apos + 11]]) as usize;
                    let value_type = body[apos + 16];
                    let value_data = u32::from_le_bytes([body[apos + 17], body[apos + 18], body[apos + 19], body[apos + 20]]);
                    let value = if raw_idx != 0xffff_ffff && raw_idx < strings.len() {
                        strings[raw_idx].clone()
                    } else {
                        typed_value(value_type, value_data, &strings)
                    };
                    let aname = strings.get(aname_idx).cloned().unwrap_or_default();
                    attrs.push((aname, value));
                    apos += attr_size.max(20);
                }
                match tag.as_str() {
                    "manifest" => {
                        for (k, v) in &attrs {
                            match k.as_str() {
                                "package" => out.package = Some(v.clone()),
                                "versionName" => out.version_name = Some(v.clone()),
                                "versionCode" => out.version_code = Some(v.clone()),
                                _ => {}
                            }
                        }
                    }
                    "uses-sdk" => {
                        for (k, v) in &attrs {
                            match k.as_str() {
                                "minSdkVersion" => out.min_sdk = Some(v.clone()),
                                "targetSdkVersion" => out.target_sdk = Some(v.clone()),
                                _ => {}
                            }
                        }
                    }
                    "uses-permission" => {
                        for (k, v) in &attrs {
                            if k == "name" {
                                out.permissions.push(
                                    v.trim_start_matches("android.permission.").to_string(),
                                );
                            }
                        }
                    }
                    "application" => {
                        for (k, v) in &attrs {
                            if matches!(
                                k.as_str(),
                                "debuggable"
                                    | "allowBackup"
                                    | "usesCleartextTraffic"
                                    | "networkSecurityConfig"
                                    | "label"
                                    | "name"
                            ) {
                                out.application.push((k.clone(), v.clone()));
                            }
                        }
                    }
                    "activity" | "service" | "receiver" | "provider" | "activity-alias" => {
                        for (k, v) in &attrs {
                            if k == "name" {
                                out.components.push((tag.clone(), v.clone()));
                            }
                        }
                    }
                    _ => {}
                }
            }
            _ => {}
        }
        pos += chunk_size;
    }
    Ok(out)
}

fn parse_string_pool(body: &[u8]) -> Option<Vec<String>> {
    if body.len() < 28 {
        return None;
    }
    let header_size = u16::from_le_bytes([body[2], body[3]]) as usize;
    let string_count = u32::from_le_bytes([body[8], body[9], body[10], body[11]]) as usize;
    let flags = u32::from_le_bytes([body[12], body[13], body[14], body[15]]);
    let strings_start = u32::from_le_bytes([body[16], body[17], body[18], body[19]]) as usize;
    let utf8 = flags & 0x100 != 0;
    let mut pos = header_size.max(28);
    let mut offsets = Vec::new();
    for _ in 0..string_count.min(4096) {
        if pos + 4 > body.len() {
            break;
        }
        offsets.push(u32::from_le_bytes([body[pos], body[pos + 1], body[pos + 2], body[pos + 3]]) as usize);
        pos += 4;
    }
    let mut out = Vec::new();
    for o in offsets {
        let so = strings_start + o;
        if so >= body.len() {
            out.push(String::new());
            continue;
        }
        let s = if utf8 {
            let (len16, n1) = read_u16len(body, so);
            let (blen, n2) = read_u16len(body, so + n1);
            let end = (so + n1 + n2 + blen).min(body.len());
            let _ = len16;
            String::from_utf8_lossy(&body[so + n1 + n2..end]).into_owned()
        } else {
            let (len, n1) = read_u16len(body, so);
            let char_end = (so + n1 + len * 2).min(body.len());
            let mut units = Vec::new();
            let mut i = so + n1;
            while i + 1 < char_end && i + 1 < body.len() {
                units.push(u16::from_le_bytes([body[i], body[i + 1]]));
                i += 2;
            }
            String::from_utf16_lossy(&units)
        };
        out.push(s);
    }
    Some(out)
}

fn read_u16len(body: &[u8], p: usize) -> (usize, usize) {
    let Some(&first) = body.get(p) else {
        return (0, 1);
    };
    if first & 0x80 == 0 {
        (first as usize, 1)
    } else if p + 3 <= body.len() {
        let v = u16::from_le_bytes([body[p + 1], body[p + 2]]) as usize;
        (v, 3)
    } else {
        (0, 1)
    }
}

fn typed_value(vtype: u8, data: u32, strings: &[String]) -> String {
    match vtype {
        0x03 => {
            if (data as usize) < strings.len() {
                strings[data as usize].clone()
            } else {
                "0x".to_string() + &format!("{data:x}")
            }
        }
        0x10 | 0x18 | 0x01 => "0x".to_string() + &format!("{data:x}"),
        0x1c | 0x11 | 0x1e | 0x1f | 0x12 => (data as i32).to_string(),
        _ => "0x".to_string() + &format!("{data:x}"),
    }
}

fn manifest_into_findings(
    m: &ManifestInfo,
    findings: &mut Vec<Finding>,
    report: &mut AnalysisReport,
) {
    let pkg = m.package.clone().unwrap_or_default();
    let mut mf = Finding::new(
        "apk.manifest",
        format!(
            "package={} versionName={} versionCode={}",
            m.package.as_deref().unwrap_or("(unknown)"),
            m.version_name.as_deref().unwrap_or("(unknown)"),
            m.version_code.as_deref().unwrap_or("(unknown)"),
        ),
        Severity::Info,
        Confidence::Direct,
    );
    mf.evidence.push(Evidence::new(
        "apk.manifest.package",
        pkg.clone(),
        Location::entity("manifest", "package"),
    ));
    findings.push(mf);
    if !pkg.is_empty() {
        report.facts.insert("apk.package".into(), serde_json::json!(pkg));
    }
    if let Some(v) = &m.version_name {
        report.facts.insert("apk.version_name".into(), serde_json::json!(v));
    }
    if let Some(v) = &m.min_sdk {
        report.facts.insert("apk.min_sdk".into(), serde_json::json!(v));
    }
    if let Some(v) = &m.target_sdk {
        report.facts.insert("apk.target_sdk".into(), serde_json::json!(v));
    }

    if !m.permissions.is_empty() {
        let mut pf = Finding::new(
            "apk.permissions",
            format!("{} declared permissions", m.permissions.len()),
            Severity::Info,
            Confidence::Direct,
        );
        for p in m.permissions.iter().take(32) {
            pf.evidence.push(Evidence::new("apk.permission", p.clone(), Location::entity("uses-permission", p.clone())));
        }
        findings.push(pf);
    }

    if !m.components.is_empty() {
        let mut cf = Finding::new(
            "apk.components",
            format!("{} declared components", m.components.len()),
            Severity::Info,
            Confidence::Direct,
        );
        for (kind, name) in m.components.iter().take(24) {
            cf.evidence.push(Evidence::new(
                "apk.component",
                format!("{kind} {name}"),
                Location::entity(kind, name.clone()),
            ));
        }
        findings.push(cf);
    }

    if !m.application.is_empty() {
        let mut af = Finding::new(
            "apk.application",
            format!("{} application attributes", m.application.len()),
            Severity::Note,
            Confidence::Direct,
        );
        for (k, v) in m.application.iter().take(10) {
            af.evidence.push(Evidence::new(
                "apk.application",
                format!("{k} = {v}"),
                Location::entity("application", k.clone()),
            ));
        }
        findings.push(af);
        for (k, v) in &m.application {
            if k == "debuggable" && v == "true" {
                let mut df = Finding::new(
                    "apk.debuggable",
                    "application is debuggable",
                    Severity::Warning,
                    Confidence::Direct,
                );
                df.evidence.push(Evidence::new(
                    "apk.debuggable",
                    "android:debuggable=\"true\"",
                    Location::entity("application", "debuggable"),
                ));
                findings.push(df);
            }
            if k == "usesCleartextTraffic" && v == "true" {
                let mut df = Finding::new(
                    "apk.cleartext",
                    "application permits cleartext traffic",
                    Severity::Note,
                    Confidence::Direct,
                );
                df.evidence.push(Evidence::new(
                    "apk.cleartext",
                    "usesCleartextTraffic=true",
                    Location::entity("application", "usesCleartextTraffic"),
                ));
                findings.push(df);
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
