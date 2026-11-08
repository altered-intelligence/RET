//! Small byte helpers shared by every parser.

use crate::core::error::{Error, Result};

/// Byte reader that respects endianness and enforces bounds access.
pub struct Reader<'a> {
    pub bytes: &'a [u8],
    pub little: bool,
}

impl<'a> Reader<'a> {
    pub fn new(bytes: &'a [u8], little: bool) -> Self {
        Reader { bytes, little }
    }

    pub fn u16(&self, off: usize) -> Result<u16> {
        let b = self.slice(off, 2)?;
        Ok(if self.little {
            u16::from_le_bytes([b[0], b[1]])
        } else {
            u16::from_be_bytes([b[0], b[1]])
        })
    }

    pub fn u32(&self, off: usize) -> Result<u32> {
        let b = self.slice(off, 4)?;
        Ok(if self.little {
            u32::from_le_bytes([b[0], b[1], b[2], b[3]])
        } else {
            u32::from_be_bytes([b[0], b[1], b[2], b[3]])
        })
    }

    pub fn u64(&self, off: usize) -> Result<u64> {
        let b = self.slice(off, 8)?;
        if self.little {
            Ok(u64::from_le_bytes(b.try_into().unwrap()))
        } else {
            Ok(u64::from_be_bytes(b.try_into().unwrap()))
        }
    }

    pub fn slice(&self, off: usize, len: usize) -> Result<&'a [u8]> {
        self.bytes
            .get(off..off.checked_add(len).ok_or_else(|| Error::limit("offset+len"))?)
            .ok_or_else(|| {
                Error::malformed(format!(
                    "offset {off:#x}+len {len} exceeds buffer len {:#x}",
                    self.bytes.len()
                ))
            })
    }

    /// Read a NUL-terminated string starting at `off`, bounded by `max` bytes.
    pub fn cstr(&self, off: usize, max: usize) -> Result<&'a [u8]> {
        let end_cap = self.bytes.len().min(off.saturating_add(max));
        let end = self.bytes[off..end_cap]
            .iter()
            .position(|&b| b == 0)
            .map(|p| off + p)
            .ok_or_else(|| Error::malformed("unterminated string"))?;
        Ok(&self.bytes[off..end])
    }

    /// Read a NUL-terminated string, capped at 4 MiB.
    pub fn cstr_bounded(&self, off: usize) -> Result<&'a [u8]> {
        self.cstr(off, 4 * 1024 * 1024)
    }
}

/// Format a byte slice as an uppercase hex string.
pub fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{b:02X}"));
    }
    out
}

/// Human-readable byte sizes (KiB/MiB/GiB).
pub fn human_size(n: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut v = n as f64;
    let mut u = 0usize;
    while v >= 1024.0 && u < UNITS.len() - 1 {
        v /= 1024.0;
        u += 1;
    }
    if u == 0 {
        format!("{n} B")
    } else {
        format!("{v:.1} {}", UNITS[u])
    }
}
