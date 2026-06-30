//! Classic `strings`-style extraction: printable **ASCII** and **UTF-16LE** runs
//! of length ≥ `min_len`, each with a file offset and an encoding label.
//!
//! Feeds the string→indicator capability heuristics and is independently useful.
//! Bounded to [`MAX_STRINGS`] rows, each truncated to [`MAX_STRING_LEN`] chars,
//! and the whole scan to [`MAX_SCAN_BYTES`].

use crate::limits::{MAX_SCAN_BYTES, MAX_STRINGS, MAX_STRING_LEN};

/// One extracted string.
#[derive(Debug, Clone)]
pub struct StringHit {
    /// File offset of the first byte of the run.
    pub offset: u64,
    /// `ascii | utf16le`.
    pub encoding: String,
    /// The decoded run (truncated to [`MAX_STRING_LEN`]).
    pub value: String,
}

#[inline]
fn printable(b: u8) -> bool {
    // Printable ASCII plus tab — the usual `strings` definition.
    (0x20..=0x7e).contains(&b) || b == b'\t'
}

/// Extract ASCII and UTF-16LE strings of length ≥ `min_len` (clamped to ≥ 1).
pub fn strings(bytes: &[u8], min_len: usize) -> Vec<StringHit> {
    let min_len = min_len.max(1);
    let data = &bytes[..bytes.len().min(MAX_SCAN_BYTES)];
    let mut out = Vec::new();
    extract_ascii(data, min_len, &mut out);
    extract_utf16le(data, min_len, &mut out);
    out.truncate(MAX_STRINGS);
    out
}

fn push_run(out: &mut Vec<StringHit>, offset: usize, encoding: &str, run: &str) {
    if out.len() >= MAX_STRINGS {
        return;
    }
    let value: String = run.chars().take(MAX_STRING_LEN).collect();
    out.push(StringHit {
        offset: offset as u64,
        encoding: encoding.to_string(),
        value,
    });
}

fn extract_ascii(data: &[u8], min_len: usize, out: &mut Vec<StringHit>) {
    let mut start = 0usize;
    let mut cur = String::new();
    for (i, &b) in data.iter().enumerate() {
        if printable(b) {
            if cur.is_empty() {
                start = i;
            }
            cur.push(b as char);
        } else {
            if cur.chars().count() >= min_len {
                push_run(out, start, "ascii", &cur);
            }
            cur.clear();
        }
        if out.len() >= MAX_STRINGS {
            return;
        }
    }
    if cur.chars().count() >= min_len {
        push_run(out, start, "ascii", &cur);
    }
}

fn extract_utf16le(data: &[u8], min_len: usize, out: &mut Vec<StringHit>) {
    let mut i = 0usize;
    while i + 1 < data.len() {
        if printable(data[i]) && data[i + 1] == 0 {
            let start = i;
            let mut cur = String::new();
            while i + 1 < data.len() && printable(data[i]) && data[i + 1] == 0 {
                cur.push(data[i] as char);
                i += 2;
            }
            if cur.chars().count() >= min_len {
                push_run(out, start, "utf16le", &cur);
            }
            if out.len() >= MAX_STRINGS {
                return;
            }
        } else {
            i += 1;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_ascii_runs() {
        let s = strings(b"\x00\x01hello\x00wo\x00world!!\x00", 4);
        let vals: Vec<&str> = s
            .iter()
            .filter(|h| h.encoding == "ascii")
            .map(|h| h.value.as_str())
            .collect();
        assert!(vals.contains(&"hello"));
        assert!(vals.contains(&"world!!"));
        assert!(!vals.contains(&"wo")); // below min_len
    }

    #[test]
    fn finds_utf16le_runs() {
        let mut data = Vec::new();
        for c in b"PowerShell" {
            data.push(*c);
            data.push(0);
        }
        let s = strings(&data, 4);
        assert!(s
            .iter()
            .any(|h| h.encoding == "utf16le" && h.value == "PowerShell"));
    }

    #[test]
    fn empty_is_empty() {
        assert!(strings(b"", 4).is_empty());
    }
}
