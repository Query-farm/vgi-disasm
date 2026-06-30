//! Normalize Capstone instruction-group names into a small, stable, arch-portable
//! vocabulary so the `groups LIST<VARCHAR>` column is SQL-filterable without
//! re-parsing `op_str` (e.g. `list_contains(groups,'call')` enumerates call
//! sites on x86, ARM, or MIPS alike).
//!
//! Capstone exposes both the **generic** groups (`call`, `jump`, `ret`, `int`,
//! `iret`, `privilege`, `branch_relative`) and a long tail of **arch-specific**
//! groups (`mode64`, `sse1`, `avx`, `fpu`, `vm`, …). We keep only the triage-
//! relevant ones and drop the rest (notably the `modeNN` decoder-state markers,
//! which are noise for SQL filtering).

/// Map a raw Capstone group name to the normalized vocabulary, or `None` to drop
/// it. The normalized set is: `call`, `jump`, `ret`, `int`, `privileged`,
/// `branch_relative`, `fpu`, `sse`, `vm`.
pub fn normalize(raw: &str) -> Option<&'static str> {
    match raw {
        "call" => Some("call"),
        "jump" => Some("jump"),
        "ret" => Some("ret"),
        // Software interrupt / syscall and interrupt-return collapse to `int`.
        "int" | "iret" => Some("int"),
        "privilege" => Some("privileged"),
        "branch_relative" => Some("branch_relative"),
        "fpu" => Some("fpu"),
        "vm" => Some("vm"),
        other => {
            // Vector/SIMD families across arches → `sse`.
            let lower = other.to_ascii_lowercase();
            if lower.starts_with("sse")
                || lower.starts_with("avx")
                || lower.starts_with("mmx")
                || lower == "neon"
                || lower.starts_with("vec")
            {
                Some("sse")
            } else {
                // `mode16/32/64`, `not64bitmode`, and every other decoder-state
                // or feature marker are dropped to keep the vocabulary stable.
                None
            }
        }
    }
}

/// Normalize a list of raw group names, dropping unmapped ones and de-duplicating
/// while preserving first-seen order.
pub fn normalize_all<I, S>(raw: I) -> Vec<String>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let mut out: Vec<String> = Vec::new();
    for g in raw {
        if let Some(n) = normalize(g.as_ref()) {
            let n = n.to_string();
            if !out.contains(&n) {
                out.push(n);
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keeps_core_vocab_drops_mode() {
        assert_eq!(normalize("call"), Some("call"));
        assert_eq!(normalize("branch_relative"), Some("branch_relative"));
        assert_eq!(normalize("privilege"), Some("privileged"));
        assert_eq!(normalize("iret"), Some("int"));
        assert_eq!(normalize("mode64"), None);
        assert_eq!(normalize("not64bitmode"), None);
        assert_eq!(normalize("sse2"), Some("sse"));
        assert_eq!(normalize("avx512"), Some("sse"));
    }

    #[test]
    fn dedups_and_orders() {
        let g = normalize_all(["call", "mode64", "branch_relative", "call"]);
        assert_eq!(g, vec!["call".to_string(), "branch_relative".to_string()]);
    }
}
