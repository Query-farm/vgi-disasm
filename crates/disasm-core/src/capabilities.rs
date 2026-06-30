//! The §B **heuristic-only** capability surface: import / string / anti-analysis
//! patterns → MITRE ATT&CK rows. Explicitly **not** capa — no scoring, no rule
//! composition, no basic-block features; just three cheap signals matched
//! against the compiled-in [`crate::mappings`] tables plus a handful of
//! anti-analysis instruction checks.

use crate::imports;
use crate::limits::MAX_CAPABILITIES;
use crate::mappings::{self, MapEntry};
use crate::strings;
use crate::sweep;

/// One capability match.
#[derive(Debug, Clone)]
pub struct Capability {
    /// Short heuristic name, e.g. `inject:CreateRemoteThread`.
    pub rule: String,
    /// ATT&CK technique id, e.g. `T1055.002`.
    pub attack_id: String,
    /// ATT&CK technique name.
    pub attack_name: String,
    /// `info | low | medium | high` (advisory only).
    pub severity: String,
    /// The import name / string / instruction that matched.
    pub evidence: String,
}

impl Capability {
    fn from_entry(entry: &MapEntry, evidence: String) -> Self {
        let (_pattern, rule, attack_id, attack_name, severity) = *entry;
        Capability {
            rule: rule.to_string(),
            attack_id: attack_id.to_string(),
            attack_name: attack_name.to_string(),
            severity: severity.to_string(),
            evidence,
        }
    }
}

/// Run the heuristic capability matcher over `bytes`. Bounded to
/// [`MAX_CAPABILITIES`] rows; de-duplicated on `(rule, evidence)`.
pub fn capabilities(bytes: &[u8]) -> Vec<Capability> {
    let mut out: Vec<Capability> = Vec::new();
    let mut seen: Vec<(String, String)> = Vec::new();

    let mut push = |cap: Capability, seen: &mut Vec<(String, String)>| {
        if out.len() >= MAX_CAPABILITIES {
            return;
        }
        let key = (cap.rule.clone(), cap.evidence.clone());
        if !seen.contains(&key) {
            seen.push(key);
            out.push(cap);
        }
    };

    // 1. Import name → technique (exact, case-insensitive).
    for imp in imports::imports(bytes) {
        let Some(name) = imp.name.as_deref() else {
            continue;
        };
        for entry in mappings::API_MAP {
            if entry.0.eq_ignore_ascii_case(name) {
                push(Capability::from_entry(entry, name.to_string()), &mut seen);
            }
        }
    }

    // 2. Interesting string → indicator (substring, case-insensitive).
    for hit in strings::strings(bytes, 4) {
        let hay = hit.value.to_ascii_lowercase();
        for entry in mappings::STRING_MAP {
            if hay.contains(entry.0) {
                push(
                    Capability::from_entry(entry, truncate_evidence(&hit.value)),
                    &mut seen,
                );
            }
        }
    }

    // 3. Anti-analysis instruction patterns (only when a container resolves to a
    //    decodable arch; raw blobs with no arch simply contribute nothing here).
    let insns = sweep::disassemble(bytes, None, None, None, "auto");
    let mut saw_rdtsc = false;
    let mut saw_cpuid = false;
    let mut saw_int3 = false;
    let mut saw_int2d = false;
    for insn in &insns {
        match insn.mnemonic.as_str() {
            "rdtsc" | "rdtscp" => saw_rdtsc = true,
            "cpuid" => saw_cpuid = true,
            "int3" => saw_int3 = true,
            "int" if insn.op_str.trim() == "0x2d" => saw_int2d = true,
            _ => {}
        }
    }
    if saw_rdtsc {
        push(
            Capability {
                rule: "antivm:rdtsc_timing".to_string(),
                attack_id: "T1497".to_string(),
                attack_name: "Virtualization/Sandbox Evasion".to_string(),
                severity: "low".to_string(),
                evidence: "rdtsc".to_string(),
            },
            &mut seen,
        );
    }
    if saw_cpuid {
        push(
            Capability {
                rule: "antivm:cpuid_check".to_string(),
                attack_id: "T1497.001".to_string(),
                attack_name: "Virtualization/Sandbox Evasion: System Checks".to_string(),
                severity: "low".to_string(),
                evidence: "cpuid".to_string(),
            },
            &mut seen,
        );
    }
    if saw_int3 {
        push(
            Capability {
                rule: "antidbg:int3".to_string(),
                attack_id: "T1622".to_string(),
                attack_name: "Debugger Evasion".to_string(),
                severity: "low".to_string(),
                evidence: "int3".to_string(),
            },
            &mut seen,
        );
    }
    if saw_int2d {
        push(
            Capability {
                rule: "antidbg:int_0x2d".to_string(),
                attack_id: "T1622".to_string(),
                attack_name: "Debugger Evasion".to_string(),
                severity: "medium".to_string(),
                evidence: "int 0x2d".to_string(),
            },
            &mut seen,
        );
    }

    out
}

fn truncate_evidence(s: &str) -> String {
    const MAX: usize = 120;
    if s.chars().count() <= MAX {
        s.to_string()
    } else {
        s.chars().take(MAX).collect::<String>() + "…"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn raw_benign_text_no_high_rows() {
        // A benign blob with no malicious imports/strings yields no high-severity
        // capability rows (the http:// info row may appear if present; here none).
        let caps = capabilities(b"the quick brown fox jumps over the lazy dog");
        assert!(caps.iter().all(|c| c.severity != "high"));
    }

    #[test]
    fn powershell_enc_string_matches() {
        let caps = capabilities(b"powershell.exe -EncodedCommand ZQBjAGgAbwA=");
        assert!(caps
            .iter()
            .any(|c| c.attack_id == "T1059.001" && c.rule.starts_with("exec:")));
    }
}
