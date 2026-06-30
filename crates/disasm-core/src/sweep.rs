//! Top-level `disassemble`: arch/mode resolution → section selection → bounded
//! linear sweep.
//!
//! This is the load-bearing entry point behind the `disassemble()` table
//! function. It decides **what bytes** to feed Capstone and at **what address**,
//! then sweeps each selected region into instruction rows. One Capstone handle
//! is built per call and reused across regions.

use crate::engine::{self, Insn};
use crate::limits::{MAX_INSNS, MAX_SECTION_BYTES};
use crate::probe::{self, ArchSel};
use crate::sections::{self, Section};

/// How to select what to disassemble.
fn select_regions<'a>(
    blob: &'a [u8],
    secs: &'a [Section],
    section: &str,
    explicit_base: Option<u64>,
) -> Vec<(u64, &'a [u8])> {
    let whole = &blob[..blob.len().min(MAX_SECTION_BYTES)];
    match section {
        // Disassemble the entire blob as raw bytes at `base` (default 0).
        "all" => vec![(explicit_base.unwrap_or(0), whole)],
        _ if secs.is_empty() => {
            // Raw blob with an explicit arch and no container: sweep the whole
            // blob at `base`.
            vec![(explicit_base.unwrap_or(0), whole)]
        }
        "auto" => {
            let exec: Vec<&Section> = secs.iter().filter(|s| s.exec).collect();
            // `base` only overrides the start when a single region is swept;
            // across multiple exec sections each keeps its own VA.
            let single = exec.len() == 1;
            exec.into_iter()
                .map(|s| {
                    let start = if single {
                        explicit_base.unwrap_or(s.vaddr)
                    } else {
                        s.vaddr
                    };
                    (start, s.bytes(blob))
                })
                .collect()
        }
        name => {
            // A specific section by name. Mach-O names are `__SEG,__sect`; match
            // either the full name or the trailing section component.
            let matched: Vec<&Section> = secs
                .iter()
                .filter(|s| section_name_matches(&s.name, name))
                .collect();
            let single = matched.len() == 1;
            matched
                .into_iter()
                .map(|s| {
                    let start = if single {
                        explicit_base.unwrap_or(s.vaddr)
                    } else {
                        s.vaddr
                    };
                    (start, s.bytes(blob))
                })
                .collect()
        }
    }
}

fn section_name_matches(full: &str, requested: &str) -> bool {
    full == requested || full.split(',').next_back() == Some(requested)
}

/// Disassemble `blob` into instruction rows.
///
/// * `arch` / `mode` — explicit Capstone selection; required for a raw blob,
///   else read from the container header.
/// * `base` — virtual address of the first byte (default = section VA, or 0).
/// * `section` — `auto` (every executable section), `all` (whole blob), or a
///   section name.
///
/// Bounded to [`MAX_INSNS`] total rows. A raw blob with no `arch` yields a
/// single diagnostic row; the scan never panics.
pub fn disassemble(
    blob: &[u8],
    arch: Option<&str>,
    mode: Option<&str>,
    base: Option<u64>,
    section: &str,
) -> Vec<Insn> {
    // 1. Resolve (arch, mode).
    let sel: ArchSel = match arch {
        Some(a) => match probe::resolve_explicit(a, mode) {
            Some(s) => s,
            None => return vec![Insn::arch_required()],
        },
        None => match probe::probe(blob).arch_sel() {
            Some(s) => s,
            None => return vec![Insn::arch_required()],
        },
    };

    // 2. Enumerate sections (empty for a raw blob).
    let secs = sections::sections(blob);

    // 3. Pick regions to sweep.
    let regions = select_regions(blob, &secs, section, base);

    // 4. One handle for the whole request; sweep each region in address order.
    let mut out: Vec<Insn> = Vec::new();
    let Ok(cs) = engine::build(&sel) else {
        return vec![Insn::arch_required()];
    };
    for (start, code) in regions {
        if out.len() >= MAX_INSNS {
            break;
        }
        engine::sweep_into(&cs, code, start, &mut out, MAX_INSNS);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn raw_blob_without_arch_is_diagnostic_row() {
        let out = disassemble(b"\x90\x90\x90", None, None, None, "auto");
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].mnemonic, "(error)");
    }

    #[test]
    fn raw_shellcode_with_arch_sweeps_at_base() {
        // nop; nop; ret  at base 0x4000.
        let out = disassemble(
            b"\x90\x90\xc3",
            Some("x86"),
            Some("x64"),
            Some(0x4000),
            "auto",
        );
        assert_eq!(out[0].address, 0x4000);
        assert_eq!(out[0].mnemonic, "nop");
        assert_eq!(out[2].mnemonic, "ret");
        assert!(out[2].groups.contains(&"ret".to_string()));
    }

    #[test]
    fn unknown_arch_is_diagnostic_row() {
        let out = disassemble(b"\x90", Some("nonsense"), None, None, "auto");
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].mnemonic, "(error)");
    }
}
