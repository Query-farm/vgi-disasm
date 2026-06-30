//! The Capstone decode engine: build a handle for an [`ArchSel`] and decode a
//! bounded byte slice into normalized [`Insn`] rows with a **linear sweep** and
//! **bad-byte resume**.
//!
//! Capstone's own correctness is upstream; this module owns *our* concerns:
//! arch/mode → handle mapping, base-address seeding (so branch targets print
//! absolute), group normalization, and the resume-on-undecodable-byte loop that
//! keeps the sweep from ever stalling.

use capstone::arch::BuildsCapstone;
use capstone::arch::BuildsCapstoneEndian;
use capstone::prelude::*;
use capstone::{Capstone, Endian};

use crate::groups;
use crate::limits::MAX_INSNS;
use crate::probe::ArchSel;

/// A single decoded instruction row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Insn {
    /// Absolute virtual address (`base + offset`).
    pub address: u64,
    /// Instruction length in bytes (0 only for the synthetic `(error)` row).
    pub size: u8,
    /// Raw machine bytes of this instruction.
    pub bytes: Vec<u8>,
    /// Mnemonic (`mov`, `call`, `bl`); `.byte` for an undecodable byte;
    /// `(error)` for a diagnostic row.
    pub mnemonic: String,
    /// Operand text.
    pub op_str: String,
    /// Normalized instruction groups (see [`crate::groups`]).
    pub groups: Vec<String>,
}

impl Insn {
    /// A one-byte "bad" instruction emitted when Capstone cannot decode the byte
    /// at `addr`; the sweep resumes at the next byte.
    fn bad(addr: u64, byte: u8) -> Self {
        Insn {
            address: addr,
            size: 1,
            bytes: vec![byte],
            mnemonic: ".byte".to_string(),
            op_str: format!("0x{byte:02x}"),
            groups: Vec::new(),
        }
    }

    /// The single diagnostic row for "raw blob with no arch supplied".
    pub fn arch_required() -> Self {
        Insn {
            address: 0,
            size: 0,
            bytes: Vec::new(),
            mnemonic: "(error)".to_string(),
            op_str: "arch required for raw blob".to_string(),
            groups: Vec::new(),
        }
    }
}

/// Build a Capstone handle for the resolved [`ArchSel`], with detail on (needed
/// for group classification) and Intel syntax for x86.
pub fn build(sel: &ArchSel) -> CsResult<Capstone> {
    let endian = if sel.big_endian {
        Endian::Big
    } else {
        Endian::Little
    };
    let cs = match sel.arch.as_str() {
        "x86" => {
            let mode = match sel.mode.as_str() {
                "x16" => arch::x86::ArchMode::Mode16,
                "x32" => arch::x86::ArchMode::Mode32,
                _ => arch::x86::ArchMode::Mode64,
            };
            Capstone::new()
                .x86()
                .mode(mode)
                .syntax(arch::x86::ArchSyntax::Intel)
                .detail(true)
                .build()?
        }
        "arm" => {
            let mode = if sel.mode == "thumb" {
                arch::arm::ArchMode::Thumb
            } else {
                arch::arm::ArchMode::Arm
            };
            Capstone::new()
                .arm()
                .mode(mode)
                .endian(endian)
                .detail(true)
                .build()?
        }
        "arm64" => Capstone::new()
            .arm64()
            .mode(arch::arm64::ArchMode::Arm)
            .detail(true)
            .build()?,
        "mips" => Capstone::new()
            .mips()
            .mode(arch::mips::ArchMode::Mips64)
            .endian(endian)
            .detail(true)
            .build()?,
        "ppc" => Capstone::new()
            .ppc()
            .mode(arch::ppc::ArchMode::Mode64)
            .endian(endian)
            .detail(true)
            .build()?,
        "sysz" => Capstone::new()
            .sysz()
            .mode(arch::sysz::ArchMode::Default)
            .detail(true)
            .build()?,
        "riscv" => Capstone::new()
            .riscv()
            .mode(arch::riscv::ArchMode::RiscV64)
            .detail(true)
            .build()?,
        _ => {
            // Unknown arch: fall back to x86-64 so build never errors out the
            // whole scan; resolution upstream should prevent reaching here.
            Capstone::new()
                .x86()
                .mode(arch::x86::ArchMode::Mode64)
                .syntax(arch::x86::ArchSyntax::Intel)
                .detail(true)
                .build()?
        }
    };
    Ok(cs)
}

/// Linear-sweep `code` starting at virtual address `base`, appending decoded
/// rows to `out`. Undecodable bytes become one-byte `.byte` rows and the sweep
/// resumes at the next byte. Stops when `out` reaches `max_total` rows (the
/// global cap shared across sections). Returns the number of rows appended.
pub fn sweep_into(
    cs: &Capstone,
    code: &[u8],
    base: u64,
    out: &mut Vec<Insn>,
    max_total: usize,
) -> usize {
    let start = out.len();
    let mut offset: usize = 0;
    while offset < code.len() {
        if out.len() >= max_total {
            break;
        }
        let addr = base.wrapping_add(offset as u64);
        let remaining = &code[offset..];
        match cs.disasm_all(remaining, addr) {
            Ok(insns) if !insns.is_empty() => {
                let mut consumed = 0usize;
                for insn in insns.iter() {
                    if out.len() >= max_total {
                        break;
                    }
                    let groups = match cs.insn_detail(insn) {
                        Ok(detail) => groups::normalize_all(
                            detail
                                .groups()
                                .iter()
                                .filter_map(|g| cs.group_name(*g))
                                .collect::<Vec<_>>(),
                        ),
                        Err(_) => Vec::new(),
                    };
                    out.push(Insn {
                        address: insn.address(),
                        size: insn.bytes().len().min(u8::MAX as usize) as u8,
                        bytes: insn.bytes().to_vec(),
                        mnemonic: insn.mnemonic().unwrap_or("").to_string(),
                        op_str: insn.op_str().unwrap_or("").to_string(),
                        groups,
                    });
                    consumed += insn.bytes().len();
                }
                if consumed == 0 {
                    // Defensive: avoid an infinite loop if nothing advanced.
                    out.push(Insn::bad(addr, code[offset]));
                    offset += 1;
                } else {
                    offset += consumed;
                }
            }
            _ => {
                // Undecodable byte: emit a bad row and resume at the next byte.
                out.push(Insn::bad(addr, code[offset]));
                offset += 1;
            }
        }
    }
    out.len() - start
}

/// Convenience: decode a standalone slice in one call (used by tests and the
/// raw/all path). Bounded to [`MAX_INSNS`].
pub fn decode(sel: &ArchSel, code: &[u8], base: u64) -> Vec<Insn> {
    let mut out = Vec::new();
    if let Ok(cs) = build(sel) {
        sweep_into(&cs, code, base, &mut out, MAX_INSNS);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn x64() -> ArchSel {
        crate::probe::resolve_explicit("x86", Some("x64")).unwrap()
    }

    #[test]
    fn decodes_x64_prologue_with_absolute_call() {
        // push rbp; mov rax,[rip+0x13b8]; call rel32(=0).
        let code = b"\x55\x48\x8b\x05\xb8\x13\x00\x00\xe8\x00\x00\x00\x00";
        let insns = decode(&x64(), code, 0x1000);
        assert_eq!(insns[0].mnemonic, "push");
        assert_eq!(insns[0].address, 0x1000);
        assert_eq!(insns[2].mnemonic, "call");
        // call at 0x1008, len 5 → absolute target 0x100d printed by Capstone.
        assert!(insns[2].op_str.contains("0x100d"), "{}", insns[2].op_str);
        assert!(insns[2].groups.contains(&"call".to_string()));
        assert!(insns[2].groups.contains(&"branch_relative".to_string()));
        assert!(!insns[2].groups.iter().any(|g| g.starts_with("mode")));
    }

    #[test]
    fn bad_byte_resumes_never_stalls() {
        // 0x06 is invalid in x64; the sweep must emit a .byte row and continue.
        let code = b"\x06\x90"; // (bad); nop
        let insns = decode(&x64(), code, 0);
        assert_eq!(insns[0].mnemonic, ".byte");
        assert_eq!(insns[0].op_str, "0x06");
        assert_eq!(insns[1].mnemonic, "nop");
    }
}
