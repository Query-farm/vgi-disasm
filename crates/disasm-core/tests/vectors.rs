//! Golden instruction vectors: hand-checked shellcode blobs decoded row-for-row
//! across arches. Capstone's own correctness is upstream; these pin *our* sweep,
//! base-address math, group normalization, and arch/mode resolution.

use disasm_core::disassemble;

fn mnems(insns: &[disasm_core::Insn]) -> Vec<String> {
    insns.iter().map(|i| i.mnemonic.clone()).collect()
}

#[test]
fn x64_prologue_call_ret_at_base() {
    // push rbp; mov rbp,rsp; call rel32(->next); ret.
    let code = b"\x55\x48\x89\xe5\xe8\x00\x00\x00\x00\xc3";
    let insns = disassemble(code, Some("x86"), Some("x64"), Some(0x1000), "all");
    assert_eq!(mnems(&insns), ["push", "mov", "call", "ret"]);
    assert_eq!(insns[0].address, 0x1000);
    assert_eq!(insns[2].address, 0x1004);
    // call's absolute target prints (0x1004 + 5 = 0x1009).
    assert!(insns[2].op_str.contains("0x1009"), "{}", insns[2].op_str);
    assert!(insns[2].groups.contains(&"call".to_string()));
    assert!(insns[2].groups.contains(&"branch_relative".to_string()));
    assert!(insns[3].groups.contains(&"ret".to_string()));
    // No decoder-state noise leaks into the normalized vocabulary.
    assert!(!insns
        .iter()
        .any(|i| i.groups.iter().any(|g| g.starts_with("mode"))));
}

#[test]
fn x86_32_prologue() {
    // push ebp; mov ebp,esp; ret.
    let code = b"\x55\x89\xe5\xc3";
    let insns = disassemble(code, Some("x86"), Some("x32"), Some(0), "all");
    assert_eq!(mnems(&insns), ["push", "mov", "ret"]);
    assert_eq!(insns[1].op_str, "ebp, esp");
}

#[test]
fn arm64_mov_ret() {
    // mov x0, #0 ; ret.
    let code = b"\x00\x00\x80\xd2\xc0\x03\x5f\xd6";
    let insns = disassemble(code, Some("arm64"), None, Some(0x4000), "all");
    assert_eq!(mnems(&insns), ["mov", "ret"]);
    assert_eq!(insns[0].address, 0x4000);
}

#[test]
fn arm32_mov_bx() {
    // mov r0, #0 ; bx lr   (ARM mode, little-endian).
    let code = b"\x00\x00\xa0\xe3\x1e\xff\x2f\xe1";
    let insns = disassemble(code, Some("arm"), Some("arm"), Some(0), "all");
    assert_eq!(mnems(&insns), ["mov", "bx"]);
}

#[test]
fn mips_nops_big_endian() {
    // Two MIPS nops (0x00000000), big-endian.
    let code = b"\x00\x00\x00\x00\x00\x00\x00\x00";
    let insns = disassemble(code, Some("mips"), Some("big"), Some(0), "all");
    assert_eq!(mnems(&insns), ["nop", "nop"]);
}

#[test]
fn bad_byte_resume_keeps_count_bounded() {
    // An undecodable byte in x64 becomes a one-byte `.byte` row; the sweep
    // resumes and never stalls.
    let code = b"\x06\x90\x06\xc3"; // (bad); nop; (bad); ret
    let insns = disassemble(code, Some("x86"), Some("x64"), Some(0), "all");
    assert_eq!(mnems(&insns), [".byte", "nop", ".byte", "ret"]);
    assert_eq!(insns[0].op_str, "0x06");
    assert_eq!(insns[0].size, 1);
}

#[test]
fn raw_blob_without_arch_yields_single_diagnostic_row() {
    let insns = disassemble(b"\x90\x90", None, None, None, "auto");
    assert_eq!(insns.len(), 1);
    assert_eq!(insns[0].mnemonic, "(error)");
    assert_eq!(insns[0].op_str, "arch required for raw blob");
}
