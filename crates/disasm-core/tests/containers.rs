//! Container parse tests across ELF / PE / Mach-O: arch detection, section
//! enumeration + exec flagging, entry resolution, imports, and that the
//! `section:='auto'` sweep decodes the real `.text` bytes.

mod common;
use common::{build_elf_x64, build_pe_x64, PE_IMAGE_BASE, PE_TEXT_RVA};

/// push rbp; mov rbp,rsp; ret — the bytes we embed in the ELF/PE `.text`.
const X64_TEXT: &[u8] = b"\x55\x48\x89\xe5\xc3";

#[test]
fn elf_x64_parses_and_sweeps() {
    let bytes = build_elf_x64(X64_TEXT);

    let p = disasm_core::probe(&bytes);
    assert_eq!(p.container, "elf");
    assert_eq!(p.arch.as_deref(), Some("x86"));
    assert_eq!(p.mode.as_deref(), Some("x64"));
    assert_eq!(p.bits, Some(64));

    let secs = disasm_core::sections(&bytes);
    let text = secs
        .iter()
        .find(|s| s.exec && s.name == ".text")
        .expect("executable .text section");
    assert_eq!(text.kind, "code");
    assert_eq!(text.bytes(&bytes), X64_TEXT);
    assert!(text.entropy > 0.0);

    let insns = disasm_core::disassemble(&bytes, None, None, None, "auto");
    let mnems: Vec<&str> = insns.iter().map(|i| i.mnemonic.as_str()).collect();
    assert_eq!(mnems, ["push", "mov", "ret"]);
}

#[test]
fn pe_x64_parses_entry_absolute() {
    let bytes = build_pe_x64(X64_TEXT);

    let p = disasm_core::probe(&bytes);
    assert_eq!(p.container, "pe");
    assert_eq!(p.arch.as_deref(), Some("x86"));
    assert_eq!(p.mode.as_deref(), Some("x64"));
    // Entry is absolute (image base + RVA), consistent with section VAs.
    assert_eq!(p.entry, Some(PE_IMAGE_BASE + PE_TEXT_RVA as u64));

    let secs = disasm_core::sections(&bytes);
    let text = secs.iter().find(|s| s.exec).expect("exec section");
    assert_eq!(text.name, ".text");
    assert_eq!(text.vaddr, PE_IMAGE_BASE + PE_TEXT_RVA as u64);
    assert_eq!(text.bytes(&bytes), X64_TEXT);

    let e = disasm_core::entrypoint(&bytes);
    assert_eq!(e.arch.as_deref(), Some("x86"));
    assert_eq!(e.vaddr, Some(PE_IMAGE_BASE + PE_TEXT_RVA as u64));
    assert_eq!(e.section.as_deref(), Some(".text"));

    // section:='auto' decodes the real .text at its absolute VA.
    let insns = disasm_core::disassemble(&bytes, None, None, None, "auto");
    assert_eq!(insns[0].address, PE_IMAGE_BASE + PE_TEXT_RVA as u64);
    assert_eq!(insns[0].mnemonic, "push");

    // A named-section sweep restricts to .text.
    let named = disasm_core::disassemble(&bytes, None, None, None, ".text");
    assert_eq!(named.len(), 3);
}

/// A committed real arm64 Mach-O executable (built on macOS with classic bind
/// opcodes so its imports are readable), covering the Mach-O + imports path.
const MACHO_ARM64: &[u8] = include_bytes!("fixtures/hello-macho-arm64");

#[test]
fn macho_arm64_parses_imports_and_entry() {
    let p = disasm_core::probe(MACHO_ARM64);
    assert_eq!(p.container, "macho");
    assert_eq!(p.arch.as_deref(), Some("arm64"));
    assert_eq!(p.bits, Some(64));

    let secs = disasm_core::sections(MACHO_ARM64);
    assert!(secs.iter().any(|s| s.exec && s.name == "__TEXT,__text"));

    // The fixture imports `_puts` from libSystem.
    let imps = disasm_core::imports(MACHO_ARM64);
    assert!(
        imps.iter().any(|i| i.name.as_deref() == Some("_puts")),
        "expected _puts import, got {:?}",
        imps.iter().map(|i| &i.name).collect::<Vec<_>>()
    );

    let e = disasm_core::entrypoint(MACHO_ARM64);
    assert_eq!(e.arch.as_deref(), Some("arm64"));
    assert_eq!(e.section.as_deref(), Some("__TEXT,__text"));

    // The entry sweep decodes real arm64 instructions.
    let insns = disasm_core::disassemble(MACHO_ARM64, None, None, None, "auto");
    assert!(insns.len() > 3);
    assert!(insns.iter().any(|i| i.groups.contains(&"call".to_string())));

    // Capabilities runs cleanly over a real binary (no panic, bounded).
    let _caps = disasm_core::capabilities(MACHO_ARM64);
}

#[test]
fn format_probe_matches_container() {
    assert_eq!(
        disasm_core::probe(&build_elf_x64(X64_TEXT)).container,
        "elf"
    );
    assert_eq!(disasm_core::probe(&build_pe_x64(X64_TEXT)).container, "pe");
    assert_eq!(disasm_core::probe(MACHO_ARM64).container, "macho");
    assert_eq!(
        disasm_core::probe(b"plain text, not a binary").container,
        "raw"
    );
}
