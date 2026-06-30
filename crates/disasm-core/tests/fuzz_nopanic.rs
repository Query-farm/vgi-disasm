//! Property test: every public transform must be **panic-free and bounded** on
//! arbitrary bytes — the worker's input *is* the malware. This is the in-crate
//! stand-in for the `cargo-fuzz` zero-panic gate (the parsers are goblin/Capstone,
//! both heavily fuzzed upstream; here we fuzz *our* wrapping/sweep/bounds logic).

use disasm_core::limits::MAX_INSNS;
use proptest::prelude::*;

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2000))]

    /// Disassembly never panics, across every arch, on arbitrary bytes — and the
    /// row count stays bounded.
    #[test]
    fn disassemble_never_panics(data in proptest::collection::vec(any::<u8>(), 0..4096)) {
        for arch in ["x86", "arm", "arm64", "mips", "ppc", "sysz", "riscv"] {
            let insns = disasm_core::disassemble(&data, Some(arch), None, Some(0x1000), "all");
            prop_assert!(insns.len() <= MAX_INSNS);
        }
        // Container-auto path (arch from header, else diagnostic row).
        let _ = disasm_core::disassemble(&data, None, None, None, "auto");
    }

    /// Every other transform is panic-free on arbitrary bytes too.
    #[test]
    fn parsers_never_panic(data in proptest::collection::vec(any::<u8>(), 0..8192)) {
        let _ = disasm_core::probe(&data);
        let _ = disasm_core::sections(&data);
        let _ = disasm_core::imports(&data);
        let _ = disasm_core::entrypoint(&data);
        let _ = disasm_core::strings(&data, 4);
        let _ = disasm_core::capabilities(&data);
    }

    /// Truncating a real-ish header at any prefix length is still safe.
    #[test]
    fn truncated_headers_are_safe(prefix in 0usize..256) {
        // ELF magic + arbitrary continuation, truncated.
        let mut v = vec![0x7f, b'E', b'L', b'F', 2, 1, 1, 0];
        v.extend(std::iter::repeat_n(0x41u8, 256));
        let slice = &v[..prefix.min(v.len())];
        let _ = disasm_core::probe(slice);
        let _ = disasm_core::sections(slice);
        let _ = disasm_core::disassemble(slice, None, None, None, "auto");
    }
}
