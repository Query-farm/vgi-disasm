//! Composed example queries: realistic triage SQL that combines two or more of
//! the worker's own objects in one query. Each `(description, sql)` pair is
//! defined once here and referenced from both the schema-level
//! `vgi.example_queries` list (`lib.rs`) and the example list of the object that
//! drives the query, so the copies cannot drift.
//!
//! The fixture-based examples read the committed arm64 Mach-O hello-world at
//! `test/sql/data/hello-macho-arm64` (a repo-relative path, resolved from the
//! directory DuckDB was started in); substitute your own sample's path.

/// `capabilities()` joined to `strings()`: locate each string-based ATT&CK
/// indicator in the file. A capability's `evidence` for a string hit is the
/// whole extracted string, so it joins to `strings().value` and picks up the
/// file offset the indicator lives at.
pub const CAPABILITY_STRING_OFFSETS: (&str, &str) = (
    "Locate each string-based ATT&CK indicator in a sample: join capabilities() to strings() on \
     the matched evidence to get the file offset of every flagged string (offsets 0, 18 and 56 \
     here).",
    "SELECT c.rule, c.attack_id, c.severity, s.\"offset\", s.value FROM \
     disasm.main.capabilities('cmd.exe /c whoami\\x00schtasks /create /tn upd /tr evil.exe\\x00http://evil.example/c2'::BLOB) AS c \
     JOIN disasm.main.strings('cmd.exe /c whoami\\x00schtasks /create /tn upd /tr evil.exe\\x00http://evil.example/c2'::BLOB) AS s \
     ON s.value = c.evidence ORDER BY s.\"offset\", c.rule;",
);

/// `sections()` joined to `disassemble()`: per-executable-section instruction
/// and call counts next to the section's entropy (the containing section is
/// found by address range, since instruction rows carry only an address).
pub const SECTION_INSN_PROFILE: (&str, &str) = (
    "Profile every executable section of a binary: join sections() to disassemble() by address \
     range to count decoded instructions and calls per section next to its entropy (the \
     hello-world Mach-O fixture: __text 8 instructions / 1 call, __stubs 3, __stub_helper 9).",
    "SELECT s.name, round(s.entropy, 2) AS entropy, count(d.address) AS n_insns, \
     count(d.address) FILTER (WHERE list_contains(d.groups, 'call')) AS n_calls \
     FROM disasm.main.sections('test/sql/data/hello-macho-arm64') AS s \
     LEFT JOIN disasm.main.disassemble('test/sql/data/hello-macho-arm64') AS d \
     ON d.address >= s.vaddr AND d.address < s.vaddr + s.size \
     WHERE s.exec GROUP BY s.name, s.vaddr, s.entropy ORDER BY s.vaddr;",
);

/// `entrypoint()` joined to `sections()`: the layout of the section the entry
/// point lands in — an entry in a non-`code` or high-entropy section is a
/// classic packer tell.
pub const ENTRY_SECTION: (&str, &str) = (
    "Check where a binary starts executing: join entrypoint() to sections() on the entry's \
     section name to report that section's kind, exec flag and entropy (an entry point in a \
     non-code or near-8-bit-entropy section suggests a packer; the fixture's entry is in \
     __TEXT,__text, kind code).",
    "SELECT ep.e.section, ep.e.vaddr AS entry_vaddr, s.kind, s.exec, round(s.entropy, 2) AS entropy \
     FROM (SELECT disasm.main.entrypoint('test/sql/data/hello-macho-arm64') AS e) AS ep \
     JOIN disasm.main.sections('test/sql/data/hello-macho-arm64') AS s ON s.name = ep.e.section \
     ORDER BY s.vaddr;",
);

/// Wrap a composed `(description, sql)` pair as a [`vgi::FunctionExample`] for
/// an object's `FunctionMetadata.examples` list.
pub fn function_example((description, sql): (&str, &str)) -> vgi::FunctionExample {
    vgi::FunctionExample {
        sql: sql.into(),
        description: description.into(),
        expected_output: None,
    }
}
