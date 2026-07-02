//! The `disasm` VGI worker.
//!
//! A standalone binary that DuckDB launches and talks to over Apache Arrow IPC
//! (`ATTACH 'vgi-disasm' AS disasm (TYPE vgi, LOCATION '…')`). It disassembles
//! the executable sections of PE/ELF/Mach-O binaries — and raw shellcode blobs —
//! into one instruction row per machine instruction, and surfaces section,
//! import, string, and heuristic ATT&CK-tagged capability relations for
//! malware triage. Catalog `disasm`, schema `main`:
//!
//! ```sql
//! ATTACH 'vgi-disasm' AS disasm (TYPE vgi, LOCATION './target/release/disasm-worker');
//! SET search_path = 'disasm.main';
//!
//! SELECT address, mnemonic, op_str, groups
//!   FROM disassemble(from_hex('554889e5c3'), arch := 'x86', mode := 'x64');
//! SELECT * FROM sections((SELECT content FROM read_blob('sample.bin')));
//! SELECT name, library, ordinal FROM imports((SELECT content FROM read_blob('sample.bin')));
//! SELECT * FROM capabilities((SELECT content FROM read_blob('sample.bin')));
//! SELECT format('not a binary'::BLOB);
//! ```
//!
//! The pure decode/parse engine lives in `disasm-core`; the `scalar/` and
//! `table/` modules are thin Arrow adapters over it. The worker **never executes**
//! the input — disassembly is static decoding of bytes only.

mod arrow_io;
mod meta;
mod scalar;
mod table;

use vgi::catalog::{CatSchema, CatalogModel};
use vgi::Worker;

/// Worker version string, surfaced by `disasm_version()`.
pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

/// The schema's ordered category registry (VGI413), emitted as `vgi.categories`.
/// Every function's `vgi.category` tag must name one of these `name` values.
pub const CATEGORIES: &[(&str, &str)] = &[
    (
        "Disassembly",
        "Decode a binary or shellcode blob into one row per machine instruction.",
    ),
    (
        "Container Probe",
        "Cheap header probes that identify the container format and resolve the entry point.",
    ),
    (
        "Static Extraction",
        "Enumerate the static contents of a binary: sections, imported symbols, and strings.",
    ),
    (
        "Malware Triage",
        "Heuristic MITRE ATT&CK capability tagging over imports, strings, and instructions.",
    ),
    (
        "Utility",
        "Worker metadata helpers, such as the running version probe.",
    ),
];

/// Catalog + schema metadata (description, provenance) surfaced to DuckDB and
/// the `vgi-lint` metadata-quality linter.
fn catalog_metadata(name: &str) -> CatalogModel {
    CatalogModel {
        name: name.to_string(),
        comment: Some(
            "Disassemble PE/ELF/Mach-O binaries and shellcode into instruction rows, with \
             section/import/string/capability triage for malware analysis."
                .to_string(),
        ),
        tags: vec![
            (
                "vgi.title".to_string(),
                "Disassembly & Malware Triage".to_string(),
            ),
            (
                "vgi.keywords".to_string(),
                crate::meta::keywords_json(
                    "disassemble, disassembly, capstone, instructions, shellcode, malware, \
                     triage, dfir, sections, imports, strings, capabilities, mitre att&ck, pe, \
                     elf, macho, x86, arm",
                ),
            ),
            (
                "vgi.doc_llm".to_string(),
                "Disassemble the executable sections of PE/ELF/Mach-O binaries and raw shellcode \
                 into one row per machine instruction (address, bytes, mnemonic, operands, \
                 instruction groups) via Capstone, and surface section/import/string relations \
                 plus heuristic MITRE ATT&CK capability tags for malware triage. Pure in-engine \
                 static decoding over a BLOB — never executes the input, no network, no state."
                    .to_string(),
            ),
            (
                "vgi.doc_md".to_string(),
                "# Disasm — Disassembly & Malware Triage in SQL\n\n\
                 **Disassemble PE/ELF/Mach-O binaries and raw shellcode directly in DuckDB SQL** \
                 — one instruction row per machine instruction, with section, import, string, and \
                 heuristic MITRE ATT&CK capability relations alongside. The `disasm` worker is \
                 driven by [Capstone](https://www.capstone-engine.org/) with container parsing by \
                 goblin, and is built for **fleet-scale, in-SQL triage**: disassemble and \
                 capability-tag thousands of samples and join the instruction stats and ATT&CK \
                 tags to the rest of your security tables — with no per-sample tooling and zero \
                 egress.\n\n\
                 It pairs with `vgi-pe` (static PE/ELF/Mach-O metadata), `vgi-yara` (rule hits), \
                 and `vgi-ioc` (indicators) in a VGI security bundle. The worker is **pure static \
                 compute over the input BLOB — it never executes the sample**, making it safe for \
                 air-gapped / regulated malware repositories.\n\n\
                 **How it works.** You supply a sample as inline bytes or a filesystem path; the \
                 worker sniffs the container, resolves architecture and mode, statically decodes \
                 the executable sections, and tags heuristic behaviours against MITRE ATT&CK — all \
                 as ordinary SQL relations you can filter, aggregate, and join. Nothing is ever \
                 run or emulated. List the schema to discover the available functions, or see the \
                 [source repository](https://github.com/Query-farm/vgi-disasm)."
                    .to_string(),
            ),
            (
                "vgi.agent_test_tasks".to_string(),
                crate::meta::agent_test_tasks_json(&[
                    (
                        "disassemble_shellcode_count",
                        "I have x64 shellcode as the hex string '554889e5c3'. Disassemble it and \
                         tell me how many machine instructions it contains. Return a single \
                         column named n.",
                        "SELECT count(*) AS n FROM disasm.main.disassemble(from_hex('554889e5c3'), \
                         arch := 'x86', mode := 'x64')",
                    ),
                    (
                        "find_ret_sites",
                        "In the x64 shellcode hex '554889e5c3', list the addresses of every \
                         return instruction, assuming it loads at address 4096. Return a single \
                         column named address.",
                        "SELECT address FROM disasm.main.disassemble(from_hex('554889e5c3'), \
                         arch := 'x86', mode := 'x64', base := 4096) WHERE list_contains(groups, \
                         'ret') ORDER BY address",
                    ),
                    (
                        "probe_container",
                        "Is the blob with hex bytes '7f454c46' a recognized binary container, and \
                         which one? Return a single column named container.",
                        "SELECT (disasm.main.format(from_hex('7f454c46'))).container AS container",
                    ),
                    (
                        "powershell_capability",
                        "Does the text 'powershell.exe -EncodedCommand ZQA=' trip any MITRE \
                         ATT&CK capability heuristic? Return the distinct attack_id values in a \
                         column named attack_id.",
                        "SELECT DISTINCT attack_id FROM \
                         disasm.main.capabilities('powershell.exe -EncodedCommand ZQA='::BLOB) \
                         ORDER BY attack_id",
                    ),
                    (
                        "worker_version",
                        "What version of the disasm worker is currently running? Return a single \
                         row with one column named version.",
                        "SELECT disasm.main.disasm_version() AS version",
                    ),
                ]),
            ),
            ("vgi.author".to_string(), "Query.Farm".to_string()),
            (
                "vgi.copyright".to_string(),
                "Copyright 2026 Query Farm LLC - https://query.farm".to_string(),
            ),
            ("vgi.license".to_string(), "MIT".to_string()),
            (
                "vgi.support_contact".to_string(),
                "https://github.com/Query-farm/vgi-disasm/issues".to_string(),
            ),
            (
                "vgi.support_policy_url".to_string(),
                "https://github.com/Query-farm/vgi-disasm/blob/main/README.md".to_string(),
            ),
        ],
        source_url: Some("https://github.com/Query-farm/vgi-disasm".to_string()),
        schemas: vec![CatSchema {
            name: "main".to_string(),
            comment: Some(
                "Disassembly, container-introspection, and malware-triage functions.".to_string(),
            ),
            tags: vec![
                ("vgi.title".to_string(), "Disasm — main".to_string()),
                (
                    "vgi.keywords".to_string(),
                    crate::meta::keywords_json(
                        "disassemble, sections, imports, strings, capabilities, entrypoint, \
                         format, capstone, mitre att&ck, malware, triage",
                    ),
                ),
                ("domain".to_string(), "security".to_string()),
                ("category".to_string(), "malware-analysis".to_string()),
                ("topic".to_string(), "disassembly".to_string()),
                (
                    "vgi.doc_llm".to_string(),
                    "Disassembly and malware-triage functions: disassemble binaries/shellcode \
                     into instruction rows, enumerate sections/imports/strings, surface heuristic \
                     MITRE ATT&CK capabilities, and probe container format / entry point."
                        .to_string(),
                ),
                (
                    "vgi.doc_md".to_string(),
                    "The single schema for the `disasm` worker. Everything here turns an opaque \
                     executable — a PE/ELF/Mach-O file or a raw shellcode blob, supplied inline or \
                     as a path — into queryable SQL relations: machine instructions, container \
                     layout, imported symbols, printable strings, and heuristic MITRE ATT&CK \
                     capability tags. All decoding is static; the sample is never executed. List \
                     the schema to browse the available functions."
                        .to_string(),
                ),
                (
                    "vgi.categories".to_string(),
                    crate::meta::categories_json(CATEGORIES),
                ),
                (
                    "vgi.example_queries".to_string(),
                    "SELECT address, mnemonic, op_str FROM disasm.main.disassemble(from_hex('554889e5c3'), arch := 'x86', mode := 'x64');\n\
                     SELECT (disasm.main.format(from_hex('7f454c46'))).container;\n\
                     SELECT count(*) FROM disasm.main.capabilities('powershell -enc ZQA='::BLOB);"
                        .to_string(),
                ),
            ],
            views: Vec::new(),
            macros: Vec::new(),
            tables: Vec::new(),
        }],
        ..Default::default()
    }
}

fn main() {
    // Logs MUST go to stderr — stdout is the Arrow-IPC channel.
    let _ = env_logger::Builder::from_env(env_logger::Env::default().filter_or("VGI_LOG", "info"))
        .format_timestamp_millis()
        .try_init();

    // The catalog name DuckDB sees in `ATTACH 'vgi-disasm' AS disasm (TYPE vgi, …)`.
    if std::env::var_os("VGI_WORKER_CATALOG_NAME").is_none() {
        std::env::set_var("VGI_WORKER_CATALOG_NAME", "disasm");
    }
    let catalog_name =
        std::env::var("VGI_WORKER_CATALOG_NAME").unwrap_or_else(|_| "disasm".to_string());

    let mut worker = Worker::new();
    scalar::register(&mut worker);
    table::register(&mut worker);
    worker.set_catalog(catalog_metadata(&catalog_name));
    worker.run();
}
