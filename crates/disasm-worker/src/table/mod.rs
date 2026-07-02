//! Table functions exposed by the disasm worker, registered under `disasm.main`.
//!
//! Each function fans **one** input blob into **N** rows (instructions /
//! sections / imports / strings / capabilities) with no resumable cursor — the
//! whole result for a row is produced eagerly and bounded (see
//! `disasm_core::limits`), so the externalized-cursor rule does not apply.
//!
//! Each function's input argument is typed **ANY**, so a single registration
//! binds both call forms — an inline `BLOB` (`disassemble(from_hex('…'))`) and a
//! `VARCHAR` path (`disassemble('sample.bin')`). The producer reads whichever of
//! `const_bytes` / `const_str` the caller supplied (see [`crate::arrow_io`]).
//! This is the path|bytes arg overloading the SQL surface advertises, in one
//! named argument (which also keeps the metadata lint clean).

mod capabilities;
mod disassemble;
mod imports;
mod sections;
mod strings;

use std::collections::HashMap;

use arrow_schema::{DataType, Field};
use vgi::{ArgSpec, Worker};

/// Register every table function once. Each takes a single named `blob` input
/// argument typed ANY, so DuckDB binds it to either an inline BLOB
/// (`disassemble(from_hex('…'))`) or a VARCHAR path
/// (`disassemble('sample.bin')`) without a separate per-type overload — the
/// path|bytes arg overloading is handled at producer time by reading whichever
/// of `const_bytes` / `const_str` the caller supplied.
pub fn register(worker: &mut Worker) {
    worker.register_table(disassemble::Disassemble);
    worker.register_table(sections::Sections);
    worker.register_table(imports::Imports);
    worker.register_table(strings::Strings);
    worker.register_table(capabilities::Capabilities);
}

/// A column field carrying a `comment` (surfaced via `duckdb_columns().comment`)
/// so every output column is documented for `vgi-lint`.
pub(crate) fn commented(name: &str, dt: DataType, comment: &str) -> Field {
    Field::new(name, dt, true).with_metadata(HashMap::from([(
        "comment".to_string(),
        comment.to_string(),
    )]))
}

/// The single constant input argument shared by every table function: the binary
/// supplied inline as a BLOB **or** as a VARCHAR path to open. Typed ANY so one
/// registration binds both call forms (DuckDB names the parameter `blob`, which
/// also satisfies the "no positional/unnamed argument" lint).
pub(crate) fn input_arg() -> ArgSpec {
    ArgSpec::const_arg(
        "blob",
        0,
        "any",
        "The binary or shellcode to analyze: either the raw bytes supplied inline, or a \
         filesystem path to the file to open and read. The bytes are statically decoded \
         only — never executed.",
    )
}
