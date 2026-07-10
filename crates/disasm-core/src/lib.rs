//! `disasm-core` — the pure disassembly + container-triage engine behind the
//! `vgi-disasm` VGI worker.
//!
//! No Arrow, no RPC, no I/O: every public function is a stateless transform over
//! an in-memory `&[u8]` blob, returning plain Rust structs. The worker crate
//! (`disasm-worker`) is a thin Arrow adapter over this; the golden-vector and
//! proptest suites exercise it directly.
//!
//! ## Surface
//! - [`probe::probe`] / [`probe::Probe`] — container sniff → arch/mode/bits/endian/entry.
//! - [`sections::sections`] — section/segment table with exec flag + entropy.
//! - [`imports::imports`] — PE/ELF/Mach-O imported symbols.
//! - [`entrypoint::entrypoint`] — resolved entry point.
//! - [`sweep::disassemble`] — the linear-sweep instruction relation.
//! - [`strings::strings`] — ASCII + UTF-16LE extraction.
//! - [`capabilities::capabilities`] — heuristic ATT&CK-tagged triage rows.
//!
//! ## Hardening
//! Every entry point is wrapped against malformed/hostile input (a bad blob
//! yields empty/diagnostic output, never a panic) and bounded by the caps in
//! [`limits`]. The worker **never executes** the input — disassembly is static
//! decoding only.

pub mod capabilities;
pub mod engine;
pub mod entrypoint;
pub mod groups;
pub mod imports;
pub mod limits;
pub mod mappings;
pub mod probe;
pub mod sections;
pub mod strings;
pub mod sweep;

// Re-exports of the primary types for ergonomic worker-side use.
pub use capabilities::{capabilities, Capability};
pub use engine::Insn;
pub use entrypoint::{entrypoint, EntryPoint};
pub use imports::{imports, Import};
pub use probe::{probe, ArchSel, Probe, SUPPORTED_ARCHES, SUPPORTED_MODES};
pub use sections::{sections, Section};
pub use strings::{strings, StringHit};
pub use sweep::disassemble;
