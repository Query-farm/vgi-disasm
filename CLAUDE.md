# CLAUDE.md — vgi-disasm

Guidance for working in this repo. vgi-disasm is a **VGI worker** (a standalone
binary DuckDB launches over Apache Arrow IPC) that disassembles PE/ELF/Mach-O
binaries and shellcode into instruction rows and surfaces section/import/string/
capability triage relations. Catalog `disasm`, schema `main`.

## Layout

```
crates/
  disasm-core/          # PURE engine: no Arrow, no RPC, no I/O. Plain &[u8] -> structs.
    src/probe.rs        #   container sniff + (arch,mode) resolution  -> format()/entrypoint()
    src/sections.rs     #   section/segment enumeration + Shannon entropy
    src/imports.rs      #   PE/ELF/Mach-O imported symbols
    src/engine.rs       #   Capstone handle per (arch,mode); linear sweep + bad-byte resume
    src/groups.rs       #   Capstone group ids -> normalized {call,jump,ret,int,...} vocab
    src/sweep.rs        #   top-level disassemble(): arch resolve -> section select -> sweep
    src/strings.rs      #   ascii + utf16le extraction (bounded)
    src/capabilities.rs #   §B heuristic matcher (import/string/anti-analysis -> ATT&CK)
    src/mappings.rs     #   compiled-in ATT&CK reference DATA tables
    src/limits.rs       #   hard caps (MAX_INSNS, MAX_SECTION_BYTES, …)
    tests/              #   golden vectors, container parse, proptest no-panic gate
  disasm-worker/        # VGI SDK Arrow adapter over disasm-core.
    src/main.rs         #   catalog metadata + scalar/table registration + Worker::run
    src/arrow_io.rs     #   BLOB|path input resolution + struct field types + test harness
    src/scalar/         #   disasm_version, format, entrypoint
    src/table/          #   disassemble, sections, imports, strings, capabilities
ci/                     # haybarn SQLLogic E2E across the subprocess/unix/http transport matrix
test/sql/               # the .test files (LOAD vgi; ATTACH; assert) + test/sql/data fixtures
```

## Invariants (do not regress)

- **Never executes the input.** Disassembly is static decoding only — no
  emulation, no running. The input *is* malware.
- **Panic-free + bounded.** Every public `disasm-core` function wraps its parse
  and clamps its output to `limits.rs`. A malformed/hostile blob yields empty or
  diagnostic output, never a panic. The `proptest` gate
  (`tests/fuzz_nopanic.rs`) enforces this across every arch — keep it green.
- **Pure core / thin worker.** All decode/parse/triage logic lives in
  `disasm-core` and is tested there directly. The worker crate only marshals
  Arrow. Don't put logic in the worker.
- **Published SDK only.** `vgi = "0.9.5"`, arrow 59, vgi-rpc 0.7 — **no path
  deps**. Keep arrow/vgi-rpc pins in lockstep with vgi.
- **License is MIT** (fleet convention). All deps are permissive (Capstone C
  engine BSD-3-Clause; bindings/goblin MIT; object MIT/Apache-2.0).

## VGI platform facts (learned the hard way)

- **Table functions take CONSTANT arguments** — they cannot take a correlated /
  `LATERAL` column reference. The blob input is a constant `BLOB` or a `VARCHAR`
  path. In tests use `from_hex('…')` / `'…'::BLOB` literals or a path string.
  Per-row column input is only for the **scalars** (`format`, `entrypoint`).
- **One ANY-typed input arg, one registration.** Each table function's input is a
  single `ArgSpec::const_arg("blob", 0, "any", …)`, so DuckDB binds both an inline
  BLOB and a VARCHAR path to the same named parameter. The producer reads
  whichever of `const_bytes(0)` / `const_str(0)` is present. A named arg (not a
  positional `col0`) is also what keeps `vgi-lint`'s VGI305 clean.
- **Arg-type tokens** map via the SDK's `arg_type_to_arrow`: use `"uint64"` (not
  `"ubigint"`), `"varchar"`, `"any"`, `"blob"`, … An unrecognized token silently
  becomes `DataType::Null` and fails at bind with a confusing cast error.
- **Scalar output type is fixed at bind** (`on_bind` returns the schema).
- **`vgi.source_url` is catalog-only** (VGI139) — do not set it per-function;
  point to Capstone/ATT&CK in the prose `doc_*` tags instead.
- **Example SQL is executed by `vgi-lint`** (VGI901/902/906): every
  `FunctionExample` and `vgi.executable_examples` query must bind and run as
  written — catalog-qualified, no subqueries in a table-function argument, and
  returning at least one row for a scalar (use `count(*)` for table fns). Quote
  the reserved column name `offset` as `"offset"`.

## Gates (all must be green)

```sh
cargo build --release
cargo clippy --all-targets --all-features -- -D warnings
cargo fmt --all -- --check
cargo test --workspace
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --workspace
uvx --from vgi-lint-check@0.37.0 vgi-lint lint "$PWD/target/release/disasm-worker" --catalog disasm --fail-on info
HAYBARN_UNITTEST=$(command -v haybarn-unittest) WORKER_BIN="$PWD/target/release/disasm-worker" TRANSPORT=subprocess ci/run-integration.sh   # also http, unix
```

## Scope (v1)

v1 ships the **disassembly table function + the container/triage relations**.
**Out of scope:** the capa rule engine (Python; heuristic-only here),
recursive-descent/CFG disassembly (linear sweep only), decompilation/emulation,
unpacking/deobfuscation. See the spec's "Non-goals / roadmap".
