# vgi-disasm

A [VGI](https://query.farm) worker that **disassembles** the code sections of
PE / ELF / Mach-O binaries — and raw shellcode blobs — into one **row per machine
instruction** (address, raw bytes, mnemonic, operands, instruction groups),
driven by [Capstone](https://www.capstone-engine.org/) with container parsing by
[goblin](https://github.com/m4b/goblin). On top of the instruction stream it
surfaces section/import/string relations and **lightweight, MITRE ATT&CK-tagged
capability indicators** for malware triage.

It is the disassembly sibling to `vgi-pe`, and pairs with `vgi-yara` / `vgi-ioc`
in a VGI **security bundle**: *disassemble and capability-tag thousands of
samples and join the instruction stats and ATT&CK tags to your YARA hits and IOC
feeds in one SQL query — with no per-sample tooling and zero egress.* The worker
is **pure static decoding over a `BLOB` — it never executes the input**, no
network, no state, making it safe for air-gapped / regulated malware
repositories.

> **Value framing (honest).** The disassembly primitive is a commodity surrounded
> by free, best-in-class incumbents (objdump, radare2/rizin, Ghidra, the Capstone
> CLI, and **capa** for capability detection). vgi-disasm does **not** try to win
> "disassemble one binary". Its value is **fleet-scale, in-SQL triage** that joins
> to the rest of the security bundle — the thing the GUIs and shell loops do not
> do. v1 capability detection is a small import/string/anti-analysis heuristic; it
> is deliberately **not** a port of capa's rule engine.

## SQL surface

```sql
INSTALL vgi FROM community;
LOAD vgi;
ATTACH 'vgi-disasm' AS disasm (TYPE vgi, LOCATION '/path/to/disasm-worker');
SET search_path = 'disasm.main';
```

| Function | Signature | Kind |
| --- | --- | --- |
| Disassembly | `disassemble(blob [, arch, mode, base, section]) -> TABLE(address UBIGINT, size UTINYINT, bytes BLOB, mnemonic VARCHAR, op_str VARCHAR, groups VARCHAR[])` | table |
| Sections | `sections(blob) -> TABLE(name, kind, vaddr UBIGINT, size UBIGINT, file_off UBIGINT, exec BOOL, entropy DOUBLE)` | table |
| Imports | `imports(blob) -> TABLE(library, name, ordinal INTEGER, kind)` | table |
| Strings | `strings(blob [, min_len]) -> TABLE(offset UBIGINT, encoding, value)` | table |
| Capabilities | `capabilities(blob) -> TABLE(rule, attack_id, attack_name, severity, evidence)` | table |
| Entry point | `entrypoint(blob) -> STRUCT(arch, mode, vaddr UBIGINT, file_off UBIGINT, section)` | scalar |
| Format probe | `format(blob) -> STRUCT(container, arch, mode, bits UTINYINT, endian, entry UBIGINT)` | scalar |
| Version | `disasm_version() -> VARCHAR` | scalar |

**Input: bytes _or_ path.** Every function accepts the binary either as inline
`BLOB` bytes or as a `VARCHAR` filesystem path it opens and reads (the bytes are
statically decoded, **never executed**). The table-function input is a single
`ANY`-typed argument, so both `disassemble(from_hex('…'))` and
`disassemble('sample.bin')` bind.

> **A note on the SQL form.** DuckDB **table functions take constant arguments**
> (they cannot take a correlated/`LATERAL` column reference). Feed the binary as a
> literal `BLOB` (e.g. `from_hex(...)` or `'…'::BLOB`) or as a path string. The
> per-row **scalars** `format()` / `entrypoint()` *do* take a column expression.
> (`read_text(...)` is a DuckDB **table** function and is not a scalar argument —
> use the worker's BLOB/path input modes instead.)

### Examples

```sql
-- 1. Disassemble x64 shellcode at an explicit base; enumerate its call sites.
SELECT address, mnemonic, op_str
FROM disassemble(from_hex('554889e5e800000000c3'), arch := 'x86', mode := 'x64', base := 4096)
WHERE list_contains(groups, 'call')
ORDER BY address;

-- 2. Disassemble a binary's executable sections (arch auto-detected from the
--    container; base = each section's virtual address). Pass a path or BLOB.
SELECT address, mnemonic, op_str, groups
FROM disassemble('sample.bin')          -- or disassemble(<blob>)
ORDER BY address;

-- 3. Sections, imports, and the entry point of a sample.
SELECT name, kind, exec, entropy FROM sections('sample.bin');
SELECT library, name, ordinal, kind   FROM imports('sample.bin');
SELECT (entrypoint('sample.bin')).*;
SELECT (format('sample.bin')).*;        -- fast "is this a binary I can disassemble?"

-- 4. Heuristic capabilities mapped to MITRE ATT&CK for one sample (the input is
--    a constant path or BLOB, per the note above), filtered to a technique family.
SELECT rule, attack_id, attack_name, severity, evidence
FROM capabilities('sample.bin')
WHERE attack_id LIKE 'T1055%';            -- process-injection family
```

## The disassembly model

- **Arch / mode resolution** (priority order): explicit `arch`/`mode` args →
  container header (goblin: ELF `e_machine`, PE machine, Mach-O `cputype`) →
  otherwise a single diagnostic row (`mnemonic='(error)'`,
  `op_str='arch required for raw blob'`). Supported: **x86 (16/32/64), ARM,
  ARM64, MIPS, PPC, SystemZ, RISC-V**.
- **Base address** seeds the `address` column and makes branch-relative operands
  print **absolute** targets (`call 0x401050`). Default = the section's VA (or 0
  for a raw blob); pass `base :=` for shellcode so operands line up with a memory
  dump.
- **Section selection** (`section` arg): `auto` (every executable section, the
  default), `all` (the whole blob as raw bytes at `base`), or a section name
  (`.text`, `__text`).
- **Linear sweep with bad-byte resume.** v1 decodes forward from the start of
  each selected section; an undecodable byte becomes a one-byte `.byte` row and
  the sweep resumes at the next byte — it never stalls. (Recursive-descent /
  from-entry CFG following is roadmap.)
- **Normalized instruction groups.** Capstone's group detail is normalized to a
  small, arch-portable vocabulary — `call`, `jump`, `ret`, `int`, `privileged`,
  `branch_relative`, `fpu`, `sse`, `vm` — so `WHERE list_contains(groups, 'call')`
  works on x86, ARM, or MIPS alike.

## Capabilities (heuristic, not capa)

`capabilities(blob)` produces ATT&CK-tagged triage indicators from three cheap
signals: **import name → technique** (e.g. `VirtualAllocEx`/`WriteProcessMemory`/
`CreateRemoteThread` → T1055 Process Injection), **interesting string → indicator**
(PowerShell `-enc`, `cmd.exe /c`, autorun registry paths, VM-artifact names,
ransom-note markers), and **anti-analysis instruction patterns** (`rdtsc`/`cpuid`
timing, `int3` / `int 0x2d`). The mapping tables ship as compiled-in reference
data; ATT&CK technique IDs/names come from
[attack.mitre.org](https://attack.mitre.org/). There is **no scoring, no rule
composition, no basic-block features** — that is the line that separates this from
[capa](https://github.com/mandiant/capa) (which is free, Python, and better at
single-sample depth; consuming `capa-rules`-as-data is roadmap).

## Hardening

The input *is* the malware, so every transform is wrapped and bounded:

- **Per-row catch:** a malformed/hostile blob yields empty or diagnostic output,
  never a panic or a crashed scan (a `proptest` fuzz gate asserts zero panics on
  arbitrary bytes across every arch).
- **Bounded everything:** hard caps on instructions per blob (`MAX_INSNS` ≈ 5M),
  bytes fed to Capstone per section, and string/import/section/capability counts,
  so a crafted "huge declared size" header cannot OOM the worker.
- **Never executes the input:** disassembly is static decoding of bytes, not
  emulation or running.

## Building & testing

```sh
cargo build --release            # produces target/release/disasm-worker
cargo test                       # unit + golden vectors + proptest no-panic gate
cargo clippy --all-targets -- -D warnings
./run_tests.sh                   # haybarn SQLLogic E2E (needs haybarn-unittest + the vgi ext)
```

The crate is split into `disasm-core` (pure decode/parse/triage engine; no Arrow,
no RPC) and `disasm-worker` (the VGI SDK Arrow adapter). CI runs fmt/clippy/build/
doc, the Rust suite, the SQLLogic E2E across the **subprocess + unix + HTTP**
transport matrix, and the `vgi-lint` metadata gate at `--fail-on info`.

## License & dependencies

**MIT** (see [`LICENSE`](LICENSE)). All dependencies are permissive, no copyleft:
the bundled Capstone C engine is BSD-3-Clause (embedding BSD-3-Clause LLVM MC
tables); the `capstone`/`capstone-sys` bindings are MIT; `goblin` is MIT;
`object` is MIT/Apache-2.0. No GPL/AGPL anywhere.

Part of the [Query.Farm](https://query.farm) VGI ecosystem of DuckDB workers.
Copyright 2026 Query Farm LLC.
