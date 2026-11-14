# Static disassembly notebooks

[01 · The decoding mode changes the instruction stream](01_decoding_mode_changes_the_instruction_stream.ipynb)
compares x86-64 and x86-32 interpretations of one synthetic byte string. Visible
SQL preserves diagnostics and fallback bytes, verifies exact byte accounting,
and measures instruction counts and decoded-byte fractions. Two charts show
instruction boundaries and the differing counts/coverage.

## Run from this directory

Install [uv](https://docs.astral.sh/uv/), then:

```sh
cd notebooks
uv sync --locked
uv run --locked python execute.py
```

For interactive use select `notebooks/.venv/bin/python` as the notebook kernel
and run all cells. The locked environment supports Python 3.13–3.14 and uses
Haybarn 2.0.0rc11, JupySQL, Seaborn and Matplotlib. No local worker build, Rust
compiler or worker checkout is needed; the complete notebook directory works
on its own. Initial worker/extension downloads need network access. Subsequent
analysis reads the literal bytes without contacting any external data service.

The connection SQL stays visible:

```sql
INSTALL vgi FROM community;
LOAD vgi;
ATTACH 'disasm' (TYPE vgi,
 LOCATION 'github-auto://Query-farm/vgi-disasm@v0.4.0');
```

The engine downloads, verifies and caches the native platform release. v0.4.0
publishes macOS arm64, Linux amd64/arm64 and Windows amd64 assets. This notebook
was validated on macOS arm64. Change the visible release pin and rerun both modes
when upgrading. Parameters and analytical SQL stay expanded; Python setup,
plotting source and cleanup are folded while useful results remain visible.
Official local Strata Sun branding closes both ends of the notebook, with the
VGI logo and links near the top.

## One-parameter experiment

`MODE` accepts `"x64"` (default) or `"x32"`. The raw input, `arch := 'x86'`
and `base := 4096` stay fixed. Both reference modes are materialized on every run;
the parameter selects the instruction table and the outlined chart row.

```sh
uv run --locked python execute.py --parameters '{"MODE":"x32"}' \
  --output-dir validation/x32
```

The runner uses a fresh kernel, saves only successful execution and requires a
separate output directory for overrides. Unknown names and source-directory
overwrites are rejected. Copies include assets, helpers, the guide and locked
environment. Generated PNGs and experiment copies under `validation/` are ignored;
charts remain embedded in the successful default notebook.

## Provenance and meaning

The input is the literal hex string `4885ff7406488d4701eb0231c0c30690` (16 bytes),
a hand-authored teaching sequence. Its 64-bit interpretation contains test,
conditional/unconditional jumps, arithmetic and a return, followed by `06 90`.
The last bytes expose fallback handling and linear sweep beyond a return. No
sample binary is downloaded, compiled, emulated or executed.

A raw format probe has no header-provided architecture. Without an architecture,
the worker emits a size-zero `(error)` diagnostic; it is not an instruction. With
explicit modes, the same `48` bytes join instructions in x64 but decode separately
in x32. The tail `06` is a `.byte` fallback in x64 and a decoded instruction in x32.
This fixture therefore illustrates why a higher decoded-byte fraction cannot
establish the intended mode.

The coverage denominator is the original input length. Decoded bytes exclude
fallback and diagnostic rows; represented bytes retain fallbacks. Ordered byte
reconstruction, contiguous addresses and correct row lengths validate accounting
without requiring perfect decoding. Group tags can overlap, so the span chart
uses a single explicit category per row rather than summing group memberships.

Linear sweep is not a runtime trace or a control-flow graph. It does not establish
which instructions execute, separate code from embedded data or demonstrate any
malicious capability. For container-backed input, use the worker's `format`,
`entrypoint` and `sections` relations alongside disassembly. Capability indicators
are separate heuristics and are outside this notebook's claims.

References: [worker documentation](https://github.com/Query-farm/vgi-disasm),
[pinned native release](https://github.com/Query-farm/vgi-disasm/releases/tag/v0.4.0).
