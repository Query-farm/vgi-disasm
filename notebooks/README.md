# Static decoding and evidence triage

Two focused notebooks use the public **VGI Disasm v0.4.0** native release:

- [01 · The decoding mode changes the instruction stream](01_decoding_mode_changes_the_instruction_stream.ipynb) compares x86-64 and x86-32 interpretations of the same authored 16 bytes. The supported-target vocabulary validates the request, while instruction boundaries and byte accounting show why more decoded bytes cannot establish the intended mode. [Open in Colab](https://colab.research.google.com/github/Query-farm/vgi-disasm/blob/main/notebooks/01_decoding_mode_changes_the_instruction_stream.ipynb).
- [02 · Static evidence changes with the string filter](02_static_evidence_changes_with_the_string_filter.ipynb) locates a hello-world Mach-O entry point and imports, then separates extracted text from heuristic findings. Raising the display threshold can hide supporting text while the original findings remain unchanged. [Open in Colab](https://colab.research.google.com/github/Query-farm/vgi-disasm/blob/main/notebooks/02_static_evidence_changes_with_the_string_filter.ipynb).

In Colab choose **Runtime → Run all**. The visible bootstrap installs the base
shared package, verifies immutable companions and preserves compatible existing
kernel/data/plotting libraries. The local locked environment adds `[runner]`:

```sh
uv sync --locked
uv run --locked vgi-notebooks
uv run --locked vgi-notebooks 01_decoding_mode_changes_the_instruction_stream.ipynb --parameters '{"MODE":"x32"}' --output-dir artifacts/x32
uv run --locked vgi-notebooks 02_static_evidence_changes_with_the_string_filter.ipynb --parameters '{"MIN_CHARACTERS":12}' --output-dir artifacts/minimum-12
```

Run from `notebooks/`; it also works independently of the worker checkout.
For interactive Jupyter select `.venv/bin/python`. The runner uses a temporary
kernel, requires separate experiment destinations and protects the saved defaults
when an execution fails. Unknown parameters and source-directory overwrites are
rejected. If an old bootstrap replaced kernel libraries, save your work and open
the current notebook in a fresh runtime.

The launch stays visible and literal:

```sql
INSTALL vgi FROM community;
LOAD vgi;
ATTACH 'disasm' (TYPE vgi,
 LOCATION 'github-auto://Query-farm/vgi-disasm@v0.4.0');
```

The engine downloads, verifies and caches the platform release. No Rust compiler,
worker build, local source directory or credentials are required. The release
publishes macOS arm64, Linux amd64/arm64 and Windows amd64 binaries; execution here
was validated on macOS arm64. Initial dependency, extension, binary and companion
setup needs network access. Analysis is local static computation over supplied
bytes; no sample is executed, emulated, uploaded or fetched from a malware corpus.

The [shared v0.3.11 standard](https://github.com/Query-farm/vgi-example-notebooks/blob/v0.3.11/docs/standard.md)
provides actual catalog title/subtitle branding, isolated SQL secrets, SVG figures,
portable companions and execution protections. The published subtitle's whitespace
is normalized for display; its text comes from `coverage/catalog-metadata.json`.
Keep committed `charts/` with the saved notebooks for GitHub's SVG image-link
rendering. Colab and Jupyter reruns emit native SVG. PNG review exports, environments
and experimental executions remain ignored. Haybarn **2.0.0rc11** is locked locally.

Coverage is **8 of 8 public named SQL surfaces**: `format`, `entrypoint`,
`disassemble`, `sections`, `imports`, `strings`, `capabilities`, and the
`supported_targets` view. The actual catalog contains seven functions and one view,
with full signatures and table-function/view output columns retained. No public
objects are excluded. `coverage.json` binds released/current catalogs, successful
execution receipts and reviewed SQL/narrative/result mappings. The notebooks run
the pinned release. Current mappings attest interface/source compatibility, not
current-main notebook execution. The release-to-main source difference adds only
composed examples and descriptive metadata; worker source and root locks stay
unchanged during this notebook migration.

The first input is the literal hex `4885ff7406488d4701eb0231c0c30690`. Without an
architecture, the worker emits a size-zero diagnostic; this is not an instruction.
With x64, one `.byte` fallback remains and 15/16 bytes decode into seven instructions.
With x32, all 16 bytes decode into ten instructions. The same bytes and base address
remain fixed. Linear sweep continues beyond `ret`; its output is neither a runtime
trace nor a control-flow graph. Fallback bytes stay in the decoding denominator,
and ordered returned bytes reconstruct the original input.

The second input is the repository's existing 49,952-byte ARM64 Mach-O hello-world
test fixture, copied unchanged to a non-executable
[`assets/hello-macho-arm64.bin`](assets/hello-macho-arm64.bin).
[Fixture provenance and digest](assets/README.md) identify the exact source revision.
The eight reported sections total 219 bytes; that scope differs from the whole file,
which also contains headers, padding and other container data. The entry address
maps to file offset 1464 in `__TEXT,__text`. Two import rows describe dependencies,
not observed calls. Zero capability rows for this fixture cannot establish safety.

The separate authored documentation BLOB contains NUL-separated command-option,
example-domain URL and note strings. They are inert data. The fixed capability
matcher yields four rules over three distinct supporting strings, including two
rules for the same PowerShell text. Every rule remains visible in the evidence
table even when the selected string threshold hides its supporting row. The
capability matcher uses its own fixed minimum of four characters; changing
`MIN_CHARACTERS` does not change that independent scan. Advisory severity labels
are not probabilities or evidence that a command executed or a connection occurred.

`MIN_CHARACTERS` accepts integers **4 through 24**. Base ASCII/UTF-16LE extraction
uses a constant minimum of one; selected extraction uses the actual worker at the
chosen threshold. A local filter of the base rows independently reconciles the
selected output for these short, untruncated fixtures. The sensitivity curve uses
local rows over thresholds 4–24 and makes no extra worker calls. Long truncated
strings, repeated evidence and obfuscation need additional handling; this example
does not claim arbitrary string reconstruction or heuristic completeness.

The worker table functions require constant inputs, so their calls use literal
paths/BLOBs. Scalars can read a BLOB column. SQL materializes results before display.
The first notebook has eight byte-accounting checks plus target-token validation;
the second has twelve checks for container mapping, selected populations and
source-byte evidence. Defaults, one-parameter experiments, four reviewed SVG
figures, runner guards and a fresh preloaded compatible kernel are validated.
Hosted Colab was not manually operated. Existing green source CI at
[cb7d007](https://github.com/Query-farm/vgi-disasm/actions/runs/43563889174)
is reused; no worker builds, transport suites or full CI are repeated for these
notebook-only changes. The prior source validation passed 36 Rust tests, 83 stdio,
93 HTTP and 83 Unix SQL assertions, with metadata 100/100 L2 and zero findings.
