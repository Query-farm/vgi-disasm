# CI: the vgi-disasm worker integration suite

[`.github/workflows/ci.yml`](../.github/workflows/ci.yml) runs fmt/clippy/build,
the Rust unit + golden-vector + proptest tests, and this repo's sqllogictest
suite (`test/sql/*.test`) against the vgi-disasm VGI worker through the **real
DuckDB `vgi` extension** on every push / PR.

## Transport matrix

The integration suite runs over **every transport the vgi extension supports**.
The exact same `test/sql/*.test` files run three ways; the only thing that
changes is what LOCATION the `.test` files `ATTACH` (set by
[`run-integration.sh`](run-integration.sh) from the `TRANSPORT` env var):

| `TRANSPORT`  | `VGI_DISASM_WORKER` (the ATTACH LOCATION) | how the worker is launched |
|--------------|-------------------------------------------|----------------------------|
| `subprocess` | `…/target/release/disasm-worker`          | DuckDB spawns the stdio binary (default) |
| `http`       | `http://127.0.0.1:<port>`                 | `disasm-worker --http` (auto port; prints `PORT:<n>`) |
| `unix`       | `unix:///tmp/disasm.<pid>.sock`           | `disasm-worker --unix <sock>` (prints `UNIX:<sock>` + creates the socket) |

CI runs `transport: [subprocess, http, unix]` × `os: [ubuntu, macos]`. Build the
worker once with a plain `cargo build --release` — the workspace already pins
`vgi-rpc = { features = ["macros", "http"] }`, so the one binary serves all three
transports; **no extra cargo feature is needed**.

### The `http` leg needs DuckDB's `httpfs` extension

The vgi extension's **HTTP client** is built on DuckDB's `httpfs`. Over `http://`,
`ATTACH` fails without it, and DuckDB's sqllogictest runner **silently SKIPs**
any test whose error contains the substring `HTTP` — so a missing `httpfs` looks
like a (deceptive) pass-by-skip. We handle this in two places:

1. [`preprocess-require.awk`](preprocess-require.awk), invoked with
   `-v transport=http`, injects a signed `INSTALL httpfs FROM core; LOAD httpfs;`
   right after each `LOAD vgi;`.
2. [`run-integration.sh`](run-integration.sh) fails the job if the runner reports
   *any* skipped tests (a skip is never a pass).

## How it works (no C++ build)

Rather than building the vgi DuckDB extension from source, the integration job
drives a **prebuilt** standalone `haybarn-unittest` (the DuckDB/Haybarn
sqllogictest runner) and installs the **signed** `vgi` extension from the
Haybarn community channel:

1. **Build the worker** — `cargo build --release --bin disasm-worker`.
2. **Download the runner** — the matching `haybarn_unittest-*` asset per platform.
3. **Preprocess** — [`preprocess-require.awk`](preprocess-require.awk) rewrites
   each `require <ext>`/`LOAD vgi;` into explicit signed installs.
4. **Run** — [`run-integration.sh`](run-integration.sh) brings up the worker for
   the selected `TRANSPORT`, stages the preprocessed tree (plus `test/sql/data`
   fixtures), warms the extension cache once, then runs the suite. Any failed
   assertion — or any skipped test — exits non-zero and fails the job.

## Run it locally

```bash
cargo build --release --bin disasm-worker
HAYBARN_UNITTEST=/path/to/haybarn-unittest \
WORKER_BIN="$PWD/target/release/disasm-worker" \
TRANSPORT=subprocess \
  ci/run-integration.sh

# HTTP / unix legs:
HAYBARN_UNITTEST=/path/to/haybarn-unittest WORKER_BIN="$PWD/target/release/disasm-worker" \
  TRANSPORT=http ci/run-integration.sh
HAYBARN_UNITTEST=/path/to/haybarn-unittest WORKER_BIN="$PWD/target/release/disasm-worker" \
  TRANSPORT=unix ci/run-integration.sh
```

Or use `./run_tests.sh`, which builds the release worker and runs the suite
against a `haybarn-unittest` on `PATH`.
