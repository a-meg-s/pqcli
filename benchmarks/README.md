# PQCLI Benchmark Harness

Benchmarks for classical, PQC, composite, hybrid, and dual/RFC 9763 certificate workflows.

## Benchmark Suite Methodology

Four suites with different cost models. Do not mix timing fields across suites without context.

### macro
**Cold CLI invocation.** One JVM process per operation. Every invocation includes JVM startup,
Bouncy Castle provider registration, CLI argument parsing, the PKI operation, and JVM shutdown.
Timing: `/usr/bin/time -v` wall clock (`cli_wall_time_ms`).
Answers: *How long does a user wait when running `java -jar pqcli.jar ...` from a shell?*

### industrial
**Long-lived JVM.** One JVM process per `(algo_tag, operation)` pair. Providers initialized once
before the warmup loop. Measured iterations call PKI logic directly — no CLI overhead per iteration.
File I/O (reading/writing PEM artifacts) is included in measured time.

Benchmark helper code lives under `benchmarks/java/pqcli/IndustrialBenchmarkRunner.java` — it is
**not** part of `pqcli-main`. The run script compiles it against the pqcli JAR before launching.

Timing: `System.nanoTime()` per iteration (`elapsed_ms` in CSVs).  
RSS: process-level peak RSS from `/usr/bin/time -v` per `(algo_tag, operation)` JVM process;
per-iteration RSS is unavailable. `rss_scope = process_peak_per_algo_operation`.

Answers: *How expensive are full PKI operations when JVM startup and provider init are not paid
on every operation?*

`verify-dynamic` = Mode B dynamic path-building verification (same name as macro harness).

Workflow ops (`workflow-2tier`, `workflow-3tier`) run all steps sequentially inside one JVM in
one timing window. Macro workflow ops launch a separate JVM process per step and sum wall times.
These are methodologically distinct.

`elapsed_ms` (industrial) ≠ `cli_wall_time_ms` (macro). They measure different cost models.
Both are needed for a complete picture of PKI operation cost.

### micro
**JMH microbenchmarks.** Warmed JVM, narrow primitive operations. Not full PKI operations;
excludes certificate construction overhead and file I/O. For low-level primitive timing only.

### openssl
**Native CLI baseline.** OpenSSL native implementations. Different runtime and algorithm
availability from the JVM/BC path. Comparability is limited; see `metadata.json` in each run.

---

## Prerequisites

- JDK 17+ on PATH
- Maven 3.6+ on PATH
- Python 3.8+
- `/usr/bin/time -v` (GNU time, standard on Debian/Ubuntu)
- `pqcli-main/target/pqcli-0.1.0.jar` (built via `mvn clean package`)
- Optional: `taskset` for CPU pinning, `perf` for software counters

Build pqcli first:
```bash
cd pqcli-main
mvn clean package
```

## Macro benchmark (run_macro_benchmarks.py)

Measures CLI wall time, peak RSS, and software/runtime metrics.
Includes JVM startup overhead (~100–400ms per invocation).

### Run profiles

| Profile | Single configs | Dual configs | Iterations | Notes |
|---------|---------------|-------------|------------|-------|
| smoke | 5 | 1 | 3 | Fast sanity check |
| thesis-core | 12 | 2 | 100 | Representative, not exhaustive |
| slh-heavy | 12 | — | 100 | All SLH-DSA variants |
| composite-heavy | 13 | — | 100 | All composite variants |
| hybrid-heavy | 6 | — | 100 | All hybrid variants |
| verify-heavy | 12 | — | 100 | Verification mode comparison |
| full | all (28+) | 2 | 100 | Exhaustive sweep |

**thesis-core** is intentionally representative, not exhaustive. Exhaustive coverage of
all SLH-DSA, composite, and hybrid variants lives in the specialist profiles
(`slh-heavy`, `composite-heavy`, `hybrid-heavy`) and `full`.

thesis-core single-algo ops use `THESIS_CORE_OPS`: `keygen`, `cert`, `csr`, `sign-leaf`,
`sign-intermediate-ca`, `verify-dynamic`, `workflow-2tier`, `workflow-3tier`.
`verify-dynamic` is the sole standalone verification benchmark in `thesis-core`. Use
`verify-heavy` to compare all verification modes (`verify-selfsigned`, `verify-issued`,
`verify-modeA-chain`, `verify-modeB-strict`, `verify-dynamic`, `verify-modeB-direct`).

thesis-core composition:
- Classical: `rsa3072`, `ecdsa-p256`, `ed25519`
- Pure-PQC: `mldsa65`, `slh-dsa-sha2-128f`, `slh-dsa-sha2-128s`
- Composite: `composite-rsa3072-mldsa65`, `composite-ed25519-mldsa65`, `composite-ed448-mldsa87`
- Hybrid: `hybrid-rsa3072-mldsa65`, `hybrid-ecdsa-p256-mldsa65`, `hybrid-ed25519-mldsa65`
- Dual: `dual-classical-primary`, `dual-pqc-primary`

**Dual / RFC 9763:** Dual configs (`dual-classical-primary`, `dual-pqc-primary`) are
included in `smoke`, `thesis-core`, and `full`.

Primary output in `measured_iterations.csv` and `summary.csv` uses **canonical operation names**
(`sign-leaf`, `csr`, `verify-issued`, `verify-modeA-chain`, `verify-modeB-strict`, `verify-dynamic`).
The `certificate_mode = dual-rfc9763` column distinguishes dual rows from single-algo rows.

For operations that require multiple RFC 9763 stages (e.g., `sign-leaf` = stage2-sign + stage4-sign),
the row contains the **sum of all stage wall times** and the **max of all stage RSS values**
for that iter_index. This makes dual rows directly comparable to single-algo rows in plots and tables.

Raw per-stage rows (`rfc9763-stage*`) go to `dual_step_breakdown.csv` — diagnostic only.

If a stage or pregen step fails, an explicit skip row is written to `skips.csv` with the reason.

### Quick start

```bash
# Smoke dry run (always do this first)
python3 benchmarks/run_macro_benchmarks.py --profile smoke --mode dry

# Dual-only dry run
python3 benchmarks/run_macro_benchmarks.py --category dual-rfc9763 --mode dry

# Thesis-core dry run
python3 benchmarks/run_macro_benchmarks.py --profile thesis-core --mode dry

# Thesis-core full run (main benchmark)
python3 benchmarks/run_macro_benchmarks.py --profile thesis-core

# Category slice (e.g. classical only)
python3 benchmarks/run_macro_benchmarks.py --profile thesis-core --category classical

# Single algo test
python3 benchmarks/run_macro_benchmarks.py --algos mldsa65 --ops keygen,cert --iter 10

# With CPU pinning (recommended on VM)
python3 benchmarks/run_macro_benchmarks.py --profile smoke --taskset-cpu 0

# Rebuild jar before run
python3 benchmarks/run_macro_benchmarks.py --profile smoke --rebuild
```

### Options

```
--profile        smoke | thesis-core | slh-heavy | composite-heavy | hybrid-heavy | verify-heavy | full
--mode           stable (default) | dry
--jar            path to pqcli-0.1.0.jar
--out            results output directory
--staging        staging directory for temp artifacts
--tmpdir         temp directory for timev/perf files
--ops            comma-separated op subset
--algos          comma-separated algo tag subset
--category       comma-separated category subset (classical|pure-pqc|composite|hybrid|dual-rfc9763)
--iter           override iteration count
--warmup         override warmup count (default 5)
--taskset-cpu    CPU affinity list (e.g. "0")
--no-perf        disable software perf stat
--rebuild        run mvn clean package before benchmarking
--allow-version-mismatch  skip BC version gate
```

### Output

```
benchmarks/results/<YYYYMMDD_HHMMSS>/
  metadata.json
  macro/
    raw_iterations.jsonl
    measured_iterations.csv     # consolidated: all algos/ops, timing+memory. Dual rows use canonical op names.
    sizing_measurements.csv     # consolidated: all algos/ops, artifact size fields only
    dual_step_breakdown.csv     # RFC 9763 raw stage rows (diagnostic only; NOT in measured_iterations.csv)
    summary.csv                 # generated by aggregate_results.py; includes mean/median/stddev/q1/q3/p95/p99
    sizes_summary.csv
    skips.csv
    <algo_tag>/<op>/
      command.log
      iterations.csv
      warmup_iterations.csv
      stdout/<iter>.log
      stderr/<iter>.log
      timev/<iter>.txt
      [perf/<iter>.txt]
```

## Micro benchmark (run_micro_benchmarks.py)

Measures JMH-internal operation time (pre-warmed JVM, no startup overhead)
and per-(algo x op) peak RSS via /usr/bin/time -v.

```bash
# Dry run
python3 benchmarks/run_micro_benchmarks.py --mode dry

# Layer A only (primitive crypto)
python3 benchmarks/run_micro_benchmarks.py --filter LayerA

# Stable run (100 rows per algo x op)
python3 benchmarks/run_micro_benchmarks.py --mode stable
```

## Aggregation (aggregate_results.py)

Run automatically after each benchmark. Run manually on existing results:

```bash
python3 benchmarks/aggregate_results.py benchmarks/results/<timestamp>/macro
python3 benchmarks/aggregate_results.py benchmarks/results/<timestamp>/micro
```

## Measurement notes

- **cli_wall_time_ms**: GNU time wall clock including JVM startup. Not pure operation time.
- **jmh_score_ms**: JMH internal pre-warmed operation time. Excludes startup.
- **peak_rss_kb**: Maximum resident set size from GNU time.
- **task_clock, cpu_clock**: From software perf stat if available; null otherwise.
- **DER sizes**: computed by base64-decoding PEM blocks (not inferred from file size).
- **Hardware PMU counters** (cycles, instructions, branches, cache): not used. VM has no PMU.

---

## OpenSSL benchmark (run_openssl_benchmarks.py)

Benchmarks the locally configured OpenSSL CLI for classical and (where available) pure-PQC
algorithm workloads. Results are kept separate from pqcli macro and JMH micro results and
stored under `results/<timestamp>/openssl/`.

**Important**: OpenSSL macro rows include native process startup (openssl CLI launch).
pqcli macro rows include JVM startup. Neither is overhead-free; the overheads differ in
kind and magnitude. Do **not** compare OpenSSL macro `wall_time_ms` to JMH `jmh_score_ms`.

### OpenSSL executable selection

1. `--openssl-bin <path>` (CLI override) takes highest priority.
2. `OQS_OPENSSL` environment variable, if set.
3. Fallback: `openssl` on PATH.

`OPENSSL_MODULES` is read from the environment (or `--openssl-modules`) and preserved in
subprocess environments when loading oqsprovider. All effective values are recorded in
`openssl/metadata.json`.

### Supported algorithms

**Classical** (always benchmarked when available):
- `rsa2048`, `rsa3072`, `rsa4096`
- `ecdsa-p256`, `ecdsa-p384`
- `ed25519`, `ed448`

RSA hash flags match pqcli: RSA:2048 → SHA-256, RSA:3072 → SHA-384, RSA:4096 → SHA-512.

**Pure PQC** (benchmarked only when a pure equivalent is detected and probed):
- ML-DSA: `mldsa44`, `mldsa65`, `mldsa87` (native OpenSSL 3.5+ preferred; oqsprovider pure names as fallback)
- SLH-DSA SHA2: `slh-dsa-sha2-{128s,128f,192s,192f,256s,256f}`
- SLH-DSA SHAKE: `slh-dsa-shake-{128s,128f,192s,192f,256s,256f}`

Pure PQC availability is detected at startup via `openssl list -signature-algorithms` and a
lightweight `genpkey` probe using the same provider flags as benchmark execution. If a pure
equivalent is not available, explicit skip rows are written to `openssl/skips.csv`.

**Not benchmarked** (explicit skips with documented reasons):
- Composite algorithms (BC PKIX-arc OIDs not supported by OpenSSL)
- Hybrid alternate-signature certificates (OIDs 2.5.29.72/73/74 not supported by OpenSSL)
- oqsprovider combined/hybrid names (`p256_mldsa44`, `rsa3072_mldsa44`, etc.) — these are
  **not** equivalent to pqcli pure ML-DSA, pqcli hybrid, or pqcli composite
- Falcon / MAYO / CROSS / OV / SNOVA
- KEM / ML-KEM algorithms
- RFC 9763 dual workflows
- `verify-modeA-chain` (no OpenSSL CLI equivalent for raw per-link verification)
- `workflow-2tier`, `workflow-3tier`
- JMH/micro operations

### Supported operations

All 8 OpenSSL operations use `genpkey + req -key` (not `-newkey`) for key generation
inside the timed boundary:

| Operation | Timed scope | pqcli equivalent | Comparability |
|-----------|-------------|-----------------|---------------|
| `keygen` | `genpkey` + `pkey -pubout` | `pqcli key` | Partial |
| `cert` | `genpkey` + `req -x509 -key` | `pqcli cert` | Partial |
| `csr` | `genpkey` + `req -new -key` | `pqcli csr` | Partial |
| `sign-leaf` | `openssl x509 -req` (pre-gen inputs) | `pqcli sign --profile leaf` | Partial* |
| `sign-intermediate-ca` | `openssl x509 -req` (pre-gen inputs) | `pqcli sign --profile intermediate-ca` | Partial* |
| `verify-issued` | `openssl verify -CAfile ca leaf` | `pqcli verify -CAfile` | Partial |
| `verify-modeB-dynamic` | `openssl verify -CAfile root -untrusted int leaf` | `pqcli verify -untrusted` | Partial |
| `verify-modeB-direct` | `openssl verify -CAfile root leaf` | `pqcli verify -trust` | Partial |

\* `pqcli sign` verifies CSR proof-of-possession before issuance; `openssl x509 -req` does not.
sign-leaf and sign-intermediate-ca are therefore partial comparisons: OpenSSL omits the PoP
verification step that pqcli performs.

### OpenSSL profiles

| Profile | Algorithms | Operations | Default iter | Notes |
|---------|-----------|------------|-------------|-------|
| `openssl-thesis-core` (default) | thesis-core classical + pure-PQC | all 8 ops | 100 | Matches pqcli thesis-core scope; PQC skipped if unavailable |
| `openssl-smoke` | rsa3072, ecdsa-p256, ed25519 | keygen, cert, csr, sign-leaf, verify-issued | 3 | Classical only; no PQC skips |
| `openssl-thesis-core-classical` | thesis-core classical tags only | all 8 ops | 100 | — |
| `openssl-thesis-core-pure-pqc` | thesis-core pure-PQC tags only | all 8 ops | 100 | All skipped if PQC unavailable |
| `openssl-full` | all classical + all pure-PQC variants | all 8 ops | 100 | Opt-in extended run |

thesis-core algorithm tags mirror `benchmark_config.py` `_TC_CLASSICAL_TAGS` and
`_TC_PQC_TAGS` (pure-pqc subset).

### Quick start

```bash
# Capability detection (no benchmarking)
python3 benchmarks/run_openssl_benchmarks.py --detect-only

# Smoke run — classical only, 3 iterations
python3 benchmarks/run_openssl_benchmarks.py --profile openssl-smoke --mode dry

# Thesis-core run (default; PQC skipped if unavailable)
python3 benchmarks/run_openssl_benchmarks.py --profile openssl-thesis-core --mode dry

# Full measured run
python3 benchmarks/run_openssl_benchmarks.py --profile openssl-thesis-core

# Classical-only baseline
python3 benchmarks/run_openssl_benchmarks.py --profile openssl-thesis-core-classical

# Opt-in extended run
python3 benchmarks/run_openssl_benchmarks.py --profile openssl-full

# With explicit OQS provider
OQS_OPENSSL=/usr/bin/openssl OPENSSL_MODULES=/opt/oqs/lib \
  python3 benchmarks/run_openssl_benchmarks.py --profile openssl-thesis-core

# Single algo slice
python3 benchmarks/run_openssl_benchmarks.py --algos rsa3072 --ops keygen,cert --iter 10

# Aggregate an existing result
python3 benchmarks/aggregate_results.py benchmarks/results/<timestamp>/openssl
```

### Result structure

```
benchmarks/results/<timestamp>/openssl/
  metadata.json          — OpenSSL capabilities, provider state, run parameters
  skips.csv              — Algorithms/operations skipped with explicit reasons
  measured_iterations.csv
  sizing_measurements.csv
  summary.csv            — Aggregated stats (generated after run)
  sizes_summary.csv
  config/
    openssl-ca.cnf       — CA certificate config (preserved for reproducibility)
    openssl-leaf.cnf
    openssl-int.cnf
  <algo_tag>/<op>/
    command.log          — Shell script or command that was timed
    iterations.csv
    warmup_iterations.csv
    stdout/<iter>.log
    stderr/<iter>.log
    timev/<iter>.txt
```

---

## Deprecated scripts

The following old scripts remain for reference but are not used by the new harness:
- `bench.sh` — replaced by `run_macro_benchmarks.py`
- `parse.py` — replaced by `aggregate_results.py`
- `micro/run_micro.sh` — replaced by `run_micro_benchmarks.py`
