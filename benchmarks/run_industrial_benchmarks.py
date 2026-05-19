#!/usr/bin/env python3
"""
run_industrial_benchmarks.py — PQCLI industrial (warmed-JVM) benchmark orchestrator

One JVM per (algo_tag, operation). Bouncy Castle providers initialized once before
warmup. Measured iterations call PKI logic directly via direct-core static methods
(no CLI argument parsing per iteration). File-backed I/O included.

Timing: System.nanoTime() per iteration (elapsed_ms in measured_iterations.csv).
Process-level peak RSS from /usr/bin/time -v in process_metrics.csv.

Usage:
  python3 run_industrial_benchmarks.py [options]

Key options:
  --profile    industrial-smoke | industrial-thesis-core | industrial-full
  --mode       dry | stable
  --iter N     measured iterations override
  --warmup N   warmup iterations override
  --jar        path to pqcli JAR (default: auto-detect)
  --out        results root      (default: results/<timestamp>/industrial)
  --staging    staging root      (default: .staging/<timestamp>/industrial)
  --taskset-cpu  CPU affinity (e.g. "0")
  --algos      comma-separated algo tag subset
  --ops        comma-separated op subset
  --no-perf    disable perf stat
  --verbose
"""

from __future__ import annotations
import argparse
import base64
import csv
import hashlib
import json
import logging
import os
import re
import shutil
import socket
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

SCRIPT_DIR      = Path(__file__).resolve().parent
PROJECT_DIR     = SCRIPT_DIR.parent
PQCLI_DIR       = PROJECT_DIR / 'pqcli-main'
BENCH_JAVA_SRC  = SCRIPT_DIR / 'java' / 'pqcli' / 'IndustrialBenchmarkRunner.java'
BENCH_BUILD_DIR = SCRIPT_DIR / '.build' / 'industrial'

sys.path.insert(0, str(SCRIPT_DIR))
from benchmark_config import (
    AlgoConfig, INDUSTRIAL_PROFILES, DEFAULT_JVM_FLAGS,
    EXPECTED_BC_VERSION, WARMUP_ITERATIONS, MEASURED_ITERATIONS, DRY_ITERATIONS,
)

log = logging.getLogger('industrial')


# ── GNU time parsing (reused from macro runner) ───────────────────────────────

def _parse_elapsed_ms(text: str) -> Optional[float]:
    m = re.search(r'Elapsed.*?:\s+(?:(\d+):)?(\d+):(\d+(?:\.\d+)?)', text)
    if not m:
        return None
    h = int(m.group(1) or 0)
    return (h * 3600 + int(m.group(2)) * 60 + float(m.group(3))) * 1000.0

def _parse_rss_kb(text: str) -> Optional[int]:
    m = re.search(r'Maximum resident set size.*?:\s+(\d+)', text)
    return int(m.group(1)) if m else None

def _parse_user_s(text: str) -> Optional[float]:
    m = re.search(r'User time.*?:\s+(\d+(?:\.\d+)?)', text)
    return float(m.group(1)) if m else None

def _parse_sys_s(text: str) -> Optional[float]:
    m = re.search(r'System time.*?:\s+(\d+(?:\.\d+)?)', text)
    return float(m.group(1)) if m else None

def _parse_cpu_pct(text: str) -> Optional[float]:
    m = re.search(r'Percent of CPU.*?:\s+(\d+)%', text)
    return float(m.group(1)) if m else None

def _parse_ctx_switches(text: str) -> Optional[int]:
    vol   = re.search(r'Voluntary context.*?:\s+(\d+)', text)
    invol = re.search(r'Involuntary context.*?:\s+(\d+)', text)
    return int(vol.group(1)) + int(invol.group(1)) if vol and invol else None

def _parse_page_faults(text: str) -> Optional[int]:
    m = re.search(r'Minor \(reclaiming.*?:\s+(\d+)', text)
    return int(m.group(1)) if m else None


# ── CSV field definitions ──────────────────────────────────────────────────────

INDUSTRIAL_MEASURED_FIELDS = [
    'run_id', 'timestamp_utc', 'suite', 'tool', 'profile', 'mode',
    'algo_tag', 'algorithm', 'certificate_mode', 'primitive_standard_scope', 'operation',
    'iter_index', 'warmup', 'success', 'elapsed_ms', 'error', 'execution_model',
    'stdout_path', 'stderr_path',
]

PROCESS_METRICS_FIELDS = [
    'run_id', 'timestamp_utc', 'suite', 'tool', 'profile', 'mode',
    'algo_tag', 'operation',
    'process_wall_time_ms', 'peak_rss_kb', 'user_cpu_s', 'sys_cpu_s',
    'cpu_pct', 'context_switches', 'page_faults',
    'exit_code', 'timev_path', 'stdout_path', 'stderr_path',
]

SIZING_FIELDS = [
    'run_id', 'timestamp_utc', 'suite', 'profile', 'mode', 'algo_tag', 'operation',
    'out_pub_key_pem_bytes', 'out_pub_key_der_bytes',
    'out_priv_key_pem_bytes', 'out_priv_key_der_bytes',
    'out_alt_pub_pem_bytes', 'out_alt_pub_der_bytes',
    'out_alt_priv_pem_bytes', 'out_alt_priv_der_bytes',
    'out_cert_pem_bytes', 'out_cert_der_bytes',
    'out_csr_pem_bytes', 'out_csr_der_bytes',
    'out_int_cert_pem_bytes', 'out_int_cert_der_bytes',
    'out_leaf_cert_pem_bytes', 'out_leaf_cert_der_bytes',
    'out_chain_total_pem_bytes', 'out_chain_total_der_bytes',
]

SIZES_CSV_COLUMNS = [
    'out_pub_key_pem_bytes', 'out_pub_key_der_bytes',
    'out_priv_key_pem_bytes', 'out_priv_key_der_bytes',
    'out_alt_pub_pem_bytes', 'out_alt_pub_der_bytes',
    'out_alt_priv_pem_bytes', 'out_alt_priv_der_bytes',
    'out_cert_pem_bytes', 'out_cert_der_bytes',
    'out_csr_pem_bytes', 'out_csr_der_bytes',
    'out_int_cert_pem_bytes', 'out_int_cert_der_bytes',
    'out_leaf_cert_pem_bytes', 'out_leaf_cert_der_bytes',
    'out_chain_total_pem_bytes', 'out_chain_total_der_bytes',
]

SKIPS_FIELDS = ['run_id', 'algo_tag', 'operation', 'exit_code', 'reason']


# ── Helpers ────────────────────────────────────────────────────────────────────

def _ts() -> str:
    return time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())

def _fstr(v) -> str:
    if v is None:
        return ''
    if isinstance(v, float):
        return str(round(v, 4))
    return str(v)

def jar_sha256(jar: Path) -> str:
    h = hashlib.sha256()
    with open(jar, 'rb') as f:
        for chunk in iter(lambda: f.read(65536), b''):
            h.update(chunk)
    return h.hexdigest()

def detect_java_version() -> str:
    try:
        r = subprocess.run(['java', '-version'], capture_output=True, text=True)
        return (r.stderr or r.stdout).splitlines()[0].strip()
    except Exception:
        return 'unknown'

def detect_bc_version(pqcli_dir: Path) -> Optional[str]:
    pom = pqcli_dir / 'pom.xml'
    if not pom.exists():
        return None
    text = pom.read_text(errors='replace')
    m = re.search(r'bcprov-jdk18on[\s\S]{0,300}?<version>([^<]+)</version>', text)
    return m.group(1).strip() if m else None

def collect_system_metadata() -> dict:
    meta: dict = {}
    try: meta['hostname'] = socket.gethostname()
    except Exception: meta['hostname'] = 'unknown'
    try: meta['os'] = subprocess.check_output(['uname', '-srv'], text=True).strip()
    except Exception: meta['os'] = 'unknown'
    try:
        meta['cpu_model'] = subprocess.check_output(
            ['grep', '-m1', 'model name', '/proc/cpuinfo'], text=True
        ).strip().split(':', 1)[-1].strip()
    except Exception: meta['cpu_model'] = 'unknown'
    try: meta['cpu_cores_logical'] = int(subprocess.check_output(['nproc'], text=True).strip())
    except Exception: meta['cpu_cores_logical'] = 'unknown'
    try:
        meta['ram_kb'] = int(
            subprocess.check_output(['grep', 'MemTotal', '/proc/meminfo'], text=True).split()[1])
    except Exception: meta['ram_kb'] = 'unknown'
    for path, key in [
        ('/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor', 'cpu_governor'),
        ('/sys/devices/system/cpu/smt/active', 'smt_active'),
    ]:
        try: meta[key] = Path(path).read_text().strip()
        except Exception: meta[key] = 'unknown'
    meta['turbo_boost'] = 'not_detectable'
    return meta

def check_timev(tmpdir: Path) -> bool:
    f = tmpdir / '_tv_check.txt'
    try:
        r = subprocess.run(['/usr/bin/time', '-v', '--output', str(f), 'true'],
                           capture_output=True)
        if r.returncode != 0: return False
        text = f.read_text(errors='replace') if f.exists() else ''
        return 'Maximum resident set size' in text
    except Exception: return False
    finally: f.unlink(missing_ok=True)

def auto_detect_jar() -> Optional[Path]:
    candidate = PQCLI_DIR / 'target' / 'pqcli-0.1.0.jar'
    return candidate if candidate.exists() else None


def compile_bench_helper(jar: Path, build_dir: Path) -> bool:
    """Compile the benchmark-side Java helper against the pqcli JAR."""
    build_dir.mkdir(parents=True, exist_ok=True)
    r = subprocess.run(
        ['javac', '-cp', str(jar), '-d', str(build_dir), str(BENCH_JAVA_SRC)],
        capture_output=True, text=True,
    )
    if r.returncode != 0:
        log.error('Benchmark helper compile failed:\n%s', r.stderr)
        return False
    log.info('Benchmark helper compiled → %s', build_dir)
    return True


# ── Runner invocation ──────────────────────────────────────────────────────────

@dataclass
class ProcessResult:
    exit_code: int
    process_wall_time_ms: Optional[float]
    peak_rss_kb: Optional[int]
    user_cpu_s: Optional[float]
    sys_cpu_s: Optional[float]
    cpu_pct: Optional[float]
    context_switches: Optional[int]
    page_faults: Optional[int]
    stdout_path: Optional[Path]
    stderr_path: Optional[Path]
    timev_path: Optional[Path]


def run_industrial_process(
    jar: Path,
    jvm_flags: list[str],
    algo: str,
    algo_tag: str,
    op: str,
    warmup: int,
    iterations: int,
    out_dir: Path,
    staging_dir: Path,
    log_dir: Path,
    taskset_cpu: Optional[str],
    timeout_s: int = 1800,
) -> ProcessResult:
    """Launch one IndustrialBenchmarkRunner JVM process wrapped with /usr/bin/time -v."""
    import tempfile
    tmpdir = log_dir / 'timev'
    tmpdir.mkdir(parents=True, exist_ok=True)
    timev_file = tmpdir / f'timev_{algo_tag}_{op}.txt'

    java_cmd = ['java'] + jvm_flags + [
        '-cp', f'{jar}:{BENCH_BUILD_DIR}', 'pqcli.IndustrialBenchmarkRunner',
        '--algo', algo,
        '--algo-tag', algo_tag,
        '--operation', op,
        '--warmup', str(warmup),
        '--iterations', str(iterations),
        '--out', str(out_dir),
        '--staging', str(staging_dir),
    ]

    wrapped = []
    if taskset_cpu:
        wrapped += ['taskset', '-c', taskset_cpu]
    wrapped += ['/usr/bin/time', '-v', '--output', str(timev_file)]
    wrapped += java_cmd

    stdout_file = log_dir / f'stdout_{algo_tag}_{op}.log'
    stderr_file = log_dir / f'stderr_{algo_tag}_{op}.log'

    exit_code = -1
    with open(stdout_file, 'wb') as fout, open(stderr_file, 'wb') as ferr:
        try:
            proc = subprocess.run(wrapped, stdout=fout, stderr=ferr, timeout=timeout_s)
            exit_code = proc.returncode
        except subprocess.TimeoutExpired:
            log.warning('Timeout after %ds for %s/%s', timeout_s, algo_tag, op)

    timev_text = timev_file.read_text(errors='replace') if timev_file.exists() else ''

    return ProcessResult(
        exit_code=exit_code,
        process_wall_time_ms=_parse_elapsed_ms(timev_text),
        peak_rss_kb=_parse_rss_kb(timev_text),
        user_cpu_s=_parse_user_s(timev_text),
        sys_cpu_s=_parse_sys_s(timev_text),
        cpu_pct=_parse_cpu_pct(timev_text),
        context_switches=_parse_ctx_switches(timev_text),
        page_faults=_parse_page_faults(timev_text),
        stdout_path=stdout_file,
        stderr_path=stderr_file,
        timev_path=timev_file if timev_file.exists() else None,
    )


# ── CSV collection ─────────────────────────────────────────────────────────────

def collect_per_op_iterations(op_dir: Path, algo_cfg: AlgoConfig, op: str,
                               run_id: str, profile: str, mode: str) -> list[dict]:
    """Read per-op iterations.csv and augment with run-level metadata."""
    csv_path = op_dir / 'iterations.csv'
    if not csv_path.exists():
        return []
    rows = []
    with open(csv_path, newline='') as f:
        for row in csv.DictReader(f):
            rows.append({
                'run_id': run_id,
                'timestamp_utc': _ts(),
                'suite': 'industrial',
                'tool': 'pqcli',
                'profile': profile,
                'mode': mode,
                'algo_tag': algo_cfg.tag,
                'algorithm': algo_cfg.cli_syntax,
                'certificate_mode': algo_cfg.certificate_mode,
                'primitive_standard_scope': algo_cfg.primitive_standard_scope,
                'operation': op,
                'iter_index': row.get('iter_index', ''),
                'warmup': '0',
                'success': row.get('success', ''),
                'elapsed_ms': row.get('elapsed_ms', ''),
                'error': row.get('error', ''),
                'execution_model': row.get('execution_model', ''),
                'stdout_path': str(op_dir / f'stdout_{algo_cfg.tag}_{op}.log'),
                'stderr_path': str(op_dir / f'stderr_{algo_cfg.tag}_{op}.log'),
            })
    return rows


def collect_per_op_warmup(op_dir: Path, algo_cfg: AlgoConfig, op: str,
                           run_id: str, profile: str, mode: str) -> list[dict]:
    csv_path = op_dir / 'warmup_iterations.csv'
    if not csv_path.exists():
        return []
    rows = []
    with open(csv_path, newline='') as f:
        for row in csv.DictReader(f):
            rows.append({
                'run_id': run_id, 'timestamp_utc': _ts(),
                'suite': 'industrial', 'tool': 'pqcli',
                'profile': profile, 'mode': mode,
                'algo_tag': algo_cfg.tag, 'algorithm': algo_cfg.cli_syntax,
                'certificate_mode': algo_cfg.certificate_mode,
                'primitive_standard_scope': algo_cfg.primitive_standard_scope,
                'operation': op,
                'iter_index': row.get('iter_index', ''),
                'warmup': '1',
                'success': row.get('success', ''),
                'elapsed_ms': row.get('elapsed_ms', ''),
                'error': row.get('error', ''),
                'execution_model': row.get('execution_model', ''),
                'stdout_path': '', 'stderr_path': '',
            })
    return rows


def collect_sizes(op_dir: Path, algo_cfg: AlgoConfig, op: str,
                  run_id: str, profile: str, mode: str) -> Optional[dict]:
    sizes_path = op_dir / 'sizes.csv'
    if not sizes_path.exists():
        return None
    with open(sizes_path, newline='') as f:
        reader = csv.DictReader(f)
        row = next(reader, None)
    if row is None:
        return None
    result = {
        'run_id': run_id, 'timestamp_utc': _ts(),
        'suite': 'industrial', 'profile': profile, 'mode': mode,
        'algo_tag': algo_cfg.tag, 'operation': op,
    }
    for col in SIZES_CSV_COLUMNS:
        result[col] = row.get(col, '0')
    return result


# ── Main orchestration ─────────────────────────────────────────────────────────

def run(args) -> None:
    profile_name = args.profile
    if profile_name not in INDUSTRIAL_PROFILES:
        log.error('Unknown industrial profile: %s. Available: %s',
                  profile_name, list(INDUSTRIAL_PROFILES.keys()))
        sys.exit(1)

    profile = INDUSTRIAL_PROFILES[profile_name]
    mode = args.mode

    iters   = args.iter   if args.iter   is not None else profile['iterations']
    warmup  = args.warmup if args.warmup is not None else profile['warmup']

    if mode == 'dry':
        iters  = args.iter   if args.iter   is not None else DRY_ITERATIONS
        warmup = args.warmup if args.warmup is not None else 2

    run_id = time.strftime('%Y%m%d_%H%M%S')

    # Paths
    out_root     = Path(args.out)     if args.out     else SCRIPT_DIR / 'results' / run_id / 'industrial'
    staging_root = Path(args.staging) if args.staging else SCRIPT_DIR / '.staging' / run_id / 'industrial'
    out_root.mkdir(parents=True, exist_ok=True)
    staging_root.mkdir(parents=True, exist_ok=True)

    # JAR
    jar = Path(args.jar) if args.jar else auto_detect_jar()
    if not jar or not jar.exists():
        log.error('JAR not found. Build with mvn clean package or pass --jar.')
        sys.exit(1)

    jvm_flags = DEFAULT_JVM_FLAGS

    # Compile benchmark helper
    if not compile_bench_helper(jar, BENCH_BUILD_DIR):
        log.error('Cannot continue without benchmark helper.')
        sys.exit(1)

    # Pre-flight
    if not check_timev(staging_root):
        log.warning('/usr/bin/time -v not available — process metrics will be empty')

    # Algo/op filtering
    algo_filter = set(args.algos.split(',')) if args.algos else None
    op_filter   = set(args.ops.split(','))   if args.ops   else None

    single_algos = profile['single_algos']
    ops          = profile['ops']

    if algo_filter:
        single_algos = [a for a in single_algos if a.tag in algo_filter]
    if op_filter:
        ops = [o for o in ops if o in op_filter]

    log.info('Industrial benchmark: profile=%s mode=%s iters=%d warmup=%d',
             profile_name, mode, iters, warmup)
    log.info('  algos=%d ops=%d jar=%s', len(single_algos), len(ops), jar)

    # Open root CSV writers
    meas_path  = out_root / 'measured_iterations.csv'
    warm_path  = out_root / 'warmup_iterations.csv'
    sizes_path = out_root / 'sizing_measurements.csv'
    proc_path  = out_root / 'process_metrics.csv'
    skips_path = out_root / 'skips.csv'

    meas_f  = open(meas_path,  'w', newline='')
    warm_f  = open(warm_path,  'w', newline='')
    sizes_f = open(sizes_path, 'w', newline='')
    proc_f  = open(proc_path,  'w', newline='')
    skips_f = None
    skips_w = None

    meas_w  = csv.DictWriter(meas_f,  fieldnames=INDUSTRIAL_MEASURED_FIELDS, extrasaction='ignore')
    warm_w  = csv.DictWriter(warm_f,  fieldnames=INDUSTRIAL_MEASURED_FIELDS, extrasaction='ignore')
    sizes_w = csv.DictWriter(sizes_f, fieldnames=SIZING_FIELDS, extrasaction='ignore')
    proc_w  = csv.DictWriter(proc_f,  fieldnames=PROCESS_METRICS_FIELDS, extrasaction='ignore')
    meas_w.writeheader()
    warm_w.writeheader()
    sizes_w.writeheader()
    proc_w.writeheader()

    total_algos = len(single_algos)
    total_ops   = len(ops)

    try:
        for ai, cfg in enumerate(single_algos):
            log.info('── [%d/%d] %s (%s) ──', ai+1, total_algos, cfg.tag, cfg.cli_syntax)

            for oi, op in enumerate(ops):
                if op not in cfg.applicable_ops:
                    log.debug('  skip %s/%s (not in applicable_ops)', cfg.tag, op)
                    continue

                log.info('  [op %d/%d] %s/%s', oi+1, total_ops, cfg.tag, op)

                op_out     = out_root     / cfg.tag / op
                op_staging = staging_root / cfg.tag / op
                op_out.mkdir(parents=True, exist_ok=True)
                op_staging.mkdir(parents=True, exist_ok=True)

                proc = run_industrial_process(
                    jar=jar,
                    jvm_flags=jvm_flags,
                    algo=cfg.cli_syntax,
                    algo_tag=cfg.tag,
                    op=op,
                    warmup=warmup,
                    iterations=iters,
                    out_dir=op_out,
                    staging_dir=op_staging,
                    log_dir=op_out,
                    taskset_cpu=args.taskset_cpu,
                )

                # Process metrics row
                proc_row = {
                    'run_id': run_id, 'timestamp_utc': _ts(),
                    'suite': 'industrial', 'tool': 'pqcli',
                    'profile': profile_name, 'mode': mode,
                    'algo_tag': cfg.tag, 'operation': op,
                    'process_wall_time_ms': _fstr(proc.process_wall_time_ms),
                    'peak_rss_kb':          _fstr(proc.peak_rss_kb),
                    'user_cpu_s':           _fstr(proc.user_cpu_s),
                    'sys_cpu_s':            _fstr(proc.sys_cpu_s),
                    'cpu_pct':              _fstr(proc.cpu_pct),
                    'context_switches':     _fstr(proc.context_switches),
                    'page_faults':          _fstr(proc.page_faults),
                    'exit_code':            proc.exit_code,
                    'timev_path':           str(proc.timev_path) if proc.timev_path else '',
                    'stdout_path':          str(proc.stdout_path) if proc.stdout_path else '',
                    'stderr_path':          str(proc.stderr_path) if proc.stderr_path else '',
                }
                proc_w.writerow(proc_row)
                proc_f.flush()

                if proc.exit_code != 0:
                    log.warning('  [FAIL] %s/%s exited %d', cfg.tag, op, proc.exit_code)
                    if skips_f is None:
                        skips_f = open(skips_path, 'w', newline='')
                        skips_w = csv.DictWriter(skips_f, fieldnames=SKIPS_FIELDS, extrasaction='ignore')
                        skips_w.writeheader()
                    skips_w.writerow({
                        'run_id': run_id, 'algo_tag': cfg.tag, 'operation': op,
                        'exit_code': proc.exit_code,
                        'reason': f'runner exited {proc.exit_code}',
                    })
                    skips_f.flush()
                    continue

                # Collect per-op CSVs → root CSVs
                for row in collect_per_op_iterations(op_out, cfg, op, run_id, profile_name, mode):
                    meas_w.writerow(row)
                for row in collect_per_op_warmup(op_out, cfg, op, run_id, profile_name, mode):
                    warm_w.writerow(row)
                meas_f.flush()
                warm_f.flush()

                sz = collect_sizes(op_out, cfg, op, run_id, profile_name, mode)
                if sz:
                    sizes_w.writerow(sz)
                    sizes_f.flush()

    finally:
        meas_f.close()
        warm_f.close()
        sizes_f.close()
        proc_f.close()
        if skips_f:
            skips_f.close()

    # Write metadata
    sys_meta = collect_system_metadata()
    bc_ver   = detect_bc_version(PQCLI_DIR)
    jar_hash = jar_sha256(jar)
    metadata = {
        'suite': 'industrial',
        'tool': 'pqcli',
        'run_id': run_id,
        'timestamp': _ts(),
        'runtime_type': 'jvm-long-lived',
        'startup_model': 'one JVM per (algo_tag, operation); providers initialized once before warmup',
        'provider_init_included_in_measured_iterations': False,
        'file_io_policy': 'file-backed',
        'timing_source': 'System.nanoTime',
        'timing_field': 'elapsed_ms',
        'execution_model': 'direct-core (promoted package-private static methods; no picocli per iteration)',
        'rss_scope': 'process_peak_per_algo_operation',
        'rss_note': ('peak_rss_kb covers the entire JVM process lifetime (pregen + warmup + measured iterations). '
                     'Per-iteration RSS is unavailable.'),
        'jvm_flags': jvm_flags,
        'profile': profile_name,
        'mode': mode,
        'iterations': iters,
        'warmup_iterations': warmup,
        'operation_name_note': (
            'Operation names are identical to the macro harness. '
            'verify-dynamic = Mode B dynamic path-building verification. '
            'No name mapping required.'
        ),
        'macro_comparability_note': (
            'elapsed_ms (industrial) measures amortized PKI operation cost with warm JVM and providers. '
            'cli_wall_time_ms (macro) measures total cold invocation cost including JVM startup and provider init. '
            'NOT directly comparable without context. Both are needed for a complete picture.'
        ),
        'micro_comparability_note': (
            'industrial measures full PKI operations with file I/O and certificate construction. '
            'JMH micro measures narrow primitives without file I/O. Different scope, not comparable.'
        ),
        'openssl_comparability_note': (
            'openssl uses native implementations; industrial uses BC JCE. '
            'Different runtime, different algorithm availability.'
        ),
        'workflow_semantics_note': (
            'industrial workflow ops run all steps sequentially in one JVM, one timing window. '
            'macro workflow ops launch a separate JVM process per step and sum wall times. '
            'Methodologically distinct.'
        ),
        'workflow_2tier_verify_step': 'modeA single-link (leaf vs CA cert.verify — matches macro)',
        'workflow_3tier_verify_step': 'modeB-strict (leaf chain -chain int -trust root — matches macro)',
        'verify_modeB_direct_note': (
            'verify-modeB-direct routes through verifyDynamic() with empty untrusted list '
            '(trust-alone path). Same VerifyCommand code path as CLI -trust alone.'
        ),
        'excluded_operations': 'RFC 9763 dual configs excluded (multi-stage multi-identity workflow)',
        'jar_path': str(jar),
        'jar_sha256': jar_hash,
        'bc_version': bc_ver,
        'java_version': detect_java_version(),
        **sys_meta,
    }
    (out_root / 'metadata.json').write_text(
        json.dumps(metadata, indent=2, default=str))

    log.info('Industrial benchmark complete.')
    log.info('  measured_iterations.csv: %s', meas_path)
    log.info('  process_metrics.csv:     %s', proc_path)
    log.info('  metadata.json:           %s', out_root / 'metadata.json')
    if skips_path.exists():
        log.info('  skips.csv:               %s', skips_path)
    print(f'\n[DONE] Results in: {out_root}')


# ── CLI ────────────────────────────────────────────────────────────────────────

def parse_args():
    p = argparse.ArgumentParser(description='PQCLI industrial (warmed-JVM) benchmarks')
    p.add_argument('--profile', default='industrial-thesis-core',
                   choices=list(INDUSTRIAL_PROFILES.keys()),
                   help='Benchmark profile')
    p.add_argument('--mode', default='stable', choices=['dry', 'stable'],
                   help='dry=few iters for sanity check, stable=full run')
    p.add_argument('--iter', type=int, default=None,
                   help='Override measured iteration count')
    p.add_argument('--warmup', type=int, default=None,
                   help='Override warmup iteration count')
    p.add_argument('--algos', default=None,
                   help='Comma-separated algo tag subset')
    p.add_argument('--ops', default=None,
                   help='Comma-separated op subset')
    p.add_argument('--jar', default=None,
                   help='Path to pqcli JAR')
    p.add_argument('--out', default=None,
                   help='Results root directory')
    p.add_argument('--staging', default=None,
                   help='Staging root directory')
    p.add_argument('--taskset-cpu', default=None,
                   help='CPU affinity for taskset (e.g. "0")')
    p.add_argument('--no-perf', action='store_true',
                   help='Disable perf stat (currently unused; reserved)')
    p.add_argument('--verbose', action='store_true',
                   help='Enable verbose logging')
    return p.parse_args()


def main():
    args = parse_args()
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format='%(asctime)s %(levelname)s %(message)s',
    )
    run(args)


if __name__ == '__main__':
    main()
