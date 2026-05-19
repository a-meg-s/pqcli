#!/usr/bin/env python3
"""
run_micro_benchmarks.py — PQCLI JMH micro benchmark orchestrator

Captures per-(algo x op) JMH timing and RSS.

For each (algo_tag, operation) pair:
  - Runs the JMH benchmark with -e <Class>.<op> -p algoTag=<tag>
  - Wraps the JMH process with /usr/bin/time -v to capture peak RSS
  - Records JMH score (pre-warmed op timing) and process RSS separately

Output:
  results/<timestamp>/micro/
    <algo_tag>/<op>/
      raw.json          — JMH JSON output
      timev.txt         — /usr/bin/time -v output
      iterations.csv    — one row per JMH measurement iteration
      jmh_rss.csv       — one row: jmh_peak_rss_kb, jmh_process_wall_time_s
    summary.csv         — aggregated stats

Usage:
  python3 run_micro_benchmarks.py [options]

Key options:
  --mode      dry | stable
  --filter    LayerA | LayerB | ".*"   (JMH -wi regex)
  --no-perf   disable software perf stat
  --jar       pqcli jar path (for mvn install)
  --out       output directory
"""

from __future__ import annotations
import argparse
import base64
import csv
import json
import logging
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Optional

SCRIPT_DIR  = Path(__file__).resolve().parent
PROJECT_DIR = SCRIPT_DIR.parent
PQCLI_DIR   = PROJECT_DIR / 'pqcli-main'
MICRO_DIR   = SCRIPT_DIR / 'micro'

sys.path.insert(0, str(SCRIPT_DIR))
from benchmark_config import DEFAULT_JVM_FLAGS, EXPECTED_BC_VERSION

log = logging.getLogger('micro')


# ── JMH configuration ─────────────────────────────────────────────────────────

DRY   = dict(forks=1,  warmup=2,  iters=5)
STABLE = dict(forks=5, warmup=10, iters=20)

# Layer A: primitive crypto (no CLI, no file I/O)
LAYER_A_CLASS  = 'pqcli.bench.LayerABenchmark'
LAYER_A_ALGOS  = ['rsa3072', 'ecdsa-p256', 'ed25519', 'mldsa65']
LAYER_A_OPS    = ['keygen', 'sign', 'verify']

# Layer B: PKI object operations
LAYER_B_CLASS  = 'pqcli.bench.LayerBBenchmark'
LAYER_B_ALGOS  = ['rsa3072', 'ecdsa-p256', 'ed25519', 'mldsa65',
                  'hybrid-rsa-mldsa65', 'composite-rsa-mldsa65']
LAYER_B_OPS    = ['csrBuild', 'certBuild', 'certVerify', 'chainVerify',
                  'derEncode', 'derDecode', 'pemEncode', 'pemDecode']
LAYER_B_OPS_HYBRID = LAYER_B_OPS + ['altVerify']


# ── GNU time parsing ───────────────────────────────────────────────────────────

def _parse_elapsed_ms(text: str) -> Optional[float]:
    m = re.search(r'Elapsed.*?:\s+(?:(\d+):)?(\d+):(\d+(?:\.\d+)?)', text)
    if not m:
        return None
    h = int(m.group(1) or 0)
    return (h * 3600 + int(m.group(2)) * 60 + float(m.group(3))) * 1000.0

def _parse_rss_kb(text: str) -> Optional[int]:
    m = re.search(r'Maximum resident set size.*?:\s+(\d+)', text)
    return int(m.group(1)) if m else None

def _parse_elapsed_s(text: str) -> Optional[float]:
    ms = _parse_elapsed_ms(text)
    return ms / 1000.0 if ms is not None else None


# ── JMH runner ────────────────────────────────────────────────────────────────

def run_jmh_selection(
    *,
    algo_tag: str,
    class_name: str,
    op: str,
    micro_jar: Path,
    out_dir: Path,
    jvm_flags: list[str],
    jmh_cfg: dict,
    taskset_cpu: Optional[str],
    tmpdir: Path,
) -> None:
    """
    Run JMH for a specific (algo_tag, op) selection, wrapped with /usr/bin/time -v.
    Records per-iteration JMH scores and process-level RSS.
    """
    sel_dir = out_dir / algo_tag / op
    sel_dir.mkdir(parents=True, exist_ok=True)

    raw_json = sel_dir / 'raw.json'
    timev_file = tmpdir / f'timev_{algo_tag}_{op}_{time.monotonic_ns()}.txt'

    full_cmd = []
    if taskset_cpu:
        full_cmd += ['taskset', '-c', taskset_cpu]
    full_cmd += ['/usr/bin/time', '-v', '--output', str(timev_file)]
    full_cmd += ['java'] + jvm_flags + ['-jar', str(micro_jar)]
    full_cmd += [
        '-e', f'{class_name}.{op}',
        '-p', f'algoTag={algo_tag}',
        '-wi', str(jmh_cfg['warmup']),
        '-i',  str(jmh_cfg['iters']),
        '-f',  str(jmh_cfg['forks']),
        '-bm', 'avgt',
        '-tu', 'ms',
        '-rf', 'json',
        '-rff', str(raw_json),
    ]

    log.info('[JMH] %s/%s/%s', class_name.split('.')[-1], algo_tag, op)
    stdout_log = sel_dir / 'jmh_stdout.log'
    stderr_log = sel_dir / 'jmh_stderr.log'

    with open(stdout_log, 'wb') as fout, open(stderr_log, 'wb') as ferr:
        proc = subprocess.run(full_cmd, stdout=fout, stderr=ferr, timeout=3600)

    # Persist timev
    timev_dest = sel_dir / 'timev.txt'
    if timev_file.exists():
        shutil.move(str(timev_file), str(timev_dest))
    timev_text = timev_dest.read_text(errors='replace') if timev_dest.exists() else ''

    peak_rss_kb   = _parse_rss_kb(timev_text)
    process_wall_s = _parse_elapsed_s(timev_text)

    # Write jmh_rss.csv
    with open(sel_dir / 'jmh_rss.csv', 'w', newline='') as f:
        w = csv.DictWriter(f, fieldnames=['algo_tag', 'operation',
                                          'jmh_peak_rss_kb', 'jmh_process_wall_time_s'])
        w.writeheader()
        w.writerow({
            'algo_tag': algo_tag, 'operation': op,
            'jmh_peak_rss_kb': peak_rss_kb if peak_rss_kb is not None else '',
            'jmh_process_wall_time_s': process_wall_s if process_wall_s is not None else '',
        })

    # Parse JMH JSON into iterations.csv
    # fork_index and measurement_iteration are zero-based (from enumerate).
    # jmh_error_ms is left blank: JMH rawData contains only raw scores;
    # error bounds are available only at aggregate level (primaryMetric.scoreError).
    iter_rows = []
    if raw_json.exists():
        try:
            jmh_data = json.loads(raw_json.read_text())
            for bench in jmh_data:
                bench_name  = bench.get('benchmark', '')
                bench_mode  = bench.get('mode', '')
                score_unit  = bench.get('primaryMetric', {}).get('scoreUnit', '')
                rawdata     = bench.get('primaryMetric', {}).get('rawData', [[]])
                global_idx  = 0
                for fork_idx, fork_data in enumerate(rawdata):
                    for meas_idx, score in enumerate(fork_data):
                        iter_rows.append({
                            'fork_index': fork_idx,
                            'measurement_iteration': meas_idx,
                            'iter_index': global_idx,
                            'jmh_score_ms': score,
                            'jmh_error_ms': '',
                            'benchmark': bench_name,
                            'benchmark_mode': bench_mode,
                            'score_unit': score_unit,
                        })
                        global_idx += 1
        except Exception as e:
            log.warning('Failed to parse JMH JSON for %s/%s: %s', algo_tag, op, e)

    _ITER_FIELDS = [
        'algo_tag', 'operation', 'fork_index', 'measurement_iteration', 'iter_index',
        'jmh_score_ms', 'jmh_error_ms', 'benchmark', 'benchmark_mode', 'score_unit',
    ]
    with open(sel_dir / 'iterations.csv', 'w', newline='') as f:
        w = csv.DictWriter(f, fieldnames=_ITER_FIELDS, extrasaction='ignore')
        w.writeheader()
        for row in iter_rows:
            w.writerow({'algo_tag': algo_tag, 'operation': op, **row})

    if proc.returncode != 0:
        log.warning('[JMH FAIL] %s/%s/%s: exit %d', class_name.split('.')[-1], algo_tag, op,
                    proc.returncode)
    else:
        log.info('[JMH OK]   %s/%s — %d measurement rows, RSS=%s KB',
                 algo_tag, op, len(iter_rows),
                 peak_rss_kb if peak_rss_kb is not None else 'N/A')


# ── Main ──────────────────────────────────────────────────────────────────────

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description='PQCLI JMH micro benchmark orchestrator')
    p.add_argument('--mode', default='stable', choices=['stable', 'dry'])
    p.add_argument('--filter', default='.*',
                   help='JMH benchmark class filter: LayerA, LayerB, or ".*" for all')
    p.add_argument('--jar', type=Path, default=None,
                   help='pqcli jar (used for mvn install; not the JMH jar)')
    p.add_argument('--out', type=Path, default=None)
    p.add_argument('--tmpdir', type=Path, default=None)
    p.add_argument('--taskset-cpu', default=None)
    p.add_argument('--no-perf', action='store_true')
    p.add_argument('--allow-version-mismatch', action='store_true')
    p.add_argument('--verbose', '-v', action='store_true')
    return p.parse_args()


def detect_bc_version(pqcli_dir: Path) -> Optional[str]:
    pom = pqcli_dir / 'pom.xml'
    if not pom.exists():
        return None
    text = pom.read_text(errors='replace')
    m = re.search(r'bcprov-jdk18on[\s\S]{0,200}?<version>([^<]+)</version>', text)
    return m.group(1).strip() if m else None


def main() -> int:
    args = parse_args()
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format='%(asctime)s %(levelname)s %(message)s', datefmt='%H:%M:%S')

    ts = time.strftime('%Y%m%d_%H%M%S')
    if args.out is None:
        args.out = SCRIPT_DIR / 'results' / ts
    if args.tmpdir is None:
        args.tmpdir = Path(tempfile.gettempdir())

    out_dir = args.out / 'micro'
    out_dir.mkdir(parents=True, exist_ok=True)

    jmh_cfg = DRY if args.mode == 'dry' else STABLE
    log.info('[MICRO] mode=%s forks=%d warmup=%d iters=%d',
             args.mode, jmh_cfg['forks'], jmh_cfg['warmup'], jmh_cfg['iters'])

    jvm_flags = os.environ.get('JAVA_OPTS', '').split() or DEFAULT_JVM_FLAGS

    # Step 1: BC version check
    bc = detect_bc_version(PQCLI_DIR)
    if bc != EXPECTED_BC_VERSION and not args.allow_version_mismatch:
        log.error('[PREFLIGHT] BC version mismatch: detected=%s expected=%s', bc, EXPECTED_BC_VERSION)
        return 1

    # Step 2: Install pqcli to local Maven repo
    log.info('[MICRO] Installing pqcli to local Maven repo...')
    r = subprocess.run(['mvn', 'install', '-q', '-DskipTests'], cwd=PQCLI_DIR)
    if r.returncode != 0:
        log.error('[MICRO] mvn install failed')
        return 1

    # Step 3: Build JMH jar
    log.info('[MICRO] Building JMH benchmark jar...')
    r = subprocess.run(['mvn', 'clean', 'package', '-q'], cwd=MICRO_DIR)
    if r.returncode != 0:
        log.error('[MICRO] mvn package (micro) failed')
        return 1
    micro_jar = MICRO_DIR / 'target' / 'pqcli-bench-micro.jar'
    if not micro_jar.exists():
        log.error('[MICRO] JMH jar not found: %s', micro_jar)
        return 1
    log.info('[MICRO] JMH jar: %s', micro_jar)

    # Step 4: Check timev
    timev_check = args.tmpdir / '_timev_micro_check.txt'
    try:
        r = subprocess.run(['/usr/bin/time', '-v', '--output', str(timev_check), 'true'],
                           capture_output=True)
        if r.returncode != 0:
            log.error('[PREFLIGHT] /usr/bin/time -v not functional')
            return 1
    finally:
        timev_check.unlink(missing_ok=True)

    # Write metadata
    meta = {
        'timestamp': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
        'mode': args.mode,
        'forks': jmh_cfg['forks'],
        'warmup_iters': jmh_cfg['warmup'],
        'meas_iters': jmh_cfg['iters'],
        'filter': args.filter,
        'jvm_flags': ' '.join(jvm_flags),
        'detected_bc_version': bc or 'unknown',
        'expected_bc_version': EXPECTED_BC_VERSION,
        'micro_rss_definition':
            'Peak RSS of full JMH process for this (algo x op), '
            'includes JVM startup and all forks',
        'jmh_score_definition':
            'JMH AverageTime score: pre-warmed operation time per invocation (ms)',
    }
    (args.out / 'metadata.json').write_text(json.dumps(meta, indent=2))

    # Step 5: Run benchmarks
    layer_a = args.filter in ('LayerA', '.*') or args.filter == 'pqcli.bench.LayerABenchmark'
    layer_b = args.filter in ('LayerB', '.*') or args.filter == 'pqcli.bench.LayerBBenchmark'

    if layer_a:
        log.info('[MICRO] Layer A: %d algos × %d ops', len(LAYER_A_ALGOS), len(LAYER_A_OPS))
        for algo in LAYER_A_ALGOS:
            for op in LAYER_A_OPS:
                run_jmh_selection(
                    algo_tag=algo, class_name=LAYER_A_CLASS, op=op,
                    micro_jar=micro_jar, out_dir=out_dir / 'LayerA',
                    jvm_flags=jvm_flags, jmh_cfg=jmh_cfg,
                    taskset_cpu=args.taskset_cpu, tmpdir=args.tmpdir)

    if layer_b:
        log.info('[MICRO] Layer B: %d algos × up to %d ops', len(LAYER_B_ALGOS), len(LAYER_B_OPS))
        for algo in LAYER_B_ALGOS:
            ops = LAYER_B_OPS_HYBRID if 'hybrid' in algo else LAYER_B_OPS
            for op in ops:
                run_jmh_selection(
                    algo_tag=algo, class_name=LAYER_B_CLASS, op=op,
                    micro_jar=micro_jar, out_dir=out_dir / 'LayerB',
                    jvm_flags=jvm_flags, jmh_cfg=jmh_cfg,
                    taskset_cpu=args.taskset_cpu, tmpdir=args.tmpdir)

    # Step 6: Aggregate
    aggregate_py = SCRIPT_DIR / 'aggregate_results.py'
    if aggregate_py.exists():
        log.info('[AGGREGATE] Running aggregate_results.py ...')
        subprocess.run([sys.executable, str(aggregate_py), str(out_dir)])

    log.info('━━━ Micro benchmark done ━━━')
    log.info('Results: %s', args.out)
    return 0


if __name__ == '__main__':
    sys.exit(main())
