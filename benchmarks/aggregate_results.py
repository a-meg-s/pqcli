#!/usr/bin/env python3
"""
aggregate_results.py — PQCLI benchmark result aggregator

Reads per-iteration CSV files from a results/macro/ or results/micro/ directory.
Computes mean, median, stddev, min, max, p95, p99 for wall time and RSS.
Writes summary.csv and sizes_summary.csv.

Usage:
  python3 aggregate_results.py <results_dir>
  python3 aggregate_results.py benchmarks/results/20260504_120000/macro
  python3 aggregate_results.py benchmarks/results/20260504_120000/micro
"""

import csv
import json
import math
import statistics
import sys
from pathlib import Path
from typing import Optional

# Schema for micro/measured_iterations.csv.
# run_id: timestamp directory name (parent of 'micro/'), or '' during manual re-aggregation
#   if metadata.json is absent.
# mode: from metadata.json if present next to 'micro/', else ''.
# jmh_error_ms: always blank at iteration level; JMH provides error only at aggregate level.
# fork_index / measurement_iteration: zero-based; '' for old per-op CSVs that predate this field.
MICRO_MEASURED_FIELDS = [
    'run_id', 'mode',
    'layer', 'algo_tag', 'operation', 'benchmark',
    'benchmark_mode', 'score_unit',
    'fork_index', 'measurement_iteration', 'iter_index',
    'jmh_score_ms', 'jmh_error_ms',
    'jmh_peak_rss_kb', 'jmh_process_wall_time_s',
    'success', 'error',
]

NUMERIC_FIELDS = [
    'cli_wall_time_ms', 'peak_rss_kb',
    'user_cpu_s', 'sys_cpu_s', 'cpu_pct',
    'context_switches', 'page_faults',
    'task_clock', 'cpu_clock',
]

SIZE_OUT_FIELDS = [
    'out_pub_key_pem_bytes', 'out_pub_key_der_bytes',
    'out_priv_key_pem_bytes', 'out_priv_key_der_bytes',
    'out_alt_pub_pem_bytes', 'out_alt_pub_der_bytes',
    'out_alt_priv_pem_bytes', 'out_alt_priv_der_bytes',
    'out_cert_pem_bytes', 'out_cert_der_bytes',
    'out_csr_pem_bytes', 'out_csr_der_bytes',
    'out_int_cert_pem_bytes', 'out_int_cert_der_bytes',
    'out_leaf_cert_pem_bytes', 'out_leaf_cert_der_bytes',
    'out_chain_total_pem_bytes', 'out_chain_total_der_bytes',
    'out_related_cert_pem_bytes', 'out_related_cert_der_bytes',
]

SIZE_IN_FIELDS = [
    'input_leaf_cert_pem_bytes', 'input_leaf_cert_der_bytes',
    'input_root_pem_bytes', 'input_root_der_bytes',
    'input_int_pem_bytes', 'input_int_der_bytes',
    'input_related_pem_bytes', 'input_related_der_bytes',
]


def _pct(data: list[float], p: float) -> float:
    """Percentile via linear interpolation."""
    if not data:
        return 0.0
    s = sorted(data)
    n = len(s)
    idx = (p / 100) * (n - 1)
    lo = int(idx)
    hi = min(lo + 1, n - 1)
    frac = idx - lo
    return s[lo] + frac * (s[hi] - s[lo])


def summarize(values: list[float]) -> dict:
    if not values:
        return {k: '' for k in ['count', 'mean', 'median', 'stddev', 'min', 'max', 'q1', 'q3', 'p95', 'p99']}
    return {
        'count':  len(values),
        'mean':   round(statistics.mean(values), 4),
        'median': round(statistics.median(values), 4),
        'stddev': round(statistics.stdev(values), 4) if len(values) > 1 else 0.0,
        'min':    round(min(values), 4),
        'max':    round(max(values), 4),
        'q1':     round(_pct(values, 25), 4),
        'q3':     round(_pct(values, 75), 4),
        'p95':    round(_pct(values, 95), 4),
        'p99':    round(_pct(values, 99), 4),
    }


def _float(val) -> Optional[float]:
    try:
        if val is None:
            return None
        return float(val) if str(val).strip() not in ('', 'None', 'null') else None
    except (ValueError, TypeError):
        return None


def aggregate_macro(results_dir: Path) -> None:
    rows_by_key: dict[tuple, list[dict]] = {}

    # Read from the consolidated measured_iterations.csv (authoritative source).
    # This ensures dual/RFC 9763 rows use canonical operation names (not rfc9763-stage*).
    # Raw stage rows live only in dual_step_breakdown.csv.
    meas_csv = results_dir / 'measured_iterations.csv'
    if meas_csv.exists():
        with open(meas_csv, newline='') as f:
            reader = csv.DictReader(f)
            for row in reader:
                if row.get('warmup', '0') == '1':
                    continue
                if row.get('success', '1') != '1':
                    continue
                key = (
                    row.get('algo_tag', ''),
                    row.get('certificate_mode', ''),
                    row.get('operation', ''),
                    row.get('cert_profile', ''),
                    row.get('profile', ''),
                )
                rows_by_key.setdefault(key, []).append(row)
    else:
        # Fallback: read per-op iteration CSVs (for old result directories)
        for iter_csv in sorted(results_dir.glob('*/*/iterations.csv')):
            with open(iter_csv, newline='') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    if row.get('warmup', '0') == '1':
                        continue
                    if row.get('exit_code', '0') != '0':
                        continue
                    key = (
                        row.get('algo_tag', ''),
                        row.get('certificate_mode', ''),
                        row.get('operation', ''),
                        row.get('cert_profile', ''),
                        row.get('profile', ''),
                    )
                    rows_by_key.setdefault(key, []).append(row)

    summary_path = results_dir / 'summary.csv'
    sizes_path   = results_dir / 'sizes_summary.csv'

    summary_fields = [
        'algo_tag', 'certificate_mode', 'operation', 'cert_profile', 'profile',
        'n', 'success_n',
        'cli_wall_time_mean_ms', 'cli_wall_time_median_ms', 'cli_wall_time_stddev_ms',
        'cli_wall_time_min_ms', 'cli_wall_time_max_ms',
        'cli_wall_time_q1_ms', 'cli_wall_time_q3_ms',
        'cli_wall_time_p95_ms', 'cli_wall_time_p99_ms',
        'peak_rss_mean_kb', 'peak_rss_median_kb', 'peak_rss_stddev_kb',
        'peak_rss_min_kb', 'peak_rss_max_kb',
        'peak_rss_q1_kb', 'peak_rss_q3_kb',
        'peak_rss_p95_kb', 'peak_rss_p99_kb',
        'user_cpu_mean_s', 'sys_cpu_mean_s', 'cpu_pct_mean',
        'context_switches_mean', 'page_faults_mean',
        'task_clock_mean_ms', 'cpu_clock_mean_ms',
    ]

    sizes_fields = [
        'algo_tag', 'certificate_mode', 'operation',
        *[f + '_mean' for f in SIZE_OUT_FIELDS + SIZE_IN_FIELDS],
        *[f + '_stddev' for f in SIZE_OUT_FIELDS + SIZE_IN_FIELDS],
    ]

    with (open(summary_path, 'w', newline='') as sf,
          open(sizes_path, 'w', newline='') as szf):
        sw  = csv.DictWriter(sf,  fieldnames=summary_fields,  extrasaction='ignore')
        szw = csv.DictWriter(szf, fieldnames=sizes_fields,    extrasaction='ignore')
        sw.writeheader()
        szw.writeheader()

        for (algo_tag, cert_mode, op, cert_prof, profile), rows in sorted(rows_by_key.items()):
            wall = [v for r in rows if (v := _float(r.get('cli_wall_time_ms'))) is not None]
            rss  = [v for r in rows if (v := _float(r.get('peak_rss_kb'))) is not None]
            wsum = summarize(wall)
            rsum = summarize(rss)

            sw.writerow({
                'algo_tag': algo_tag,
                'certificate_mode': cert_mode,
                'operation': op,
                'cert_profile': cert_prof,
                'profile': profile,
                'n': len(rows),
                'success_n': len(rows),
                'cli_wall_time_mean_ms':   wsum['mean'],
                'cli_wall_time_median_ms': wsum['median'],
                'cli_wall_time_stddev_ms': wsum['stddev'],
                'cli_wall_time_min_ms':    wsum['min'],
                'cli_wall_time_max_ms':    wsum['max'],
                'cli_wall_time_q1_ms':     wsum['q1'],
                'cli_wall_time_q3_ms':     wsum['q3'],
                'cli_wall_time_p95_ms':    wsum['p95'],
                'cli_wall_time_p99_ms':    wsum['p99'],
                'peak_rss_mean_kb':   rsum['mean'],
                'peak_rss_median_kb': rsum['median'],
                'peak_rss_stddev_kb': rsum['stddev'],
                'peak_rss_min_kb':    rsum['min'],
                'peak_rss_max_kb':    rsum['max'],
                'peak_rss_q1_kb':     rsum['q1'],
                'peak_rss_q3_kb':     rsum['q3'],
                'peak_rss_p95_kb':    rsum['p95'],
                'peak_rss_p99_kb':    rsum['p99'],
                'user_cpu_mean_s': round(statistics.mean(
                    [v for r in rows if (v := _float(r.get('user_cpu_s'))) is not None]
                ), 4) if any(_float(r.get('user_cpu_s')) is not None for r in rows) else '',
                'sys_cpu_mean_s': round(statistics.mean(
                    [v for r in rows if (v := _float(r.get('sys_cpu_s'))) is not None]
                ), 4) if any(_float(r.get('sys_cpu_s')) is not None for r in rows) else '',
                'cpu_pct_mean': round(statistics.mean(
                    [v for r in rows if (v := _float(r.get('cpu_pct'))) is not None]
                ), 1) if any(_float(r.get('cpu_pct')) is not None for r in rows) else '',
                'context_switches_mean': round(statistics.mean(
                    [v for r in rows if (v := _float(r.get('context_switches'))) is not None]
                ), 1) if any(_float(r.get('context_switches')) is not None for r in rows) else '',
                'page_faults_mean': round(statistics.mean(
                    [v for r in rows if (v := _float(r.get('page_faults'))) is not None]
                ), 1) if any(_float(r.get('page_faults')) is not None for r in rows) else '',
                'task_clock_mean_ms': round(statistics.mean(
                    [v for r in rows if (v := _float(r.get('task_clock'))) is not None]
                ), 4) if any(_float(r.get('task_clock')) is not None for r in rows) else '',
                'cpu_clock_mean_ms': round(statistics.mean(
                    [v for r in rows if (v := _float(r.get('cpu_clock'))) is not None]
                ), 4) if any(_float(r.get('cpu_clock')) is not None for r in rows) else '',
            })

            # Sizes
            sz_row = {'algo_tag': algo_tag, 'certificate_mode': cert_mode, 'operation': op}
            for f in SIZE_OUT_FIELDS + SIZE_IN_FIELDS:
                vals = [v for r in rows if (v := _float(r.get(f))) is not None and v > 0]
                sz_row[f + '_mean']   = round(statistics.mean(vals), 1) if vals else 0
                sz_row[f + '_stddev'] = round(statistics.stdev(vals), 2) if len(vals) > 1 else 0
            szw.writerow(sz_row)

    print(f'[AGGREGATE] summary.csv: {summary_path}')
    print(f'[AGGREGATE] sizes_summary.csv: {sizes_path}')
    aggregate_startup_breakdown(results_dir)


_STARTUP_TIMING_FIELDS = [
    'cli_wall_time_ms',
    'startup_picocli_ms',
    'dispatch_to_call_ms',
    'provider_total_ms',
    'bc_provider_ms',
    'bcpqc_provider_ms',
    'command_body_ms',
    'measured_unattributed_ms',
]


def aggregate_startup_breakdown(results_dir: Path) -> None:
    """
    Aggregate startup_breakdown.csv into:
      startup_summary.csv       — grouped by (algo_tag, operation, step_name)
      workflow_startup_summary.csv — workflow ops only, grouped by (algo_tag, operation);
                                     sums timing fields per iteration across steps, then
                                     aggregates those per-iteration sums.

    Only measured (warmup==0) rows with exit_code==0 are included.
    """
    bd_path = results_dir / 'startup_breakdown.csv'
    if not bd_path.exists():
        return

    rows: list[dict] = []
    with open(bd_path, newline='') as f:
        reader = csv.DictReader(f)
        for row in reader:
            if row.get('warmup', '0') == '1':
                continue
            if str(row.get('exit_code', '0')) != '0':
                continue
            rows.append(row)

    if not rows:
        print(f'[AGGREGATE] startup_breakdown.csv: no measured rows with exit_code=0')
        return

    # ── startup_summary.csv ────────────────────────────────────────────────────
    # Group by (algo_tag, operation, step_name).
    by_step: dict[tuple, list[dict]] = {}
    for row in rows:
        key = (row.get('algo_tag', ''), row.get('operation', ''), row.get('step_name', ''))
        by_step.setdefault(key, []).append(row)

    summary_fields = [
        'algo_tag', 'operation', 'step_name', 'is_workflow_step', 'n',
    ]
    for tf in _STARTUP_TIMING_FIELDS:
        summary_fields += [f'{tf}_mean', f'{tf}_median', f'{tf}_stddev',
                           f'{tf}_min', f'{tf}_max', f'{tf}_p95']

    summary_path = results_dir / 'startup_summary.csv'
    with open(summary_path, 'w', newline='') as sf:
        w = csv.DictWriter(sf, fieldnames=summary_fields, extrasaction='ignore')
        w.writeheader()
        for (algo_tag, op, step_name), step_rows in sorted(by_step.items()):
            is_wf = step_rows[0].get('is_workflow_step', '0')
            row_out: dict = {
                'algo_tag': algo_tag, 'operation': op,
                'step_name': step_name, 'is_workflow_step': is_wf,
                'n': len(step_rows),
            }
            for tf in _STARTUP_TIMING_FIELDS:
                vals = [v for r in step_rows if (v := _float(r.get(tf))) is not None]
                s = summarize(vals)
                row_out[f'{tf}_mean']   = s['mean']
                row_out[f'{tf}_median'] = s['median']
                row_out[f'{tf}_stddev'] = s['stddev']
                row_out[f'{tf}_min']    = s['min']
                row_out[f'{tf}_max']    = s['max']
                row_out[f'{tf}_p95']    = s['p95']
            w.writerow(row_out)
    print(f'[AGGREGATE] startup_summary.csv: {summary_path}')

    # ── workflow_startup_summary.csv ───────────────────────────────────────────
    # Filter to workflow rows only (is_workflow_step==1).
    # Sum timing fields per (algo_tag, operation, iter_index) across steps,
    # then aggregate those per-iteration sums grouped by (algo_tag, operation).
    wf_rows = [r for r in rows if r.get('is_workflow_step', '0') == '1']
    if not wf_rows:
        return

    # Per-iteration sums: key = (algo_tag, operation, iter_index)
    iter_sums: dict[tuple, dict] = {}
    for row in wf_rows:
        key = (row.get('algo_tag', ''), row.get('operation', ''), row.get('iter_index', ''))
        if key not in iter_sums:
            iter_sums[key] = {tf: 0.0 for tf in _STARTUP_TIMING_FIELDS}
            iter_sums[key]['_n_steps'] = 0
        for tf in _STARTUP_TIMING_FIELDS:
            v = _float(row.get(tf))
            if v is not None:
                iter_sums[key][tf] = (iter_sums[key][tf] or 0.0) + v
        iter_sums[key]['_n_steps'] += 1

    # Group per-iteration sums by (algo_tag, operation)
    by_op: dict[tuple, list[dict]] = {}
    for (algo_tag, op, _iter_idx), sums in iter_sums.items():
        k2 = (algo_tag, op)
        by_op.setdefault(k2, []).append(sums)

    wf_summary_fields = ['algo_tag', 'operation', 'n_iterations', 'steps_per_iteration']
    for tf in _STARTUP_TIMING_FIELDS:
        wf_summary_fields += [f'sum_{tf}_mean', f'sum_{tf}_median',
                               f'sum_{tf}_stddev', f'sum_{tf}_p95']

    wf_path = results_dir / 'workflow_startup_summary.csv'
    with open(wf_path, 'w', newline='') as wf:
        w = csv.DictWriter(wf, fieldnames=wf_summary_fields, extrasaction='ignore')
        w.writeheader()
        for (algo_tag, op), sum_list in sorted(by_op.items()):
            n_steps_vals = [d['_n_steps'] for d in sum_list]
            steps_per_iter = round(statistics.mean(n_steps_vals), 1) if n_steps_vals else ''
            row_out: dict = {
                'algo_tag': algo_tag, 'operation': op,
                'n_iterations': len(sum_list),
                'steps_per_iteration': steps_per_iter,
            }
            for tf in _STARTUP_TIMING_FIELDS:
                vals = [v for d in sum_list if (v := _float(str(d.get(tf, '')))) is not None]
                s = summarize(vals)
                row_out[f'sum_{tf}_mean']   = s['mean']
                row_out[f'sum_{tf}_median'] = s['median']
                row_out[f'sum_{tf}_stddev'] = s['stddev']
                row_out[f'sum_{tf}_p95']    = s['p95']
            w.writerow(row_out)
    print(f'[AGGREGATE] workflow_startup_summary.csv: {wf_path}')


def aggregate_micro(results_dir: Path) -> None:
    """Aggregate JMH micro benchmark results from per-op iterations.csv files.

    Directory structure under results_dir: <Layer>/<algo_tag>/<op>/iterations.csv
    The glob depth is */*/*/iterations.csv (3 levels: layer/algo/op).
    """
    # Derive run_id and mode for consolidated CSV.
    # results_dir is e.g. .../results/20260504_120000/micro
    run_id = results_dir.parent.name  # timestamp directory
    mode   = ''
    metadata_path = results_dir.parent / 'metadata.json'
    if metadata_path.exists():
        try:
            meta = json.loads(metadata_path.read_text())
            mode = meta.get('mode', '')
        except Exception:
            pass

    # Collect RSS data keyed by (layer, algo_tag, op).
    # Path: results_dir/<layer>/<algo>/<op>/jmh_rss.csv
    rss_by_key: dict[tuple, dict] = {}
    for rss_csv in sorted(results_dir.glob('*/*/*/jmh_rss.csv')):
        op_dir   = rss_csv.parent
        op       = op_dir.name
        algo_tag = op_dir.parent.name
        layer    = op_dir.parent.parent.name
        with open(rss_csv, newline='') as f:
            reader = csv.DictReader(f)
            for row in reader:
                rss_by_key[(layer, algo_tag, op)] = {
                    'jmh_peak_rss_kb':        row.get('jmh_peak_rss_kb', ''),
                    'jmh_process_wall_time_s': row.get('jmh_process_wall_time_s', ''),
                }

    # Collect iteration data.
    # Path: results_dir/<layer>/<algo>/<op>/iterations.csv
    all_rows: list[dict] = []
    rows_by_key: dict[tuple, list[float]] = {}

    for iter_csv in sorted(results_dir.glob('*/*/*/iterations.csv')):
        op_dir   = iter_csv.parent
        op       = op_dir.name
        algo_tag = op_dir.parent.name
        layer    = op_dir.parent.parent.name

        rss_info = rss_by_key.get((layer, algo_tag, op), {})

        with open(iter_csv, newline='') as f:
            reader = csv.DictReader(f)
            for row in reader:
                v = _float(row.get('jmh_score_ms'))
                if v is None:
                    continue
                bench = row.get('benchmark', '')
                key   = (layer, algo_tag, op, bench)
                rows_by_key.setdefault(key, []).append(v)
                all_rows.append({
                    'run_id':                  run_id,
                    'mode':                    mode,
                    'layer':                   layer,
                    'algo_tag':                row.get('algo_tag', algo_tag),
                    'operation':               row.get('operation', op),
                    'benchmark':               bench,
                    'benchmark_mode':          row.get('benchmark_mode', ''),
                    'score_unit':              row.get('score_unit', ''),
                    'fork_index':              row.get('fork_index', ''),
                    'measurement_iteration':   row.get('measurement_iteration', ''),
                    'iter_index':              row.get('iter_index', ''),
                    'jmh_score_ms':            row.get('jmh_score_ms', ''),
                    'jmh_error_ms':            row.get('jmh_error_ms', ''),
                    'jmh_peak_rss_kb':         rss_info.get('jmh_peak_rss_kb', ''),
                    'jmh_process_wall_time_s': rss_info.get('jmh_process_wall_time_s', ''),
                    'success':                 '1',
                    'error':                   '',
                })

    # Write measured_iterations.csv — all rows, all layers/algos/ops.
    meas_path = results_dir / 'measured_iterations.csv'
    with open(meas_path, 'w', newline='') as f:
        w = csv.DictWriter(f, fieldnames=MICRO_MEASURED_FIELDS, extrasaction='ignore')
        w.writeheader()
        for row in all_rows:
            w.writerow(row)
    print(f'[AGGREGATE] micro measured_iterations.csv: {meas_path}')

    # Write summary.csv — aggregated stats per (layer, algo_tag, op, benchmark).
    summary_path = results_dir / 'summary.csv'
    summary_fields = [
        'layer', 'algo_tag', 'operation', 'benchmark', 'n',
        'jmh_mean_ms', 'jmh_median_ms', 'jmh_stddev_ms',
        'jmh_min_ms', 'jmh_max_ms',
        'jmh_q1_ms', 'jmh_q3_ms',
        'jmh_p95_ms', 'jmh_p99_ms',
        'jmh_peak_rss_kb',
    ]
    with open(summary_path, 'w', newline='') as sf:
        w = csv.DictWriter(sf, fieldnames=summary_fields, extrasaction='ignore')
        w.writeheader()
        for (layer, algo_tag, op, bench), vals in sorted(rows_by_key.items()):
            s = summarize(vals)
            rss_info = rss_by_key.get((layer, algo_tag, op), {})
            w.writerow({
                'layer':    layer,
                'algo_tag': algo_tag, 'operation': op, 'benchmark': bench,
                'n':             len(vals),
                'jmh_mean_ms':   s['mean'],   'jmh_median_ms': s['median'],
                'jmh_stddev_ms': s['stddev'], 'jmh_min_ms':    s['min'],
                'jmh_max_ms':    s['max'],
                'jmh_q1_ms':     s['q1'],    'jmh_q3_ms':     s['q3'],
                'jmh_p95_ms':    s['p95'],   'jmh_p99_ms':    s['p99'],
                'jmh_peak_rss_kb': rss_info.get('jmh_peak_rss_kb', ''),
            })
    print(f'[AGGREGATE] micro summary.csv: {summary_path}')


def aggregate_openssl(results_dir: Path) -> None:
    """Aggregate OpenSSL benchmark results from consolidated measured_iterations.csv.

    WARNING: OpenSSL macro wall_time_ms values are CLI macro timings and must NOT
    be compared to JMH jmh_score_ms values from micro/ results. They reflect
    OpenSSL native process startup + operation, not JVM startup + operation.

    Reads from results_dir/measured_iterations.csv (consolidated) and
    results_dir/sizing_measurements.csv for size data.
    """
    meas_path  = results_dir / 'measured_iterations.csv'
    sizes_path_in = results_dir / 'sizing_measurements.csv'

    rows_by_key: dict[tuple, list[dict]] = {}

    if not meas_path.exists():
        print(f'[AGGREGATE] {meas_path} not found — nothing to aggregate')
        return

    with open(meas_path, newline='') as f:
        reader = csv.DictReader(f)
        for row in reader:
            if row.get('warmup', '0') == '1':
                continue
            if row.get('success', '1') != '1':
                continue
            key = (
                row.get('algo_tag', ''),
                row.get('certificate_mode', ''),
                row.get('openssl_operation', ''),
                row.get('algorithm_source', ''),
                row.get('profile', ''),
            )
            rows_by_key.setdefault(key, []).append(row)

    # Load size rows keyed by (algo_tag, openssl_operation, iter_index)
    size_rows: list[dict] = []
    if sizes_path_in.exists():
        with open(sizes_path_in, newline='') as f:
            size_rows = list(csv.DictReader(f))

    summary_path = results_dir / 'summary.csv'
    sizes_path   = results_dir / 'sizes_summary.csv'

    summary_fields = [
        'algo_tag', 'certificate_mode', 'openssl_operation',
        'algorithm_source', 'profile',
        'n', 'success_n',
        'wall_time_mean_ms', 'wall_time_median_ms', 'wall_time_stddev_ms',
        'wall_time_min_ms', 'wall_time_max_ms',
        'wall_time_q1_ms', 'wall_time_q3_ms',
        'wall_time_p95_ms', 'wall_time_p99_ms',
        'peak_rss_mean_kb', 'peak_rss_median_kb', 'peak_rss_stddev_kb',
        'peak_rss_min_kb', 'peak_rss_max_kb',
        'peak_rss_q1_kb', 'peak_rss_q3_kb',
        'peak_rss_p95_kb', 'peak_rss_p99_kb',
        'comparability_class',
        'warning',
    ]

    openssl_size_out_fields = [
        'out_pub_key_pem_bytes', 'out_pub_key_der_bytes',
        'out_priv_key_pem_bytes', 'out_priv_key_der_bytes',
        'out_cert_pem_bytes', 'out_cert_der_bytes',
        'out_csr_pem_bytes', 'out_csr_der_bytes',
        'out_int_cert_pem_bytes', 'out_int_cert_der_bytes',
        'out_leaf_cert_pem_bytes', 'out_leaf_cert_der_bytes',
    ]
    openssl_size_in_fields = [
        'input_leaf_cert_pem_bytes', 'input_leaf_cert_der_bytes',
        'input_int_pem_bytes', 'input_int_der_bytes',
        'input_root_pem_bytes', 'input_root_der_bytes',
    ]
    sizes_fields = (
        ['algo_tag', 'certificate_mode', 'openssl_operation', 'algorithm_source'] +
        [f + '_mean' for f in openssl_size_out_fields + openssl_size_in_fields] +
        [f + '_stddev' for f in openssl_size_out_fields + openssl_size_in_fields]
    )

    COMPARABILITY_WARNING = (
        'partial — OpenSSL CLI wall times are NOT comparable to JMH jmh_score_ms. '
        'See metadata.json for full caveats.'
    )

    with (open(summary_path, 'w', newline='') as sf,
          open(sizes_path,   'w', newline='') as szf):
        sw  = csv.DictWriter(sf,  fieldnames=summary_fields,  extrasaction='ignore')
        szw = csv.DictWriter(szf, fieldnames=sizes_fields,    extrasaction='ignore')
        sw.writeheader()
        szw.writeheader()

        for (algo_tag, cert_mode, op, algo_src, profile), rows in sorted(rows_by_key.items()):
            wall = [v for r in rows if (v := _float(r.get('wall_time_ms', ''))) is not None]
            rss  = [v for r in rows if (v := _float(r.get('peak_rss_kb', ''))) is not None]
            wsum = summarize(wall)
            rsum = summarize(rss)

            sw.writerow({
                'algo_tag': algo_tag, 'certificate_mode': cert_mode,
                'openssl_operation': op, 'algorithm_source': algo_src,
                'profile': profile,
                'n': len(rows), 'success_n': len(rows),
                'wall_time_mean_ms':   wsum['mean'],
                'wall_time_median_ms': wsum['median'],
                'wall_time_stddev_ms': wsum['stddev'],
                'wall_time_min_ms':    wsum['min'],
                'wall_time_max_ms':    wsum['max'],
                'wall_time_q1_ms':     wsum['q1'],
                'wall_time_q3_ms':     wsum['q3'],
                'wall_time_p95_ms':    wsum['p95'],
                'wall_time_p99_ms':    wsum['p99'],
                'peak_rss_mean_kb':    rsum['mean'],
                'peak_rss_median_kb':  rsum['median'],
                'peak_rss_stddev_kb':  rsum['stddev'],
                'peak_rss_min_kb':     rsum['min'],
                'peak_rss_max_kb':     rsum['max'],
                'peak_rss_q1_kb':      rsum['q1'],
                'peak_rss_q3_kb':      rsum['q3'],
                'peak_rss_p95_kb':     rsum['p95'],
                'peak_rss_p99_kb':     rsum['p99'],
                'comparability_class': 'partial',
                'warning': COMPARABILITY_WARNING,
            })

            # Size aggregation from sizing_measurements.csv rows
            matching_sz = [r for r in size_rows
                           if r.get('algo_tag') == algo_tag
                           and r.get('openssl_operation') == op
                           and r.get('warmup', '0') != '1']
            sz_row: dict = {'algo_tag': algo_tag, 'certificate_mode': cert_mode,
                            'openssl_operation': op, 'algorithm_source': algo_src}
            for f in openssl_size_out_fields + openssl_size_in_fields:
                vals = [v for r in matching_sz
                        if (v := _float(r.get(f, ''))) is not None and v > 0]
                sz_row[f + '_mean']   = round(statistics.mean(vals), 1) if vals else 0
                sz_row[f + '_stddev'] = round(statistics.stdev(vals), 2) if len(vals) > 1 else 0
            szw.writerow(sz_row)

    print('[NOTE] OpenSSL results: wall_time_ms values are CLI macro times and must '
          'NOT be compared to JMH jmh_score_ms from micro/ results.')
    print(f'[AGGREGATE] openssl summary.csv:       {summary_path}')
    print(f'[AGGREGATE] openssl sizes_summary.csv: {sizes_path}')


def aggregate_industrial(results_dir: Path) -> None:
    """Aggregate industrial benchmark results from measured_iterations.csv.

    Timing field: elapsed_ms (from System.nanoTime). NOT cli_wall_time_ms.
    Do not mix industrial rows into macro, micro, or OpenSSL summaries.
    RSS: process-level per (algo_tag, operation); from process_metrics.csv.
    """
    meas_path      = results_dir / 'measured_iterations.csv'
    sizes_path_in  = results_dir / 'sizing_measurements.csv'
    proc_path      = results_dir / 'process_metrics.csv'

    if not meas_path.exists():
        print(f'[AGGREGATE] {meas_path} not found — nothing to aggregate')
        return

    rows_by_key: dict[tuple, list[dict]] = {}
    with open(meas_path, newline='') as f:
        reader = csv.DictReader(f)
        for row in reader:
            if row.get('warmup', '0') == '1':
                continue
            if row.get('success', '1') != '1':
                continue
            key = (
                row.get('algo_tag', ''),
                row.get('certificate_mode', ''),
                row.get('operation', ''),
                row.get('profile', ''),
                row.get('execution_model', ''),
            )
            rows_by_key.setdefault(key, []).append(row)

    # Load process-level RSS: one row per (algo_tag, operation) from /usr/bin/time -v
    proc_by_key: dict[tuple, float] = {}
    if proc_path.exists():
        with open(proc_path, newline='') as f:
            for row in csv.DictReader(f):
                rss = _float(row.get('peak_rss_kb', ''))
                if rss is not None:
                    proc_by_key[(row.get('algo_tag', ''), row.get('operation', ''))] = rss

    summary_path = results_dir / 'summary.csv'
    sizes_path   = results_dir / 'sizes_summary.csv'

    summary_fields = [
        'algo_tag', 'certificate_mode', 'operation', 'profile', 'execution_model',
        'n', 'success_n',
        'elapsed_ms_mean', 'elapsed_ms_median', 'elapsed_ms_stddev',
        'elapsed_ms_min', 'elapsed_ms_max',
        'elapsed_ms_q1', 'elapsed_ms_q3',
        'elapsed_ms_p95', 'elapsed_ms_p99',
        'peak_rss_kb_count', 'peak_rss_kb_mean', 'peak_rss_kb_median',
        'peak_rss_kb_stddev', 'peak_rss_kb_min', 'peak_rss_kb_max',
        'peak_rss_kb_q1', 'peak_rss_kb_q3',
        'peak_rss_kb_p95', 'peak_rss_kb_p99',
        'rss_scope', 'rss_iteration_semantics',
    ]

    industrial_size_fields = [
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

    sizes_fields = (
        ['algo_tag', 'certificate_mode', 'operation', 'profile'] +
        [f + '_mean'   for f in industrial_size_fields] +
        [f + '_stddev' for f in industrial_size_fields]
    )

    size_rows: list[dict] = []
    if sizes_path_in.exists():
        with open(sizes_path_in, newline='') as f:
            size_rows = list(csv.DictReader(f))

    with (open(summary_path, 'w', newline='') as sf,
          open(sizes_path,   'w', newline='') as szf):
        sw  = csv.DictWriter(sf,  fieldnames=summary_fields,  extrasaction='ignore')
        szw = csv.DictWriter(szf, fieldnames=sizes_fields,    extrasaction='ignore')
        sw.writeheader()
        szw.writeheader()

        for (algo_tag, cert_mode, op, profile, exec_model), rows in sorted(rows_by_key.items()):
            elapsed = [v for r in rows if (v := _float(r.get('elapsed_ms'))) is not None]
            s = summarize(elapsed)
            # RSS: single process-level data point per (algo_tag, op)
            rss_val = proc_by_key.get((algo_tag, op))
            rs = summarize([rss_val]) if rss_val is not None else summarize([])
            sw.writerow({
                'algo_tag': algo_tag, 'certificate_mode': cert_mode,
                'operation': op, 'profile': profile, 'execution_model': exec_model,
                'n': len(rows), 'success_n': len(rows),
                'elapsed_ms_mean':   s['mean'],   'elapsed_ms_median': s['median'],
                'elapsed_ms_stddev': s['stddev'],  'elapsed_ms_min':    s['min'],
                'elapsed_ms_max':    s['max'],
                'elapsed_ms_q1':     s['q1'],     'elapsed_ms_q3':     s['q3'],
                'elapsed_ms_p95':    s['p95'],    'elapsed_ms_p99':    s['p99'],
                'peak_rss_kb_count':  rs['count'], 'peak_rss_kb_mean':   rs['mean'],
                'peak_rss_kb_median': rs['median'], 'peak_rss_kb_stddev': rs['stddev'],
                'peak_rss_kb_min':    rs['min'],   'peak_rss_kb_max':    rs['max'],
                'peak_rss_kb_q1':     rs['q1'],   'peak_rss_kb_q3':     rs['q3'],
                'peak_rss_kb_p95':    rs['p95'],  'peak_rss_kb_p99':    rs['p99'],
                'rss_scope': 'process_peak_per_algo_operation',
                'rss_iteration_semantics': 'not_per_iteration',
            })

            matching_sz = [r for r in size_rows
                           if r.get('algo_tag') == algo_tag
                           and r.get('operation') == op]
            sz_row: dict = {'algo_tag': algo_tag, 'certificate_mode': cert_mode,
                            'operation': op, 'profile': profile}
            for f in industrial_size_fields:
                vals = [v for r in matching_sz
                        if (v := _float(r.get(f, ''))) is not None and v > 0]
                sz_row[f + '_mean']   = round(statistics.mean(vals), 1) if vals else 0
                sz_row[f + '_stddev'] = round(statistics.stdev(vals), 2) if len(vals) > 1 else 0
            szw.writerow(sz_row)

    print(f'[AGGREGATE] industrial summary.csv:       {summary_path}')
    print(f'[AGGREGATE] industrial sizes_summary.csv: {sizes_path}')
    print('[NOTE] elapsed_ms (industrial) is System.nanoTime per iteration. '
          'NOT comparable to cli_wall_time_ms (macro).')


def main() -> int:
    if len(sys.argv) < 2:
        print(__doc__)
        return 1
    results_dir = Path(sys.argv[1]).resolve()
    if not results_dir.exists():
        print(f'Directory not found: {results_dir}')
        return 1

    suite = results_dir.name
    if suite == 'micro':
        aggregate_micro(results_dir)
    elif suite == 'openssl':
        print('[NOTE] OpenSSL results: wall_time_ms values are CLI macro times and must '
              'NOT be compared to JMH jmh_score_ms from micro/ results.')
        aggregate_openssl(results_dir)
    elif suite == 'industrial':
        aggregate_industrial(results_dir)
    elif suite == 'macro':
        aggregate_macro(results_dir)
    else:
        print(f'[ERROR] Cannot determine suite from directory name "{suite}".')
        print('Expected path ending in: macro | openssl | industrial | micro')
        print(f'Got: {results_dir}')
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
