#!/usr/bin/env python3
"""
run_macro_benchmarks.py — PQCLI macro benchmark orchestrator

Measures CLI wall time, peak RSS, and software/runtime metrics for all five
certificate types.

Usage:
  python3 run_macro_benchmarks.py [options]

Key options:
  --profile    smoke | thesis-core | slh-heavy | composite-heavy | hybrid-heavy | full
  --jar        path to pqcli-0.1.0.jar  (default: auto-detect)
  --out        results directory         (default: results/<timestamp>)
  --staging    staging directory         (default: .staging/<timestamp>)
  --tmpdir     temp directory for timev/perf files  (default: system tmpdir)
  --ops        comma-separated op subset
  --algos      comma-separated algo tag subset
  --category   comma-separated category subset
  --iter       override iteration count  (default from profile)
  --warmup     override warmup count     (default 5)
  --taskset-cpu  CPU affinity for taskset (e.g. "0")
  --no-perf    disable software perf
  --rebuild    run mvn clean package before benchmarking
  --allow-version-mismatch  skip BC version gate
  --mode       dry | stable
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
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

SCRIPT_DIR  = Path(__file__).resolve().parent
PROJECT_DIR = SCRIPT_DIR.parent
PQCLI_DIR   = PROJECT_DIR / 'pqcli-main'

sys.path.insert(0, str(SCRIPT_DIR))
from benchmark_config import (
    AlgoConfig, DualConfig, PROFILES, DEFAULT_JVM_FLAGS,
    EXPECTED_BC_VERSION, WARMUP_ITERATIONS, DUAL_STAGE_TO_CANONICAL_OP,
)

log = logging.getLogger('bench')


# ── Time and RSS parsing ───────────────────────────────────────────────────────

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

def _parse_perf_task_clock(text: str) -> Optional[float]:
    m = re.search(r'([\d,]+(?:\.\d+)?)\s+msec\s+task-clock', text)
    return float(m.group(1).replace(',', '')) if m else None

def _parse_perf_cpu_clock(text: str) -> Optional[float]:
    m = re.search(r'([\d,]+(?:\.\d+)?)\s+msec\s+cpu-clock', text)
    return float(m.group(1).replace(',', '')) if m else None


# ── Startup timing parsing ────────────────────────────────────────────────────
#
# pqcli emits [TIMING] lines to stderr when PQCLI_TIMING_DEBUG=1.
# Format: "[TIMING] %-45s +%d ms" — label left-padded to 45 chars, then +N ms.
#
# Disambiguation note: "BCPQC provider registered" is checked before
# "BC provider registered" to avoid substring false-match (not actually needed
# since "BC provider" != "BCPQC provider", but ordering makes intent clear).
_TIMING_PATTERNS: list[tuple[str, str]] = [
    ('main() entry',                   'timing_main_entry_ms'),
    ('CommandLine constructed',        'timing_commandline_constructed_ms'),
    ('.call() entered',                'timing_call_entered_ms'),
    ('setupProvider() entered',        'timing_setupProvider_entered_ms'),
    ('BCPQC provider registered',      'timing_bcpqc_registered_ms'),
    ('BC provider registered',         'timing_bc_registered_ms'),
    ('command body start',             'timing_command_body_start_ms'),
    ('.call() returning',              'timing_call_returning_ms'),
]
_TIMING_LINE_RE = re.compile(r'^\[TIMING\]\s+(.+?)\s+\+(\d+)\s+ms\s*$')


def parse_timing_breakdown(stderr_text: str) -> dict:
    """
    Parse [TIMING] lines from pqcli stderr produced by PQCLI_TIMING_DEBUG=1.
    Returns dict: timing_*_ms fields (float or None) and 'timing_parse_error' (str).
    Fields with no matching label are None (e.g. provider fields absent for --help).
    """
    result: dict = {field_name: None for _, field_name in _TIMING_PATTERNS}
    errors: list[str] = []
    for line in stderr_text.splitlines():
        m = _TIMING_LINE_RE.match(line.strip())
        if not m:
            continue
        label = m.group(1).strip()
        ms = float(m.group(2))
        for key, field_name in _TIMING_PATTERNS:
            if key in label:
                if result[field_name] is None:
                    result[field_name] = ms
                # On duplicate, keep first occurrence; ignore subsequent.
                break
    result['timing_parse_error'] = '; '.join(errors)
    return result


def _delta(a: Optional[float], b: Optional[float]) -> Optional[float]:
    if a is not None and b is not None:
        return round(b - a, 4)
    return None


def _fstr(v) -> str:
    if v is None:
        return ''
    if isinstance(v, float):
        return str(round(v, 4))
    return str(v)


def _make_breakdown_row(
    *, run_id: str, profile: str, mode: str, algo_tag: str,
    operation: str, iter_index: int, warmup: bool,
    step_index: int, step_name: str, is_workflow_step: bool,
    result: 'RunResult',
) -> dict:
    """Build one startup_breakdown.csv row from a RunResult."""
    ts = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())
    r = result
    unattr: Optional[float] = None
    if r.cli_wall_time_ms is not None and r.timing_call_returning_ms is not None:
        unattr = round(r.cli_wall_time_ms - r.timing_call_returning_ms, 4)
    return {
        'run_id':                           run_id,
        'timestamp_utc':                    ts,
        'suite':                            'macro',
        'profile':                          profile,
        'mode':                             mode,
        'algo_tag':                         algo_tag,
        'operation':                        operation,
        'iter_index':                       iter_index,
        'warmup':                           '1' if warmup else '0',
        'step_index':                       step_index,
        'step_name':                        step_name,
        'is_workflow_step':                 '1' if is_workflow_step else '0',
        'cli_wall_time_ms':                 _fstr(r.cli_wall_time_ms),
        'peak_rss_kb':                      _fstr(r.peak_rss_kb),
        'exit_code':                        r.exit_code,
        'timing_main_entry_ms':             _fstr(r.timing_main_entry_ms),
        'timing_commandline_constructed_ms':_fstr(r.timing_commandline_constructed_ms),
        'timing_call_entered_ms':           _fstr(r.timing_call_entered_ms),
        'timing_setupProvider_entered_ms':  _fstr(r.timing_setupProvider_entered_ms),
        'timing_bc_registered_ms':          _fstr(r.timing_bc_registered_ms),
        'timing_bcpqc_registered_ms':       _fstr(r.timing_bcpqc_registered_ms),
        'timing_command_body_start_ms':     _fstr(r.timing_command_body_start_ms),
        'timing_call_returning_ms':         _fstr(r.timing_call_returning_ms),
        'startup_picocli_ms':               _fstr(_delta(r.timing_main_entry_ms,
                                                r.timing_commandline_constructed_ms)),
        'dispatch_to_call_ms':              _fstr(_delta(r.timing_commandline_constructed_ms,
                                                r.timing_call_entered_ms)),
        'provider_total_ms':                _fstr(_delta(r.timing_setupProvider_entered_ms,
                                                r.timing_bcpqc_registered_ms)),
        'bc_provider_ms':                   _fstr(_delta(r.timing_setupProvider_entered_ms,
                                                r.timing_bc_registered_ms)),
        'bcpqc_provider_ms':                _fstr(_delta(r.timing_bc_registered_ms,
                                                r.timing_bcpqc_registered_ms)),
        'command_body_ms':                  _fstr(_delta(r.timing_command_body_start_ms,
                                                r.timing_call_returning_ms)),
        'measured_unattributed_ms':         _fstr(unattr),
        'stderr_path':                      str(r.stderr_path) if r.stderr_path else '',
        'timev_path':                       str(r.timev_path) if r.timev_path else '',
        'parse_error':                      r.timing_parse_error,
    }


# ── DER size helpers ───────────────────────────────────────────────────────────

def pem_der_total(path: Path) -> int:
    if not path.exists():
        return 0
    text = path.read_text(errors='replace')
    total = 0
    for m in re.finditer(r'-----BEGIN[^-]+-----\r?\n([\s\S]+?)-----END[^-]+-----', text):
        body = re.sub(r'\s', '', m.group(1))
        try:
            total += len(base64.b64decode(body + '=='))
        except Exception:
            pass
    return total

def measure_pem_file(path: Path) -> tuple[int, int]:
    if not path.exists():
        return 0, 0
    return path.stat().st_size, pem_der_total(path)

_mf = measure_pem_file


# ── Command invocation ─────────────────────────────────────────────────────────

@dataclass
class RunResult:
    exit_code: int
    cli_wall_time_ms: Optional[float]
    peak_rss_kb: Optional[int]
    user_cpu_s: Optional[float]
    sys_cpu_s: Optional[float]
    cpu_pct: Optional[float]
    context_switches: Optional[int]
    page_faults: Optional[int]
    task_clock: Optional[float] = None
    cpu_clock: Optional[float] = None
    stdout_path: Optional[Path] = None
    stderr_path: Optional[Path] = None
    timev_path: Optional[Path] = None
    perf_path: Optional[Path] = None
    # Startup timing breakdown — populated when timing_debug=True (PQCLI_TIMING_DEBUG=1).
    # Values are milliseconds since pqcli class-init T0 inside the child JVM.
    timing_main_entry_ms: Optional[float] = None
    timing_commandline_constructed_ms: Optional[float] = None
    timing_call_entered_ms: Optional[float] = None
    timing_setupProvider_entered_ms: Optional[float] = None
    timing_bc_registered_ms: Optional[float] = None
    timing_bcpqc_registered_ms: Optional[float] = None
    timing_command_body_start_ms: Optional[float] = None
    timing_call_returning_ms: Optional[float] = None
    timing_parse_error: str = ''
    # Per-step sub-results — non-empty only for workflow ops (verify-modeA-chain,
    # workflow-2tier, workflow-3tier). List of (step_name, RunResult).
    step_results: list = field(default_factory=list)


def _pqcli_cmd(jar: Path, jvm_flags: list[str], pqcli_args: list[str]) -> list[str]:
    """Build the full Java command for a pqcli invocation."""
    return ['java'] + jvm_flags + ['-jar', str(jar)] + pqcli_args


def run_timed(
    full_cmd: list[str],        # complete process command (e.g. ['java', ..., '-jar', jar, ...])
    log_dir: Path,
    iter_tag: str,
    tmpdir: Path,
    taskset_cpu: Optional[str],
    perf_available: bool,
    perf_events: str,
    timeout_s: int = 600,
    timing_debug: bool = False,
) -> RunResult:
    """
    Wrap a command with [taskset] /usr/bin/time -v [perf stat] and run it.
    full_cmd is the complete process command; this function only adds measurement wrappers.

    When timing_debug=True, sets PQCLI_TIMING_DEBUG=1 in the subprocess environment
    and parses [TIMING] lines from stderr into RunResult timing_*_ms fields.
    This does not change cli_wall_time_ms, which always comes from /usr/bin/time -v.
    """
    ts = str(time.monotonic_ns())
    timev_file = tmpdir / f'timev_{ts}.txt'
    perf_file  = tmpdir / f'perf_{ts}.txt' if perf_available else None

    for subdir in ('stdout', 'stderr', 'timev'):
        (log_dir / subdir).mkdir(parents=True, exist_ok=True)

    wrapped = []
    if taskset_cpu:
        wrapped += ['taskset', '-c', taskset_cpu]
    wrapped += ['/usr/bin/time', '-v', '--output', str(timev_file)]
    if perf_available and perf_file:
        wrapped += ['perf', 'stat', '-e', perf_events, '--output', str(perf_file), '--']
    wrapped += full_cmd

    stdout_file = log_dir / 'stdout' / f'{iter_tag}.log'
    stderr_file = log_dir / 'stderr' / f'{iter_tag}.log'

    # Pass PQCLI_TIMING_DEBUG=1 when requested; otherwise inherit env unchanged.
    run_env = {**os.environ, 'PQCLI_TIMING_DEBUG': '1'} if timing_debug else None

    exit_code = -1
    with open(stdout_file, 'wb') as fout, open(stderr_file, 'wb') as ferr:
        try:
            proc = subprocess.run(wrapped, stdout=fout, stderr=ferr,
                                  timeout=timeout_s, env=run_env)
            exit_code = proc.returncode
        except subprocess.TimeoutExpired:
            log.warning('Timeout after %ds for iter %s', timeout_s, iter_tag)

    timev_dest = log_dir / 'timev' / f'{iter_tag}.txt'
    if timev_file.exists():
        shutil.move(str(timev_file), str(timev_dest))
    timev_text = timev_dest.read_text(errors='replace') if timev_dest.exists() else ''

    perf_dest = None
    perf_text = ''
    if perf_file and perf_file.exists():
        (log_dir / 'perf').mkdir(parents=True, exist_ok=True)
        perf_dest = log_dir / 'perf' / f'{iter_tag}.txt'
        shutil.move(str(perf_file), str(perf_dest))
        perf_text = perf_dest.read_text(errors='replace')

    # Parse startup timing from stderr when timing_debug is active.
    # The raw [TIMING] lines remain in the stderr file unchanged.
    timing_fields: dict = {}
    timing_parse_error = ''
    if timing_debug:
        stderr_text = stderr_file.read_text(errors='replace') if stderr_file.exists() else ''
        timing_fields = parse_timing_breakdown(stderr_text)
        timing_parse_error = timing_fields.pop('timing_parse_error', '')

    return RunResult(
        exit_code=exit_code,
        cli_wall_time_ms=_parse_elapsed_ms(timev_text),
        peak_rss_kb=_parse_rss_kb(timev_text),
        user_cpu_s=_parse_user_s(timev_text),
        sys_cpu_s=_parse_sys_s(timev_text),
        cpu_pct=_parse_cpu_pct(timev_text),
        context_switches=_parse_ctx_switches(timev_text),
        page_faults=_parse_page_faults(timev_text),
        task_clock=_parse_perf_task_clock(perf_text),
        cpu_clock=_parse_perf_cpu_clock(perf_text),
        stdout_path=stdout_file,
        stderr_path=stderr_file,
        timev_path=timev_dest if timev_dest.exists() else None,
        perf_path=perf_dest,
        timing_main_entry_ms=timing_fields.get('timing_main_entry_ms'),
        timing_commandline_constructed_ms=timing_fields.get('timing_commandline_constructed_ms'),
        timing_call_entered_ms=timing_fields.get('timing_call_entered_ms'),
        timing_setupProvider_entered_ms=timing_fields.get('timing_setupProvider_entered_ms'),
        timing_bc_registered_ms=timing_fields.get('timing_bc_registered_ms'),
        timing_bcpqc_registered_ms=timing_fields.get('timing_bcpqc_registered_ms'),
        timing_command_body_start_ms=timing_fields.get('timing_command_body_start_ms'),
        timing_call_returning_ms=timing_fields.get('timing_call_returning_ms'),
        timing_parse_error=timing_parse_error,
    )


def run_workflow_steps(
    steps: list[tuple[str, list[str]]],   # [(step_name, full_cmd), ...]
    log_dir: Path,
    iter_tag: str,
    tmpdir: Path,
    taskset_cpu: Optional[str],
    perf_available: bool,
    perf_events: str,
    timing_debug: bool = False,
) -> RunResult:
    """
    Run multiple full_cmd commands sequentially; aggregate wall time and max RSS.
    When timing_debug=True, per-step timing breakdowns are stored in the returned
    RunResult.step_results as a list of (step_name, RunResult) pairs.
    The aggregate cli_wall_time_ms is unchanged: sum of per-step GNU time wall times.
    """
    named_step_results: list[tuple[str, RunResult]] = []
    for i, (step_name, full_cmd) in enumerate(steps):
        step_tag = f'{iter_tag}_step{i+1:02d}_{step_name}'
        r = run_timed(full_cmd, log_dir=log_dir, iter_tag=step_tag, tmpdir=tmpdir,
                      taskset_cpu=taskset_cpu, perf_available=perf_available,
                      perf_events=perf_events, timing_debug=timing_debug)
        named_step_results.append((step_name, r))
        if r.exit_code != 0:
            log.warning('Workflow step %s exited %d', step_name, r.exit_code)
            break

    step_rr = [r for _, r in named_step_results]
    last    = step_rr[-1]
    walls   = [r.cli_wall_time_ms for r in step_rr if r.cli_wall_time_ms is not None]
    rss     = [r.peak_rss_kb      for r in step_rr if r.peak_rss_kb is not None]

    def _sum(vals: list) -> Optional[float]:
        return sum(r or 0 for r in vals) or None

    return RunResult(
        exit_code=last.exit_code,
        cli_wall_time_ms=sum(walls) if walls else None,
        peak_rss_kb=max(rss) if rss else None,
        user_cpu_s=_sum([r.user_cpu_s for r in step_rr]),
        sys_cpu_s=_sum([r.sys_cpu_s for r in step_rr]),
        cpu_pct=max((r.cpu_pct or 0) for r in step_rr) or None,
        context_switches=_sum([r.context_switches for r in step_rr]),
        page_faults=_sum([r.page_faults for r in step_rr]),
        task_clock=_sum([r.task_clock for r in step_rr]),
        cpu_clock=_sum([r.cpu_clock for r in step_rr]),
        step_results=named_step_results,
    )


# ── Artifact sizes ─────────────────────────────────────────────────────────────

@dataclass
class ArtifactSizes:
    out_pub_key_pem: int = 0;   out_pub_key_der: int = 0
    out_priv_key_pem: int = 0;  out_priv_key_der: int = 0
    out_alt_pub_pem: int = 0;   out_alt_pub_der: int = 0
    out_alt_priv_pem: int = 0;  out_alt_priv_der: int = 0
    out_cert_pem: int = 0;      out_cert_der: int = 0
    out_csr_pem: int = 0;       out_csr_der: int = 0
    out_int_cert_pem: int = 0;  out_int_cert_der: int = 0
    out_leaf_cert_pem: int = 0; out_leaf_cert_der: int = 0
    out_chain_total_pem: int = 0; out_chain_total_der: int = 0
    out_related_cert_pem: int = 0; out_related_cert_der: int = 0
    input_leaf_cert_pem: int = 0;  input_leaf_cert_der: int = 0
    input_int_pem: int = 0;        input_int_der: int = 0
    input_root_pem: int = 0;       input_root_der: int = 0
    input_untrusted_pem: int = 0;  input_untrusted_der_total: int = 0
    input_trust_pem: int = 0;      input_trust_der_total: int = 0
    input_related_pem: int = 0;    input_related_der: int = 0


def measure_produced(s: Path, op: str, is_hybrid: bool = False) -> ArtifactSizes:
    sz = ArtifactSizes()
    if op == 'keygen':
        sz.out_pub_key_pem,  sz.out_pub_key_der  = _mf(s / 'key_public_key.pem')
        sz.out_priv_key_pem, sz.out_priv_key_der = _mf(s / 'key_private_key.pem')
        if is_hybrid:
            sz.out_alt_pub_pem,  sz.out_alt_pub_der  = _mf(s / 'key_alt_public_key.pem')
            sz.out_alt_priv_pem, sz.out_alt_priv_der = _mf(s / 'key_alt_private_key.pem')
    elif op == 'cert':
        sz.out_cert_pem,     sz.out_cert_der     = _mf(s / 'cert_certificate.pem')
        sz.out_pub_key_pem,  sz.out_pub_key_der  = _mf(s / 'cert_public_key.pem')
        sz.out_priv_key_pem, sz.out_priv_key_der = _mf(s / 'cert_private_key.pem')
        if is_hybrid:
            sz.out_alt_pub_pem,  sz.out_alt_pub_der  = _mf(s / 'cert_alt_public_key.pem')
            sz.out_alt_priv_pem, sz.out_alt_priv_der = _mf(s / 'cert_alt_private_key.pem')
    elif op == 'csr':
        sz.out_csr_pem,      sz.out_csr_der      = _mf(s / 'csr_csr.pem')
        sz.out_pub_key_pem,  sz.out_pub_key_der  = _mf(s / 'csr_public_key.pem')
        sz.out_priv_key_pem, sz.out_priv_key_der = _mf(s / 'csr_private_key.pem')
        if is_hybrid:
            sz.out_alt_pub_pem,  sz.out_alt_pub_der  = _mf(s / 'csr_alt_public_key.pem')
            sz.out_alt_priv_pem, sz.out_alt_priv_der = _mf(s / 'csr_alt_private_key.pem')
    elif op == 'sign-leaf':
        sz.out_cert_pem, sz.out_cert_der = _mf(s / 'signed_certificate.pem')
    elif op == 'sign-intermediate-ca':
        sz.out_cert_pem, sz.out_cert_der = _mf(s / 'issigned_certificate.pem')
    elif op == 'workflow-2tier':
        ca_pem, ca_der = _mf(s / 'wf2_ca_certificate.pem')
        ee_pem, ee_der = _mf(s / 'wf2_signed_certificate.pem')
        sz.out_cert_pem       = ca_pem; sz.out_cert_der = ca_der
        sz.out_leaf_cert_pem  = ee_pem; sz.out_leaf_cert_der = ee_der
        sz.out_chain_total_pem = ca_pem + ee_pem
        sz.out_chain_total_der = ca_der + ee_der
    elif op == 'workflow-3tier':
        root_pem, root_der = _mf(s / 'wf3_root_certificate.pem')
        int_pem,  int_der  = _mf(s / 'wf3_int_certificate.pem')
        leaf_pem, leaf_der = _mf(s / 'wf3_leaf_certificate.pem')
        sz.out_cert_pem      = root_pem; sz.out_cert_der = root_der
        sz.out_int_cert_pem  = int_pem;  sz.out_int_cert_der = int_der
        sz.out_leaf_cert_pem = leaf_pem; sz.out_leaf_cert_der = leaf_der
        sz.out_chain_total_pem = root_pem + int_pem + leaf_pem
        sz.out_chain_total_der = root_der + int_der + leaf_der
    return sz


def measure_verify_inputs(s: Path, op: str) -> ArtifactSizes:
    sz = ArtifactSizes()
    if op == 'verify-selfsigned':
        sz.input_leaf_cert_pem, sz.input_leaf_cert_der = _mf(s / 'cert_certificate.pem')
    elif op == 'verify-issued':
        sz.input_leaf_cert_pem, sz.input_leaf_cert_der = _mf(s / 'vcert_leaf_certificate.pem')
        sz.input_root_pem,      sz.input_root_der      = _mf(s / 'vcert_ca_certificate.pem')
    elif op in ('verify-modeA-chain', 'verify-modeB-strict', 'verify-dynamic'):
        sz.input_leaf_cert_pem, sz.input_leaf_cert_der = _mf(s / 'cv_leaf_certificate.pem')
        sz.input_int_pem,       sz.input_int_der       = _mf(s / 'cv_int_certificate.pem')
        sz.input_root_pem,      sz.input_root_der      = _mf(s / 'cv_root_certificate.pem')
    elif op == 'verify-modeB-direct':
        sz.input_leaf_cert_pem, sz.input_leaf_cert_der = _mf(s / 'direct_leaf_certificate.pem')
        sz.input_root_pem,      sz.input_root_der      = _mf(s / 'direct_root_certificate.pem')
    return sz


# ── CSV / JSONL output ─────────────────────────────────────────────────────────

ITER_FIELDS = [
    'timestamp_utc', 'pqcli_jar', 'jar_sha256', 'java_version', 'os_kernel',
    'certificate_mode', 'primitive_standard_scope', 'profile',
    'operation', 'algo_tag', 'cert_profile', 'iter_index', 'warmup',
    'exit_code',
    'cli_wall_time_ms', 'peak_rss_kb',
    'user_cpu_s', 'sys_cpu_s', 'cpu_pct', 'context_switches', 'page_faults',
    'task_clock', 'cpu_clock',
    # Output artifact sizes
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
    # Input artifact sizes (verify ops)
    'input_leaf_cert_pem_bytes', 'input_leaf_cert_der_bytes',
    'input_int_pem_bytes', 'input_int_der_bytes',
    'input_root_pem_bytes', 'input_root_der_bytes',
    'input_untrusted_pem_bytes', 'input_untrusted_der_total_bytes',
    'input_trust_pem_bytes', 'input_trust_der_total_bytes',
    'input_related_pem_bytes', 'input_related_der_bytes',
    'error',
    'stdout_path', 'stderr_path', 'timev_path', 'perf_path',
]

# Consolidated CSV schemas — explicit field lists for measured_iterations.csv and
# sizing_measurements.csv.  These use only fields that are present in every row
# (via base_common or make_row) plus two deliberately-added fields (run_id, mode).
# Environment-level fields (pqcli_jar, jar_sha256, java_version, os_kernel) are
# excluded; they belong in metadata.json.
#
# Verified: all 32 artifact size fields in ITER_FIELDS end in _pem_bytes,
# _der_bytes, or _der_total_bytes.  peak_rss_kb ends in _kb and belongs in
# MACRO_MEASURED_FIELDS, not MACRO_SIZE_FIELDS.

_MACRO_ID_FIELDS = [
    'run_id', 'timestamp_utc', 'profile', 'mode',
    'algo_tag', 'certificate_mode', 'primitive_standard_scope',
    'operation', 'cert_profile', 'iter_index', 'warmup',
    'success', 'exit_code',
]

MACRO_MEASURED_FIELDS = _MACRO_ID_FIELDS + [
    'cli_wall_time_ms', 'peak_rss_kb',
    'user_cpu_s', 'sys_cpu_s', 'cpu_pct', 'context_switches', 'page_faults',
    'task_clock', 'cpu_clock',
    'error',
    'stdout_path', 'stderr_path', 'timev_path', 'perf_path',
]

MACRO_SIZE_FIELDS = _MACRO_ID_FIELDS + [
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
    'input_leaf_cert_pem_bytes', 'input_leaf_cert_der_bytes',
    'input_int_pem_bytes', 'input_int_der_bytes',
    'input_root_pem_bytes', 'input_root_der_bytes',
    'input_untrusted_pem_bytes', 'input_untrusted_der_total_bytes',
    'input_trust_pem_bytes', 'input_trust_der_total_bytes',
    'input_related_pem_bytes', 'input_related_der_bytes',
]


# startup_breakdown.csv — one row per actual java -jar subprocess invocation.
# Written only when --timing-debug is active. Never mixed into measured_iterations.csv.
# measured_unattributed_ms = cli_wall_time_ms - timing_call_returning_ms.
# This is NOT a clean phase: it includes OS process creation overhead, JVM
# initialization before PqCliCommand.T0, JVM shutdown, and the measurement
# boundary gap between the last [TIMING] line and GNU time's wall clock endpoint.
STARTUP_BREAKDOWN_FIELDS = [
    'run_id', 'timestamp_utc', 'suite', 'profile', 'mode',
    'algo_tag', 'operation', 'iter_index', 'warmup',
    'step_index', 'step_name', 'is_workflow_step',
    'cli_wall_time_ms', 'peak_rss_kb', 'exit_code',
    'timing_main_entry_ms', 'timing_commandline_constructed_ms',
    'timing_call_entered_ms', 'timing_setupProvider_entered_ms',
    'timing_bc_registered_ms', 'timing_bcpqc_registered_ms',
    'timing_command_body_start_ms', 'timing_call_returning_ms',
    'startup_picocli_ms', 'dispatch_to_call_ms',
    'provider_total_ms', 'bc_provider_ms', 'bcpqc_provider_ms',
    'command_body_ms', 'measured_unattributed_ms',
    'stderr_path', 'timev_path', 'parse_error',
]


def make_row(*, common: dict, operation: str, iter_index: int, warmup: bool,
             result: RunResult, sizes: ArtifactSizes) -> dict:
    ts = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())
    sz = sizes
    row = {**common}
    row.update({
        'timestamp_utc': ts,
        'operation': operation,
        'iter_index': iter_index,
        'warmup': '1' if warmup else '0',
        'exit_code': result.exit_code,
        'cli_wall_time_ms': result.cli_wall_time_ms if result.cli_wall_time_ms is not None else '',
        'peak_rss_kb': result.peak_rss_kb if result.peak_rss_kb is not None else '',
        'user_cpu_s': result.user_cpu_s if result.user_cpu_s is not None else '',
        'sys_cpu_s': result.sys_cpu_s if result.sys_cpu_s is not None else '',
        'cpu_pct': result.cpu_pct if result.cpu_pct is not None else '',
        'context_switches': result.context_switches if result.context_switches is not None else '',
        'page_faults': result.page_faults if result.page_faults is not None else '',
        'task_clock': result.task_clock if result.task_clock is not None else '',
        'cpu_clock': result.cpu_clock if result.cpu_clock is not None else '',
        'out_pub_key_pem_bytes': sz.out_pub_key_pem, 'out_pub_key_der_bytes': sz.out_pub_key_der,
        'out_priv_key_pem_bytes': sz.out_priv_key_pem, 'out_priv_key_der_bytes': sz.out_priv_key_der,
        'out_alt_pub_pem_bytes': sz.out_alt_pub_pem, 'out_alt_pub_der_bytes': sz.out_alt_pub_der,
        'out_alt_priv_pem_bytes': sz.out_alt_priv_pem, 'out_alt_priv_der_bytes': sz.out_alt_priv_der,
        'out_cert_pem_bytes': sz.out_cert_pem, 'out_cert_der_bytes': sz.out_cert_der,
        'out_csr_pem_bytes': sz.out_csr_pem, 'out_csr_der_bytes': sz.out_csr_der,
        'out_int_cert_pem_bytes': sz.out_int_cert_pem, 'out_int_cert_der_bytes': sz.out_int_cert_der,
        'out_leaf_cert_pem_bytes': sz.out_leaf_cert_pem, 'out_leaf_cert_der_bytes': sz.out_leaf_cert_der,
        'out_chain_total_pem_bytes': sz.out_chain_total_pem, 'out_chain_total_der_bytes': sz.out_chain_total_der,
        'out_related_cert_pem_bytes': sz.out_related_cert_pem, 'out_related_cert_der_bytes': sz.out_related_cert_der,
        'input_leaf_cert_pem_bytes': sz.input_leaf_cert_pem, 'input_leaf_cert_der_bytes': sz.input_leaf_cert_der,
        'input_int_pem_bytes': sz.input_int_pem, 'input_int_der_bytes': sz.input_int_der,
        'input_root_pem_bytes': sz.input_root_pem, 'input_root_der_bytes': sz.input_root_der,
        'input_untrusted_pem_bytes': sz.input_untrusted_pem, 'input_untrusted_der_total_bytes': sz.input_untrusted_der_total,
        'input_trust_pem_bytes': sz.input_trust_pem, 'input_trust_der_total_bytes': sz.input_trust_der_total,
        'input_related_pem_bytes': sz.input_related_pem, 'input_related_der_bytes': sz.input_related_der,
        'error': '' if result.exit_code == 0 else f'exit {result.exit_code}',
        'stdout_path': str(result.stdout_path) if result.stdout_path else '',
        'stderr_path': str(result.stderr_path) if result.stderr_path else '',
        'timev_path': str(result.timev_path) if result.timev_path else '',
        'perf_path': str(result.perf_path) if result.perf_path else '',
    })
    return row


class ResultWriter:
    def __init__(self, macro_dir: Path):
        self.macro_dir = macro_dir
        self.jsonl_path = macro_dir / 'raw_iterations.jsonl'
        self.skips_path = macro_dir / 'skips.csv'
        self._skip_file = None
        self._skip_w = None
        # Consolidated CSVs — opened immediately so headers exist even with zero rows.
        self._meas_file = open(macro_dir / 'measured_iterations.csv', 'w', newline='')
        self._meas_w = csv.DictWriter(self._meas_file,
            fieldnames=MACRO_MEASURED_FIELDS, extrasaction='ignore')
        self._meas_w.writeheader()
        self._size_file = open(macro_dir / 'sizing_measurements.csv', 'w', newline='')
        self._size_w = csv.DictWriter(self._size_file,
            fieldnames=MACRO_SIZE_FIELDS, extrasaction='ignore')
        self._size_w.writeheader()
        # startup_breakdown.csv — opened lazily on first write_breakdown_row() call.
        self._breakdown_file = None
        self._breakdown_w: Optional[csv.DictWriter] = None
        # dual_step_breakdown.csv — opened lazily; contains raw RFC 9763 stage rows
        # (diagnostic only; NOT in measured_iterations.csv or summary.csv).
        self._dual_step_file = None
        self._dual_step_w: Optional[csv.DictWriter] = None

    def write_row(self, row: dict, csv_w: csv.DictWriter) -> None:
        """Write a measured iteration row to CSV, raw_iterations.jsonl, and consolidated CSVs."""
        csv_w.writerow({k: row.get(k, '') for k in ITER_FIELDS})
        with open(self.jsonl_path, 'a') as f:
            f.write(json.dumps({k: (str(v) if v is not None else None)
                                for k, v in row.items()}) + '\n')
        # success: exit_code may be int or str; normalize to avoid type mismatch.
        _ec = row.get('exit_code', '')
        _ec_s = str(_ec) if _ec != '' else ''
        success = '1' if _ec_s == '0' else ('0' if _ec_s != '' else '')
        row_ext = {**row, 'success': success}
        self._meas_w.writerow({k: row_ext.get(k, '') for k in MACRO_MEASURED_FIELDS})
        self._size_w.writerow({k: row_ext.get(k, '') for k in MACRO_SIZE_FIELDS})
        self._meas_file.flush()
        self._size_file.flush()

    def write_warmup(self, row: dict, csv_w: csv.DictWriter) -> None:
        """Write a warmup iteration row to per-op CSV only — NOT to consolidated CSVs or JSONL."""
        csv_w.writerow({k: row.get(k, '') for k in ITER_FIELDS})

    def write_breakdown_row(self, row: dict) -> None:
        """Write one row to startup_breakdown.csv (opened lazily). warmup rows included."""
        if self._breakdown_file is None:
            self._breakdown_file = open(
                self.macro_dir / 'startup_breakdown.csv', 'w', newline='')
            self._breakdown_w = csv.DictWriter(
                self._breakdown_file,
                fieldnames=STARTUP_BREAKDOWN_FIELDS, extrasaction='ignore')
            self._breakdown_w.writeheader()
        self._breakdown_w.writerow({k: row.get(k, '') for k in STARTUP_BREAKDOWN_FIELDS})
        self._breakdown_file.flush()

    def write_dual_step_row(self, row: dict, csv_w: csv.DictWriter) -> None:
        """Write a dual stage row to per-op CSV and dual_step_breakdown.csv.
        NOT written to measured_iterations.csv — diagnostic only."""
        csv_w.writerow({k: row.get(k, '') for k in ITER_FIELDS})
        if self._dual_step_file is None:
            self._dual_step_file = open(
                self.macro_dir / 'dual_step_breakdown.csv', 'w', newline='')
            self._dual_step_w = csv.DictWriter(
                self._dual_step_file,
                fieldnames=MACRO_MEASURED_FIELDS, extrasaction='ignore')
            self._dual_step_w.writeheader()
        _ec = row.get('exit_code', '')
        _ec_s = str(_ec) if _ec != '' else ''
        success = '1' if _ec_s == '0' else ('0' if _ec_s != '' else '')
        self._dual_step_w.writerow({k: {**row, 'success': success}.get(k, '') for k in MACRO_MEASURED_FIELDS})
        self._dual_step_file.flush()

    def write_measured_only(self, row: dict) -> None:
        """Write a row directly to measured_iterations.csv and sizing_measurements.csv.
        Used for dual canonical-op aggregated rows."""
        _ec = row.get('exit_code', '')
        _ec_s = str(_ec) if _ec != '' else ''
        success = '1' if _ec_s == '0' else ('0' if _ec_s != '' else '')
        row_ext = {**row, 'success': success}
        self._meas_w.writerow({k: row_ext.get(k, '') for k in MACRO_MEASURED_FIELDS})
        self._size_w.writerow({k: row_ext.get(k, '') for k in MACRO_SIZE_FIELDS})
        self._meas_file.flush()
        self._size_file.flush()

    def skip(self, algo_tag: str, step: str, exit_code: int, reason: str) -> None:
        if self._skip_file is None:
            self._skip_file = open(self.skips_path, 'w', newline='')
            self._skip_w = csv.DictWriter(self._skip_file,
                fieldnames=['algo_tag', 'failed_step', 'exit_code', 'reason'])
            self._skip_w.writeheader()
        self._skip_w.writerow({'algo_tag': algo_tag, 'failed_step': step,
                               'exit_code': exit_code, 'reason': reason})
        self._skip_file.flush()

    def close(self):
        if self._skip_file:
            self._skip_file.close()
        self._meas_file.close()
        self._size_file.close()
        if self._breakdown_file:
            self._breakdown_file.close()
        if self._dual_step_file:
            self._dual_step_file.close()


# ── Preflight ──────────────────────────────────────────────────────────────────

def detect_bc_version(pqcli_dir: Path) -> Optional[str]:
    pom = pqcli_dir / 'pom.xml'
    if not pom.exists():
        return None
    text = pom.read_text(errors='replace')
    m = re.search(r'bcprov-jdk18on[\s\S]{0,300}?<version>([^<]+)</version>', text)
    return m.group(1).strip() if m else None


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


def collect_system_metadata() -> dict:
    meta: dict = {}
    try:
        meta['hostname'] = socket.gethostname()
    except Exception:
        meta['hostname'] = 'unknown'
    try:
        meta['os'] = subprocess.check_output(['uname', '-srv'], text=True).strip()
    except Exception:
        meta['os'] = 'unknown'
    try:
        meta['cpu_model'] = subprocess.check_output(
            ['grep', '-m1', 'model name', '/proc/cpuinfo'], text=True
        ).strip().split(':', 1)[-1].strip()
    except Exception:
        meta['cpu_model'] = 'unknown'
    try:
        meta['cpu_cores_logical'] = int(subprocess.check_output(['nproc'], text=True).strip())
    except Exception:
        meta['cpu_cores_logical'] = 'unknown'
    try:
        meta['ram_kb'] = int(
            subprocess.check_output(['grep', 'MemTotal', '/proc/meminfo'], text=True).split()[1])
    except Exception:
        meta['ram_kb'] = 'unknown'
    for path, key in [
        ('/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor', 'cpu_governor'),
        ('/sys/devices/system/cpu/smt/active', 'smt_active'),
    ]:
        try:
            meta[key] = Path(path).read_text().strip()
        except Exception:
            meta[key] = 'unknown'
    meta['turbo_boost'] = 'not_detectable'
    try:
        aff = subprocess.check_output(['taskset', '-p', str(os.getpid())], text=True)
        meta['cpu_affinity_hex'] = aff.strip().split()[-1]
    except Exception:
        meta['cpu_affinity_hex'] = 'unknown'
    try:
        meta['openssl_version'] = subprocess.check_output(
            ['openssl', 'version'], text=True).strip()
    except Exception:
        meta['openssl_version'] = 'not found'
    try:
        meta['hyperfine_version'] = subprocess.check_output(
            ['hyperfine', '--version'], text=True).strip()
    except Exception:
        meta['hyperfine_version'] = 'not found'
    return meta


def check_timev(tmpdir: Path) -> bool:
    f = tmpdir / '_tv_check.txt'
    try:
        r = subprocess.run(['/usr/bin/time', '-v', '--output', str(f), 'true'],
                           capture_output=True)
        if r.returncode != 0:
            return False
        text = f.read_text(errors='replace') if f.exists() else ''
        return 'Maximum resident set size' in text
    except Exception:
        return False
    finally:
        f.unlink(missing_ok=True)


def check_software_perf() -> bool:
    try:
        r = subprocess.run(
            ['perf', 'stat', '-e', 'task-clock,cpu-clock', '--', 'true'],
            capture_output=True, timeout=10)
        return r.returncode == 0
    except Exception:
        return False


def check_taskset(cpu: str) -> bool:
    try:
        return subprocess.run(['taskset', '-c', cpu, 'true'],
                              capture_output=True).returncode == 0
    except Exception:
        return False


def preflight_algo(jar: Path, jvm_flags: list[str], cli_syntax: str) -> tuple[bool, str]:
    with tempfile.TemporaryDirectory() as td:
        r = subprocess.run(
            _pqcli_cmd(jar, jvm_flags, ['key', '-newkey', cli_syntax,
                                        '-out', str(Path(td) / 'pf')]),
            capture_output=True, timeout=120)
        if r.returncode != 0:
            err = r.stderr.decode(errors='replace')[:200]
            return False, f'exit {r.returncode}: {err}'
        return True, 'ok'


# ── Pre-generation ─────────────────────────────────────────────────────────────

def _run_quiet(jar: Path, jvm_flags: list[str], pqcli_args: list[str],
               pregen_dir: Path, step: str, taskset_cpu: Optional[str]) -> bool:
    """Run a pqcli command quietly for pre-generation; persist stdout/stderr."""
    cmd = []
    if taskset_cpu:
        cmd += ['taskset', '-c', taskset_cpu]
    cmd += _pqcli_cmd(jar, jvm_flags, pqcli_args)
    for d in ('stdout', 'stderr'):
        (pregen_dir / d).mkdir(parents=True, exist_ok=True)
    with open(pregen_dir / 'stdout' / f'{step}.log', 'wb') as fo, \
         open(pregen_dir / 'stderr' / f'{step}.log', 'wb') as fe:
        r = subprocess.run(cmd, stdout=fo, stderr=fe, timeout=300)
    if r.returncode != 0:
        log.debug('[PREGEN FAIL] %s: exit %d', step, r.returncode)
    return r.returncode == 0


def pregen_single_algo(cfg: AlgoConfig, algo_dir: Path, jar: Path,
                       jvm_flags: list[str], writer: ResultWriter,
                       taskset_cpu: Optional[str]) -> dict[str, bool]:
    """
    Pre-generate all artifacts needed for a single-algorithm config.
    Returns op -> success mapping.
    """
    tag = cfg.tag
    algo = cfg.cli_syntax
    h = cfg.is_hybrid
    s = algo_dir
    pregen_dir = algo_dir / 'pregeneration'
    pregen_dir.mkdir(parents=True, exist_ok=True)
    (pregen_dir / 'command.log').write_text(f'tag={tag} algo={algo}\n')

    def run(step: str, args: list[str]) -> bool:
        ok = _run_quiet(jar, jvm_flags, args, pregen_dir, step, taskset_cpu)
        if not ok:
            writer.skip(tag, step, -1, f'pre-gen {step} failed')
        return ok

    ok: dict[str, bool] = {}

    # Self-signed cert (used by cert op, verify-selfsigned, and as fallback for verify-issued)
    ok['cert'] = run('cert',
        ['cert', '-newkey', algo, '-subj', f'/CN=Bench-{tag}', '-out', str(s / 'cert')])

    # sign-leaf: CA cert + EE CSR
    ok_sigca = run('sigca', ['cert', '-newkey', algo, '-subj', f'/CN=SignCA-{tag}',
                             '-out', str(s / 'sigca')])
    ok_sigee = run('sigee', ['csr', '-newkey', algo, '-subj', f'/CN=SignEE-{tag}',
                             '-out', str(s / 'sigee')])
    ok['sign-leaf'] = ok_sigca and ok_sigee

    # sign-intermediate-ca: root + int CSR
    ok_isr = run('isroot', ['cert', '-newkey', algo, '-subj', f'/CN=ISRoot-{tag}',
                            '-out', str(s / 'isroot')])
    ok_isi = run('isint',  ['csr',  '-newkey', algo, '-subj', f'/CN=ISInt-{tag}',
                            '-out', str(s / 'isint')])
    ok['sign-intermediate-ca'] = ok_isr and ok_isi

    # verify-issued: CA + signed leaf
    ok_vca = run('vcert_ca', ['cert', '-newkey', algo, '-subj', f'/CN=VCertCA-{tag}',
                              '-out', str(s / 'vcert_ca')])
    if ok_vca:
        ok_vcsr = run('vcert_leaf_csr', ['csr', '-newkey', algo, '-subj', f'/CN=VLeaf-{tag}',
                                         '-out', str(s / 'vcert_leaf_csr')])
        if ok_vcsr:
            sign_args = ['sign', '-csr', str(s / 'vcert_leaf_csr_csr.pem'),
                         '-CAcert', str(s / 'vcert_ca_certificate.pem'),
                         '-CAkey',  str(s / 'vcert_ca_private_key.pem'),
                         '--profile', 'leaf', '-out', str(s / 'vcert_leaf')]
            if h and (s / 'vcert_ca_alt_private_key.pem').exists():
                sign_args += ['-CAaltkey', str(s / 'vcert_ca_alt_private_key.pem')]
            ok['verify-issued'] = run('vcert_leaf', sign_args)
        else:
            ok['verify-issued'] = False
    else:
        ok['verify-issued'] = False

    # 3-tier chain (cv_ prefix) — shared for modeA-chain, modeB-strict, modeB-dynamic
    ok_cr = run('cv_root', ['cert', '-newkey', algo, '-subj', f'/CN=CVRoot-{tag}',
                            '-out', str(s / 'cv_root')])
    if ok_cr:
        ok_ci_csr = run('cv_int_csr', ['csr', '-newkey', algo, '-subj', f'/CN=CVInt-{tag}',
                                       '-out', str(s / 'cv_int_csr')])
        if ok_ci_csr:
            int_sign = ['sign', '-csr', str(s / 'cv_int_csr_csr.pem'),
                        '-CAcert', str(s / 'cv_root_certificate.pem'),
                        '-CAkey',  str(s / 'cv_root_private_key.pem'),
                        '--profile', 'intermediate-ca', '-out', str(s / 'cv_int')]
            if h and (s / 'cv_root_alt_private_key.pem').exists():
                int_sign += ['-CAaltkey', str(s / 'cv_root_alt_private_key.pem')]
            ok_ci = run('cv_int', int_sign)
            if ok_ci:
                ok_cl_csr = run('cv_leaf_csr', ['csr', '-newkey', algo,
                                                '-subj', f'/CN=CVLeaf-{tag}',
                                                '-out', str(s / 'cv_leaf_csr')])
                if ok_cl_csr:
                    leaf_sign = ['sign', '-csr', str(s / 'cv_leaf_csr_csr.pem'),
                                 '-CAcert', str(s / 'cv_int_certificate.pem'),
                                 '-CAkey',  str(s / 'cv_int_csr_private_key.pem'),
                                 '--profile', 'leaf', '-out', str(s / 'cv_leaf')]
                    if h and (s / 'cv_int_csr_alt_private_key.pem').exists():
                        leaf_sign += ['-CAaltkey', str(s / 'cv_int_csr_alt_private_key.pem')]
                    chain_ok = run('cv_leaf', leaf_sign)
                else:
                    chain_ok = False
            else:
                chain_ok = False
        else:
            chain_ok = False
    else:
        chain_ok = False
    ok['verify-modeA-chain']   = chain_ok
    ok['verify-modeB-strict']  = chain_ok
    ok['verify-dynamic'] = chain_ok

    # verify-modeB-direct: root signs leaf directly
    ok_dr = run('direct_root', ['cert', '-newkey', algo, '-subj', f'/CN=DRoot-{tag}',
                                '-out', str(s / 'direct_root')])
    if ok_dr:
        ok_dl_csr = run('direct_leaf_csr', ['csr', '-newkey', algo,
                                            '-subj', f'/CN=DLeaf-{tag}',
                                            '-out', str(s / 'direct_leaf_csr')])
        if ok_dl_csr:
            dl_sign = ['sign', '-csr', str(s / 'direct_leaf_csr_csr.pem'),
                       '-CAcert', str(s / 'direct_root_certificate.pem'),
                       '-CAkey',  str(s / 'direct_root_private_key.pem'),
                       '--profile', 'leaf', '-out', str(s / 'direct_leaf')]
            if h and (s / 'direct_root_alt_private_key.pem').exists():
                dl_sign += ['-CAaltkey', str(s / 'direct_root_alt_private_key.pem')]
            ok['verify-modeB-direct'] = run('direct_leaf', dl_sign)
        else:
            ok['verify-modeB-direct'] = False
    else:
        ok['verify-modeB-direct'] = False

    return ok


# ── Dual / RFC 9763 pre-generation ────────────────────────────────────────────

def pregen_dual_config(dc: DualConfig, dual_dir: Path, jar: Path,
                       jvm_flags: list[str], writer: ResultWriter,
                       taskset_cpu: Optional[str]) -> dict[str, bool]:
    """
    Pre-generate all RFC 9763 dual-workflow artifacts for a DualConfig.

    Pregen produces stable artifacts used as inputs across all measured iterations.
    Benchmarked sign/csr operations write to distinct per-iteration output prefixes
    (bench_s2, bench_s3csr, bench_s4) so they never overwrite pregen artifacts.

    Returns an op-availability map: op -> bool (False means skip all iterations).
    """
    tag      = dc.tag
    primary  = dc.primary_algo
    related  = dc.related_algo
    s        = dual_dir
    pregen_d = dual_dir / 'pregeneration'
    pregen_d.mkdir(parents=True, exist_ok=True)
    (pregen_d / 'command.log').write_text(
        f'tag={tag}\nprimary={primary}\nrelated={related}\n')

    def run(step: str, args: list[str]) -> bool:
        ok = _run_quiet(jar, jvm_flags, args, pregen_d, step, taskset_cpu)
        if not ok:
            log.warning('[DUAL PREGEN FAIL] %s/%s', tag, step)
            writer.skip(tag, step, -1, f'dual pregeneration failed: {step}')
        return ok

    log.info('  [dual pregen] %s: generating RFC 9763 artifacts ...', tag)

    ok_ref      = run('ref_cert',   ['cert', '-newkey', related, '-subj', f'/CN=DualRef-{tag}',
                                     '-out', str(s / 'ref')])
    ok_ca_root  = run('ca_root',    ['cert', '-newkey', primary, '-subj', f'/CN=DualCA-{tag}',
                                     '-out', str(s / 'ca_root')])
    ok_int_csr  = run('int_csr',    ['csr',  '-newkey', primary, '-subj', f'/CN=DualInt-{tag}',
                                     '-out', str(s / 'int_csr')])

    ok_int_cert = False
    if ok_ca_root and ok_int_csr:
        ok_int_cert = run('int_cert', ['sign',
                                       '-csr',    str(s / 'int_csr_csr.pem'),
                                       '-CAcert', str(s / 'ca_root_certificate.pem'),
                                       '-CAkey',  str(s / 'ca_root_private_key.pem'),
                                       '--profile', 'intermediate-ca',
                                       '-out', str(s / 'int')])
    else:
        log.warning('  [dual pregen] %s/int_cert skipped — ca_root or int_csr failed', tag)

    ok_leaf_csr = run('leaf_csr',   ['csr',  '-newkey', primary, '-subj', f'/CN=DualLeaf-{tag}',
                                     '-out', str(s / 'leaf_csr')])

    ok_stage2_cert = False
    if ok_int_cert and ok_leaf_csr and ok_ref:
        ok_stage2_cert = run('stage2_cert', ['sign',
                                             '-csr',    str(s / 'leaf_csr_csr.pem'),
                                             '-CAcert', str(s / 'int_certificate.pem'),
                                             '-CAkey',  str(s / 'int_csr_private_key.pem'),
                                             '--profile', 'leaf',
                                             '--related-cert-test-extension', str(s / 'ref_certificate.pem'),
                                             '-out', str(s / 'stage2')])
    else:
        log.warning('  [dual pregen] %s/stage2_cert skipped — int_cert, leaf_csr, or ref_cert failed', tag)

    ok_stage3_csr = False
    if ok_ref:
        ok_stage3_csr = run('stage3_csr', ['csr', '-newkey', primary,
                                           '-subj', f'/CN=DualStage3-{tag}',
                                           '-out', str(s / 'stage3_csr'),
                                           '--related-cert', str(s / 'ref_certificate.pem'),
                                           '--related-cert-key', str(s / 'ref_private_key.pem'),
                                           '--related-cert-url', 'https://bench.example/ref'])
    else:
        log.warning('  [dual pregen] %s/stage3_csr skipped — ref_cert failed', tag)

    ok_stage4_cert = False
    if ok_stage3_csr and ok_int_cert and ok_ref:
        ok_stage4_cert = run('stage4_cert', ['sign',
                                             '-csr',    str(s / 'stage3_csr_csr.pem'),
                                             '-CAcert', str(s / 'int_certificate.pem'),
                                             '-CAkey',  str(s / 'int_csr_private_key.pem'),
                                             '--profile', 'leaf',
                                             '--related-cert', str(s / 'ref_certificate.pem'),
                                             '-out', str(s / 'stage4')])
    else:
        log.warning('  [dual pregen] %s/stage4_cert skipped — stage3_csr, int_cert, or ref_cert failed', tag)

    steps_ok = sum([ok_ref, ok_ca_root, ok_int_cert, ok_leaf_csr,
                    ok_stage2_cert, ok_stage3_csr, ok_stage4_cert])
    log.info('  [dual pregen] %s: %d/7 steps OK', tag, steps_ok)

    return {
        'rfc9763-stage2-sign':         ok_leaf_csr and ok_int_cert and ok_ref,
        'rfc9763-stage2-verify':       ok_stage2_cert and ok_ref,
        'rfc9763-stage3-csr':          ok_ref,
        'rfc9763-stage4-sign':         ok_stage3_csr and ok_int_cert and ok_ref,
        'rfc9763-stage4-chain-verify': ok_stage4_cert and ok_ca_root and ok_int_cert,
        'rfc9763-stage4-hash-verify':  ok_stage4_cert and ok_ref,
        'verify-modeB-strict':         ok_stage4_cert and ok_ca_root and ok_int_cert,
        'verify-dynamic':              ok_stage4_cert and ok_ca_root and ok_int_cert,
    }


def measure_dual_artifacts(s: Path, op: str) -> ArtifactSizes:
    """Map dual staging artifacts into ArtifactSizes using existing fields."""
    sz = ArtifactSizes()
    if op == 'rfc9763-stage2-sign':
        sz.out_cert_pem, sz.out_cert_der = _mf(s / 'bench_s2_certificate.pem')
    elif op == 'rfc9763-stage2-verify':
        sz.input_leaf_cert_pem, sz.input_leaf_cert_der = _mf(s / 'stage2_certificate.pem')
        sz.input_related_pem,   sz.input_related_der   = _mf(s / 'ref_certificate.pem')
    elif op == 'rfc9763-stage3-csr':
        sz.out_csr_pem, sz.out_csr_der = _mf(s / 'bench_s3csr_csr.pem')
    elif op == 'rfc9763-stage4-sign':
        sz.out_cert_pem,      sz.out_cert_der      = _mf(s / 'bench_s4_certificate.pem')
        sz.input_related_pem, sz.input_related_der = _mf(s / 'ref_certificate.pem')
    elif op in ('rfc9763-stage4-chain-verify', 'verify-modeB-strict', 'verify-dynamic'):
        sz.input_leaf_cert_pem, sz.input_leaf_cert_der = _mf(s / 'stage4_certificate.pem')
        sz.input_int_pem,       sz.input_int_der       = _mf(s / 'int_certificate.pem')
        sz.input_root_pem,      sz.input_root_der      = _mf(s / 'ca_root_certificate.pem')
    elif op == 'rfc9763-stage4-hash-verify':
        sz.input_leaf_cert_pem, sz.input_leaf_cert_der = _mf(s / 'stage4_certificate.pem')
        sz.input_related_pem,   sz.input_related_der   = _mf(s / 'ref_certificate.pem')
    return sz


def run_dual_op_iterations(
    *,
    dc: DualConfig,
    dual_ops: list[str],
    dual_dir: Path,
    macro_dir: Path,
    jar: Path,
    jvm_flags: list[str],
    tmpdir: Path,
    taskset_cpu: Optional[str],
    perf_available: bool,
    perf_events: str,
    warmup_count: int,
    measured_count: int,
    base_common: dict,
    writer: ResultWriter,
    pregen_ok_map: dict[str, bool],
    timing_debug: bool = False,
) -> None:
    """Run measured iterations for all dual ops of one DualConfig.

    Stage-level rows go to dual_step_breakdown.csv (diagnostic only).
    Aggregated canonical-op rows go to measured_iterations.csv.
    Aggregation: sum cli_wall_time_ms, max peak_rss_kb, per (canonical_op, iter_index).
    """
    s   = dual_dir
    tag = dc.tag

    common = {**base_common,
              'algo_tag': tag,
              'certificate_mode': 'dual-rfc9763',
              'primitive_standard_scope': 'RFC-9763-dual',
              'cert_profile': 'none'}

    def _rt(full_cmd: list[str], log_d: Path, it: str) -> RunResult:
        return run_timed(full_cmd, log_dir=log_d, iter_tag=it, tmpdir=tmpdir,
                         taskset_cpu=taskset_cpu, perf_available=perf_available,
                         perf_events=perf_events, timing_debug=timing_debug)

    # Accumulate measured stage rows: {canonical_op: {iter_index: [row, ...]}}
    canonical_accumulator: dict[str, dict[int, list[dict]]] = {}

    ops_total = len(dual_ops)
    for op_idx, op in enumerate(dual_ops):
        if not pregen_ok_map.get(op, False):
            log.info('  [SKIP] %s/%s — dual pregeneration failed', tag, op)
            writer.skip(tag, op, -1, f'dual pregeneration failed (required artifact unavailable)')
            continue

        canonical_op = DUAL_STAGE_TO_CANONICAL_OP.get(op, op)

        op_dir = macro_dir / tag / op
        op_dir.mkdir(parents=True, exist_ok=True)
        (op_dir / 'command.log').write_text(f'op={op} dual_tag={tag}\n')
        (op_dir / 'warmup').mkdir(exist_ok=True)

        log.info('  [dual op %d/%d] %s/%s → canonical=%s: %d iter + %d warmup',
                 op_idx+1, ops_total, tag, op, canonical_op, measured_count, warmup_count)

        total = warmup_count + measured_count
        with (open(op_dir / 'warmup_iterations.csv', 'w', newline='') as wf,
              open(op_dir / 'iterations.csv', 'w', newline='') as mf_):
            wcsv = csv.DictWriter(wf,  fieldnames=ITER_FIELDS, extrasaction='ignore')
            mcsv = csv.DictWriter(mf_, fieldnames=ITER_FIELDS, extrasaction='ignore')
            wcsv.writeheader()
            mcsv.writeheader()

            for idx in range(total):
                is_w     = idx < warmup_count
                meas_idx = idx - warmup_count if not is_w else idx
                tag_str  = f'warmup_{idx:03d}' if is_w else f'{meas_idx:03d}'
                log_d    = op_dir / ('warmup' if is_w else '')

                # Build CLI command for this dual op
                if op == 'rfc9763-stage2-sign':
                    cmd = _pqcli_cmd(jar, jvm_flags, [
                        'sign',
                        '-csr',    str(s / 'leaf_csr_csr.pem'),
                        '-CAcert', str(s / 'int_certificate.pem'),
                        '-CAkey',  str(s / 'int_csr_private_key.pem'),
                        '--profile', 'leaf',
                        '--related-cert-test-extension', str(s / 'ref_certificate.pem'),
                        '-out', str(s / 'bench_s2'),
                    ])
                elif op == 'rfc9763-stage2-verify':
                    cmd = _pqcli_cmd(jar, jvm_flags, [
                        'verify',
                        '-in', str(s / 'stage2_certificate.pem'),
                        '--related-cert', str(s / 'ref_certificate.pem'),
                    ])
                elif op == 'rfc9763-stage3-csr':
                    cmd = _pqcli_cmd(jar, jvm_flags, [
                        'csr',
                        '-newkey', dc.primary_algo,
                        '-subj', f'/CN=DualStage3-{tag}',
                        '-out', str(s / 'bench_s3csr'),
                        '--related-cert', str(s / 'ref_certificate.pem'),
                        '--related-cert-key', str(s / 'ref_private_key.pem'),
                        '--related-cert-url', 'https://bench.example/ref',
                    ])
                elif op == 'rfc9763-stage4-sign':
                    cmd = _pqcli_cmd(jar, jvm_flags, [
                        'sign',
                        '-csr',    str(s / 'stage3_csr_csr.pem'),
                        '-CAcert', str(s / 'int_certificate.pem'),
                        '-CAkey',  str(s / 'int_csr_private_key.pem'),
                        '--profile', 'leaf',
                        '--related-cert', str(s / 'ref_certificate.pem'),
                        '-out', str(s / 'bench_s4'),
                    ])
                elif op == 'rfc9763-stage4-chain-verify':
                    cmd = _pqcli_cmd(jar, jvm_flags, [
                        'verify',
                        '-in',    str(s / 'stage4_certificate.pem'),
                        '-chain', str(s / 'int_certificate.pem'),
                        '-trust', str(s / 'ca_root_certificate.pem'),
                    ])
                elif op == 'rfc9763-stage4-hash-verify':
                    cmd = _pqcli_cmd(jar, jvm_flags, [
                        'verify',
                        '-in', str(s / 'stage4_certificate.pem'),
                        '--related-cert', str(s / 'ref_certificate.pem'),
                    ])
                elif op == 'verify-modeB-strict':
                    cmd = _pqcli_cmd(jar, jvm_flags, [
                        'verify',
                        '-in',    str(s / 'stage4_certificate.pem'),
                        '-chain', str(s / 'int_certificate.pem'),
                        '-trust', str(s / 'ca_root_certificate.pem'),
                    ])
                elif op == 'verify-dynamic':
                    cmd = _pqcli_cmd(jar, jvm_flags, [
                        'verify',
                        '-in',        str(s / 'stage4_certificate.pem'),
                        '-untrusted', str(s / 'int_certificate.pem'),
                        '-trust',     str(s / 'ca_root_certificate.pem'),
                    ])
                else:
                    log.warning('Unknown dual op: %s', op)
                    continue

                result = _rt(cmd, log_d, tag_str)
                sizes  = measure_dual_artifacts(s, op)

                iter_idx = meas_idx if not is_w else idx
                row = make_row(common={**common, 'operation': op},
                               operation=op,
                               iter_index=iter_idx,
                               warmup=is_w,
                               result=result, sizes=sizes)

                if is_w:
                    writer.write_warmup(row, wcsv)
                else:
                    # Write stage row to diagnostic file only (NOT measured_iterations.csv)
                    writer.write_dual_step_row(row, mcsv)
                    if result.exit_code != 0:
                        log.warning('[FAIL] %s/%s iter %d: exit %d',
                                    tag, op, meas_idx, result.exit_code)
                    # Accumulate for canonical-op aggregation
                    canonical_accumulator.setdefault(canonical_op, {}).setdefault(meas_idx, []).append(row)

                if timing_debug:
                    writer.write_breakdown_row(_make_breakdown_row(
                        run_id=common.get('run_id', ''),
                        profile=common.get('profile', ''),
                        mode=common.get('mode', ''),
                        algo_tag=tag,
                        operation=op,
                        iter_index=iter_idx,
                        warmup=is_w,
                        step_index=0,
                        step_name=op,
                        is_workflow_step=False,
                        result=result,
                    ))

    # Emit aggregated canonical-op rows to measured_iterations.csv
    # For each (canonical_op, iter_index): sum wall times, max RSS.
    ts = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())
    for canonical_op, by_iter in sorted(canonical_accumulator.items()):
        for iter_idx, stage_rows in sorted(by_iter.items()):
            successful = [r for r in stage_rows if str(r.get('exit_code', '')) == '0']
            all_ok = len(successful) == len(stage_rows)

            def _f(val) -> Optional[float]:
                try: return float(val) if val not in ('', None) else None
                except (ValueError, TypeError): return None

            wall_times = [v for r in stage_rows if (v := _f(r.get('cli_wall_time_ms'))) is not None]
            rss_vals   = [v for r in stage_rows if (v := _f(r.get('peak_rss_kb')))      is not None]

            agg_wall = sum(wall_times) if wall_times else ''
            agg_rss  = max(rss_vals)   if rss_vals   else ''

            # Use last stage row as base for metadata fields; override with aggregated values
            base = stage_rows[-1]
            agg_row = {
                **{k: base.get(k, '') for k in MACRO_MEASURED_FIELDS},
                'timestamp_utc':     ts,
                'operation':         canonical_op,
                'iter_index':        iter_idx,
                'warmup':            '0',
                'exit_code':         0 if all_ok else 1,
                'cli_wall_time_ms':  round(agg_wall, 4) if agg_wall != '' else '',
                'peak_rss_kb':       agg_rss,
                # CPU/perf fields are not summable across processes; leave empty
                'user_cpu_s': '', 'sys_cpu_s': '', 'cpu_pct': '',
                'context_switches': '', 'page_faults': '',
                'task_clock': '', 'cpu_clock': '',
                'error': '' if all_ok else f'{len(stage_rows)-len(successful)} stage(s) failed',
                'stdout_path': '', 'stderr_path': '', 'timev_path': '', 'perf_path': '',
            }
            writer.write_measured_only(agg_row)


# ── Iteration runner ───────────────────────────────────────────────────────────

def run_op_iterations(
    *,
    op: str,
    cfg: AlgoConfig,
    algo_dir: Path,
    op_log_dir: Path,
    jar: Path,
    jvm_flags: list[str],
    tmpdir: Path,
    taskset_cpu: Optional[str],
    perf_available: bool,
    perf_events: str,
    warmup_count: int,
    measured_count: int,
    common: dict,
    writer: ResultWriter,
    meas_csv: csv.DictWriter,
    warm_csv: csv.DictWriter,
    pregen_ok: bool,
    pre_inputs: ArtifactSizes,
    op_idx: int = 0,
    ops_total: int = 0,
    timing_debug: bool = False,
) -> None:
    if not pregen_ok:
        log.info('  [SKIP] %s/%s — pre-generation failed', cfg.tag, op)
        return

    if ops_total > 0:
        log.info('  [op %d/%d] %s: %d iter + %d warmup',
                 op_idx+1, ops_total, op, measured_count, warmup_count)

    tag  = cfg.tag
    algo = cfg.cli_syntax
    h    = cfg.is_hybrid
    s    = algo_dir

    def _rt(full_cmd: list[str], log_d: Path, it: str) -> RunResult:
        return run_timed(full_cmd, log_dir=log_d, iter_tag=it, tmpdir=tmpdir,
                         taskset_cpu=taskset_cpu, perf_available=perf_available,
                         perf_events=perf_events, timing_debug=timing_debug)

    def _rwf(steps: list[tuple[str, list[str]]], log_d: Path, it: str) -> RunResult:
        return run_workflow_steps(steps, log_dir=log_d, iter_tag=it, tmpdir=tmpdir,
                                  taskset_cpu=taskset_cpu, perf_available=perf_available,
                                  perf_events=perf_events, timing_debug=timing_debug)

    total = warmup_count + measured_count
    for idx in range(total):
        is_w     = idx < warmup_count
        meas_idx = idx - warmup_count if not is_w else idx
        tag_str  = f'warmup_{idx:03d}' if is_w else f'{meas_idx:03d}'
        log_d    = op_log_dir / ('warmup' if is_w else '')

        result: RunResult
        sizes:  ArtifactSizes

        if op == 'keygen':
            result = _rt(_pqcli_cmd(jar, jvm_flags,
                ['key', '-newkey', algo, '-out', str(s / 'key')]), log_d, tag_str)
            sizes = measure_produced(s, 'keygen', h)

        elif op == 'cert':
            result = _rt(_pqcli_cmd(jar, jvm_flags,
                ['cert', '-newkey', algo, '-subj', f'/CN=Bench-{tag}',
                 '-out', str(s / 'cert')]), log_d, tag_str)
            sizes = measure_produced(s, 'cert', h)

        elif op == 'csr':
            result = _rt(_pqcli_cmd(jar, jvm_flags,
                ['csr', '-newkey', algo, '-subj', f'/CN=Bench-{tag}',
                 '-out', str(s / 'csr')]), log_d, tag_str)
            sizes = measure_produced(s, 'csr', h)

        elif op == 'sign-leaf':
            sign_args = ['sign', '-csr', str(s / 'sigee_csr.pem'),
                         '-CAcert', str(s / 'sigca_certificate.pem'),
                         '-CAkey',  str(s / 'sigca_private_key.pem'),
                         '--profile', 'leaf', '-out', str(s / 'signed')]
            if h and (s / 'sigca_alt_private_key.pem').exists():
                sign_args += ['-CAaltkey', str(s / 'sigca_alt_private_key.pem')]
            result = _rt(_pqcli_cmd(jar, jvm_flags, sign_args), log_d, tag_str)
            sizes  = measure_produced(s, 'sign-leaf', h)

        elif op == 'sign-intermediate-ca':
            sign_args = ['sign', '-csr', str(s / 'isint_csr.pem'),
                         '-CAcert', str(s / 'isroot_certificate.pem'),
                         '-CAkey',  str(s / 'isroot_private_key.pem'),
                         '--profile', 'intermediate-ca', '-out', str(s / 'issigned')]
            if h and (s / 'isroot_alt_private_key.pem').exists():
                sign_args += ['-CAaltkey', str(s / 'isroot_alt_private_key.pem')]
            result = _rt(_pqcli_cmd(jar, jvm_flags, sign_args), log_d, tag_str)
            sizes  = measure_produced(s, 'sign-intermediate-ca', h)

        elif op == 'verify-selfsigned':
            result = _rt(_pqcli_cmd(jar, jvm_flags,
                ['verify', '-in', str(s / 'cert_certificate.pem')]), log_d, tag_str)
            sizes = pre_inputs

        elif op == 'verify-issued':
            result = _rt(_pqcli_cmd(jar, jvm_flags,
                ['verify', '-in', str(s / 'vcert_leaf_certificate.pem'),
                 '-CAfile', str(s / 'vcert_ca_certificate.pem')]), log_d, tag_str)
            sizes = pre_inputs

        elif op == 'verify-modeA-chain':
            steps = [
                ('leaf_vs_int', _pqcli_cmd(jar, jvm_flags,
                    ['verify', '-in', str(s / 'cv_leaf_certificate.pem'),
                     '-CAfile', str(s / 'cv_int_certificate.pem')])),
                ('int_vs_root', _pqcli_cmd(jar, jvm_flags,
                    ['verify', '-in', str(s / 'cv_int_certificate.pem'),
                     '-CAfile', str(s / 'cv_root_certificate.pem')])),
            ]
            result = _rwf(steps, log_d, tag_str)
            sizes = pre_inputs

        elif op == 'verify-modeB-strict':
            result = _rt(_pqcli_cmd(jar, jvm_flags,
                ['verify', '-in', str(s / 'cv_leaf_certificate.pem'),
                 '-chain', str(s / 'cv_int_certificate.pem'),
                 '-trust', str(s / 'cv_root_certificate.pem')]), log_d, tag_str)
            sizes = pre_inputs

        elif op == 'verify-dynamic':
            result = _rt(_pqcli_cmd(jar, jvm_flags,
                ['verify', '-in', str(s / 'cv_leaf_certificate.pem'),
                 '-untrusted', str(s / 'cv_int_certificate.pem'),
                 '-trust', str(s / 'cv_root_certificate.pem')]), log_d, tag_str)
            sizes = pre_inputs

        elif op == 'verify-modeB-direct':
            result = _rt(_pqcli_cmd(jar, jvm_flags,
                ['verify', '-in', str(s / 'direct_leaf_certificate.pem'),
                 '-trust', str(s / 'direct_root_certificate.pem')]), log_d, tag_str)
            sizes = pre_inputs

        elif op == 'workflow-2tier':
            int_alt = s / 'wf2_ca_alt_private_key.pem'
            sign_args = ['sign', '-csr', str(s / 'wf2_ee_csr.pem'),
                         '-CAcert', str(s / 'wf2_ca_certificate.pem'),
                         '-CAkey',  str(s / 'wf2_ca_private_key.pem'),
                         '--profile', 'leaf', '-out', str(s / 'wf2_signed')]
            if h and int_alt.exists():
                sign_args += ['-CAaltkey', str(int_alt)]
            steps = [
                ('cert',   _pqcli_cmd(jar, jvm_flags, ['cert', '-newkey', algo,
                    '-subj', f'/CN=CA-{tag}', '-out', str(s / 'wf2_ca')])),
                ('csr',    _pqcli_cmd(jar, jvm_flags, ['csr', '-newkey', algo,
                    '-subj', f'/CN=EE-{tag}', '-out', str(s / 'wf2_ee')])),
                ('sign',   _pqcli_cmd(jar, jvm_flags, sign_args)),
                ('verify', _pqcli_cmd(jar, jvm_flags, ['verify', '-in',
                    str(s / 'wf2_signed_certificate.pem'),
                    '-CAfile', str(s / 'wf2_ca_certificate.pem')])),
            ]
            result = _rwf(steps, log_d, tag_str)
            sizes  = measure_produced(s, 'workflow-2tier', h)

        elif op == 'workflow-3tier':
            root_alt = s / 'wf3_root_alt_private_key.pem'
            int_alt  = s / 'wf3_int_csr_alt_private_key.pem'
            int_sign = ['sign', '-csr', str(s / 'wf3_int_csr_csr.pem'),
                        '-CAcert', str(s / 'wf3_root_certificate.pem'),
                        '-CAkey',  str(s / 'wf3_root_private_key.pem'),
                        '--profile', 'intermediate-ca', '-out', str(s / 'wf3_int')]
            leaf_sign = ['sign', '-csr', str(s / 'wf3_leaf_csr_csr.pem'),
                         '-CAcert', str(s / 'wf3_int_certificate.pem'),
                         '-CAkey',  str(s / 'wf3_int_csr_private_key.pem'),
                         '--profile', 'leaf', '-out', str(s / 'wf3_leaf')]
            if h and root_alt.exists():
                int_sign  += ['-CAaltkey', str(root_alt)]
            if h and int_alt.exists():
                leaf_sign += ['-CAaltkey', str(int_alt)]
            steps = [
                ('cert',      _pqcli_cmd(jar, jvm_flags, ['cert', '-newkey', algo,
                    '-subj', f'/CN=W3Root-{tag}', '-out', str(s / 'wf3_root')])),
                ('csr_int',   _pqcli_cmd(jar, jvm_flags, ['csr', '-newkey', algo,
                    '-subj', f'/CN=W3Int-{tag}', '-out', str(s / 'wf3_int_csr')])),
                ('sign_int',  _pqcli_cmd(jar, jvm_flags, int_sign)),
                ('csr_leaf',  _pqcli_cmd(jar, jvm_flags, ['csr', '-newkey', algo,
                    '-subj', f'/CN=W3Leaf-{tag}', '-out', str(s / 'wf3_leaf_csr')])),
                ('sign_leaf', _pqcli_cmd(jar, jvm_flags, leaf_sign)),
                ('verify',    _pqcli_cmd(jar, jvm_flags, ['verify',
                    '-in',    str(s / 'wf3_leaf_certificate.pem'),
                    '-chain', str(s / 'wf3_int_certificate.pem'),
                    '-trust', str(s / 'wf3_root_certificate.pem')])),
            ]
            result = _rwf(steps, log_d, tag_str)
            sizes  = measure_produced(s, 'workflow-3tier', h)

        else:
            log.warning('Unknown op: %s', op)
            continue

        iter_idx = meas_idx if not is_w else idx
        row = make_row(common={**common, 'operation': op,
                                'algo_tag': cfg.tag,
                                'cert_profile': 'none',
                                'certificate_mode': cfg.certificate_mode,
                                'primitive_standard_scope': cfg.primitive_standard_scope},
                       operation=op,
                       iter_index=iter_idx,
                       warmup=is_w,
                       result=result, sizes=sizes)

        if is_w:
            writer.write_warmup(row, warm_csv)
        else:
            writer.write_row(row, meas_csv)
            if result.exit_code != 0:
                log.warning('[FAIL] %s/%s iter %d: exit %d', tag, op, meas_idx, result.exit_code)

        if timing_debug:
            if result.step_results:
                # Workflow op: one breakdown row per subprocess step.
                for si, (sname, sr) in enumerate(result.step_results):
                    writer.write_breakdown_row(_make_breakdown_row(
                        run_id=common.get('run_id', ''),
                        profile=common.get('profile', ''),
                        mode=common.get('mode', ''),
                        algo_tag=tag,
                        operation=op,
                        iter_index=iter_idx,
                        warmup=is_w,
                        step_index=si,
                        step_name=sname,
                        is_workflow_step=True,
                        result=sr,
                    ))
            else:
                # Single-subprocess op: one breakdown row.
                writer.write_breakdown_row(_make_breakdown_row(
                    run_id=common.get('run_id', ''),
                    profile=common.get('profile', ''),
                    mode=common.get('mode', ''),
                    algo_tag=tag,
                    operation=op,
                    iter_index=iter_idx,
                    warmup=is_w,
                    step_index=0,
                    step_name=op,
                    is_workflow_step=False,
                    result=result,
                ))


# ── Main orchestration ─────────────────────────────────────────────────────────

def run_single_algo(cfg: AlgoConfig, ops: list[str], macro_dir: Path, staging: Path,
                    jar: Path, jvm_flags: list[str], tmpdir: Path,
                    taskset_cpu: Optional[str], perf_available: bool, perf_events: str,
                    warmup_count: int, measured_count: int,
                    base_common: dict, writer: ResultWriter,
                    algo_idx: int = 0, algo_total: int = 0,
                    timing_debug: bool = False) -> None:
    tag = cfg.tag
    algo_dir = staging / tag
    algo_dir.mkdir(parents=True, exist_ok=True)
    log.info('── [%d/%d] %s  (%s / %s) ──',
             algo_idx+1, algo_total, tag, cfg.certificate_mode, cfg.cli_syntax)
    pregen_ok_map = pregen_single_algo(cfg, algo_dir, jar, jvm_flags, writer, taskset_cpu)

    ops_for_algo = [o for o in ops if o in cfg.applicable_ops]
    ops_total    = len(ops_for_algo)
    for op_idx, op in enumerate(ops_for_algo):
        op_dir = macro_dir / tag / op
        op_dir.mkdir(parents=True, exist_ok=True)
        (op_dir / 'command.log').write_text(f'op={op} algo={cfg.cli_syntax}\n')
        (op_dir / 'warmup').mkdir(exist_ok=True)

        pregen_ok   = pregen_ok_map.get(op, True)
        pre_inputs  = measure_verify_inputs(algo_dir, op) if op.startswith('verify') else ArtifactSizes()

        with (open(op_dir / 'warmup_iterations.csv', 'w', newline='') as wf,
              open(op_dir / 'iterations.csv', 'w', newline='') as mf_):
            wcsv = csv.DictWriter(wf,  fieldnames=ITER_FIELDS, extrasaction='ignore')
            mcsv = csv.DictWriter(mf_, fieldnames=ITER_FIELDS, extrasaction='ignore')
            wcsv.writeheader()
            mcsv.writeheader()
            run_op_iterations(
                op=op, cfg=cfg, algo_dir=algo_dir, op_log_dir=op_dir,
                jar=jar, jvm_flags=jvm_flags, tmpdir=tmpdir, taskset_cpu=taskset_cpu,
                perf_available=perf_available, perf_events=perf_events,
                warmup_count=warmup_count, measured_count=measured_count,
                common=base_common, writer=writer,
                meas_csv=mcsv, warm_csv=wcsv,
                pregen_ok=pregen_ok, pre_inputs=pre_inputs,
                op_idx=op_idx, ops_total=ops_total,
                timing_debug=timing_debug,
            )


def build_metadata(args, sys_meta: dict, bc: Optional[str], sha: str,
                   jvm_flags: list[str], perf_avail: bool, perf_used: bool,
                   perf_events: str, taskset_used: bool,
                   timing_debug: bool = False) -> dict:
    return {
        'timestamp': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
        **sys_meta,
        'java_version': detect_java_version(),
        'detected_bc_version': bc or 'unknown',
        'expected_bc_version': EXPECTED_BC_VERSION,
        'bc_version_matches_expected': (bc == EXPECTED_BC_VERSION),
        'bcpqc_version': 'merged-into-bcprov-jdk18on',
        'pqcli_jar': str(args.jar.resolve()),
        'jar_sha256': sha,
        'jvm_flags': ' '.join(jvm_flags),
        'env_java_opts': os.environ.get('JAVA_OPTS', 'not_set'),
        'env_maven_opts': os.environ.get('MAVEN_OPTS', 'not_set'),
        'env_tmpdir': os.environ.get('TMPDIR', 'not_set'),
        'staging_dir': str(args.staging.resolve()),
        'results_dir': str(args.out.resolve()),
        'timev_available': True,
        'perf_available': perf_avail,
        'perf_hw_available': False,
        'software_perf_requested': not args.no_perf,
        'software_perf_available': perf_avail,
        'software_perf_used': perf_used,
        'software_perf_events': perf_events.split(',') if perf_events else [],
        'hardware_counters_used': False,
        'taskset_available': taskset_used,
        'taskset_used': taskset_used,
        'cpu_affinity_requested': args.taskset_cpu,
        'cpu_affinity_effective': args.taskset_cpu if taskset_used else None,
        'profile': args.profile,
        'mode': args.mode,
        'warmup_iterations': args.warmup,
        'measured_iterations': args.iter,
        'measurement_tool': '/usr/bin/time -v',
        'hyperfine_used': False,
        'hyperfine_version': sys_meta.get('hyperfine_version', 'not found'),
        'cli_wall_time_definition':
            'GNU time Elapsed (wall clock) — includes JVM startup, BC provider init, operation',
        'workflow_wall_time_definition': 'Sum of per-step wall times',
        'workflow_peak_rss_definition': 'Max of per-step peak RSS values',
        'hardware_counters_explanation':
            'Hardware PMU counters unavailable (VM without PMU virtualization). '
            'hardware_counters_used=false in all outputs.',
        'size_methodology':
            'PEM size by file size; DER size by base64-decoding PEM body; '
            'producing operations measured per iteration; '
            'verify input artifacts measured after pre-generation and repeated per iteration',
        'benchmark_target_env': {
            'classification':
                'Benchmark intent and target environment — NOT a hardware-portable performance claim',
            'target_device_class': 'QEMU/KVM virtual machine, x86-64, Linux',
            'minimum_practical_requirements':
                'JDK 17+, 2 GB heap budget, 2 logical CPU cores, Linux amd64',
            'jvm_startup_note':
                'Macro CLI timings (~900-1000 ms on the reference VM) include JVM startup, '
                'BC provider init, and picocli dispatch; '
                'do not compare directly with JMH micro timings.',
        },
        'timing_debug_enabled': timing_debug,
        **({'timing_debug_env':          'PQCLI_TIMING_DEBUG=1',
            'startup_breakdown_file':    'startup_breakdown.csv',
            'startup_breakdown_note':
                'Timing fields parsed from pqcli stderr [TIMING] lines. '
                'Values are milliseconds since pqcli class-init T0 inside the child JVM. '
                'One row per actual java -jar subprocess invocation. '
                'measured_unattributed_ms = cli_wall_time_ms - timing_call_returning_ms; '
                'this is not a precise phase — it includes OS process creation overhead, '
                'JVM initialization before PqCliCommand.T0, JVM shutdown, '
                'and the measurement boundary gap between the last [TIMING] line '
                'and GNU time wall clock endpoint.',
            'workflow_startup_note':
                'Workflow cli_wall_time_ms is still the sum of individual java -jar '
                'subprocess wall times. startup_breakdown.csv has one row per step.',
           } if timing_debug else {}),
    }


# ── CLI ────────────────────────────────────────────────────────────────────────

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description='PQCLI macro benchmark orchestrator')
    p.add_argument('--profile', default='thesis-core', choices=list(PROFILES))
    p.add_argument('--mode', default='stable', choices=['stable', 'dry'])
    p.add_argument('--jar',     type=Path, default=None)
    p.add_argument('--out',     type=Path, default=None)
    p.add_argument('--staging', type=Path, default=None)
    p.add_argument('--tmpdir',  type=Path, default=None)
    p.add_argument('--ops',      default=None)
    p.add_argument('--algos',    default=None)
    p.add_argument('--category', default=None)
    p.add_argument('--iter',     type=int, default=None)
    p.add_argument('--warmup',   type=int, default=None)
    p.add_argument('--taskset-cpu', default=None, dest='taskset_cpu')
    p.add_argument('--no-perf',  action='store_true')
    p.add_argument('--rebuild',  action='store_true')
    p.add_argument('--allow-version-mismatch', action='store_true')
    p.add_argument('--verbose', '-v', action='store_true')
    p.add_argument('--timing-debug', action='store_true', dest='timing_debug',
                   help='Set PQCLI_TIMING_DEBUG=1 for every pqcli subprocess and record '
                        'parsed startup phase timings in startup_breakdown.csv. '
                        'Does not change cli_wall_time_ms semantics.')
    return p.parse_args()


def main() -> int:
    args = parse_args()
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format='%(asctime)s %(levelname)s %(message)s', datefmt='%H:%M:%S')

    ts = time.strftime('%Y%m%d_%H%M%S')
    if args.jar is None:
        args.jar = PQCLI_DIR / 'target' / 'pqcli-0.1.0.jar'
    if args.out is None:
        args.out = SCRIPT_DIR / 'results' / ts
    if args.staging is None:
        args.staging = SCRIPT_DIR / '.staging' / ts
    if args.tmpdir is None:
        args.tmpdir = Path(tempfile.gettempdir())

    args.out.mkdir(parents=True, exist_ok=True)
    args.staging.mkdir(parents=True, exist_ok=True)
    macro_dir = args.out / 'macro'
    macro_dir.mkdir(exist_ok=True)

    if args.rebuild:
        log.info('[BUILD] mvn clean package ...')
        if subprocess.run(['mvn', 'clean', 'package', '-q'], cwd=PQCLI_DIR).returncode != 0:
            log.error('[BUILD FAIL]')
            return 1

    if not args.jar.exists():
        log.error('[PREFLIGHT] JAR not found: %s', args.jar)
        return 1

    if not check_timev(args.tmpdir):
        log.error('[PREFLIGHT] /usr/bin/time -v --output not functional — cannot proceed')
        return 1

    bc = detect_bc_version(PQCLI_DIR)
    if bc != EXPECTED_BC_VERSION and not args.allow_version_mismatch:
        log.error('[PREFLIGHT] BC version mismatch: detected=%s expected=%s '
                  '(--allow-version-mismatch to override)', bc, EXPECTED_BC_VERSION)
        return 1

    perf_avail = check_software_perf()
    use_perf   = perf_avail and not args.no_perf
    perf_events = 'task-clock,cpu-clock' if use_perf else ''
    if not perf_avail:
        log.info('[PERF] Software perf unavailable — task_clock/cpu_clock will be null')

    taskset_cpu = args.taskset_cpu
    taskset_ok  = False
    if taskset_cpu:
        taskset_ok = check_taskset(taskset_cpu)
        if not taskset_ok:
            log.warning('[TASKSET] taskset -c %s failed — continuing without CPU pinning', taskset_cpu)
            taskset_cpu = None

    sys_meta = collect_system_metadata()
    ram_kb = sys_meta.get('ram_kb', 0)
    if isinstance(ram_kb, int) and ram_kb < 1_500_000:
        log.warning('[MEMORY] RAM %d KB < 1.5 GB — JVM flags may need adjustment', ram_kb)

    jvm_flags = os.environ.get('JAVA_OPTS', '').split() or DEFAULT_JVM_FLAGS
    sha = jar_sha256(args.jar)
    log.info('[JAR] %s  sha256=%s...', args.jar.name, sha[:16])

    profile_cfg = PROFILES[args.profile]
    measured_count = args.iter  if args.iter   else profile_cfg['iterations']
    warmup_count   = args.warmup if args.warmup else WARMUP_ITERATIONS
    if args.mode == 'dry':
        measured_count = min(measured_count, 3)
        warmup_count   = 2

    single_algos: list[AlgoConfig] = list(profile_cfg['single_algos'])
    dual_cfgs:    list[DualConfig]  = list(profile_cfg['dual_configs'])
    single_ops:   list[str]         = list(profile_cfg['single_ops'])

    if args.algos:
        tags = set(args.algos.split(','))
        single_algos = [a for a in single_algos if a.tag in tags]
        dual_cfgs    = [d for d in dual_cfgs    if d.tag in tags]
    if args.category:
        cats = set(args.category.split(','))
        single_algos = [a for a in single_algos if a.certificate_mode in cats]
        if 'dual-rfc9763' not in cats:
            dual_cfgs = []
    if args.ops:
        allowed = {('verify-dynamic' if o == 'verify-modeB-dynamic' else o) for o in args.ops.split(',')}
        single_ops = [o for o in single_ops if o in allowed]

    # Preflight each algo
    skip_tags: set[str] = set()
    for cfg in single_algos:
        ok, msg = preflight_algo(args.jar, jvm_flags, cfg.cli_syntax)
        if not ok:
            log.warning('[SKIP] %s — preflight: %s', cfg.tag, msg)
            skip_tags.add(cfg.tag)
    single_algos = [a for a in single_algos if a.tag not in skip_tags]

    timing_debug: bool = getattr(args, 'timing_debug', False)

    writer = ResultWriter(macro_dir)
    meta = build_metadata(args, sys_meta, bc, sha, jvm_flags,
                          perf_avail, use_perf, perf_events, taskset_ok,
                          timing_debug=timing_debug)
    meta['args_iter']   = measured_count
    meta['args_warmup'] = warmup_count
    meta['args_ops']    = args.ops or 'all'
    (args.out / 'metadata.json').write_text(json.dumps(meta, indent=2))
    if timing_debug:
        log.info('[TIMING DEBUG] enabled — PQCLI_TIMING_DEBUG=1 will be set for all subprocesses')

    java_ver  = detect_java_version()
    os_kernel = sys_meta.get('os', 'unknown')
    base_common = {
        'run_id': ts,
        'mode': args.mode,
        'pqcli_jar': str(args.jar.resolve()),
        'jar_sha256': sha,
        'java_version': java_ver,
        'os_kernel': os_kernel,
        'profile': args.profile,
    }

    # ── Runtime summary ────────────────────────────────────────────────────────
    log.info('━━━ PQCLI macro benchmark ━━━')
    log.info('Profile:    %s    Mode: %s    Run-ID: %s', args.profile, args.mode, ts)
    log.info('Output:     %s', args.out)
    log.info('Staging:    %s', args.staging)
    log.info('Iterations: %d measured + %d warmup', measured_count, warmup_count)
    if args.mode == 'dry':
        log.info('[DRY MODE] iterations capped to %d, warmup to 2', measured_count)
    log.info('Perf:       available=%s  used=%s  events=%s',
             perf_avail, use_perf, perf_events or 'none')
    if taskset_cpu:
        log.info('Taskset:    cpu=%s  available=%s', taskset_cpu, taskset_ok)
    else:
        log.info('Taskset:    disabled')

    # Algorithm set breakdown
    by_cat: dict[str, list[str]] = {}
    for a in single_algos:
        by_cat.setdefault(a.certificate_mode, []).append(a.tag)
    log.info('Algorithm set:')
    for cat, tags in by_cat.items():
        log.info('  %-18s %d  (%s)', cat + ':', len(tags), ', '.join(tags))
    log.info('  %-18s %d single-algo configs', 'TOTAL:', len(single_algos))
    log.info('  %-18s %d  (%s)', 'dual:', len(dual_cfgs),
             ', '.join(d.tag for d in dual_cfgs) if dual_cfgs else 'none')

    dual_ops_informational = list(profile_cfg['dual_ops'])
    log.info('Single ops  (%d): %s', len(single_ops), ', '.join(single_ops))
    if dual_cfgs:
        log.info('Dual ops    (%d): %s', len(dual_ops_informational),
                 ', '.join(dual_ops_informational))

    skipped_tags = set(a.tag for a in list(profile_cfg['single_algos'])
                       if args.algos and a.tag not in set(args.algos.split(',')))
    if args.category:
        cats = set(args.category.split(','))
        for a in list(profile_cfg['single_algos']):
            if a.certificate_mode not in cats:
                skipped_tags.add(a.tag)
    if skipped_tags:
        log.info('Filtered out: %s', ', '.join(sorted(skipped_tags)))

    # ── Single-algo benchmark loop ─────────────────────────────────────────────
    algo_total = len(single_algos)
    for algo_idx, cfg in enumerate(single_algos):
        run_single_algo(cfg, single_ops, macro_dir, args.staging, args.jar, jvm_flags,
                        args.tmpdir, taskset_cpu, use_perf, perf_events,
                        warmup_count, measured_count, base_common, writer,
                        algo_idx=algo_idx, algo_total=algo_total,
                        timing_debug=timing_debug)

    # ── Dual / RFC 9763 benchmark loop ─────────────────────────────────────────
    if dual_cfgs:
        dual_ops = list(profile_cfg['dual_ops'])
        if args.ops:
            allowed = {('verify-dynamic' if o == 'verify-modeB-dynamic' else o) for o in args.ops.split(',')}
            dual_ops = [o for o in dual_ops if o in allowed]
        log.info('━━━ Dual/RFC 9763: %d config(s) ━━━', len(dual_cfgs))
        for i, dc in enumerate(dual_cfgs):
            log.info('[%d/%d] %s  (primary=%s  related=%s)',
                     i+1, len(dual_cfgs), dc.tag, dc.primary_algo, dc.related_algo)
            dual_dir = args.staging / dc.tag
            dual_dir.mkdir(parents=True, exist_ok=True)
            pregen_ok_map = pregen_dual_config(
                dc, dual_dir, args.jar, jvm_flags, writer, taskset_cpu)
            run_dual_op_iterations(
                dc=dc, dual_ops=dual_ops, dual_dir=dual_dir,
                macro_dir=macro_dir, jar=args.jar, jvm_flags=jvm_flags,
                tmpdir=args.tmpdir, taskset_cpu=taskset_cpu,
                perf_available=use_perf, perf_events=perf_events,
                warmup_count=warmup_count, measured_count=measured_count,
                base_common=base_common, writer=writer,
                pregen_ok_map=pregen_ok_map,
                timing_debug=timing_debug,
            )

    writer.close()

    # ── Aggregation ────────────────────────────────────────────────────────────
    log.info('━━━ Done ━━━')
    log.info('Output:  %s', args.out)
    log.info('Configs: %d single-algo  %d dual', len(single_algos), len(dual_cfgs))
    skips_path = macro_dir / 'skips.csv'
    if skips_path.exists():
        log.info('Skips:   %s', skips_path)

    aggregate_py = SCRIPT_DIR / 'aggregate_results.py'
    if aggregate_py.exists():
        log.info('[AGGREGATE] Running aggregate_results.py ...')
        subprocess.run([sys.executable, str(aggregate_py), str(macro_dir)])
        log.info('[AGGREGATE] summary: %s', macro_dir / 'summary.csv')
        log.info('[AGGREGATE] sizes:   %s', macro_dir / 'sizes_summary.csv')

    return 0


if __name__ == '__main__':
    sys.exit(main())
