#!/usr/bin/env python3
"""
run_openssl_benchmarks.py — OpenSSL macro benchmark harness

Benchmarks the locally configured OpenSSL CLI for classical and (when a pure
equivalent is available) pure-PQC algorithm workloads. Results are kept separate
from pqcli macro and JMH micro results.

OpenSSL macro rows include native process startup (openssl CLI launch).
pqcli macro rows include JVM startup.
Neither is overhead-free; the startup overheads differ in kind and magnitude.
Do NOT compare OpenSSL macro rows to JMH micro rows (jmh_score_ms).

Usage:
  python3 run_openssl_benchmarks.py [options]

Key options:
  --profile       openssl-thesis-core (default) | openssl-smoke |
                  openssl-thesis-core-classical | openssl-thesis-core-pure-pqc |
                  openssl-full
  --openssl-bin   path to OpenSSL executable (overrides OQS_OPENSSL; falls back to 'openssl')
  --openssl-modules  path to OpenSSL modules dir (overrides OPENSSL_MODULES)
  --detect-only   run capability detection and print results, then exit
  --out           results directory (default: results/<timestamp>)
  --staging       staging directory (default: .staging/<timestamp>)
  --tmpdir        temp directory for shell scripts and timev files
  --ops           comma-separated op subset
  --algos         comma-separated algo tag subset
  --iter          override iteration count
  --warmup        override warmup count
  --taskset-cpu   CPU affinity for taskset (e.g. "0")
  --no-perf       disable software perf counters
  --mode          dry | stable
  --verbose / -v
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
import socket
import stat
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

SCRIPT_DIR  = Path(__file__).resolve().parent
PROJECT_DIR = SCRIPT_DIR.parent

sys.path.insert(0, str(SCRIPT_DIR))
from benchmark_config import (
    CLASSICAL, MLDSA, SLH_DSA_CORE, SLH_DSA_HEAVY_EXTRA,
    _TC_CLASSICAL_TAGS, _TC_PQC_TAGS,
    WARMUP_ITERATIONS, MEASURED_ITERATIONS, DRY_ITERATIONS,
)

log = logging.getLogger('openssl_bench')


# ── Constants ──────────────────────────────────────────────────────────────────

OPENSSL_OPS = [
    'keygen',
    'cert',
    'csr',
    'sign-leaf',
    'sign-intermediate-ca',
    'verify-issued',
    'verify-modeB-dynamic',
    'verify-modeB-direct',
]

# Explicit allowlist of pure pqcli-equivalent oqsprovider names.
# Everything else from oqsprovider is combined/hybrid and must not be used.
OQS_PURE_MLDSA_NAMES: frozenset[str] = frozenset({
    'mldsa44', 'mldsa65', 'mldsa87',
})
OQS_PURE_SLHDSA_NAMES: frozenset[str] = frozenset({
    'slhdsasha2128s', 'slhdsasha2128f',
    'slhdsasha2192s', 'slhdsasha2192f',
    'slhdsasha2256s', 'slhdsasha2256f',
    'slhdsashake128s', 'slhdsashake128f',
    'slhdsashake192s', 'slhdsashake192f',
    'slhdsashake256s', 'slhdsashake256f',
})
OQS_PURE_NAMES: frozenset[str] = OQS_PURE_MLDSA_NAMES | OQS_PURE_SLHDSA_NAMES

# Native OpenSSL 3.5+ ML-DSA names to probe for (case-sensitive variants tried in order)
NATIVE_MLDSA_CANDIDATES: dict[str, list[str]] = {
    'mldsa44': ['ml-dsa-44', 'ML-DSA-44'],
    'mldsa65': ['ml-dsa-65', 'ML-DSA-65'],
    'mldsa87': ['ml-dsa-87', 'ML-DSA-87'],
}

# Native OpenSSL 3.5+ SLH-DSA names to probe for
NATIVE_SLHDSA_CANDIDATES: dict[str, list[str]] = {
    'slh-dsa-sha2-128s':  ['SLH-DSA-SHA2-128s'],
    'slh-dsa-sha2-128f':  ['SLH-DSA-SHA2-128f'],
    'slh-dsa-sha2-192s':  ['SLH-DSA-SHA2-192s'],
    'slh-dsa-sha2-192f':  ['SLH-DSA-SHA2-192f'],
    'slh-dsa-sha2-256s':  ['SLH-DSA-SHA2-256s'],
    'slh-dsa-sha2-256f':  ['SLH-DSA-SHA2-256f'],
    'slh-dsa-shake-128s': ['SLH-DSA-SHAKE-128s'],
    'slh-dsa-shake-128f': ['SLH-DSA-SHAKE-128f'],
    'slh-dsa-shake-192s': ['SLH-DSA-SHAKE-192s'],
    'slh-dsa-shake-192f': ['SLH-DSA-SHAKE-192f'],
    'slh-dsa-shake-256s': ['SLH-DSA-SHAKE-256s'],
    'slh-dsa-shake-256f': ['SLH-DSA-SHAKE-256f'],
}

# Mapping: pqcli_tag → oqsprovider pure name
OQS_SLHDSA_TAG_TO_NAME: dict[str, str] = {
    'slh-dsa-sha2-128s':  'slhdsasha2128s',
    'slh-dsa-sha2-128f':  'slhdsasha2128f',
    'slh-dsa-sha2-192s':  'slhdsasha2192s',
    'slh-dsa-sha2-192f':  'slhdsasha2192f',
    'slh-dsa-sha2-256s':  'slhdsasha2256s',
    'slh-dsa-sha2-256f':  'slhdsasha2256f',
    'slh-dsa-shake-128s': 'slhdsashake128s',
    'slh-dsa-shake-128f': 'slhdsashake128f',
    'slh-dsa-shake-192s': 'slhdsashake192s',
    'slh-dsa-shake-192f': 'slhdsashake192f',
    'slh-dsa-shake-256s': 'slhdsashake256s',
    'slh-dsa-shake-256f': 'slhdsashake256f',
}

# pqcli thesis-core tags: must mirror benchmark_config._TC_CLASSICAL_TAGS
# and the pure-pqc subset of _TC_PQC_TAGS. Comment here if benchmark_config changes.
_OPENSSL_TC_CLASSICAL_TAGS: frozenset[str] = frozenset(_TC_CLASSICAL_TAGS)
_TC_PQC_TAGS_PURE_PQC = {
    t for t in _TC_PQC_TAGS
    if any(a.tag == t and a.certificate_mode == 'pure-pqc'
           for a in MLDSA + SLH_DSA_CORE)
}

ALL_PQC_TAGS: list[str] = (
    ['mldsa44', 'mldsa65', 'mldsa87'] +
    [a.tag for a in SLH_DSA_CORE + SLH_DSA_HEAVY_EXTRA]
)

OPENSSL_PROFILES: dict[str, dict] = {
    # Quick classical-only sanity check (pqc_tags=[] → no PQC skip rows)
    'openssl-smoke': {
        'classical_tags': ['rsa3072', 'ecdsa-p256', 'ed25519'],
        'pqc_tags': [],
        'operations': ['keygen', 'cert', 'csr', 'sign-leaf', 'verify-issued'],
        'default_iter': DRY_ITERATIONS,
        'default_warmup': 2,
        'description': 'Quick classical-only sanity check',
    },
    # Matches pqcli thesis-core; unsupported algorithms are skipped explicitly
    'openssl-thesis-core': {
        'classical_tags': sorted(_OPENSSL_TC_CLASSICAL_TAGS),
        'pqc_tags': sorted(_TC_PQC_TAGS_PURE_PQC),
        'operations': OPENSSL_OPS,
        'default_iter': MEASURED_ITERATIONS,
        'default_warmup': WARMUP_ITERATIONS,
        'description': 'OpenSSL equivalent of pqcli thesis-core macro profile',
    },
    # Classical subset of thesis-core
    'openssl-thesis-core-classical': {
        'classical_tags': sorted(_OPENSSL_TC_CLASSICAL_TAGS),
        'pqc_tags': [],
        'operations': OPENSSL_OPS,
        'default_iter': MEASURED_ITERATIONS,
        'default_warmup': WARMUP_ITERATIONS,
        'description': 'Classical subset of thesis-core OpenSSL baseline',
    },
    # Pure-PQC subset of thesis-core
    'openssl-thesis-core-pure-pqc': {
        'classical_tags': [],
        'pqc_tags': sorted(_TC_PQC_TAGS_PURE_PQC),
        'operations': OPENSSL_OPS,
        'default_iter': MEASURED_ITERATIONS,
        'default_warmup': WARMUP_ITERATIONS,
        'description': 'Pure-PQC subset of thesis-core OpenSSL baseline',
    },
    # Opt-in extended run — not the default baseline
    'openssl-full': {
        'classical_tags': [a.tag for a in CLASSICAL],
        'pqc_tags': ALL_PQC_TAGS,
        'operations': OPENSSL_OPS,
        'default_iter': MEASURED_ITERATIONS,
        'default_warmup': WARMUP_ITERATIONS,
        'description': 'Opt-in extended OpenSSL run; not the default baseline',
    },
}


# ── OpenSSL config file templates ──────────────────────────────────────────────

CA_CNF = """\
[ req ]
distinguished_name = req_distinguished_name
prompt = no
x509_extensions = v3_ca

[ req_distinguished_name ]
CN = Bench

[ v3_ca ]
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid:always,issuer
basicConstraints       = critical, CA:true
keyUsage               = critical, keyCertSign, cRLSign
"""

LEAF_CNF = """\
[ leaf_ext ]
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid:always
basicConstraints       = critical, CA:false
keyUsage               = critical, digitalSignature
"""

INT_CNF = """\
[ intermediate_ca_ext ]
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid:always
basicConstraints       = critical, CA:true, pathlen:0
keyUsage               = critical, keyCertSign, cRLSign
"""


# ── Dataclasses ────────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class OpenSSLAlgoConfig:
    pqcli_tag: str
    openssl_algorithm: str
    genpkey_extra_args: tuple[str, ...]    # e.g. ('-pkeyopt', 'rsa_keygen_bits:3072')
    provider_flags: tuple[str, ...]        # e.g. () or ('-provider','oqsprovider','-provider','default')
    hash_flag: Optional[str]              # e.g. '-sha256' or None
    algorithm_source: str                 # 'default' | 'native-pqc' | 'oqsprovider'
    certificate_mode: str                 # 'classical' | 'pure-pqc'
    comparability_class: str = 'partial'
    available: bool = True
    skip_reason: Optional[str] = None


@dataclass
class OpenSSLCapabilities:
    openssl_bin: str
    openssl_bin_source: str               # 'cli-override' | 'OQS_OPENSSL' | 'fallback'
    openssl_modules_effective: Optional[str]
    openssl_version_full: str
    openssl_version_short: str
    provider_state: str                   # 'default_only' | 'oqs_available' | etc.
    oqs_available: bool
    oqs_version: Optional[str]
    native_mldsa: dict[str, str]          # pqcli_tag → detected native name
    native_slhdsa: dict[str, str]         # pqcli_tag → detected native name
    oqs_pure_mldsa: dict[str, str]        # pqcli_tag → oqs name
    oqs_pure_slhdsa: dict[str, str]       # pqcli_tag → oqs name
    oqs_combined: list[str]
    oqs_kem: list[str]


@dataclass
class RunResult:
    exit_code: int
    wall_time_ms: Optional[float]
    peak_rss_kb: Optional[int]
    user_cpu_s: Optional[float]
    sys_cpu_s: Optional[float]
    cpu_pct: Optional[float]
    context_switches: Optional[int]
    page_faults: Optional[int]
    stdout_path: Optional[Path] = None
    stderr_path: Optional[Path] = None
    timev_path: Optional[Path] = None


# ── Parse functions (from run_macro_benchmarks.py) ────────────────────────────

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


# ── PEM/DER size helpers ───────────────────────────────────────────────────────

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


# ── Command execution ──────────────────────────────────────────────────────────

def run_timed(
    full_cmd: list[str],
    log_dir: Path,
    iter_tag: str,
    tmpdir: Path,
    taskset_cpu: Optional[str],
    timeout_s: int = 600,
) -> RunResult:
    """Wrap a command with [taskset] /usr/bin/time -v and run it."""
    ts = str(time.monotonic_ns())
    timev_file = tmpdir / f'timev_{ts}.txt'

    for subdir in ('stdout', 'stderr', 'timev'):
        (log_dir / subdir).mkdir(parents=True, exist_ok=True)

    wrapped = []
    if taskset_cpu:
        wrapped += ['taskset', '-c', taskset_cpu]
    wrapped += ['/usr/bin/time', '-v', '--output', str(timev_file)]
    wrapped += full_cmd

    stdout_file = log_dir / 'stdout' / f'{iter_tag}.log'
    stderr_file = log_dir / 'stderr' / f'{iter_tag}.log'

    exit_code = -1
    with open(stdout_file, 'wb') as fout, open(stderr_file, 'wb') as ferr:
        try:
            proc = subprocess.run(wrapped, stdout=fout, stderr=ferr,
                                  timeout=timeout_s)
            exit_code = proc.returncode
        except subprocess.TimeoutExpired:
            log.warning('Timeout after %ds for %s', timeout_s, iter_tag)

    timev_dest = log_dir / 'timev' / f'{iter_tag}.txt'
    if timev_file.exists():
        shutil.move(str(timev_file), str(timev_dest))
    timev_text = timev_dest.read_text(errors='replace') if timev_dest.exists() else ''

    return RunResult(
        exit_code=exit_code,
        wall_time_ms=_parse_elapsed_ms(timev_text),
        peak_rss_kb=_parse_rss_kb(timev_text),
        user_cpu_s=_parse_user_s(timev_text),
        sys_cpu_s=_parse_sys_s(timev_text),
        cpu_pct=_parse_cpu_pct(timev_text),
        context_switches=_parse_ctx_switches(timev_text),
        page_faults=_parse_page_faults(timev_text),
        stdout_path=stdout_file,
        stderr_path=stderr_file,
        timev_path=timev_dest if timev_dest.exists() else None,
    )


def _write_script(content: str, script_file: Path) -> None:
    script_file.write_text(content)
    script_file.chmod(script_file.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP)


def run_shell_timed(
    script_content: str,
    log_dir: Path,
    iter_tag: str,
    tmpdir: Path,
    taskset_cpu: Optional[str],
    cmd_log_path: Optional[Path] = None,
    timeout_s: int = 600,
) -> RunResult:
    """Write a shell script to tmpdir, time it with bash, save script to command.log."""
    script_file = tmpdir / f'ossl_{time.monotonic_ns()}.sh'
    _write_script(f'#!/bin/bash\n{script_content}', script_file)

    if cmd_log_path and not cmd_log_path.exists():
        cmd_log_path.write_text(script_content)

    return run_timed(['bash', str(script_file)], log_dir, iter_tag, tmpdir,
                     taskset_cpu, timeout_s)


def _run_quiet(
    cmd: list[str],
    pregen_dir: Path,
    step: str,
    env: Optional[dict] = None,
    timeout_s: int = 300,
) -> bool:
    """Run a command quietly for pre-generation; persist stdout/stderr."""
    for d in ('stdout', 'stderr'):
        (pregen_dir / d).mkdir(parents=True, exist_ok=True)
    with (open(pregen_dir / 'stdout' / f'{step}.log', 'wb') as fo,
          open(pregen_dir / 'stderr' / f'{step}.log', 'wb') as fe):
        r = subprocess.run(cmd, stdout=fo, stderr=fe,
                           env=env, timeout=timeout_s)
    if r.returncode != 0:
        log.debug('[PREGEN FAIL] %s: exit %d', step, r.returncode)
    return r.returncode == 0


# ── Capability detection ───────────────────────────────────────────────────────

def _run_capture(cmd: list[str], env: dict) -> tuple[str, int]:
    """Run a command and return (stdout+stderr, returncode). Returns ('', -1) on exception."""
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, env=env, timeout=30)
        return r.stdout + r.stderr, r.returncode
    except Exception:
        return '', -1


def _probe_genpkey(
    openssl_bin: str,
    algo: str,
    extra_args: list[str],
    provider_flags: list[str],
    env: dict,
    tmpdir: Path,
) -> bool:
    """Quick genpkey probe using the same provider flags as benchmark execution."""
    out_file = tmpdir / f'probe_{time.monotonic_ns()}.pem'
    cmd = [openssl_bin, 'genpkey', '-algorithm', algo] + extra_args + provider_flags + ['-out', str(out_file)]
    try:
        r = subprocess.run(cmd, capture_output=True, env=env, timeout=60)
        ok = r.returncode == 0 and out_file.exists() and out_file.stat().st_size > 0
    except Exception:
        ok = False
    finally:
        out_file.unlink(missing_ok=True)
    return ok


def detect_openssl_capabilities(
    openssl_bin: str,
    openssl_bin_source: str,
    openssl_modules: Optional[str],
    tmpdir: Path,
) -> OpenSSLCapabilities:
    env = os.environ.copy()
    if openssl_modules:
        env['OPENSSL_MODULES'] = openssl_modules

    # Version
    ver_out, _ = _run_capture([openssl_bin, 'version', '-a'], env)
    ver_short = ver_out.splitlines()[0].strip() if ver_out else 'unknown'

    # Default provider sig algo list
    sig_out, _ = _run_capture([openssl_bin, 'list', '-signature-algorithms'], env)

    # Native PQC detection: name in list + genpkey probe (no provider flags)
    native_mldsa: dict[str, str] = {}
    for pqcli_tag, candidates in NATIVE_MLDSA_CANDIDATES.items():
        for cand in candidates:
            if cand.lower() in sig_out.lower():
                if _probe_genpkey(openssl_bin, cand, [], [], env, tmpdir):
                    native_mldsa[pqcli_tag] = cand
                    break

    native_slhdsa: dict[str, str] = {}
    for pqcli_tag, candidates in NATIVE_SLHDSA_CANDIDATES.items():
        for cand in candidates:
            if cand.lower() in sig_out.lower():
                if _probe_genpkey(openssl_bin, cand, [], [], env, tmpdir):
                    native_slhdsa[pqcli_tag] = cand
                    break

    # oqsprovider detection — use return code to confirm provider actually loaded
    oqs_available = False
    oqs_version: Optional[str] = None
    oqs_pure_mldsa: dict[str, str] = {}
    oqs_pure_slhdsa: dict[str, str] = {}
    oqs_combined: list[str] = []
    oqs_kem: list[str] = []

    prov_out, prov_rc = _run_capture(
        [openssl_bin, 'list', '-providers', '-provider', 'oqsprovider'], env)
    # Provider loaded successfully: return code 0 AND 'status: active' present
    if prov_rc == 0 and 'status: active' in prov_out:
        oqs_available = True
        m = re.search(r'version:\s*(\S+)', prov_out)
        oqs_version = m.group(1) if m else None

    if oqs_available:
        oqs_prov_flags = ['-provider', 'oqsprovider', '-provider', 'default']
        oqs_sig_out, _ = _run_capture(
            [openssl_bin, 'list', '-signature-algorithms'] + oqs_prov_flags, env)

        # OQS KEM list (metadata only)
        oqs_kem_out, _ = _run_capture(
            [openssl_bin, 'list', '-kem-algorithms'] + oqs_prov_flags, env)
        for line in oqs_kem_out.splitlines():
            raw = line.strip().split('@')[0].strip()
            if raw and not raw.startswith('{') and len(raw) < 80:
                oqs_kem.append(raw)

        # Parse oqsprovider sig algos using explicit allowlist
        for line in oqs_sig_out.splitlines():
            raw = line.strip()
            if not raw or raw.startswith('{') or '@' not in raw:
                continue
            name = raw.split('@')[0].strip()
            if not name or len(name) > 80:
                continue
            if name in OQS_PURE_MLDSA_NAMES:
                tag_map = {'mldsa44': 'mldsa44', 'mldsa65': 'mldsa65', 'mldsa87': 'mldsa87'}
                pqcli_tag = tag_map.get(name)
                if pqcli_tag and pqcli_tag not in native_mldsa:
                    if _probe_genpkey(openssl_bin, name, [], oqs_prov_flags, env, tmpdir):
                        oqs_pure_mldsa[pqcli_tag] = name
            elif name in OQS_PURE_SLHDSA_NAMES:
                for pt, on in OQS_SLHDSA_TAG_TO_NAME.items():
                    if on == name and pt not in native_slhdsa:
                        if _probe_genpkey(openssl_bin, name, [], oqs_prov_flags, env, tmpdir):
                            oqs_pure_slhdsa[pt] = name
                        break
            else:
                oqs_combined.append(name)

    # Determine provider_state
    has_native = bool(native_mldsa or native_slhdsa)
    has_oqs_pure = bool(oqs_pure_mldsa or oqs_pure_slhdsa)
    if has_native and oqs_available:
        provider_state = 'openssl_3_5_pqc_and_oqs_available'
    elif has_native:
        provider_state = 'openssl_3_5_pqc'
    elif has_oqs_pure:
        provider_state = 'oqs_available'
    elif oqs_available:
        provider_state = 'oqs_available_but_no_pqcli_pure_pqc_equivalents'
    else:
        provider_state = 'default_only'

    return OpenSSLCapabilities(
        openssl_bin=openssl_bin,
        openssl_bin_source=openssl_bin_source,
        openssl_modules_effective=openssl_modules,
        openssl_version_full=ver_out.strip(),
        openssl_version_short=ver_short,
        provider_state=provider_state,
        oqs_available=oqs_available,
        oqs_version=oqs_version,
        native_mldsa=native_mldsa,
        native_slhdsa=native_slhdsa,
        oqs_pure_mldsa=oqs_pure_mldsa,
        oqs_pure_slhdsa=oqs_pure_slhdsa,
        oqs_combined=oqs_combined,
        oqs_kem=oqs_kem,
    )


def print_capabilities(cap: OpenSSLCapabilities) -> None:
    print(f'OpenSSL executable: {cap.openssl_bin}  (source: {cap.openssl_bin_source})')
    print(f'Version:            {cap.openssl_version_short}')
    print(f'OPENSSL_MODULES:    {cap.openssl_modules_effective or "(not set)"}')
    print(f'Provider state:     {cap.provider_state}')
    print(f'oqsprovider:        {"YES v" + cap.oqs_version if cap.oqs_available and cap.oqs_version else ("YES" if cap.oqs_available else "NO")}')
    print(f'Native ML-DSA:      {dict(cap.native_mldsa) or "none"}')
    print(f'Native SLH-DSA:     {dict(cap.native_slhdsa) or "none"}')
    print(f'OQS pure ML-DSA:    {dict(cap.oqs_pure_mldsa) or "none"}')
    print(f'OQS pure SLH-DSA:   {dict(cap.oqs_pure_slhdsa) or "none"}')
    if cap.oqs_combined:
        print(f'OQS combined (skipped, not pqcli-equivalent): {cap.oqs_combined[:10]}{"..." if len(cap.oqs_combined)>10 else ""}')


# ── Algorithm config building ──────────────────────────────────────────────────

def build_algo_configs(
    classical_tags: list[str],
    pqc_tags: list[str],
    cap: OpenSSLCapabilities,
) -> list[OpenSSLAlgoConfig]:
    configs: list[OpenSSLAlgoConfig] = []

    # Classical — always available (genpkey already confirmed by verify in capability check)
    classical_map = {
        'rsa2048':    OpenSSLAlgoConfig('rsa2048',    'RSA', ('-pkeyopt','rsa_keygen_bits:2048'), (), '-sha256', 'default', 'classical'),
        'rsa3072':    OpenSSLAlgoConfig('rsa3072',    'RSA', ('-pkeyopt','rsa_keygen_bits:3072'), (), '-sha384', 'default', 'classical'),
        'rsa4096':    OpenSSLAlgoConfig('rsa4096',    'RSA', ('-pkeyopt','rsa_keygen_bits:4096'), (), '-sha512', 'default', 'classical'),
        'ecdsa-p256': OpenSSLAlgoConfig('ecdsa-p256', 'EC',  ('-pkeyopt','ec_paramgen_curve:P-256'), (), '-sha256', 'default', 'classical'),
        'ecdsa-p384': OpenSSLAlgoConfig('ecdsa-p384', 'EC',  ('-pkeyopt','ec_paramgen_curve:P-384'), (), '-sha384', 'default', 'classical'),
        'ed25519':    OpenSSLAlgoConfig('ed25519',    'ed25519', (), (), None, 'default', 'classical'),
        'ed448':      OpenSSLAlgoConfig('ed448',      'ed448',   (), (), None, 'default', 'classical'),
    }
    for tag in classical_tags:
        if tag in classical_map:
            configs.append(classical_map[tag])
        else:
            configs.append(OpenSSLAlgoConfig(
                tag, '', (), (), None, 'default', 'classical',
                available=False, skip_reason='unknown_classical_tag'))

    # PQC — conditional on detection + probe
    for pqcli_tag in pqc_tags:
        cfg = _build_pqc_config(pqcli_tag, cap)
        configs.append(cfg)

    return configs


def _build_pqc_config(pqcli_tag: str, cap: OpenSSLCapabilities) -> OpenSSLAlgoConfig:
    """Build OpenSSLAlgoConfig for a PQC tag, checking native then oqsprovider."""
    oqs_prov_flags = ('-provider', 'oqsprovider', '-provider', 'default')

    # ML-DSA
    if pqcli_tag in ('mldsa44', 'mldsa65', 'mldsa87'):
        # Native first
        if pqcli_tag in cap.native_mldsa:
            return OpenSSLAlgoConfig(
                pqcli_tag, cap.native_mldsa[pqcli_tag], (), (), None,
                'native-pqc', 'pure-pqc', available=True)
        # oqsprovider pure fallback
        if pqcli_tag in cap.oqs_pure_mldsa:
            return OpenSSLAlgoConfig(
                pqcli_tag, cap.oqs_pure_mldsa[pqcli_tag], (), oqs_prov_flags, None,
                'oqsprovider', 'pure-pqc', available=True)
        # Unavailable
        reason = ('openssl_3_5_native_pqc_not_available'
                  if not cap.oqs_available
                  else 'only_oqsprovider_combined_hybrid_algorithm_available_not_equivalent')
        return OpenSSLAlgoConfig(pqcli_tag, '', (), (), None,
                                 'default', 'pure-pqc', available=False, skip_reason=reason)

    # SLH-DSA
    if pqcli_tag in OQS_SLHDSA_TAG_TO_NAME:
        if pqcli_tag in cap.native_slhdsa:
            return OpenSSLAlgoConfig(
                pqcli_tag, cap.native_slhdsa[pqcli_tag], (), (), None,
                'native-pqc', 'pure-pqc', available=True)
        if pqcli_tag in cap.oqs_pure_slhdsa:
            return OpenSSLAlgoConfig(
                pqcli_tag, cap.oqs_pure_slhdsa[pqcli_tag], (), oqs_prov_flags, None,
                'oqsprovider', 'pure-pqc', available=True)
        reason = ('openssl_3_5_native_pqc_not_available'
                  if not cap.oqs_available
                  else 'only_oqsprovider_combined_hybrid_algorithm_available_not_equivalent')
        return OpenSSLAlgoConfig(pqcli_tag, '', (), (), None,
                                 'default', 'pure-pqc', available=False, skip_reason=reason)

    return OpenSSLAlgoConfig(pqcli_tag, '', (), (), None,
                             'default', 'pure-pqc', available=False,
                             skip_reason='unknown_pqc_tag')


# ── CSV schemas ────────────────────────────────────────────────────────────────

OPENSSL_MEAS_FIELDS = [
    'run_id', 'timestamp_utc', 'suite', 'tool',
    'openssl_bin', 'openssl_version', 'provider_state',
    'oqs_provider_present', 'algorithm_source',
    'profile', 'mode',
    'pqcli_equivalent_operation', 'openssl_operation',
    'algo_tag', 'openssl_algorithm', 'certificate_mode',
    'comparability_class',
    'iter_index', 'warmup', 'success', 'exit_code',
    'wall_time_ms', 'peak_rss_kb',
    'user_cpu_s', 'sys_cpu_s', 'cpu_pct',
    'context_switches', 'page_faults',
    'error', 'stdout_path', 'stderr_path', 'timev_path',
]

OPENSSL_SIZE_FIELDS = [
    'run_id', 'timestamp_utc', 'suite', 'tool',
    'algo_tag', 'openssl_operation', 'certificate_mode',
    'algorithm_source', 'profile', 'iter_index', 'warmup',
    'out_pub_key_pem_bytes', 'out_pub_key_der_bytes',
    'out_priv_key_pem_bytes', 'out_priv_key_der_bytes',
    'out_cert_pem_bytes', 'out_cert_der_bytes',
    'out_csr_pem_bytes', 'out_csr_der_bytes',
    'out_int_cert_pem_bytes', 'out_int_cert_der_bytes',
    'out_leaf_cert_pem_bytes', 'out_leaf_cert_der_bytes',
    'out_chain_total_pem_bytes', 'out_chain_total_der_bytes',
    'input_leaf_cert_pem_bytes', 'input_leaf_cert_der_bytes',
    'input_int_pem_bytes', 'input_int_der_bytes',
    'input_root_pem_bytes', 'input_root_der_bytes',
]

OPENSSL_SKIP_FIELDS = [
    'run_id', 'timestamp_utc', 'tool', 'profile',
    'algo_tag', 'pqcli_equivalent_operation', 'openssl_operation',
    'reason', 'category',
]


# ── ResultWriter ───────────────────────────────────────────────────────────────

class ResultWriter:
    def __init__(self, openssl_dir: Path, run_id: str, profile: str,
                 mode: str, cap: OpenSSLCapabilities):
        self.openssl_dir = openssl_dir
        self.run_id = run_id
        self.profile = profile
        self.mode = mode
        self.cap = cap
        self._meas_file = open(openssl_dir / 'measured_iterations.csv', 'w', newline='')
        self._meas_w = csv.DictWriter(self._meas_file, fieldnames=OPENSSL_MEAS_FIELDS,
                                      extrasaction='ignore')
        self._meas_w.writeheader()
        self._size_file = open(openssl_dir / 'sizing_measurements.csv', 'w', newline='')
        self._size_w = csv.DictWriter(self._size_file, fieldnames=OPENSSL_SIZE_FIELDS,
                                      extrasaction='ignore')
        self._size_w.writeheader()
        self._skip_file: Optional[object] = None
        self._skip_w: Optional[csv.DictWriter] = None
        self.skips_path = openssl_dir / 'skips.csv'

    def _base(self, cfg: OpenSSLAlgoConfig) -> dict:
        return {
            'run_id':            self.run_id,
            'suite':             'openssl',
            'tool':              'openssl',
            'openssl_bin':       self.cap.openssl_bin,
            'openssl_version':   self.cap.openssl_version_short,
            'provider_state':    self.cap.provider_state,
            'oqs_provider_present': '1' if self.cap.oqs_available else '0',
            'algorithm_source':  cfg.algorithm_source,
            'profile':           self.profile,
            'mode':              self.mode,
            'algo_tag':          cfg.pqcli_tag,
            'openssl_algorithm': cfg.openssl_algorithm,
            'certificate_mode':  cfg.certificate_mode,
            'comparability_class': cfg.comparability_class,
        }

    def write_iter(self, cfg: OpenSSLAlgoConfig, op: str, iter_idx: int, warmup: bool,
                   result: RunResult, sizes: dict) -> None:
        ts = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())
        success = '1' if result.exit_code == 0 else '0'
        row = {
            **self._base(cfg),
            'timestamp_utc':              ts,
            'pqcli_equivalent_operation': op,
            'openssl_operation':          op,
            'iter_index':                 iter_idx,
            'warmup':                     '1' if warmup else '0',
            'success':                    success,
            'exit_code':                  result.exit_code,
            'wall_time_ms':               result.wall_time_ms if result.wall_time_ms is not None else '',
            'peak_rss_kb':                result.peak_rss_kb if result.peak_rss_kb is not None else '',
            'user_cpu_s':                 result.user_cpu_s if result.user_cpu_s is not None else '',
            'sys_cpu_s':                  result.sys_cpu_s if result.sys_cpu_s is not None else '',
            'cpu_pct':                    result.cpu_pct if result.cpu_pct is not None else '',
            'context_switches':           result.context_switches if result.context_switches is not None else '',
            'page_faults':                result.page_faults if result.page_faults is not None else '',
            'error':                      '' if result.exit_code == 0 else f'exit {result.exit_code}',
            'stdout_path':                str(result.stdout_path) if result.stdout_path else '',
            'stderr_path':                str(result.stderr_path) if result.stderr_path else '',
            'timev_path':                 str(result.timev_path) if result.timev_path else '',
        }
        if not warmup:
            self._meas_w.writerow(row)
            self._meas_file.flush()
        sz_row = {**self._base(cfg), 'timestamp_utc': ts,
                  'openssl_operation': op, 'iter_index': iter_idx,
                  'warmup': '1' if warmup else '0', **sizes}
        self._size_w.writerow(sz_row)
        self._size_file.flush()

    def skip(self, algo_tag: str, op: str, reason: str, category: str = '') -> None:
        if self._skip_file is None:
            self._skip_file = open(self.skips_path, 'w', newline='')
            self._skip_w = csv.DictWriter(self._skip_file, fieldnames=OPENSSL_SKIP_FIELDS,
                                          extrasaction='ignore')
            self._skip_w.writeheader()
        ts = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())
        self._skip_w.writerow({
            'run_id': self.run_id,
            'timestamp_utc': ts,
            'tool': 'openssl',
            'profile': self.profile,
            'algo_tag': algo_tag,
            'pqcli_equivalent_operation': op,
            'openssl_operation': op,
            'reason': reason,
            'category': category,
        })
        self._skip_file.flush()

    def close(self) -> None:
        self._meas_file.close()
        self._size_file.close()
        if self._skip_file:
            self._skip_file.close()


# ── Config file helpers ────────────────────────────────────────────────────────

def write_config_files(staging: Path) -> tuple[Path, Path, Path]:
    ca_cnf   = staging / 'openssl-ca.cnf'
    leaf_cnf = staging / 'openssl-leaf.cnf'
    int_cnf  = staging / 'openssl-int.cnf'
    ca_cnf.write_text(CA_CNF)
    leaf_cnf.write_text(LEAF_CNF)
    int_cnf.write_text(INT_CNF)
    return ca_cnf, leaf_cnf, int_cnf


def copy_config_files(ca_cnf: Path, leaf_cnf: Path, int_cnf: Path,
                      openssl_dir: Path) -> None:
    cfg_dir = openssl_dir / 'config'
    cfg_dir.mkdir(exist_ok=True)
    for src in (ca_cnf, leaf_cnf, int_cnf):
        shutil.copy2(src, cfg_dir / src.name)


# ── Shell script builders ──────────────────────────────────────────────────────

def _algo_args(cfg: OpenSSLAlgoConfig) -> tuple[list[str], list[str]]:
    """Return (genpkey_args, provider_flags) for this config."""
    return list(cfg.genpkey_extra_args), list(cfg.provider_flags)


def _keygen_script(ossl: str, cfg: OpenSSLAlgoConfig, priv: Path, pub: Path) -> str:
    extra, prov = _algo_args(cfg)
    genpkey_cmd = ' '.join([ossl, 'genpkey', '-algorithm', cfg.openssl_algorithm]
                           + extra + prov + ['-out', str(priv)])
    pubout_cmd  = ' '.join([ossl, 'pkey'] + prov + ['-in', str(priv), '-pubout', '-out', str(pub)])
    return f'set -e\n{genpkey_cmd}\n{pubout_cmd}\n'


def _cert_script(ossl: str, cfg: OpenSSLAlgoConfig,
                 priv: Path, cert: Path, ca_cnf: Path, tag: str) -> str:
    extra, prov = _algo_args(cfg)
    hash_arg = ([cfg.hash_flag] if cfg.hash_flag else [])
    genpkey_cmd = ' '.join([ossl, 'genpkey', '-algorithm', cfg.openssl_algorithm]
                           + extra + prov + ['-out', str(priv)])
    req_cmd = ' '.join([ossl, 'req', '-x509', '-key', str(priv),
                        '-subj', f'/CN=Bench-{tag}', '-days', '365']
                       + hash_arg + ['-out', str(cert), '-config', str(ca_cnf)] + prov)
    return f'set -e\n{genpkey_cmd}\n{req_cmd}\n'


def _csr_script(ossl: str, cfg: OpenSSLAlgoConfig,
                priv: Path, csr: Path, tag: str) -> str:
    extra, prov = _algo_args(cfg)
    genpkey_cmd = ' '.join([ossl, 'genpkey', '-algorithm', cfg.openssl_algorithm]
                           + extra + prov + ['-out', str(priv)])
    req_cmd = ' '.join([ossl, 'req', '-new', '-key', str(priv),
                        '-subj', f'/CN=Bench-{tag}', '-out', str(csr)] + prov)
    return f'set -e\n{genpkey_cmd}\n{req_cmd}\n'


def _sign_cmd(ossl: str, cfg: OpenSSLAlgoConfig,
              csr: Path, ca_cert: Path, ca_key: Path,
              out_cert: Path, srl: Path, days: int,
              ext_cnf: Path, ext_name: str) -> list[str]:
    prov = list(cfg.provider_flags)
    hash_arg = ([cfg.hash_flag] if cfg.hash_flag else [])
    # -CAcreateserial creates the .srl file if absent; -CAserial specifies its path
    # for per-iteration isolation. Together they work on both first and subsequent uses.
    return ([ossl, 'x509', '-req'] + prov
            + ['-in', str(csr), '-CA', str(ca_cert), '-CAkey', str(ca_key),
               '-CAserial', str(srl), '-CAcreateserial']
            + hash_arg
            + ['-out', str(out_cert), '-days', str(days),
               '-extfile', str(ext_cnf), '-extensions', ext_name])


def _verify_cmd(ossl: str, cfg: OpenSSLAlgoConfig,
                ca_cert: Path, leaf_cert: Path,
                untrusted: Optional[Path] = None) -> list[str]:
    prov = list(cfg.provider_flags)
    cmd = [ossl, 'verify'] + prov + ['-CAfile', str(ca_cert)]
    if untrusted:
        cmd += ['-untrusted', str(untrusted)]
    cmd.append(str(leaf_cert))
    return cmd


# ── Pre-generation ─────────────────────────────────────────────────────────────

@dataclass
class PregenState:
    ok: dict[str, bool] = field(default_factory=dict)

    # Artifact paths per operation
    cert_cert: Optional[Path] = None
    cert_priv: Optional[Path] = None

    sigca_cert: Optional[Path] = None
    sigca_key: Optional[Path] = None
    sigee_csr: Optional[Path] = None
    sigee_key: Optional[Path] = None

    isroot_cert: Optional[Path] = None
    isroot_key: Optional[Path] = None
    isint_csr: Optional[Path] = None

    vcert_ca_cert: Optional[Path] = None
    vcert_leaf_cert: Optional[Path] = None

    cv_root_cert: Optional[Path] = None
    cv_int_cert: Optional[Path] = None
    cv_leaf_cert: Optional[Path] = None

    direct_root_cert: Optional[Path] = None
    direct_leaf_cert: Optional[Path] = None


def pregen_algo(
    cfg: OpenSSLAlgoConfig,
    staging: Path,
    pregen_dir: Path,
    ossl: str,
    ca_cnf: Path,
    leaf_cnf: Path,
    int_cnf: Path,
    env: dict,
    writer: ResultWriter,
    taskset_cpu: Optional[str],
) -> PregenState:
    s = PregenState()
    tag = cfg.pqcli_tag
    pregen_dir.mkdir(parents=True, exist_ok=True)
    (pregen_dir / 'command.log').write_text(
        f'tag={tag}\nalgorithm={cfg.openssl_algorithm}\nsource={cfg.algorithm_source}\n')

    extra, prov = _algo_args(cfg)
    hash_arg = ([cfg.hash_flag] if cfg.hash_flag else [])

    def _gen_key(step: str, key_path: Path) -> bool:
        cmd = [ossl, 'genpkey', '-algorithm', cfg.openssl_algorithm] + extra + prov + ['-out', str(key_path)]
        ok = _run_quiet(cmd, pregen_dir, step, env)
        if not ok:
            writer.skip(tag, step, 'pregen_genpkey_failed', 'pregen')
        return ok

    def _gen_cert(step: str, key_path: Path, cert_path: Path, cn: str) -> bool:
        cmd = ([ossl, 'req', '-x509', '-key', str(key_path),
                '-subj', f'/CN={cn}', '-days', '365']
               + hash_arg + ['-out', str(cert_path), '-config', str(ca_cnf)] + prov)
        ok = _run_quiet(cmd, pregen_dir, step, env)
        if not ok:
            writer.skip(tag, step, 'pregen_cert_failed', 'pregen')
        return ok

    def _gen_csr(step: str, key_path: Path, csr_path: Path, cn: str) -> bool:
        cmd = [ossl, 'req', '-new', '-key', str(key_path),
               '-subj', f'/CN={cn}', '-out', str(csr_path)] + prov
        ok = _run_quiet(cmd, pregen_dir, step, env)
        if not ok:
            writer.skip(tag, step, 'pregen_csr_failed', 'pregen')
        return ok

    def _sign(step: str, csr: Path, ca_cert: Path, ca_key: Path,
              out: Path, srl_path: Path, days: int, cnf: Path, ext: str) -> bool:
        cmd = _sign_cmd(ossl, cfg, csr, ca_cert, ca_key, out, srl_path, days, cnf, ext)
        ok = _run_quiet(cmd, pregen_dir, step, env)
        if not ok:
            writer.skip(tag, step, 'pregen_sign_failed', 'pregen')
        return ok

    def p(name: str) -> Path:
        return pregen_dir / name

    # cert pregen
    cert_priv = p('cert_key.pem'); cert_cert = p('cert_cert.pem')
    if _gen_key('cert_key', cert_priv) and _gen_cert('cert_cert', cert_priv, cert_cert, f'Bench-{tag}'):
        s.cert_cert = cert_cert; s.cert_priv = cert_priv
        s.ok['cert'] = True
    else:
        s.ok['cert'] = False

    # sign-leaf pregen
    sigca_key = p('sigca_key.pem'); sigca_cert = p('sigca_cert.pem')
    sigee_key = p('sigee_key.pem'); sigee_csr = p('sigee_csr.pem')
    ok_sigca = _gen_key('sigca_key', sigca_key) and _gen_cert('sigca_cert', sigca_key, sigca_cert, f'SignCA-{tag}')
    ok_sigee = _gen_key('sigee_key', sigee_key) and _gen_csr('sigee_csr', sigee_key, sigee_csr, f'SignEE-{tag}')
    s.ok['sign-leaf'] = ok_sigca and ok_sigee
    if ok_sigca and ok_sigee:
        s.sigca_cert = sigca_cert; s.sigca_key = sigca_key
        s.sigee_csr = sigee_csr; s.sigee_key = sigee_key

    # sign-intermediate-ca pregen
    isroot_key = p('isroot_key.pem'); isroot_cert = p('isroot_cert.pem')
    isint_key = p('isint_key.pem'); isint_csr = p('isint_csr.pem')
    ok_isr = _gen_key('isroot_key', isroot_key) and _gen_cert('isroot_cert', isroot_key, isroot_cert, f'ISRoot-{tag}')
    ok_isi = _gen_key('isint_key', isint_key) and _gen_csr('isint_csr', isint_key, isint_csr, f'ISInt-{tag}')
    s.ok['sign-intermediate-ca'] = ok_isr and ok_isi
    if ok_isr and ok_isi:
        s.isroot_cert = isroot_cert; s.isroot_key = isroot_key
        s.isint_csr = isint_csr

    # verify-issued pregen
    vca_key = p('vca_key.pem'); vca_cert = p('vca_cert.pem')
    vee_key = p('vee_key.pem'); vee_csr = p('vee_csr.pem'); vleaf_cert = p('vleaf_cert.pem')
    ok_vca = _gen_key('vca_key', vca_key) and _gen_cert('vca_cert', vca_key, vca_cert, f'VCA-{tag}')
    ok_vee = _gen_key('vee_key', vee_key) and _gen_csr('vee_csr', vee_key, vee_csr, f'VEE-{tag}')
    if ok_vca and ok_vee:
        ok_vs = _sign('vleaf', vee_csr, vca_cert, vca_key, vleaf_cert,
                      p('vleaf.srl'), 365, leaf_cnf, 'leaf_ext')
        s.ok['verify-issued'] = ok_vs
        if ok_vs:
            s.vcert_ca_cert = vca_cert; s.vcert_leaf_cert = vleaf_cert
    else:
        s.ok['verify-issued'] = False

    # 3-tier chain pregen (verify-modeB-dynamic)
    cr_key = p('cr_key.pem'); cr_cert = p('cr_cert.pem')
    ci_key = p('ci_key.pem'); ci_csr = p('ci_csr.pem'); ci_cert = p('ci_cert.pem')
    cl_key = p('cl_key.pem'); cl_csr = p('cl_csr.pem'); cl_cert = p('cl_cert.pem')
    ok_cr = _gen_key('cr_key', cr_key) and _gen_cert('cr_cert', cr_key, cr_cert, f'CVRoot-{tag}')
    if ok_cr:
        ok_ci_k = _gen_key('ci_key', ci_key)
        ok_ci_c = ok_ci_k and _gen_csr('ci_csr', ci_key, ci_csr, f'CVInt-{tag}')
        ok_ci = ok_ci_c and _sign('ci_cert', ci_csr, cr_cert, cr_key, ci_cert,
                                  p('ci.srl'), 1825, int_cnf, 'intermediate_ca_ext')
        if ok_ci:
            ok_cl_k = _gen_key('cl_key', cl_key)
            ok_cl_c = ok_cl_k and _gen_csr('cl_csr', cl_key, cl_csr, f'CVLeaf-{tag}')
            ok_cl = ok_cl_c and _sign('cl_cert', cl_csr, ci_cert, ci_key, cl_cert,
                                      p('cl.srl'), 365, leaf_cnf, 'leaf_ext')
            chain_ok = ok_cl
        else:
            chain_ok = False
    else:
        chain_ok = False
    s.ok['verify-modeB-dynamic'] = chain_ok
    if chain_ok:
        s.cv_root_cert = cr_cert; s.cv_int_cert = ci_cert; s.cv_leaf_cert = cl_cert

    # verify-modeB-direct pregen (root signs leaf directly)
    dr_key = p('dr_key.pem'); dr_cert = p('dr_cert.pem')
    dl_key = p('dl_key.pem'); dl_csr = p('dl_csr.pem'); dl_cert = p('dl_cert.pem')
    ok_dr = _gen_key('dr_key', dr_key) and _gen_cert('dr_cert', dr_key, dr_cert, f'DRoot-{tag}')
    if ok_dr:
        ok_dl_k = _gen_key('dl_key', dl_key)
        ok_dl_c = ok_dl_k and _gen_csr('dl_csr', dl_key, dl_csr, f'DLeaf-{tag}')
        ok_dl = ok_dl_c and _sign('dl_cert', dl_csr, dr_cert, dr_key, dl_cert,
                                  p('dl.srl'), 365, leaf_cnf, 'leaf_ext')
        s.ok['verify-modeB-direct'] = ok_dl
        if ok_dl:
            s.direct_root_cert = dr_cert; s.direct_leaf_cert = dl_cert
    else:
        s.ok['verify-modeB-direct'] = False

    return s


# ── Iteration runner ───────────────────────────────────────────────────────────

def run_op_iterations(
    cfg: OpenSSLAlgoConfig,
    op: str,
    pregen: PregenState,
    op_dir: Path,
    staging: Path,
    ossl: str,
    ca_cnf: Path,
    leaf_cnf: Path,
    int_cnf: Path,
    env: dict,
    tmpdir: Path,
    taskset_cpu: Optional[str],
    warmup_count: int,
    measured_count: int,
    writer: ResultWriter,
    op_idx: int,
    ops_total: int,
) -> None:
    op_dir.mkdir(parents=True, exist_ok=True)
    cmd_log = op_dir / 'command.log'
    tag = cfg.pqcli_tag

    # Op not available from pregen
    if not pregen.ok.get(op, op in ('keygen', 'cert', 'csr')):
        writer.skip(tag, op, 'pregen_failed', 'pregen')
        return

    log.info('  [op %d/%d] %s/%s: %d iter + %d warmup',
             op_idx + 1, ops_total, tag, op, measured_count, warmup_count)
    total = warmup_count + measured_count

    per_iter_staging = staging / tag / op
    per_iter_staging.mkdir(parents=True, exist_ok=True)

    with (open(op_dir / 'warmup_iterations.csv', 'w', newline='') as wf,
          open(op_dir / 'iterations.csv', 'w', newline='') as mf):
        wcsv = csv.DictWriter(wf, fieldnames=['iter_index', 'warmup', 'exit_code',
                                              'wall_time_ms', 'peak_rss_kb', 'error'])
        mcsv = csv.DictWriter(mf, fieldnames=['iter_index', 'warmup', 'exit_code',
                                              'wall_time_ms', 'peak_rss_kb', 'error'])
        wcsv.writeheader(); mcsv.writeheader()

        for idx in range(total):
            is_w = idx < warmup_count
            meas_idx = idx - warmup_count if not is_w else idx
            iter_tag = f'warmup_{idx:03d}' if is_w else f'{meas_idx:03d}'
            iter_dir = per_iter_staging / iter_tag
            iter_dir.mkdir(parents=True, exist_ok=True)

            result, sizes = _run_one_iter(
                cfg, op, pregen, iter_dir, ossl, ca_cnf, leaf_cnf, int_cnf,
                op_dir, iter_tag, tmpdir, taskset_cpu, cmd_log, env)

            row = {
                'iter_index': meas_idx, 'warmup': '1' if is_w else '0',
                'exit_code': result.exit_code,
                'wall_time_ms': result.wall_time_ms or '',
                'peak_rss_kb': result.peak_rss_kb or '',
                'error': '' if result.exit_code == 0 else f'exit {result.exit_code}',
            }
            (wcsv if is_w else mcsv).writerow(row)
            writer.write_iter(cfg, op, meas_idx, is_w, result, sizes)


def _run_one_iter(
    cfg: OpenSSLAlgoConfig, op: str, pregen: PregenState,
    iter_dir: Path, ossl: str, ca_cnf: Path, leaf_cnf: Path, int_cnf: Path,
    op_dir: Path, iter_tag: str, tmpdir: Path, taskset_cpu: Optional[str],
    cmd_log: Path, env: dict,
) -> tuple[RunResult, dict]:
    tag = cfg.pqcli_tag
    sizes: dict = {f: '' for f in OPENSSL_SIZE_FIELDS
                   if f.endswith('_bytes')}

    if op == 'keygen':
        priv = iter_dir / 'private_key.pem'
        pub  = iter_dir / 'public_key.pem'
        script = _keygen_script(ossl, cfg, priv, pub)
        result = run_shell_timed(script, op_dir, iter_tag, tmpdir, taskset_cpu,
                                 cmd_log if not cmd_log.exists() else None)
        if result.exit_code == 0:
            sizes['out_priv_key_pem_bytes'], sizes['out_priv_key_der_bytes'] = _mf(priv)
            sizes['out_pub_key_pem_bytes'],  sizes['out_pub_key_der_bytes']  = _mf(pub)

    elif op == 'cert':
        priv = iter_dir / 'private_key.pem'
        cert = iter_dir / 'certificate.pem'
        script = _cert_script(ossl, cfg, priv, cert, ca_cnf, tag)
        result = run_shell_timed(script, op_dir, iter_tag, tmpdir, taskset_cpu,
                                 cmd_log if not cmd_log.exists() else None)
        if result.exit_code == 0:
            sizes['out_priv_key_pem_bytes'], sizes['out_priv_key_der_bytes'] = _mf(priv)
            sizes['out_cert_pem_bytes'],     sizes['out_cert_der_bytes']     = _mf(cert)

    elif op == 'csr':
        priv = iter_dir / 'private_key.pem'
        csr  = iter_dir / 'csr.pem'
        script = _csr_script(ossl, cfg, priv, csr, tag)
        result = run_shell_timed(script, op_dir, iter_tag, tmpdir, taskset_cpu,
                                 cmd_log if not cmd_log.exists() else None)
        if result.exit_code == 0:
            sizes['out_priv_key_pem_bytes'], sizes['out_priv_key_der_bytes'] = _mf(priv)
            sizes['out_csr_pem_bytes'],      sizes['out_csr_der_bytes']      = _mf(csr)

    elif op == 'sign-leaf':
        assert pregen.sigca_cert and pregen.sigca_key and pregen.sigee_csr
        out_cert = iter_dir / 'leaf_cert.pem'
        srl = iter_dir / f'{tag}.srl'
        cmd = _sign_cmd(ossl, cfg, pregen.sigee_csr, pregen.sigca_cert,
                        pregen.sigca_key, out_cert, srl, 365, leaf_cnf, 'leaf_ext')
        if not cmd_log.exists():
            cmd_log.write_text(' '.join(cmd))
        result = run_timed(cmd, op_dir, iter_tag, tmpdir, taskset_cpu)
        if result.exit_code == 0:
            sizes['out_leaf_cert_pem_bytes'], sizes['out_leaf_cert_der_bytes'] = _mf(out_cert)
            sizes['input_leaf_cert_pem_bytes'] = str(pregen.sigee_csr.stat().st_size)

    elif op == 'sign-intermediate-ca':
        assert pregen.isroot_cert and pregen.isroot_key and pregen.isint_csr
        out_cert = iter_dir / 'int_cert.pem'
        srl = iter_dir / f'{tag}.srl'
        cmd = _sign_cmd(ossl, cfg, pregen.isint_csr, pregen.isroot_cert,
                        pregen.isroot_key, out_cert, srl, 1825, int_cnf, 'intermediate_ca_ext')
        if not cmd_log.exists():
            cmd_log.write_text(' '.join(cmd))
        result = run_timed(cmd, op_dir, iter_tag, tmpdir, taskset_cpu)
        if result.exit_code == 0:
            sizes['out_int_cert_pem_bytes'], sizes['out_int_cert_der_bytes'] = _mf(out_cert)

    elif op == 'verify-issued':
        assert pregen.vcert_ca_cert and pregen.vcert_leaf_cert
        cmd = _verify_cmd(ossl, cfg, pregen.vcert_ca_cert, pregen.vcert_leaf_cert)
        if not cmd_log.exists():
            cmd_log.write_text(' '.join(cmd))
        result = run_timed(cmd, op_dir, iter_tag, tmpdir, taskset_cpu)
        sizes['input_leaf_cert_pem_bytes'], sizes['input_leaf_cert_der_bytes'] = _mf(pregen.vcert_leaf_cert)
        sizes['input_root_pem_bytes'], sizes['input_root_der_bytes'] = _mf(pregen.vcert_ca_cert)

    elif op == 'verify-modeB-dynamic':
        assert pregen.cv_root_cert and pregen.cv_int_cert and pregen.cv_leaf_cert
        cmd = _verify_cmd(ossl, cfg, pregen.cv_root_cert, pregen.cv_leaf_cert,
                          untrusted=pregen.cv_int_cert)
        if not cmd_log.exists():
            cmd_log.write_text(' '.join(cmd))
        result = run_timed(cmd, op_dir, iter_tag, tmpdir, taskset_cpu)
        sizes['input_leaf_cert_pem_bytes'], sizes['input_leaf_cert_der_bytes'] = _mf(pregen.cv_leaf_cert)
        sizes['input_int_pem_bytes'],       sizes['input_int_der_bytes']       = _mf(pregen.cv_int_cert)
        sizes['input_root_pem_bytes'],      sizes['input_root_der_bytes']      = _mf(pregen.cv_root_cert)

    elif op == 'verify-modeB-direct':
        assert pregen.direct_root_cert and pregen.direct_leaf_cert
        cmd = _verify_cmd(ossl, cfg, pregen.direct_root_cert, pregen.direct_leaf_cert)
        if not cmd_log.exists():
            cmd_log.write_text(' '.join(cmd))
        result = run_timed(cmd, op_dir, iter_tag, tmpdir, taskset_cpu)
        sizes['input_leaf_cert_pem_bytes'], sizes['input_leaf_cert_der_bytes'] = _mf(pregen.direct_leaf_cert)
        sizes['input_root_pem_bytes'],      sizes['input_root_der_bytes']      = _mf(pregen.direct_root_cert)

    else:
        result = RunResult(exit_code=-1, wall_time_ms=None, peak_rss_kb=None,
                           user_cpu_s=None, sys_cpu_s=None, cpu_pct=None,
                           context_switches=None, page_faults=None)

    return result, sizes


def run_single_algo(
    cfg: OpenSSLAlgoConfig,
    ops: list[str],
    openssl_dir: Path,
    staging: Path,
    ossl: str,
    ca_cnf: Path,
    leaf_cnf: Path,
    int_cnf: Path,
    env: dict,
    tmpdir: Path,
    taskset_cpu: Optional[str],
    warmup_count: int,
    measured_count: int,
    writer: ResultWriter,
    algo_idx: int,
    algos_total: int,
) -> None:
    tag = cfg.pqcli_tag
    log.info('[algo %d/%d] %s (source=%s available=%s)',
             algo_idx + 1, algos_total, tag, cfg.algorithm_source, cfg.available)

    if not cfg.available:
        for op in ops:
            writer.skip(tag, op, cfg.skip_reason or 'unavailable', 'algorithm_unavailable')
        return

    # Skip operations with no OpenSSL equivalent
    always_skip = {
        'verify-modeA-chain':  'no_openssl_cli_equivalent_for_raw_per_link_verification',
        'workflow-2tier':      'no_openssl_equivalent',
        'workflow-3tier':      'no_openssl_equivalent',
        'verify-selfsigned':   'no_openssl_equivalent',
    }
    ops_to_run = []
    for op in ops:
        if op in always_skip:
            writer.skip(tag, op, always_skip[op], 'no_equivalent')
        else:
            ops_to_run.append(op)

    # Pre-generate artifacts
    algo_staging = staging / tag
    pregen_dir   = algo_staging / 'pregeneration'
    pregen = pregen_algo(cfg, algo_staging, pregen_dir, ossl, ca_cnf, leaf_cnf,
                         int_cnf, env, writer, taskset_cpu)

    # Run iterations per op
    ops_total = len(ops_to_run)
    for op_idx, op in enumerate(ops_to_run):
        op_dir = openssl_dir / tag / op
        run_op_iterations(
            cfg, op, pregen, op_dir, staging, ossl, ca_cnf, leaf_cnf, int_cnf,
            env, tmpdir, taskset_cpu, warmup_count, measured_count, writer,
            op_idx, ops_total)


# ── Metadata ───────────────────────────────────────────────────────────────────

def build_metadata(
    cap: OpenSSLCapabilities, run_id: str, profile: str, mode: str,
    ops: list[str], algo_tags: list[str],
    warmup: int, measured: int,
) -> dict:
    meta: dict = {}
    try: meta['hostname'] = socket.gethostname()
    except Exception: meta['hostname'] = 'unknown'
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
    return {
        'run_id': run_id,
        'timestamp_utc': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
        **meta,
        'suite': 'openssl',
        'tool': 'openssl',
        'openssl_bin': cap.openssl_bin,
        'openssl_bin_source': cap.openssl_bin_source,
        'OQS_OPENSSL_env': os.environ.get('OQS_OPENSSL', 'not_set'),
        'OPENSSL_MODULES_effective': cap.openssl_modules_effective or 'not_set',
        'openssl_version_full': cap.openssl_version_full,
        'openssl_version_short': cap.openssl_version_short,
        'provider_state': cap.provider_state,
        'oqs_provider_present': cap.oqs_available,
        'oqs_provider_version': cap.oqs_version,
        'native_mldsa_detected': bool(cap.native_mldsa),
        'native_slh_dsa_detected': bool(cap.native_slhdsa),
        'oqs_pure_mldsa_detected': bool(cap.oqs_pure_mldsa),
        'oqs_pure_slh_dsa_detected': bool(cap.oqs_pure_slhdsa),
        'oqs_combined_mldsa_detected': any('mldsa' in n for n in cap.oqs_combined),
        'detected_native_pqc_algorithms': {**cap.native_mldsa, **cap.native_slhdsa},
        'detected_oqs_pure_pqc_algorithms': {**cap.oqs_pure_mldsa, **cap.oqs_pure_slhdsa},
        'detected_oqs_combined_or_hybrid_signature_algorithms': cap.oqs_combined,
        'detected_oqs_kem_algorithms_metadata_only': cap.oqs_kem,
        'profile': profile,
        'mode': mode,
        'operations': ops,
        'algo_tags': algo_tags,
        'warmup_iterations': warmup,
        'measured_iterations': measured,
        'measurement_tool': '/usr/bin/time -v',
        'comparability_class': 'partial',
        'comparability_note': (
            'OpenSSL macro rows include native process startup (openssl CLI launch). '
            'pqcli macro rows include JVM startup. '
            'Neither is overhead-free; the startup overheads differ in kind and magnitude. '
            'Do NOT compare OpenSSL macro rows to JMH micro rows (jmh_score_ms).'
        ),
        'sign_op_csr_pop_caveat': (
            'pqcli sign verifies CSR proof-of-possession before issuance. '
            'openssl x509 -req does not. Therefore sign-leaf and sign-intermediate-ca '
            'are partial comparisons only.'
        ),
        'oqs_combined_excluded_note': (
            'oqsprovider combined/hybrid algorithm names (e.g. p256_mldsa44, rsa3072_mldsa44) '
            'are NOT equivalent to pqcli pure ML-DSA, pqcli hybrid alternate-signature certificates, '
            'or pqcli composite certificates. They are excluded from benchmarking.'
        ),
        'kem_note': 'KEM algorithms are out of scope and are recorded for metadata only.',
    }


# ── Aggregation call ───────────────────────────────────────────────────────────

def run_aggregator(openssl_dir: Path) -> None:
    aggregate_py = SCRIPT_DIR / 'aggregate_results.py'
    if aggregate_py.exists():
        log.info('[AGGREGATE] calling aggregate_results.py ...')
        subprocess.run([sys.executable, str(aggregate_py), str(openssl_dir)])
    else:
        log.warning('[AGGREGATE] aggregate_results.py not found — skipping')


# ── Preflight ──────────────────────────────────────────────────────────────────

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


def check_taskset(cpu: str) -> bool:
    try:
        return subprocess.run(['taskset', '-c', cpu, 'true'],
                              capture_output=True).returncode == 0
    except Exception:
        return False


# ── CLI ────────────────────────────────────────────────────────────────────────

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description='OpenSSL macro benchmark harness')
    p.add_argument('--profile', default='openssl-thesis-core',
                   choices=list(OPENSSL_PROFILES))
    p.add_argument('--mode', default='stable', choices=['stable', 'dry'])
    p.add_argument('--openssl-bin', default=None, dest='openssl_bin',
                   help='OpenSSL executable (overrides OQS_OPENSSL; falls back to "openssl")')
    p.add_argument('--openssl-modules', default=None, dest='openssl_modules',
                   help='OPENSSL_MODULES path (overrides OPENSSL_MODULES env var)')
    p.add_argument('--detect-only', action='store_true', dest='detect_only',
                   help='Run capability detection and print results, then exit')
    p.add_argument('--out',     type=Path, default=None)
    p.add_argument('--staging', type=Path, default=None)
    p.add_argument('--tmpdir',  type=Path, default=None)
    p.add_argument('--ops',     default=None)
    p.add_argument('--algos',   default=None)
    p.add_argument('--iter',    type=int, default=None)
    p.add_argument('--warmup',  type=int, default=None)
    p.add_argument('--taskset-cpu', default=None, dest='taskset_cpu')
    p.add_argument('--no-perf', action='store_true')
    p.add_argument('--verbose', '-v', action='store_true')
    return p.parse_args()


def main() -> int:
    args = parse_args()
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format='%(asctime)s %(levelname)s %(message)s', datefmt='%H:%M:%S')

    ts = time.strftime('%Y%m%d_%H%M%S')

    # OpenSSL executable selection
    if args.openssl_bin:
        ossl = args.openssl_bin
        ossl_source = 'cli-override'
    elif 'OQS_OPENSSL' in os.environ:
        ossl = os.environ['OQS_OPENSSL']
        ossl_source = 'OQS_OPENSSL'
    else:
        ossl = 'openssl'
        ossl_source = 'fallback'

    if not shutil.which(ossl):
        log.error('[PREFLIGHT] OpenSSL executable not found: %s', ossl)
        return 1

    # OPENSSL_MODULES selection
    openssl_modules: Optional[str] = args.openssl_modules or os.environ.get('OPENSSL_MODULES')

    if args.tmpdir is None:
        args.tmpdir = Path(tempfile.gettempdir())
    args.tmpdir.mkdir(parents=True, exist_ok=True)

    # Capability detection
    log.info('[DETECT] Checking OpenSSL capabilities at %s ...', ossl)
    cap = detect_openssl_capabilities(ossl, ossl_source, openssl_modules, args.tmpdir)
    print_capabilities(cap)

    if args.detect_only:
        return 0

    # Preflight
    if not check_timev(args.tmpdir):
        log.error('[PREFLIGHT] /usr/bin/time -v --output not functional — cannot proceed')
        return 1

    # Paths
    if args.out is None:
        args.out = SCRIPT_DIR / 'results' / ts
    if args.staging is None:
        args.staging = SCRIPT_DIR / '.staging' / ts

    args.out.mkdir(parents=True, exist_ok=True)
    args.staging.mkdir(parents=True, exist_ok=True)
    openssl_dir = args.out / 'openssl'
    openssl_dir.mkdir(exist_ok=True)

    # Profile resolution
    profile_cfg = OPENSSL_PROFILES[args.profile]
    classical_tags: list[str] = list(profile_cfg['classical_tags'])
    pqc_tags: list[str]       = list(profile_cfg['pqc_tags'])
    operations: list[str]     = list(profile_cfg['operations'])
    measured_count = args.iter   if args.iter   else profile_cfg['default_iter']
    warmup_count   = args.warmup if args.warmup else profile_cfg['default_warmup']
    if args.mode == 'dry':
        measured_count = min(measured_count, DRY_ITERATIONS)
        warmup_count   = min(warmup_count, 2)

    if args.algos:
        requested = set(args.algos.split(','))
        classical_tags = [t for t in classical_tags if t in requested]
        pqc_tags       = [t for t in pqc_tags       if t in requested]

    if args.ops:
        requested_ops = set(args.ops.split(','))
        operations = [o for o in operations if o in requested_ops]

    # Taskset
    taskset_cpu = args.taskset_cpu
    if taskset_cpu and not check_taskset(taskset_cpu):
        log.warning('[TASKSET] taskset -c %s failed — continuing without', taskset_cpu)
        taskset_cpu = None

    # Config files
    ca_cnf, leaf_cnf, int_cnf = write_config_files(args.staging)

    # Subprocess env
    env = os.environ.copy()
    if openssl_modules:
        env['OPENSSL_MODULES'] = openssl_modules

    # Build algo configs
    all_configs = build_algo_configs(classical_tags, pqc_tags, cap)

    run_id = ts
    writer = ResultWriter(openssl_dir, run_id, args.profile, args.mode, cap)

    # Write metadata
    all_tags = [c.pqcli_tag for c in all_configs]
    meta = build_metadata(cap, run_id, args.profile, args.mode, operations,
                          all_tags, warmup_count, measured_count)
    (openssl_dir / 'metadata.json').write_text(json.dumps(meta, indent=2))

    log.info('[RUN] profile=%s mode=%s iter=%d warmup=%d',
             args.profile, args.mode, measured_count, warmup_count)
    log.info('[RUN] %d algo configs, %d operations', len(all_configs), len(operations))

    algos_total = len(all_configs)
    for algo_idx, cfg in enumerate(all_configs):
        run_single_algo(
            cfg, operations, openssl_dir, args.staging, ossl,
            ca_cnf, leaf_cnf, int_cnf, env, args.tmpdir, taskset_cpu,
            warmup_count, measured_count, writer, algo_idx, algos_total)

    writer.close()

    # Copy config files to openssl/config/ for reproducibility
    copy_config_files(ca_cnf, leaf_cnf, int_cnf, openssl_dir)

    # Aggregation
    run_aggregator(openssl_dir)

    log.info('[DONE] OpenSSL results in: %s', openssl_dir)
    return 0


if __name__ == '__main__':
    sys.exit(main())
