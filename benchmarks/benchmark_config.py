"""
benchmark_config.py — PQCLI benchmark configuration

Single source of truth for:
- Algorithm / config matrix (classical, PQC, composite, hybrid, dual/RFC 9763)
- Operation definitions and applicable_ops per certificate_mode
- Artifact path templates (keyed to pqcli -out prefix conventions)
- Run profiles (smoke, thesis-core, slh-heavy, composite-heavy, hybrid-heavy, full)
- Constants (JVM flags, iteration counts, expected BC version)
"""

from __future__ import annotations
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

# ─── Constants ────────────────────────────────────────────────────────────────

DEFAULT_JVM_FLAGS      = ['-Xms256m', '-Xmx512m', '-XX:+UseG1GC']
EXPECTED_BC_VERSION    = '1.84'
WARMUP_ITERATIONS      = 5
MEASURED_ITERATIONS    = 100
DRY_ITERATIONS         = 3

# Operations relevant for single-algorithm configs
# Dual configs have their own op list (see DUAL_OPS)
CLASSICAL_OPS = [
    'keygen', 'cert', 'csr',
    'sign-leaf', 'sign-intermediate-ca',
    'verify-selfsigned', 'verify-issued',
    'verify-modeA-chain',
    'verify-modeB-strict', 'verify-dynamic', 'verify-modeB-direct',
    'workflow-2tier', 'workflow-3tier',
]
PQC_OPS      = CLASSICAL_OPS
COMPOSITE_OPS = CLASSICAL_OPS
HYBRID_OPS   = CLASSICAL_OPS   # hybrid also supports hybrid-sign; macro handles internally

DUAL_OPS = [
    'rfc9763-stage2-sign',
    'rfc9763-stage2-verify',
    'rfc9763-stage3-csr',
    'rfc9763-stage4-sign',
    'rfc9763-stage4-chain-verify',
    'rfc9763-stage4-hash-verify',
    'verify-modeB-strict',    # on Stage 4 issued cert chain
    'verify-dynamic',         # on Stage 4 issued cert chain
]

# Maps RFC 9763 stage operation names to canonical operation names used in
# measured_iterations.csv and summary.csv. Stages that map to the same
# canonical op are summed per iter_index in the primary output.
# verify-modeB-strict and verify-dynamic are already canonical; included for completeness.
DUAL_STAGE_TO_CANONICAL_OP: dict[str, str] = {
    'rfc9763-stage2-sign':         'sign-leaf',         # pqcli sign with --related-cert-test-extension
    'rfc9763-stage2-verify':       'verify-issued',     # pqcli verify with --related-cert
    'rfc9763-stage3-csr':          'csr',               # pqcli csr with --related-cert extension
    'rfc9763-stage4-sign':         'sign-leaf',         # pqcli sign with --related-cert (stage3 CSR)
    'rfc9763-stage4-chain-verify': 'verify-modeA-chain',# pqcli verify -chain -trust
    'rfc9763-stage4-hash-verify':  'verify-issued',     # pqcli verify hash binding (second verify-issued)
    'verify-modeB-strict':         'verify-modeB-strict',
    'verify-dynamic':              'verify-dynamic',
}

SMOKE_OPS = [
    'keygen', 'cert', 'csr',
    'sign-leaf', 'sign-intermediate-ca',
    'verify-selfsigned', 'verify-issued',
    'verify-modeB-strict', 'verify-dynamic',
]
DUAL_SMOKE_OPS = [
    'rfc9763-stage4-sign',
    'rfc9763-stage4-hash-verify',
    'verify-modeB-strict',
]

# thesis-core single-algo ops: all non-verify ops plus verify-dynamic only
THESIS_CORE_OPS = [
    'keygen', 'cert', 'csr',
    'sign-leaf', 'sign-intermediate-ca',
    'verify-dynamic',
    'workflow-2tier', 'workflow-3tier',
]

# verify-heavy: targeted comparison of all verification modes
VERIFY_HEAVY_OPS = [
    'verify-selfsigned',
    'verify-issued',
    'verify-modeA-chain',
    'verify-modeB-strict',
    'verify-dynamic',
    'verify-modeB-direct',
]


# ─── Algorithm / config dataclass ─────────────────────────────────────────────

@dataclass
class AlgoConfig:
    tag: str                      # e.g. 'mldsa65', 'composite-rsa3072-mldsa65'
    cli_syntax: str               # passed to pqcli -newkey or as algo spec
    certificate_mode: str         # classical | pure-pqc | composite | hybrid | dual-rfc9763
    primitive_standard_scope: str # NIST-standardized | BC-named-composite | X.509-alt-sig | RFC-9763-dual
    applicable_ops: list[str]
    is_hybrid: bool = False       # comma-separated primary,alt
    is_composite: bool = False    # underscore-separated
    is_dual: bool = False


# ─── Classical ────────────────────────────────────────────────────────────────

CLASSICAL = [
    AlgoConfig('rsa2048',     'RSA:2048',       'classical', 'NIST-standardized', CLASSICAL_OPS),
    AlgoConfig('rsa3072',     'RSA:3072',       'classical', 'NIST-standardized', CLASSICAL_OPS),
    AlgoConfig('rsa4096',     'RSA:4096',       'classical', 'NIST-standardized', CLASSICAL_OPS),
    AlgoConfig('ecdsa-p256',  'EC:secp256r1',   'classical', 'NIST-standardized', CLASSICAL_OPS),
    AlgoConfig('ecdsa-p384',  'EC:secp384r1',   'classical', 'NIST-standardized', CLASSICAL_OPS),
    AlgoConfig('ed25519',     'Ed25519',        'classical', 'NIST-standardized', CLASSICAL_OPS),
    AlgoConfig('ed448',       'Ed448',          'classical', 'NIST-standardized', CLASSICAL_OPS),
]

# ─── Pure PQC — ML-DSA ────────────────────────────────────────────────────────

MLDSA = [
    AlgoConfig('mldsa44', 'ML-DSA:44', 'pure-pqc', 'NIST-standardized', PQC_OPS),
    AlgoConfig('mldsa65', 'ML-DSA:65', 'pure-pqc', 'NIST-standardized', PQC_OPS),
    AlgoConfig('mldsa87', 'ML-DSA:87', 'pure-pqc', 'NIST-standardized', PQC_OPS),
]

# ─── Pure PQC — SLH-DSA (thesis-core: 4 representative; slh-heavy: all 12) ───

SLH_DSA_CORE = [
    AlgoConfig('slh-dsa-sha2-128f', 'SLH-DSA:128f', 'pure-pqc', 'NIST-standardized', PQC_OPS),
    AlgoConfig('slh-dsa-sha2-128s', 'SLH-DSA:128s', 'pure-pqc', 'NIST-standardized', PQC_OPS),
    AlgoConfig('slh-dsa-sha2-256f', 'SLH-DSA:256f', 'pure-pqc', 'NIST-standardized', PQC_OPS),
    AlgoConfig('slh-dsa-sha2-256s', 'SLH-DSA:256s', 'pure-pqc', 'NIST-standardized', PQC_OPS),
]

SLH_DSA_HEAVY_EXTRA = [
    AlgoConfig('slh-dsa-sha2-192s',   'SLH-DSA:192s',       'pure-pqc', 'NIST-standardized', PQC_OPS),
    AlgoConfig('slh-dsa-sha2-192f',   'SLH-DSA:192f',       'pure-pqc', 'NIST-standardized', PQC_OPS),
    AlgoConfig('slh-dsa-shake-128s',  'SLH-DSA:shake-128s', 'pure-pqc', 'NIST-standardized', PQC_OPS),
    AlgoConfig('slh-dsa-shake-128f',  'SLH-DSA:shake-128f', 'pure-pqc', 'NIST-standardized', PQC_OPS),
    AlgoConfig('slh-dsa-shake-192s',  'SLH-DSA:shake-192s', 'pure-pqc', 'NIST-standardized', PQC_OPS),
    AlgoConfig('slh-dsa-shake-192f',  'SLH-DSA:shake-192f', 'pure-pqc', 'NIST-standardized', PQC_OPS),
    AlgoConfig('slh-dsa-shake-256s',  'SLH-DSA:shake-256s', 'pure-pqc', 'NIST-standardized', PQC_OPS),
    AlgoConfig('slh-dsa-shake-256f',  'SLH-DSA:shake-256f', 'pure-pqc', 'NIST-standardized', PQC_OPS),
]

SLH_DSA_ALL = SLH_DSA_CORE + SLH_DSA_HEAVY_EXTRA

# ─── Composite (thesis-core: 3; composite-heavy: all 13) ──────────────────────
# Classical-first syntax. Parser normalizes component order.
# Conformance: BC 1.84 named-combination composite, PKIX-arc OIDs. Draft revision
# alignment not claimed without re-verification.

COMPOSITE_CORE = [
    AlgoConfig('composite-rsa2048-mldsa44', 'RSA:2048_ML-DSA:44',     'composite', 'BC-named-composite', COMPOSITE_OPS, is_composite=True),
    AlgoConfig('composite-rsa3072-mldsa65', 'RSA:3072_ML-DSA:65',     'composite', 'BC-named-composite', COMPOSITE_OPS, is_composite=True),
    AlgoConfig('composite-ed448-mldsa87',   'Ed448_ML-DSA:87',        'composite', 'BC-named-composite', COMPOSITE_OPS, is_composite=True),
]

COMPOSITE_HEAVY_EXTRA = [
    AlgoConfig('composite-ecdsa-p256-mldsa44', 'EC:secp256r1_ML-DSA:44',  'composite', 'BC-named-composite', COMPOSITE_OPS, is_composite=True),
    AlgoConfig('composite-ed25519-mldsa44',    'Ed25519_ML-DSA:44',       'composite', 'BC-named-composite', COMPOSITE_OPS, is_composite=True),
    AlgoConfig('composite-rsa4096-mldsa65',    'RSA:4096_ML-DSA:65',      'composite', 'BC-named-composite', COMPOSITE_OPS, is_composite=True),
    AlgoConfig('composite-ecdsa-p256-mldsa65', 'EC:secp256r1_ML-DSA:65',  'composite', 'BC-named-composite', COMPOSITE_OPS, is_composite=True),
    AlgoConfig('composite-ecdsa-p384-mldsa65', 'EC:secp384r1_ML-DSA:65',  'composite', 'BC-named-composite', COMPOSITE_OPS, is_composite=True),
    AlgoConfig('composite-ed25519-mldsa65',    'Ed25519_ML-DSA:65',       'composite', 'BC-named-composite', COMPOSITE_OPS, is_composite=True),
    AlgoConfig('composite-rsa3072-mldsa87',    'RSA:3072_ML-DSA:87',      'composite', 'BC-named-composite', COMPOSITE_OPS, is_composite=True),
    AlgoConfig('composite-rsa4096-mldsa87',    'RSA:4096_ML-DSA:87',      'composite', 'BC-named-composite', COMPOSITE_OPS, is_composite=True),
    AlgoConfig('composite-ecdsa-p384-mldsa87', 'EC:secp384r1_ML-DSA:87',  'composite', 'BC-named-composite', COMPOSITE_OPS, is_composite=True),
    AlgoConfig('composite-ecdsa-p521-mldsa87', 'EC:secp521r1_ML-DSA:87',  'composite', 'BC-named-composite', COMPOSITE_OPS, is_composite=True),
]

COMPOSITE_ALL = COMPOSITE_CORE + COMPOSITE_HEAVY_EXTRA

# ─── Hybrid / alternate-signature (thesis-core: 3; hybrid-heavy: up to 6) ────

HYBRID_CORE = [
    AlgoConfig('hybrid-rsa3072-mldsa65',     'RSA:3072,ML-DSA:65',      'hybrid', 'X.509-alt-sig', HYBRID_OPS, is_hybrid=True),
    AlgoConfig('hybrid-ecdsa-p256-mldsa65',  'EC:secp256r1,ML-DSA:65',  'hybrid', 'X.509-alt-sig', HYBRID_OPS, is_hybrid=True),
    AlgoConfig('hybrid-ed25519-mldsa65',     'Ed25519,ML-DSA:65',       'hybrid', 'X.509-alt-sig', HYBRID_OPS, is_hybrid=True),
]

HYBRID_HEAVY_EXTRA = [
    AlgoConfig('hybrid-rsa3072-mldsa87',     'RSA:3072,ML-DSA:87',      'hybrid', 'X.509-alt-sig', HYBRID_OPS, is_hybrid=True),
    AlgoConfig('hybrid-ecdsa-p384-mldsa87',  'EC:secp384r1,ML-DSA:87',  'hybrid', 'X.509-alt-sig', HYBRID_OPS, is_hybrid=True),
    AlgoConfig('hybrid-ed448-mldsa87',       'Ed448,ML-DSA:87',         'hybrid', 'X.509-alt-sig', HYBRID_OPS, is_hybrid=True),
]

HYBRID_ALL = HYBRID_CORE + HYBRID_HEAVY_EXTRA

# ─── Dual / RFC 9763 ──────────────────────────────────────────────────────────

@dataclass
class DualConfig:
    """RFC 9763 dual-certificate workflow configuration."""
    tag: str
    primary_algo: str   # CLI syntax for primary cert (single algorithm)
    related_algo: str   # CLI syntax for related cert (single algorithm)
    certificate_mode: str = 'dual-rfc9763'
    primitive_standard_scope: str = 'RFC-9763-dual'
    applicable_ops: list[str] = field(default_factory=lambda: DUAL_OPS)
    is_dual: bool = True

    @property
    def artifacts(self) -> dict[str, str]:
        """
        Artifact filenames for this dual config.
        All names follow pqcli -out prefix conventions:
        pqcli appends _certificate.pem, _private_key.pem, _public_key.pem, _csr.pem.
        """
        return {
            # Reference cert (related certificate role)
            'ref_cert':       'ref_certificate.pem',
            'ref_key':        'ref_private_key.pem',
            'ref_pub_key':    'ref_public_key.pem',
            # CA root
            'ca_root_cert':   'ca_root_certificate.pem',
            'ca_root_key':    'ca_root_private_key.pem',
            # Intermediate (pqcli sign -out int → int_certificate.pem)
            # The intermediate key comes from the CSR generation step (-out int_csr →
            # int_csr_private_key.pem). We expose it under 'int_key' here.
            'int_csr_file':   'int_csr_csr.pem',
            'int_cert':       'int_certificate.pem',
            'int_key':        'int_csr_private_key.pem',
            # Standard leaf CSR (for Stage 2 rfc9763-stage2-sign)
            'leaf_csr':       'leaf_csr_csr.pem',
            'leaf_key':       'leaf_csr_private_key.pem',
            # Stage 3 CSR (with relatedCertRequest; reused across stage4-sign iterations)
            'stage3_csr':     'stage3_csr_csr.pem',
            'stage3_key':     'stage3_csr_private_key.pem',
            # Stage 4 pre-issued cert (for chain-verify and hash-verify)
            'stage4_cert':    'stage4_certificate.pem',
            # Stage 2 pre-issued cert (for stage2-verify iterations)
            'stage2_cert':    'stage2_certificate.pem',
        }


DUAL_CONFIGS = [
    DualConfig('dual-classical-primary', primary_algo='RSA:3072', related_algo='ML-DSA:65'),
    DualConfig('dual-pqc-primary',       primary_algo='ML-DSA:65', related_algo='RSA:3072'),
]

DUAL_OPTIONAL = [
    DualConfig('dual-ecdsa-primary', primary_algo='EC:secp256r1', related_algo='ML-DSA:65'),
]


# ─── Profiles ─────────────────────────────────────────────────────────────────

SMOKE_ALGO_TAGS = {
    'rsa3072', 'mldsa65', 'slh-dsa-sha2-128f',
    'composite-rsa3072-mldsa65', 'hybrid-rsa3072-mldsa65',
    'dual-classical-primary',
}

def _build_profile(name: str, single_algos: list[AlgoConfig], duals: list[DualConfig],
                   iters: int, single_ops: list[str], dual_ops_override: Optional[list[str]] = None) -> dict:
    return {
        'name': name,
        'single_algos': single_algos,
        'dual_configs': duals,
        'iterations': iters,
        'single_ops': single_ops,
        'dual_ops': dual_ops_override or DUAL_OPS,
    }

# thesis-core: representative set, intentionally not exhaustive.
# Exhaustive sweeps live in full, slh-heavy, composite-heavy, hybrid-heavy.
# Classical: 3 representatives (baseline)
# Pure-PQC: mldsa65 (primary ML-DSA level) + 2 SLH-DSA (fast vs small)
# Composite: rsa3072+mldsa65 (primary), ed25519+mldsa65 (EdDSA representative), ed448+mldsa87
#   Note: composite-ed25519-mldsa65 is drawn from COMPOSITE_HEAVY_EXTRA (not COMPOSITE_CORE).
# Hybrid: three X.509 alt-sig representatives matching composite set
_TC_CLASSICAL_TAGS = {'rsa3072', 'ecdsa-p256', 'ed25519'}
_TC_PQC_TAGS       = {'mldsa65', 'slh-dsa-sha2-128f', 'slh-dsa-sha2-128s'}
_TC_COMPOSITE_TAGS = {'composite-rsa3072-mldsa65', 'composite-ed25519-mldsa65', 'composite-ed448-mldsa87'}

THESIS_CORE_CLASSICAL = [a for a in CLASSICAL            if a.tag in _TC_CLASSICAL_TAGS]
THESIS_CORE_PQC       = [a for a in MLDSA + SLH_DSA_CORE if a.tag in _TC_PQC_TAGS]
THESIS_CORE_COMPOSITE = [a for a in COMPOSITE_ALL        if a.tag in _TC_COMPOSITE_TAGS]
THESIS_CORE_HYBRID    = HYBRID_CORE

THESIS_CORE_SINGLE = (
    THESIS_CORE_CLASSICAL + THESIS_CORE_PQC +
    THESIS_CORE_COMPOSITE + THESIS_CORE_HYBRID
)

PROFILES: dict[str, dict] = {
    'smoke': _build_profile(
        'smoke',
        single_algos=[a for a in THESIS_CORE_SINGLE if a.tag in SMOKE_ALGO_TAGS],
        duals=[next(d for d in DUAL_CONFIGS if d.tag == 'dual-classical-primary')],
        iters=DRY_ITERATIONS,
        single_ops=SMOKE_OPS,
        dual_ops_override=DUAL_SMOKE_OPS,
    ),
    'thesis-core': _build_profile(
        'thesis-core',
        single_algos=THESIS_CORE_SINGLE,
        duals=DUAL_CONFIGS,
        iters=MEASURED_ITERATIONS,
        single_ops=THESIS_CORE_OPS,
    ),
    'slh-heavy': _build_profile(
        'slh-heavy',
        single_algos=SLH_DSA_ALL,
        duals=[],
        iters=MEASURED_ITERATIONS,
        single_ops=PQC_OPS,
    ),
    'composite-heavy': _build_profile(
        'composite-heavy',
        single_algos=COMPOSITE_ALL,
        duals=[],
        iters=MEASURED_ITERATIONS,
        single_ops=COMPOSITE_OPS,
    ),
    'hybrid-heavy': _build_profile(
        'hybrid-heavy',
        single_algos=HYBRID_ALL,
        duals=[],
        iters=MEASURED_ITERATIONS,
        single_ops=HYBRID_OPS,
    ),
    'verify-heavy': _build_profile(
        'verify-heavy',
        single_algos=THESIS_CORE_SINGLE,
        duals=[],
        iters=MEASURED_ITERATIONS,
        single_ops=VERIFY_HEAVY_OPS,
    ),
    'full': _build_profile(
        'full',
        single_algos=CLASSICAL + MLDSA + SLH_DSA_ALL + COMPOSITE_ALL + HYBRID_ALL,
        duals=DUAL_CONFIGS,
        iters=MEASURED_ITERATIONS,
        single_ops=CLASSICAL_OPS,
    ),
}


# ─── Industrial benchmark profiles ────────────────────────────────────────────
# Separate from macro PROFILES. No dual/RFC 9763 configs (not a single repeatable
# (algo, op) unit). operation names match macro exactly (verify-dynamic is canonical).

INDUSTRIAL_SMOKE_ALGO_TAGS = {'rsa3072', 'mldsa65', 'ed25519'}
INDUSTRIAL_SMOKE_OPS = ['keygen', 'cert', 'verify-dynamic']

# industrial-thesis-core: exact same single_algos as thesis-core macro profile
INDUSTRIAL_THESIS_CORE_SINGLE = THESIS_CORE_SINGLE  # 12 configs

# industrial-full: all single-algorithm configs
INDUSTRIAL_FULL_SINGLE = CLASSICAL + MLDSA + SLH_DSA_ALL + COMPOSITE_ALL + HYBRID_ALL

INDUSTRIAL_PROFILES: dict[str, dict] = {
    'industrial-smoke': {
        'name': 'industrial-smoke',
        'single_algos': [a for a in THESIS_CORE_SINGLE if a.tag in INDUSTRIAL_SMOKE_ALGO_TAGS],
        'ops': INDUSTRIAL_SMOKE_OPS,
        'iterations': DRY_ITERATIONS,
        'warmup': 2,
    },
    'industrial-thesis-core': {
        'name': 'industrial-thesis-core',
        'single_algos': INDUSTRIAL_THESIS_CORE_SINGLE,
        'ops': list(THESIS_CORE_OPS),  # keygen cert csr sign-leaf sign-intermediate-ca verify-dynamic workflow-2tier workflow-3tier
        'iterations': MEASURED_ITERATIONS,
        'warmup': WARMUP_ITERATIONS,
    },
    'industrial-full': {
        'name': 'industrial-full',
        'single_algos': INDUSTRIAL_FULL_SINGLE,
        'ops': list(CLASSICAL_OPS),   # all 13 ops including all verify modes
        'iterations': MEASURED_ITERATIONS,
        'warmup': WARMUP_ITERATIONS,
    },
}


# ─── Artifact path helpers ────────────────────────────────────────────────────
# Each macro operation uses a deterministic file naming scheme under a per-algo
# staging subdirectory. Paths here are relative to the algo_tag subdirectory.
# pqcli -out <prefix> produces:
#   <prefix>_certificate.pem, <prefix>_private_key.pem, <prefix>_public_key.pem
#   <prefix>_alt_private_key.pem, <prefix>_alt_public_key.pem  (hybrid only)
#   <prefix>_csr.pem  (for csr command)
#
# The ARTIFACT_PATHS dict maps op → dict of logical_name → filename_relative_to_staging_algo_dir.
# "pre_" prefix = pre-generated setup artifacts (produced before the iteration loop).
# "out_" prefix = output artifacts produced per iteration.

# ARTIFACT_PATHS — informational reference only.
# The macro runner (run_macro_benchmarks.py) uses hardcoded paths in
# pregen_single_algo() and run_op_iterations(). Several entries here do NOT match
# what the runner actually produces.
# Do not use this dict programmatically without verifying against runner behavior.
ARTIFACT_PATHS: dict[str, dict[str, str]] = {
    'keygen': {
        'out_pub_key':    'key_public_key.pem',
        'out_priv_key':   'key_private_key.pem',
        'out_alt_pub':    'key_alt_public_key.pem',    # hybrid only
        'out_alt_priv':   'key_alt_private_key.pem',   # hybrid only
    },
    'cert': {
        'out_cert':       'cert_certificate.pem',
        'out_pub_key':    'cert_public_key.pem',
        'out_priv_key':   'cert_private_key.pem',
        'out_alt_pub':    'cert_alt_public_key.pem',
        'out_alt_priv':   'cert_alt_private_key.pem',
    },
    'csr': {
        'out_csr':        'csr_csr.pem',
        'out_pub_key':    'csr_public_key.pem',
        'out_priv_key':   'csr_private_key.pem',
        'out_alt_pub':    'csr_alt_public_key.pem',
        'out_alt_priv':   'csr_alt_private_key.pem',
    },
    'sign-leaf': {
        # Pre-generated:
        'pre_ca_cert':    'sigca_certificate.pem',
        'pre_ca_key':     'sigca_private_key.pem',
        'pre_ca_alt_key': 'sigca_alt_private_key.pem',
        'pre_ee_csr':     'sigee_csr_csr.pem',
        'pre_ee_key':     'sigee_csr_private_key.pem',
        # Per-iteration output:
        'out_cert':       'signed_certificate.pem',
    },
    'sign-intermediate-ca': {
        'pre_root_cert':     'isroot_certificate.pem',
        'pre_root_key':      'isroot_private_key.pem',
        'pre_root_alt_key':  'isroot_alt_private_key.pem',
        'pre_int_csr':       'isint_csr.pem',
        'out_cert':          'issigned_certificate.pem',
    },
    'verify-selfsigned': {
        'pre_cert':          'selfcert_certificate.pem',
        'input_cert':        'selfcert_certificate.pem',
    },
    'verify-issued': {
        'pre_ca_cert':       'vcert_ca_certificate.pem',
        'pre_leaf_cert':     'vcert_leaf_certificate.pem',
        'input_leaf_cert':   'vcert_leaf_certificate.pem',
        'input_int_cert':    'vcert_ca_certificate.pem',
    },
    'verify-modeA-chain': {
        'pre_root_cert':     'cv_root_certificate.pem',
        'pre_int_cert':      'cv_int_certificate.pem',
        'pre_leaf_cert':     'cv_leaf_certificate.pem',
        'input_leaf_cert':   'cv_leaf_certificate.pem',
        'input_int_cert':    'cv_int_certificate.pem',
        'input_root_cert':   'cv_root_certificate.pem',
    },
    'verify-modeB-strict': {
        'pre_root_cert':     'cvb_root_certificate.pem',
        'pre_int_cert':      'cvb_int_certificate.pem',
        'pre_leaf_cert':     'cvb_leaf_certificate.pem',
        'input_leaf_cert':   'cvb_leaf_certificate.pem',
        'input_int_cert':    'cvb_int_certificate.pem',
        'input_root_cert':   'cvb_root_certificate.pem',
    },
    'verify-dynamic': {
        'pre_root_cert':     'cvd_root_certificate.pem',
        'pre_int_cert':      'cvd_int_certificate.pem',
        'pre_leaf_cert':     'cvd_leaf_certificate.pem',
        'input_leaf_cert':   'cvd_leaf_certificate.pem',
        'input_int_cert':    'cvd_int_certificate.pem',
        'input_root_cert':   'cvd_root_certificate.pem',
    },
    'verify-modeB-direct': {
        'pre_root_cert':     'direct_root_certificate.pem',
        'pre_leaf_cert':     'direct_leaf_certificate.pem',
        'input_leaf_cert':   'direct_leaf_certificate.pem',
        'input_root_cert':   'direct_root_certificate.pem',
    },
    'workflow-2tier': {
        # All artifacts produced per iteration
        'out_ca_cert':      'wf2_ca_certificate.pem',
        'out_ca_key':       'wf2_ca_private_key.pem',
        'out_ee_csr':       'wf2_ee_csr.pem',
        'out_ee_cert':      'wf2_signed_certificate.pem',
    },
    'workflow-3tier': {
        'out_root_cert':    'wf3_root_certificate.pem',
        'out_root_key':     'wf3_root_private_key.pem',
        'out_int_csr':      'wf3_int_csr.pem',
        'out_int_cert':     'wf3_int_certificate.pem',
        'out_int_key':      'wf3_int_csr_private_key.pem',
        'out_leaf_csr':     'wf3_leaf_csr.pem',
        'out_leaf_cert':    'wf3_leaf_certificate.pem',
    },
}
