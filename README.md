<div align="center">

![pqcli](.gh-assets/pqcli_banner.png)
**CLI wrapper for BouncyCastle with a particular focus on post-quantum hybrid certificates.**

[![Read the paper](https://img.shields.io/badge/Read_our_Research_Paper-preprint-yellow)](https://arxiv.org/abs/2505.04333)

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

</div>

> [!CAUTION]
> pqcli is currently intended for research purposes and in an early testing state. Do not use it in production.

The goal is to create an easily usable interface to carry out cryptographic operations using the BouncyCastle library.

## Building

Uses Maven with JDK 23.

```shell
mvn clean package
```

This generates a complete .jar file in the `/target` dir.

## Usage

> **Invocation note:** Examples using `pqcli` assume a local wrapper or shell alias pointing to the built jar. Without such a wrapper, invoke with `java -jar target/<built-jar>.jar ...` (e.g. `java -jar target/pqcli-0.1.0.jar`).

Examples

Generate a self-signed PQC X.509 Certificate using a ML-DSA key pair (FIPS 204 / RFC 9881):
```
java -jar .\target\pqcli-0.1.0.jar cert -newkey ML-DSA:65 -subj CN=Solanum
```

Generate a self-signed alternate-signature certificate (X.509 alternate-signature mechanism, ITU-T X.509 / ISO/IEC 9594-8) with RSA as primary and ML-DSA-65 as alternative:
```
java -jar .\target\pqcli-0.1.0.jar cert -newkey RSA:3072,ML-DSA:65
```

Generate a self-signed composite certificate with RSA and ML-DSA (draft-ietf-lamps-pq-composite-sigs named-combination; PKIX-arc OID):
```
java -jar .\target\pqcli-0.1.0.jar cert -newkey RSA:3072_ML-DSA:65
```

Generate a SPHINCS+ (SLH-DSA) keypair with SHA2-192f parameters:
```
java -jar .\target\pqcli-0.1.0.jar key -t slh-dsa:192f
```

Examine an existing certificate in PEM format:
```
java -jar .\target\pqcli-0.1.0.jar view certificate.pem
```

Non-practical example of a hybrid certificate combining an RSA+ML-DSA composite primary key with an EC+ML-DSA composite alt key:
```
java -jar .\target\pqcli-0.1.0.jar cert -newkey rsa:3072_mldsa:65,ec:secp384r1_mldsa:87
```

### 3-Tier PKI Workflow

PQCLI supports full root → intermediate CA → leaf certificate chains in all four modes: classical, pure PQC, composite, and hybrid (alternate-signature).

The general pattern for all modes is:

```shell
# 1. Generate a self-signed root CA certificate
pqcli cert -newkey <algo> -subj /CN=Root -out root

# 2. Generate an intermediate CA CSR
pqcli csr -newkey <algo> -subj /CN=Intermediate -out int

# 3. Issue the intermediate CA certificate (signed by root)
pqcli sign -csr int_csr.pem -CAcert root_certificate.pem -CAkey root_private_key.pem \
     --profile intermediate-ca -out int

# 4. Generate a leaf (end-entity) CSR
pqcli csr -newkey <algo> -subj /CN=EndEntity -out ee

# 5. Issue the leaf certificate (signed by intermediate)
pqcli sign -csr ee_csr.pem -CAcert int_certificate.pem -CAkey int_private_key.pem -out ee

# 6. Verify the full chain
pqcli verify -in ee_certificate.pem -chain int_certificate.pem -trust root_certificate.pem
```

#### Classical / pure PQC

Replace `<algo>` with any single algorithm, e.g. `RSA:3072`, `EC:secp256r1`, `ML-DSA:65`, `SLH-DSA:128f`.
Intermediate and leaf need not use the same algorithm as the root.

#### Composite

Replace `<algo>` with a composite algorithm, e.g. `RSA:3072_ML-DSA:65`. Typically all three certs in the chain use the same composite named-combination.

```shell
pqcli cert -newkey RSA:3072_ML-DSA:65 -subj /CN=Composite-Root -out root
pqcli csr  -newkey RSA:3072_ML-DSA:65 -subj /CN=Composite-Int  -out int
pqcli sign -csr int_csr.pem -CAcert root_certificate.pem -CAkey root_private_key.pem \
     --profile intermediate-ca -out int
# ... leaf steps as above
```

#### Hybrid (alternate-signature)

Hybrid certificates carry two independent public keys and two independent signatures (OIDs 2.5.29.72/73/74, ITU-T X.509 alternate-signature mechanism). Signing requires both the primary and the alternate CA private key via `-CAaltkey`.

```shell
pqcli cert -newkey RSA:3072,ML-DSA:65 -subj /CN=Hybrid-Root -out root
# root saves root_private_key.pem and root_alt_private_key.pem

pqcli csr -newkey RSA:3072,ML-DSA:65 -subj /CN=Hybrid-Int -out int
pqcli sign -csr int_csr.pem -CAcert root_certificate.pem \
     -CAkey root_private_key.pem -CAaltkey root_alt_private_key.pem \
     --profile intermediate-ca -out int

pqcli csr -newkey RSA:3072,ML-DSA:65 -subj /CN=Hybrid-EE -out ee
pqcli sign -csr ee_csr.pem -CAcert int_certificate.pem \
     -CAkey int_private_key.pem -CAaltkey int_alt_private_key.pem -out ee

pqcli verify -in ee_certificate.pem -chain int_certificate.pem -trust root_certificate.pem
```

A hybrid CA may also issue a non-hybrid (classical or PQC) leaf — omit `-CAaltkey` when the subject CSR has no alternate public key.

#### `sign` command options

Option | Description
--- | ---
`-csr` | PKCS#10 CSR file (PEM)
`-CAcert` | Issuer certificate file (PEM)
`-CAkey` | Issuer primary private key file (PEM, PKCS#8 or PKCS#1)
`-CAaltkey` | Issuer alternate private key (PEM). Required only when signing a hybrid CSR with a hybrid CA.
`--profile` | `leaf` (default) or `intermediate-ca`. Leaf: CA=false, digitalSignature. Intermediate CA: CA=true, keyCertSign\|cRLSign.
`--path-len` | Path length constraint for `--profile intermediate-ca` only (integer ≥ 0). Omit for unconstrained.
`-days` | Validity period in days (default: 365)
`-out` | Output filename prefix

The issuer certificate must have `BasicConstraints CA=true` and `KeyUsage keyCertSign`; otherwise signing is rejected.

#### `verify` command — one-link vs chain mode

**One-link mode** (existing behavior, unchanged):
```shell
pqcli verify -in cert.pem                    # self-signed
pqcli verify -in cert.pem -CAfile issuer.pem # one issuer
```
Checks: cryptographic signature (primary + hybrid alt if present). No semantic PKI checks.

**Chain mode:**
```shell
pqcli verify -in leaf.pem -chain intermediate.pem -trust root.pem
```
Checks per link: primary signature, hybrid alt-signature if present.
Semantic checks: certificate validity dates, `BasicConstraints` (CA=true required for root and intermediate; CA=false required for leaf), `KeyUsage keyCertSign` for CA certificates, `pathLen` constraint, SKID/AKID key identifier linkage when both are present, and unsupported critical extensions.

**Dynamic chain mode** (path building from a bundle):
```shell
pqcli verify -in leaf.pem -untrusted intermediates.pem -trust root.pem
```
Builds the chain automatically from the provided intermediate bundle. `-chain` is an alias for `-untrusted` when used with `-trust`. Add `--show-chain` to print the resolved path with indexed positions.

**What verify does not check**: revocation (OCSP/CRL not implemented). Output includes a note: `Revocation: not checked (out of scope)`.

#### Mixed-mode chains

The issuer's algorithm determines the signature on each issued certificate independently. The subject's key type may differ from the issuer's. One constraint applies: a hybrid (alternate-signature) subject CSR requires a hybrid issuer, because the issuer must produce both the primary and the alternate signature. A hybrid issuer may issue a non-hybrid subject.

#### RFC 9763 Related Certificates workflow

pqcli implements RFC 9763 (Proposed Standard) for linking two certificates (e.g. a classical and a PQC cert for the same entity) via a hash binding and proof-of-possession.

**Stage 3 — generate a CSR with a `relatedCertRequest` attribute:**
```shell
pqcli csr -newkey RSA:3072 -subj /CN=entity \
  --related-cert classical_cert.pem \
  --related-cert-key classical_private_key.pem \
  --related-cert-url https://example.com/certs/classical.pem
```
Adds attribute OID `1.2.840.113549.1.9.16.2.60` with certID, timestamp, location URI, and a PoP signature. Only valid for single-algorithm CSRs (not composite or hybrid).

**Stage 4 — CA signs the CSR and issues a cert with the `RelatedCertificate` extension (compliant issuance):**
```shell
pqcli sign -csr rc_csr.pem -CAcert ca_cert.pem -CAkey ca_private_key.pem \
  --related-cert classical_cert.pem
```
The CA verifies the `relatedCertRequest` attribute PoP before issuing. Adds OID `1.3.6.1.5.5.7.1.36` to the issued certificate. Leaf profile only.

**Stage 2 — test mode: add the extension without PoP verification (not RFC 9763-compliant issuance):**
```shell
pqcli sign -csr leaf_csr.pem -CAcert ca_cert.pem -CAkey ca_private_key.pem \
  --related-cert-test-extension some_other_cert.pem
```
Adds the `RelatedCertificate` extension as a hash-only binding. No PoP is verified. Output includes a NOTE marking this as non-compliant test mode. Leaf profile only.

**Verify the hash binding:**
```shell
pqcli verify -in issued_cert.pem --related-cert classical_cert.pem
```
Checks the `RelatedCertificate` extension hash. Does not re-verify CSR PoP or certificate chain. Cannot be combined with `-CAfile`, `-chain`, `-untrusted`, or `-trust`.

### CLI structure

Command | Description | Impl.
--- | --- | ---
cert | Generate a self-signed X.509 certificate | ✔️
key | Generate cryptographic key pair(s) | ✔️
csr | Generate a PKCS#10 certificate signing request (single, composite, hybrid) | ✔️
(crl) | Generate a certificate revocation list | —
verify | Verify certificate signature: one-link mode (primary + hybrid alt) or full chain mode (-chain/-trust) with semantic PKI checks | ✔️
sign | Sign a CSR with a CA key; --profile leaf\|intermediate-ca; issuer CA validation; SKID/AKID; 128-bit serial | ✔️
view | Display structured certificate details (subject, issuer, public key, extensions, OIDs). `--full` also prints the raw Bouncy Castle dump. | ✔️

#### `cert` command options

Option | Description
--- | ---
`-newkey` / `-nk` | Key algorithm (required). Same syntax as `key -t`. See supported algorithms table below.
`-subj` / `-subject` | Subject DN in OpenSSL format (e.g. `/CN=Root/C=DE`). Default: `CN=PQCLI Test Certificate, C=DE`
`-days` / `-d` | Certificate validity in days. Default: `365`
`-out` / `-o` | Output filename prefix (e.g. `root` → `root_certificate.pem`, `root_private_key.pem`)
`-sig` / `-s` | Reserved — no effect. Signature algorithm is always auto-derived from `-newkey`.
`--timing` | Print key generation and certificate signing timing

The `cert` command always generates a self-signed certificate. The generated keypair is always written alongside the certificate.

#### `key` command options

Option | Description
--- | ---
`-newkey` / `-nk` / `-new` / `-t` | Key algorithm (required). See supported algorithms table below. Hybrid syntax (`,`) generates two keypairs.
`-out` / `-o` | Output filename prefix
`--timing` | Print key generation timing

#### Supported signature key algorithms

Algorithm | Key sizes | Default parameter
--- | --- | ---
ML-DSA | 44, 65, 87 (aliases: 2, 3, 5) | 65
dilithium-bcpqc | 2, 3, 5 | 3
SLH-DSA SHA-2 | 128s, 128f, 192s, 192f, 256s, 256f | 192s
SLH-DSA SHAKE | shake-128s, shake-128f, shake-192s, shake-192f, shake-256s, shake-256f | —
RSA | 1024-8192 (append `-pss` for using RSASSA-PSS, e.g. `rsa:3072-pss`) | 3072
EC | All common named curves, e.g. `secp256r1` | `secp256r1`
DSA | 1024-4096 | 2048
Ed25519 | - | -
Ed448 | - | -

Note: `dilithium-bcpqc` is the Dilithium implementation from the BouncyCastle Post-Quantum Security Provider, which BC 1.79+ no longer supports for certificate signing.
It is provided for keypair generation and A/B testing only.

## Standards notes

- **ML-DSA**: FIPS 204 / RFC 9881. OIDs `2.16.840.1.101.3.4.3.17/18/19` are standards-track.
- **SLH-DSA**: FIPS 205 / RFC 9909. Pure variants only; HashSLH-DSA / HashML-DSA prehash variants are out of scope.
- **Alternate-signature certificates** (`RSA:3072,ML-DSA:65` syntax): use X.509 alternate-signature extensions (OIDs `2.5.29.72/73/74`) defined in ITU-T X.509 / ISO/IEC 9594-8. Verification uses the BC-specific `isAlternativeSignatureValid()` API. This is distinct from the IETF composite-signatures draft.
- **RFC 9763 related certificates** (Proposed Standard, June 2025): pqcli implements Stages 2–4 — `relatedCertRequest` CSR attribute generation (Stage 3), CA-side PoP verification and `RelatedCertificate` extension issuance (Stage 4), and hash-binding test mode (Stage 2, not compliant issuance). See RFC 9763 workflow section above.
- **Composite certificates** (`RSA:3072_ML-DSA:65` syntax): experimental (draft, not RFC). Uses BC 1.84 named-combination API, emitting PKIX-arc OIDs (`1.3.6.1.5.5.7.6.*`) per draft-ietf-lamps-pq-composite-sigs-18. Only ML-DSA-based named combinations from the active draft are supported; other composites are rejected. RSA composite defaults to the PSS variant.

## Acknowledgements

PQCLI is partially funded as a part of the [Trustpoint](https://industrial-security.io) project sponsored by the German Federal Ministry of Education and Research.
