package pqcli.bench;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.SubjectAltPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.openjdk.jmh.annotations.*;
import org.openjdk.jmh.infra.Blackhole;

import pqcli.KeyGenerator;

import java.io.StringReader;
import java.io.StringWriter;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.concurrent.TimeUnit;

/**
 * Layer B — PKI object operations (no CLI, no file I/O, no JVM startup cost).
 *
 * Coverage:
 *   csrBuild    — PKCS#10 CSR construction + signing (key pre-generated)
 *   certBuild   — X.509 v3 certificate construction + signing (key pre-generated)
 *   certVerify  — X509Certificate.verify() for a pre-built self-signed cert
 *   chainVerify — two verify() calls: leaf vs int, int vs root (3-cert chain)
 *   derEncode   — certificate.getEncoded() → DER byte[]
 *   derDecode   — DER byte[] → X509Certificate (via X509CertificateHolder)
 *   pemEncode   — JcaPEMWriter → PEM string (in-memory StringWriter, no file I/O)
 *   pemDecode   — PEM string → X509Certificate (via PEMParser + StringReader)
 *
 * Algorithms: RSA-3072, ECDSA-P256, Ed25519, ML-DSA-65, hybrid(RSA+MLDSA65), composite(RSA+MLDSA65)
 *
 * Logic sharing with pqcli:
 *   - KeyGenerator.generateKeyPair() — exact same public static method as CLI
 *   - BC builder classes (JcaX509v3CertificateBuilder, JcaPKCS10CertificationRequestBuilder)
 *     are the same classes pqcli uses internally
 *   - Signature algorithm mapping (makeSignerForKeyPair) mirrors
 *     CertificateGenerator.getSuitableSignatureAlgorithm() but is a separate definition
 *     because that method is package-private. The mapping is hardcoded for the first
 *     campaign algorithms; must be kept in sync if pqcli's mapping changes.
 *   - The only delta vs CLI: no JVM startup, no BC provider init overhead, no file I/O —
 *     giving pure PKI object operation timings.
 *
 * JMH defaults:
 *   mode:        AverageTime
 *   time unit:   ms
 *   warmup:      10 iterations × 1s  (not recorded)
 *   measurement: 20 iterations × 1s  (5 forks × 20 = 100 total measured)
 *   forks:       5
 */
@State(Scope.Benchmark)
@BenchmarkMode(Mode.AverageTime)
@OutputTimeUnit(TimeUnit.MILLISECONDS)
@Warmup(iterations = 10, time = 1, timeUnit = TimeUnit.SECONDS)
@Measurement(iterations = 20, time = 1, timeUnit = TimeUnit.SECONDS)
@Fork(value = 5, jvmArgsAppend = {"-Xms512m", "-Xmx512m", "-XX:+UseG1GC"})
public class LayerBBenchmark {

    @Param({"rsa3072", "ecdsa-p256", "ed25519", "mldsa65", "hybrid-rsa-mldsa65", "composite-rsa-mldsa65"})
    public String algoTag;

    // Pre-generated keys (excluded from measured time)
    private KeyPair keyPair;
    private KeyPair altKeyPair;       // non-null for hybrid only

    // Pre-built certs for verify/encode/decode benchmarks
    private X509Certificate prebuiltCert;
    private byte[]           prebuiltDer;
    private String           prebuiltPem;

    // Alt-signature verification — non-null for hybrid-rsa-mldsa65 only
    private X509CertificateHolder prebuiltHolder;
    private ContentVerifierProvider prebuiltAltProvider;

    // 3-cert chain for chainVerify
    private X509Certificate chainRootCert;
    private X509Certificate chainIntCert;
    private X509Certificate chainLeafCert;

    private static final X500Name SUBJECT   = new X500Name("CN=Bench-LayerB,O=PQCLIBench");
    private static final Date     NOT_BEFORE = new Date(System.currentTimeMillis() - 86400_000L);
    private static final Date     NOT_AFTER  = new Date(System.currentTimeMillis() + 365L * 86400_000L);

    private final JcaX509CertificateConverter certConverter =
        new JcaX509CertificateConverter().setProvider("BC");

    @Setup(Level.Trial)
    public void setupTrial() throws Exception {
        if (Security.getProvider("BC") == null)    Security.addProvider(new BouncyCastleProvider());
        if (Security.getProvider("BCPQC") == null) Security.addProvider(new BouncyCastlePQCProvider());

        // ── Key generation (not timed) ────────────────────────────────────────
        switch (algoTag) {
            case "rsa3072":
                keyPair = KeyGenerator.generateKeyPair("rsa", "3072");
                break;
            case "ecdsa-p256":
                keyPair = KeyGenerator.generateKeyPair("ec", "secp256r1");
                break;
            case "ed25519":
                keyPair = KeyGenerator.generateKeyPair("ed25519", "");
                break;
            case "mldsa65":
                keyPair = KeyGenerator.generateKeyPair("mldsa", "65");
                break;
            case "hybrid-rsa-mldsa65":
                keyPair    = KeyGenerator.generateKeyPair("rsa",   "3072");
                altKeyPair = KeyGenerator.generateKeyPair("mldsa", "65");
                break;
            case "composite-rsa-mldsa65": {
                KeyPairGenerator kpg = KeyPairGenerator.getInstance("MLDSA65-RSA3072-PSS-SHA512", "BC");
                keyPair = kpg.generateKeyPair();
                break;
            }
            default:
                throw new IllegalArgumentException("Unknown algoTag: " + algoTag);
        }

        // ── Pre-build cert and chain for verify/encode benchmarks ─────────────
        X509CertificateHolder holder = buildCertHolder(keyPair, altKeyPair, SUBJECT, SUBJECT);
        prebuiltCert = certConverter.getCertificate(holder);

        if ("hybrid-rsa-mldsa65".equals(algoTag) && altKeyPair != null) {
            prebuiltHolder = holder;
            prebuiltAltProvider = new JcaContentVerifierProviderBuilder()
                .setProvider("BC").build(altKeyPair.getPublic());
        }
        prebuiltDer  = prebuiltCert.getEncoded();

        StringWriter sw = new StringWriter();
        try (JcaPEMWriter pw = new JcaPEMWriter(sw)) { pw.writeObject(prebuiltCert); }
        prebuiltPem = sw.toString();

        // ── Build 3-cert chain for chainVerify ────────────────────────────────
        // Root CA (self-signed, same algo as primary)
        X500Name rootDN = new X500Name("CN=Root-Bench,O=PQCLIBench");
        X500Name intDN  = new X500Name("CN=Int-Bench,O=PQCLIBench");
        X500Name leafDN = new X500Name("CN=Leaf-Bench,O=PQCLIBench");

        KeyPair rootKP = buildSingleKeyPair();
        chainRootCert = certConverter.getCertificate(buildCertHolder(rootKP, null, rootDN, rootDN));

        KeyPair intKP = buildSingleKeyPair();
        chainIntCert = certConverter.getCertificate(buildCertHolder(intKP, null, intDN, rootDN,
            /* issuerKeyPair */ rootKP));

        KeyPair leafKP = buildSingleKeyPair();
        chainLeafCert = certConverter.getCertificate(buildCertHolder(leafKP, null, leafDN, intDN,
            /* issuerKeyPair */ intKP));
    }

    // ── Benchmark methods ──────────────────────────────────────────────────────

    /** Layer B — CSR generation: PKCS#10 builder + signing. Key pre-generated. */
    @Benchmark
    public PKCS10CertificationRequest csrBuild(Blackhole bh) throws Exception {
        JcaPKCS10CertificationRequestBuilder builder =
            new JcaPKCS10CertificationRequestBuilder(SUBJECT, keyPair.getPublic());
        PKCS10CertificationRequest csr;
        if ("hybrid-rsa-mldsa65".equals(algoTag)) {
            ContentSigner primary = makePrimarySigner();
            ContentSigner alt = new JcaContentSignerBuilder("ML-DSA-65").setProvider("BC")
                                    .build(altKeyPair.getPrivate());
            csr = builder.build(primary, altKeyPair.getPublic(), alt);
        } else {
            csr = builder.build(makePrimarySigner());
        }
        bh.consume(csr);
        return csr;
    }

    /** Layer B — cert generation: X.509 v3 builder + signing. Key pre-generated. */
    @Benchmark
    public X509Certificate certBuild(Blackhole bh) throws Exception {
        X509CertificateHolder h = buildCertHolder(keyPair, altKeyPair, SUBJECT, SUBJECT);
        X509Certificate cert = certConverter.getCertificate(h);
        bh.consume(cert);
        return cert;
    }

    /**
     * Layer B — self-signed certificate primary signature verification.
     * Cert pre-built in @Setup. For hybrid: only primary (RSA) sig verified here.
     * Alt-signature verification (BC-specific) is a separate operation if needed.
     */
    @Benchmark
    public void certVerify(Blackhole bh) throws Exception {
        prebuiltCert.verify(keyPair.getPublic(), "BC");
        bh.consume(prebuiltCert);
    }

    /**
     * Layer B — 3-cert chain verification: leaf→int + int→root.
     * Chain pre-built in @Setup (root CA, intermediate, leaf; using primary algo).
     * Times two sequential verify() calls.
     *
     * Note: this is the raw cryptographic equivalent of CLI Mode A (one-link crypto check).
     * It does NOT measure Mode B semantic verification (BasicConstraints, KeyUsage, PathLen,
     * SKID/AKID, date validity, critical extensions). Mode B overhead is measured at the
     * macro CLI layer via the chain-verify-mode-b benchmark op in bench.sh.
     */
    @Benchmark
    public void chainVerify(Blackhole bh) throws Exception {
        chainLeafCert.verify(chainIntCert.getPublicKey(), "BC");
        chainIntCert.verify(chainRootCert.getPublicKey(), "BC");
        bh.consume(chainLeafCert);
        bh.consume(chainIntCert);
    }

    /** Layer B — DER encoding: certificate.getEncoded() → DER byte[]. */
    @Benchmark
    public byte[] derEncode(Blackhole bh) throws Exception {
        byte[] der = prebuiltCert.getEncoded();
        bh.consume(der);
        return der;
    }

    /**
     * Layer B — DER decoding: DER byte[] → X509Certificate.
     * Uses X509CertificateHolder (BC ASN.1 layer) + JcaX509CertificateConverter.
     */
    @Benchmark
    public X509Certificate derDecode(Blackhole bh) throws Exception {
        X509CertificateHolder h = new X509CertificateHolder(prebuiltDer);
        X509Certificate cert = certConverter.getCertificate(h);
        bh.consume(cert);
        return cert;
    }

    /** Layer B — PEM encoding: JcaPEMWriter → PEM string (in-memory, no file I/O). */
    @Benchmark
    public String pemEncode(Blackhole bh) throws Exception {
        StringWriter sw = new StringWriter();
        try (JcaPEMWriter pw = new JcaPEMWriter(sw)) {
            pw.writeObject(prebuiltCert);
        }
        String pem = sw.toString();
        bh.consume(pem);
        return pem;
    }

    /**
     * Layer B — PEM decoding: PEM string → X509Certificate.
     * Uses PEMParser (BC) + JcaX509CertificateConverter (in-memory, no file I/O).
     */
    @Benchmark
    public X509Certificate pemDecode(Blackhole bh) throws Exception {
        try (PEMParser parser = new PEMParser(new StringReader(prebuiltPem))) {
            Object obj = parser.readObject();
            X509CertificateHolder h = (X509CertificateHolder) obj;
            X509Certificate cert = certConverter.getCertificate(h);
            bh.consume(cert);
            return cert;
        }
    }

    /**
     * Layer B — hybrid alt-signature verification via BC isAlternativeSignatureValid().
     * Only valid for hybrid-rsa-mldsa65. Run this benchmark only for that algo tag
     * (see run_micro.sh LAYER_B_OPS_HYBRID). Throws for non-hybrid algos.
     */
    @Benchmark
    public void altVerify(Blackhole bh) throws Exception {
        if (prebuiltAltProvider == null) {
            throw new IllegalStateException("altVerify called for non-hybrid algoTag: " + algoTag);
        }
        boolean valid = prebuiltHolder.isAlternativeSignatureValid(prebuiltAltProvider);
        bh.consume(valid);
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    /**
     * Build a X509CertificateHolder signed by issuerKP (or self-signed if issuerKP == null).
     * Uses CertificateGenerator.getSuitableSignatureAlgorithm() — same mapping as the pqcli CLI.
     */
    private X509CertificateHolder buildCertHolder(
            KeyPair subjectKP, KeyPair subjectAltKP,
            X500Name subjectDN, X500Name issuerDN) throws Exception {
        return buildCertHolder(subjectKP, subjectAltKP, subjectDN, issuerDN, null);
    }

    private X509CertificateHolder buildCertHolder(
            KeyPair subjectKP, KeyPair subjectAltKP,
            X500Name subjectDN, X500Name issuerDN,
            KeyPair issuerKP) throws Exception {

        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
            issuerDN,
            BigInteger.valueOf(System.nanoTime()),
            NOT_BEFORE, NOT_AFTER,
            subjectDN,
            subjectKP.getPublic()
        );
        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));

        if ("hybrid-rsa-mldsa65".equals(algoTag) && subjectAltKP != null) {
            SubjectAltPublicKeyInfo altKeyInfo =
                SubjectAltPublicKeyInfo.getInstance(subjectAltKP.getPublic().getEncoded());
            builder.addExtension(Extension.subjectAltPublicKeyInfo, false, altKeyInfo);
        }

        // Use issuerKP for signing if provided (chain certs), otherwise self-sign
        KeyPair signingKP = (issuerKP != null) ? issuerKP : subjectKP;

        if ("hybrid-rsa-mldsa65".equals(algoTag) && subjectAltKP != null && issuerKP == null) {
            // Self-signed hybrid: primary + alt signature
            ContentSigner primary = makeSignerForKeyPair(signingKP, "rsa3072");
            ContentSigner alt = new JcaContentSignerBuilder("ML-DSA-65").setProvider("BC")
                                    .build(subjectAltKP.getPrivate());
            return builder.build(primary, false, alt);
        } else {
            // For chain certs with hybrid/composite, sign with primary algo of issuer
            return builder.build(makeSignerForKeyPair(signingKP, algoTag));
        }
    }

    /**
     * Generate a single key pair using the primary algorithm for this algoTag.
     * Used for building the chain certs (root, intermediate, leaf).
     */
    private KeyPair buildSingleKeyPair() throws Exception {
        switch (algoTag) {
            case "rsa3072":           return KeyGenerator.generateKeyPair("rsa",   "3072");
            case "ecdsa-p256":        return KeyGenerator.generateKeyPair("ec",    "secp256r1");
            case "ed25519":           return KeyGenerator.generateKeyPair("ed25519", "");
            case "mldsa65":           return KeyGenerator.generateKeyPair("mldsa", "65");
            case "hybrid-rsa-mldsa65":  return KeyGenerator.generateKeyPair("rsa", "3072");
            case "composite-rsa-mldsa65": {
                KeyPairGenerator kpg = KeyPairGenerator.getInstance("MLDSA65-RSA3072-PSS-SHA512", "BC");
                return kpg.generateKeyPair();
            }
            default: throw new IllegalArgumentException("Unknown algoTag: " + algoTag);
        }
    }

    /**
     * Create a ContentSigner for the primary key of the current algoTag.
     *
     * The signature algorithm mapping here mirrors CertificateGenerator.getSuitableSignatureAlgorithm()
     * (package-private in pqcli). It is a separate but equivalent definition for the first campaign
     * algorithms. If pqcli's mapping changes, this must be kept in sync manually.
     * See BENCHMARKING_DEVLOG.md §"Microbenchmark logic sharing" for the rationale.
     */
    private ContentSigner makePrimarySigner() throws Exception {
        return makeSignerForKeyPair(keyPair, algoTag);
    }

    private ContentSigner makeSignerForKeyPair(KeyPair kp, String tag) throws Exception {
        switch (tag) {
            case "rsa3072":
            case "hybrid-rsa-mldsa65":  // primary of hybrid is RSA
                return new JcaContentSignerBuilder("SHA384withRSA").setProvider("BC").build(kp.getPrivate());
            case "ecdsa-p256":
                return new JcaContentSignerBuilder("SHA256withECDSA").setProvider("BC").build(kp.getPrivate());
            case "ed25519":
                return new JcaContentSignerBuilder("Ed25519").setProvider("BC").build(kp.getPrivate());
            case "mldsa65":
                return new JcaContentSignerBuilder("ML-DSA-65").setProvider("BC").build(kp.getPrivate());
            case "composite-rsa-mldsa65":
                return new JcaContentSignerBuilder("MLDSA65-RSA3072-PSS-SHA512")
                    .setProvider("BC").build(kp.getPrivate());
            default:
                throw new IllegalArgumentException("Unknown algoTag for signer: " + tag);
        }
    }
}
