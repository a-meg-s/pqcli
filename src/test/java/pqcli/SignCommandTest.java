package pqcli;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.junit.BeforeClass;
import org.junit.Test;
import picocli.CommandLine;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.PrintStream;
import java.math.BigInteger;
import java.nio.file.Files;
import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.util.Date;

import static org.junit.Assert.*;

/**
 * Tests for sign command: CSR PoP enforcement, hybrid CSR issuance, and failure cases.
 */
public class SignCommandTest {

    static {
        ProviderSetup.setupProvider();
    }

    // --- Shared fixture for hybrid tests (built once via @BeforeClass) ---

    private static X509Certificate hybridCaCert;
    private static KeyPair hybridCaPair;
    private static KeyPair hybridCaAltPair;
    private static X509Certificate hybridIssuedCert;

    @BeforeClass
    public static void buildHybridFixture() throws Exception {
        // Build hybrid CA: RSA:3072 (primary) + ML-DSA:65 (alt)
        AlgorithmSet caAlgoSet = new AlgorithmSet("RSA:3072,ML-DSA:65");
        hybridCaPair    = KeyGenerator.generateKeyPair(caAlgoSet.getAlgorithms());
        hybridCaAltPair = KeyGenerator.generateKeyPair(caAlgoSet.getAltAlgorithms());
        hybridCaCert    = makeHybridCa("CN=HybridCA", hybridCaPair, hybridCaAltPair);

        // Build hybrid CSR: RSA:3072 + ML-DSA:65
        AlgorithmSet eeAlgoSet = new AlgorithmSet("RSA:3072,ML-DSA:65");
        KeyPair eePair    = KeyGenerator.generateKeyPair(eeAlgoSet.getAlgorithms());
        KeyPair eeAltPair = KeyGenerator.generateKeyPair(eeAlgoSet.getAltAlgorithms());
        PKCS10CertificationRequest hybridCsr = makeHybridCsrFromPairs(eePair, eeAltPair, "CN=HybridEE");

        // Sign hybrid CSR via CLI
        File caCertFile   = writeCertFile(hybridCaCert);
        File caKeyFile    = writeKeyFile(hybridCaPair.getPrivate());
        File caAltKeyFile = writeKeyFile(hybridCaAltPair.getPrivate());
        File csrFile      = writeCsrFile(hybridCsr);
        File outDir       = Files.createTempDirectory("pqcli_sign_fixture").toFile();

        int exitCode = new CommandLine(new SignCommand()).execute(
            "-csr",      csrFile.getAbsolutePath(),
            "-CAcert",   caCertFile.getAbsolutePath(),
            "-CAkey",    caKeyFile.getAbsolutePath(),
            "-CAaltkey", caAltKeyFile.getAbsolutePath(),
            "-out",      new File(outDir, "issued").getAbsolutePath()
        );

        if (exitCode != 0) {
            throw new RuntimeException("@BeforeClass hybrid sign failed with exit code " + exitCode);
        }
        hybridIssuedCert = ViewCommand.loadCertificate(
                new File(outDir, "issued_certificate.pem").getAbsolutePath());
    }

    // === Test 1: existing non-hybrid path is unaffected ===

    @Test
    public void existingNonHybridSigningUnaffected() throws Exception {
        X509Certificate caCert = makeSelfSignedCa("RSA:3072", "CN=TestCA");
        PKCS10CertificationRequest csr = makeCsr("ML-DSA:65", "CN=TestEE");
        X509Certificate signed = sign(csr, caCert, makeKeyPair("RSA:3072"));

        String issuer   = signed.getIssuerX500Principal().getName();
        String caSubject = caCert.getSubjectX500Principal().getName();
        assertEquals("Issuer must equal CA subject", caSubject, issuer);
    }

    // === Test 2: primary CSR PoP rejected for non-hybrid path ===

    @Test
    public void invalidPrimaryPopRejectedNonHybrid() throws Exception {
        // Build valid CSR, corrupt its signature, verify sign command rejects it.
        AlgorithmSet caAlgo = new AlgorithmSet("RSA:3072");
        KeyPair caPair = KeyGenerator.generateKeyPair(caAlgo.getAlgorithms());
        X509Certificate caCert = makeSelfSignedCaWithKey("CN=CAForPoP", caPair);

        // Build a valid non-hybrid CSR and corrupt its DER signature bytes
        PKCS10CertificationRequest validCsr = makeCsr("RSA:3072", "CN=EEForPoP");
        byte[] der = validCsr.getEncoded();
        // Flip a byte deep in the signature area (last N bytes are signature value for RSA-3072)
        der[der.length - 10] ^= 0xFF;

        File csrFile    = writeCsrDerFile(der);
        File caCertFile = writeCertFile(caCert);
        File caKeyFile  = writeKeyFile(caPair.getPrivate());

        ByteArrayOutputStream errBuf = new ByteArrayOutputStream();
        PrintStream origErr = System.err;
        System.setErr(new PrintStream(errBuf));
        int exitCode;
        try {
            exitCode = new CommandLine(new SignCommand()).execute(
                "-csr",    csrFile.getAbsolutePath(),
                "-CAcert", caCertFile.getAbsolutePath(),
                "-CAkey",  caKeyFile.getAbsolutePath()
            );
        } finally {
            System.setErr(origErr);
        }

        assertEquals("sign must exit 1 for invalid primary CSR PoP", 1, exitCode);
        String err = errBuf.toString();
        assertTrue("stderr must mention primary signature; got: " + err,
                err.contains("primary signature is invalid") || err.contains("proof of possession"));
    }

    // === Tests 3-5: hybrid cert properties (use @BeforeClass fixture) ===

    @Test
    public void hybridCsrWithCaAltKeyIssuesHybridCert() {
        // Verify issued cert has all three hybrid extensions
        X509CertificateHolder holder;
        try {
            holder = new X509CertificateHolder(hybridIssuedCert.getEncoded());
        } catch (Exception e) {
            fail("Could not re-encode issued cert: " + e.getMessage());
            return;
        }
        var exts = holder.getExtensions();
        assertNotNull("Issued cert must have extensions", exts);
        assertNotNull("Must have SubjectAltPublicKeyInfo (2.5.29.72)",
                exts.getExtension(Extension.subjectAltPublicKeyInfo));
        assertNotNull("Must have AltSignatureAlgorithm (2.5.29.73)",
                exts.getExtension(Extension.altSignatureAlgorithm));
        assertNotNull("Must have AltSignatureValue (2.5.29.74)",
                exts.getExtension(Extension.altSignatureValue));
    }

    @Test
    public void hybridIssuedCertVerifiesPrimarySignature() throws Exception {
        hybridIssuedCert.verify(hybridCaCert.getPublicKey(), "BC");
        // No exception = pass
    }

    @Test
    public void hybridIssuedCertVerifiesAltSignature() throws Exception {
        X509CertificateHolder issuedHolder = new X509CertificateHolder(hybridIssuedCert.getEncoded());
        ContentVerifierProvider caAltVerifier = new JcaContentVerifierProviderBuilder()
                .setProvider("BC").build(hybridCaAltPair.getPublic());
        boolean altValid;
        try {
            altValid = issuedHolder.isAlternativeSignatureValid(caAltVerifier);
        } catch (org.bouncycastle.cert.CertException e) {
            fail("Alt sig verification threw CertException: " + e.getMessage());
            return;
        }
        assertTrue("isAlternativeSignatureValid must return true for correctly issued hybrid cert", altValid);
    }

    // === Test 6: hybrid CSR without -CAaltkey fails ===

    @Test
    public void hybridCsrWithoutCaAltKeyFails() throws Exception {
        AlgorithmSet eeAlgoSet = new AlgorithmSet("RSA:3072,ML-DSA:65");
        KeyPair eePair    = KeyGenerator.generateKeyPair(eeAlgoSet.getAlgorithms());
        KeyPair eeAltPair = KeyGenerator.generateKeyPair(eeAlgoSet.getAltAlgorithms());
        PKCS10CertificationRequest hybridCsr = makeHybridCsrFromPairs(eePair, eeAltPair, "CN=MissingAltKey");

        File caCertFile = writeCertFile(hybridCaCert);
        File caKeyFile  = writeKeyFile(hybridCaPair.getPrivate());
        File csrFile    = writeCsrFile(hybridCsr);

        ByteArrayOutputStream errBuf = new ByteArrayOutputStream();
        PrintStream origErr = System.err;
        System.setErr(new PrintStream(errBuf));
        int exitCode;
        try {
            exitCode = new CommandLine(new SignCommand()).execute(
                "-csr",    csrFile.getAbsolutePath(),
                "-CAcert", caCertFile.getAbsolutePath(),
                "-CAkey",  caKeyFile.getAbsolutePath()
                // -CAaltkey intentionally omitted
            );
        } finally {
            System.setErr(origErr);
        }

        assertEquals("sign must exit 1 when -CAaltkey is missing for hybrid CSR", 1, exitCode);
        assertTrue("stderr must mention -CAaltkey; got: " + errBuf,
                errBuf.toString().contains("-CAaltkey"));
    }

    // === Test 7: hybrid CSR with non-hybrid CA fails ===

    @Test
    public void hybridCsrWithNonHybridCaFails() throws Exception {
        // Non-hybrid CA cert has no SubjectAltPublicKeyInfo or AltSignatureAlgorithm
        AlgorithmSet caAlgoSet = new AlgorithmSet("RSA:3072");
        KeyPair caPair = KeyGenerator.generateKeyPair(caAlgoSet.getAlgorithms());
        X509Certificate nonHybridCaCert = makeSelfSignedCaWithKey("CN=NonHybridCA", caPair);

        AlgorithmSet eeAlgoSet = new AlgorithmSet("RSA:3072,ML-DSA:65");
        KeyPair eePair    = KeyGenerator.generateKeyPair(eeAlgoSet.getAlgorithms());
        KeyPair eeAltPair = KeyGenerator.generateKeyPair(eeAlgoSet.getAltAlgorithms());
        PKCS10CertificationRequest hybridCsr = makeHybridCsrFromPairs(eePair, eeAltPair, "CN=NonHybridCATest");

        // Use hybridCaAltPair.getPrivate() as a plausible -CAaltkey (any key, doesn't matter)
        File caCertFile   = writeCertFile(nonHybridCaCert);
        File caKeyFile    = writeKeyFile(caPair.getPrivate());
        File caAltKeyFile = writeKeyFile(hybridCaAltPair.getPrivate());
        File csrFile      = writeCsrFile(hybridCsr);

        ByteArrayOutputStream errBuf = new ByteArrayOutputStream();
        PrintStream origErr = System.err;
        System.setErr(new PrintStream(errBuf));
        int exitCode;
        try {
            exitCode = new CommandLine(new SignCommand()).execute(
                "-csr",      csrFile.getAbsolutePath(),
                "-CAcert",   caCertFile.getAbsolutePath(),
                "-CAkey",    caKeyFile.getAbsolutePath(),
                "-CAaltkey", caAltKeyFile.getAbsolutePath()
            );
        } finally {
            System.setErr(origErr);
        }

        assertEquals("sign must exit 1 when CA cert is not hybrid", 1, exitCode);
        String err = errBuf.toString();
        assertTrue("stderr must mention CA not being hybrid; got: " + err,
                err.contains("not a hybrid cert") || err.contains("SubjectAltPublicKeyInfo")
                        || err.contains("AltSignatureAlgorithm"));
    }

    // === Test 8: CA alt key mismatch — Step 7 rejects before cert building ===

    @Test
    public void caAltKeyMismatchFails() throws Exception {
        AlgorithmSet eeAlgoSet = new AlgorithmSet("RSA:3072,ML-DSA:65");
        KeyPair eePair    = KeyGenerator.generateKeyPair(eeAlgoSet.getAlgorithms());
        KeyPair eeAltPair = KeyGenerator.generateKeyPair(eeAlgoSet.getAltAlgorithms());
        PKCS10CertificationRequest hybridCsr = makeHybridCsrFromPairs(eePair, eeAltPair, "CN=WrongAltKey");

        // Generate a fresh ML-DSA:65 key that was NEVER used to produce the CA cert's alt signature
        KeyPair wrongAltPair = KeyGenerator.generateKeyPair(
                new AlgorithmSet("ML-DSA:65").getAlgorithms());

        File caCertFile      = writeCertFile(hybridCaCert);
        File caKeyFile       = writeKeyFile(hybridCaPair.getPrivate());
        File wrongAltKeyFile = writeKeyFile(wrongAltPair.getPrivate());
        File csrFile         = writeCsrFile(hybridCsr);

        ByteArrayOutputStream errBuf = new ByteArrayOutputStream();
        PrintStream origErr = System.err;
        System.setErr(new PrintStream(errBuf));
        int exitCode;
        try {
            exitCode = new CommandLine(new SignCommand()).execute(
                "-csr",      csrFile.getAbsolutePath(),
                "-CAcert",   caCertFile.getAbsolutePath(),
                "-CAkey",    caKeyFile.getAbsolutePath(),
                "-CAaltkey", wrongAltKeyFile.getAbsolutePath()
            );
        } finally {
            System.setErr(origErr);
        }

        assertEquals("sign must exit 1 when CA alt key does not match CA cert", 1, exitCode);
        String err = errBuf.toString();
        assertTrue("stderr must say 'does not correspond'; got: " + err,
                err.contains("does not correspond"));
    }

    // === Test 9: invalid CSR alt PoP fails — Step 9 rejects ===

    @Test
    public void invalidCsrAltPopFails() throws Exception {
        // Build CSR where alt sig is produced with a DIFFERENT key than the alt public key in the CSR
        AlgorithmSet eeAlgoSet = new AlgorithmSet("RSA:3072,ML-DSA:65");
        KeyPair eePair    = KeyGenerator.generateKeyPair(eeAlgoSet.getAlgorithms());
        KeyPair eeAltPair = KeyGenerator.generateKeyPair(eeAlgoSet.getAltAlgorithms()); // real alt pair
        // Use a different ML-DSA:65 key pair to sign — the public key in the CSR won't match the signer
        KeyPair wrongSigner = KeyGenerator.generateKeyPair(
                new AlgorithmSet("ML-DSA:65").getAlgorithms());

        AlgorithmSet eeAlgoSetForSig = new AlgorithmSet("RSA:3072,ML-DSA:65");
        String primarySigAlgo = CertificateGenerator.getSuitableSignatureAlgorithm(
                eeAlgoSetForSig.getAlgorithms()[0]);
        String altSigAlgo = CertificateGenerator.getSuitableSignatureAlgorithm(
                eeAlgoSetForSig.getAltAlgorithms()[0]);

        // CSR declares eeAltPair.getPublic() as alt key, but signs with wrongSigner — invalid PoP
        JcaPKCS10CertificationRequestBuilder builder = new JcaPKCS10CertificationRequestBuilder(
                new X500Name("CN=BadAltPoP"), eePair.getPublic());
        ContentSigner primarySigner = new JcaContentSignerBuilder(primarySigAlgo)
                .setProvider("BC").build(eePair.getPrivate());
        ContentSigner wrongAltSigner = new JcaContentSignerBuilder(altSigAlgo)
                .setProvider("BC").build(wrongSigner.getPrivate());
        // Pass eeAltPair.getPublic() as the declared alt key but sign with wrongSigner
        PKCS10CertificationRequest badPopCsr = builder.build(
                primarySigner, eeAltPair.getPublic(), wrongAltSigner);

        File caCertFile   = writeCertFile(hybridCaCert);
        File caKeyFile    = writeKeyFile(hybridCaPair.getPrivate());
        File caAltKeyFile = writeKeyFile(hybridCaAltPair.getPrivate());
        File csrFile      = writeCsrFile(badPopCsr);

        ByteArrayOutputStream errBuf = new ByteArrayOutputStream();
        PrintStream origErr = System.err;
        System.setErr(new PrintStream(errBuf));
        int exitCode;
        try {
            exitCode = new CommandLine(new SignCommand()).execute(
                "-csr",      csrFile.getAbsolutePath(),
                "-CAcert",   caCertFile.getAbsolutePath(),
                "-CAkey",    caKeyFile.getAbsolutePath(),
                "-CAaltkey", caAltKeyFile.getAbsolutePath()
            );
        } finally {
            System.setErr(origErr);
        }

        assertEquals("sign must exit 1 for invalid CSR alt PoP", 1, exitCode);
        String err = errBuf.toString();
        assertTrue("stderr must mention alt signature/proof; got: " + err,
                err.contains("alt") || err.contains("alternative") || err.contains("proof"));
    }

    // --- Legacy helpers (preserved from original test class) ---

    @Test
    public void signedCertHasCaIssuer() throws Exception {
        X509Certificate caCert = makeSelfSignedCa("RSA:3072", "CN=TestCA");
        PKCS10CertificationRequest csr = makeCsr("ML-DSA:65", "CN=TestEE");
        X509Certificate signed = sign(csr, caCert, makeKeyPair("RSA:3072"));

        String issuer    = signed.getIssuerX500Principal().getName();
        String caSubject = caCert.getSubjectX500Principal().getName();
        assertEquals("Issuer must equal CA subject", caSubject, issuer);
    }

    @Test
    public void signedCertVerifiesWithCa() throws Exception {
        AlgorithmSet caAlgo = new AlgorithmSet("RSA:3072");
        KeyPair caKeyPair = KeyGenerator.generateKeyPair(caAlgo.getAlgorithms());
        X509Certificate caCert = makeSelfSignedCaWithKey("CN=TestCA2", caKeyPair);

        PKCS10CertificationRequest csr = makeCsr("ML-DSA:65", "CN=TestEE2");
        X509Certificate signed = signWithKey(csr, caCert, caKeyPair);

        signed.verify(caCert.getPublicKey(), "BC"); // no exception = pass
    }

    // --- Helpers ---

    private static KeyPair makeKeyPair(String algo) throws Exception {
        return KeyGenerator.generateKeyPair(new AlgorithmSet(algo).getAlgorithms());
    }

    private static X509Certificate makeSelfSignedCa(String keyAlgo, String subject) throws Exception {
        AlgorithmSet algorithmSet = new AlgorithmSet(keyAlgo);
        KeyPair keyPair = KeyGenerator.generateKeyPair(algorithmSet.getAlgorithms());
        java.lang.reflect.Method m = CertificateGenerator.class.getDeclaredMethod(
            "generateCertificate",
            AlgorithmSet.class, KeyPair.class, KeyPair.class, String.class, double.class);
        m.setAccessible(true);
        String x500 = subject.replace('/', ',').replaceFirst("^,", "");
        return (X509Certificate) m.invoke(null, algorithmSet, keyPair, null, x500, 1.0);
    }

    private static X509Certificate makeSelfSignedCaWithKey(String subject, KeyPair keyPair) throws Exception {
        AlgorithmSet algorithmSet = new AlgorithmSet("RSA:3072");
        java.lang.reflect.Method m = CertificateGenerator.class.getDeclaredMethod(
            "generateCertificate",
            AlgorithmSet.class, KeyPair.class, KeyPair.class, String.class, double.class);
        m.setAccessible(true);
        return (X509Certificate) m.invoke(null, algorithmSet, keyPair, null, subject, 1.0);
    }

    /**
     * Build a hybrid self-signed CA cert using the provided key pairs.
     * The AlgorithmSet for RSA:3072,ML-DSA:65 is assumed; the provided key pairs must match.
     */
    private static X509Certificate makeHybridCa(String subject, KeyPair keyPair, KeyPair altKeyPair)
            throws Exception {
        AlgorithmSet algorithmSet = new AlgorithmSet("RSA:3072,ML-DSA:65");
        java.lang.reflect.Method m = CertificateGenerator.class.getDeclaredMethod(
            "generateCertificate",
            AlgorithmSet.class, KeyPair.class, KeyPair.class, String.class, double.class);
        m.setAccessible(true);
        return (X509Certificate) m.invoke(null, algorithmSet, keyPair, altKeyPair, subject, 1.0);
    }

    private static PKCS10CertificationRequest makeCsr(String keyAlgo, String subject) throws Exception {
        AlgorithmSet algorithmSet = new AlgorithmSet(keyAlgo);
        KeyPair keyPair = KeyGenerator.generateKeyPair(algorithmSet.getAlgorithms());
        String sigAlgo = CertificateGenerator.getSuitableSignatureAlgorithm(algorithmSet.getAlgorithms()[0]);
        JcaPKCS10CertificationRequestBuilder builder =
            new JcaPKCS10CertificationRequestBuilder(new X500Name(subject), keyPair.getPublic());
        ContentSigner signer = new JcaContentSignerBuilder(sigAlgo).setProvider("BC")
                .build(keyPair.getPrivate());
        return builder.build(signer);
    }

    /**
     * Build a hybrid PKCS#10 CSR using the provided primary and alt key pairs.
     * Uses RSA:3072 as primary and ML-DSA:65 as alt for signature algorithm derivation.
     */
    private static PKCS10CertificationRequest makeHybridCsrFromPairs(
            KeyPair primaryPair, KeyPair altPair, String subject) throws Exception {
        AlgorithmSet algoSet = new AlgorithmSet("RSA:3072,ML-DSA:65");
        String primarySigAlgo = CertificateGenerator.getSuitableSignatureAlgorithm(
                algoSet.getAlgorithms()[0]);
        String altSigAlgo = CertificateGenerator.getSuitableSignatureAlgorithm(
                algoSet.getAltAlgorithms()[0]);
        JcaPKCS10CertificationRequestBuilder builder = new JcaPKCS10CertificationRequestBuilder(
                new X500Name(subject), primaryPair.getPublic());
        ContentSigner primarySigner = new JcaContentSignerBuilder(primarySigAlgo)
                .setProvider("BC").build(primaryPair.getPrivate());
        ContentSigner altSigner = new JcaContentSignerBuilder(altSigAlgo)
                .setProvider("BC").build(altPair.getPrivate());
        // BC 3-arg build: stores alt public key and alt sig as PKCS#10 attributes (not extensionRequest)
        return builder.build(primarySigner, altPair.getPublic(), altSigner);
    }

    private static X509Certificate sign(PKCS10CertificationRequest csr, X509Certificate caCert,
            KeyPair caKeyPair) throws Exception {
        return signWithKey(csr, caCert, caKeyPair);
    }

    private static X509Certificate signWithKey(PKCS10CertificationRequest csr, X509Certificate caCert,
            KeyPair caKeyPair) throws Exception {
        String sigAlgo = caCert.getSigAlgName();
        Date notBefore = new Date();
        Date notAfter = new Date(notBefore.getTime() + 365L * 86400000L);
        X500Name issuer = new X500Name(caCert.getSubjectX500Principal().getName("RFC1779"));
        X500Name subject = csr.getSubject();

        X509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
            issuer, BigInteger.valueOf(System.currentTimeMillis()),
            notBefore, notAfter, subject,
            new JcaPEMKeyConverter().setProvider("BC").getPublicKey(csr.getSubjectPublicKeyInfo()));

        ContentSigner signer = new JcaContentSignerBuilder(sigAlgo).setProvider("BC")
                .build(caKeyPair.getPrivate());
        return new JcaX509CertificateConverter().setProvider("BC")
                .getCertificate(builder.build(signer));
    }

    // --- File I/O helpers ---

    private static File writeCertFile(X509Certificate cert) throws Exception {
        File f = File.createTempFile("pqcli_cert", ".pem");
        f.deleteOnExit();
        CertificateGenerator.saveCertificateToFile(f.getAbsolutePath(), cert);
        return f;
    }

    private static File writeKeyFile(java.security.PrivateKey key) throws Exception {
        File f = File.createTempFile("pqcli_key", ".pem");
        f.deleteOnExit();
        KeyGenerator.saveKeyToFile(f.getAbsolutePath(), key);
        return f;
    }

    private static File writeCsrFile(PKCS10CertificationRequest csr) throws Exception {
        return writeCsrDerFile(csr.getEncoded());
    }

    private static File writeCsrDerFile(byte[] der) throws Exception {
        File f = File.createTempFile("pqcli_csr", ".pem");
        f.deleteOnExit();
        try (FileOutputStream os = new FileOutputStream(f)) {
            os.write("-----BEGIN CERTIFICATE REQUEST-----\n".getBytes());
            os.write(KeyGenerator.wrapBase64(der).getBytes());
            os.write("-----END CERTIFICATE REQUEST-----\n".getBytes());
        }
        return f;
    }
}
