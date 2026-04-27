package pqcli;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.cert.X509CertificateHolder;
import org.junit.BeforeClass;
import org.junit.Test;
import picocli.CommandLine;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.PrintStream;
import java.nio.file.Files;
import java.security.KeyPair;
import java.security.cert.X509Certificate;

import static org.junit.Assert.*;

/**
 * RFC 9763 Stage 4 tests: CA-side relatedCertRequest PoP verification and compliant
 * RelatedCertificate extension issuance.
 *
 * Stage 4 is the only path that may be labeled RFC 9763-compliant issuance.
 * Stage 2 test-mode (--related-cert-test-extension) remains separate and non-compliant.
 */
public class RelatedCertStage4Test {

    private static final ASN1ObjectIdentifier OID_RELATED_CERT =
            new ASN1ObjectIdentifier("1.3.6.1.5.5.7.1.36");

    static {
        ProviderSetup.setupProvider();
    }

    // Shared fixture
    private static File refCertFile;     // RSA cert: Stage 3 PoP target (the "referenced cert")
    private static File refKeyFile;      // RSA private key for refCert
    private static File signCaCertFile;  // EC CA cert: issues the EE cert in Stage 4 signing
    private static File signCaKeyFile;   // EC CA private key
    private static File pqcCsrFile;      // ML-DSA CSR carrying relatedCertRequest attribute
    private static File plainCsrFile;    // plain RSA CSR with no relatedCertRequest attribute

    @BeforeClass
    public static void buildFixture() throws Exception {
        java.lang.reflect.Method genCert = CertificateGenerator.class.getDeclaredMethod(
                "generateCertificate",
                AlgorithmSet.class, KeyPair.class, KeyPair.class, String.class, double.class);
        genCert.setAccessible(true);

        // 1. RSA:3072 referenced cert (the cert the Stage 3 CSR PoP was built against)
        AlgorithmSet refAlgo = new AlgorithmSet("RSA:3072");
        KeyPair refKP = KeyGenerator.generateKeyPair(refAlgo.getAlgorithms());
        X509Certificate refCertObj = (X509Certificate) genCert.invoke(
                null, refAlgo, refKP, null, "CN=Ref-Stage4", 1.0);
        refCertFile = writeCertFile(refCertObj);
        refKeyFile  = writeKeyFile(refKP.getPrivate());

        // 2. EC:secp256r1 signing CA (issues the EE cert; distinct from the referenced cert)
        AlgorithmSet caAlgo = new AlgorithmSet("EC:secp256r1");
        KeyPair caKP = KeyGenerator.generateKeyPair(caAlgo.getAlgorithms());
        X509Certificate caCertObj = (X509Certificate) genCert.invoke(
                null, caAlgo, caKP, null, "CN=SignCA-Stage4", 1.0);
        signCaCertFile = writeCertFile(caCertObj);
        signCaKeyFile  = writeKeyFile(caKP.getPrivate());

        // 3. ML-DSA:65 CSR with Stage 3 relatedCertRequest attribute targeting refCert
        File s3Out = Files.createTempDirectory("pqcli_s4_csr").toFile();
        int csrExit = new CommandLine(new CSRCommand()).execute(
                "-nk",                "ML-DSA:65",
                "-subj",              "CN=PQC-EE-Stage4",
                "--related-cert",     refCertFile.getAbsolutePath(),
                "--related-cert-key", refKeyFile.getAbsolutePath(),
                "--related-cert-url", "https://example.com/ref-stage4.pem",
                "-out",               new File(s3Out, "pqc_ee").getAbsolutePath()
        );
        if (csrExit != 0) throw new RuntimeException("@BeforeClass: Stage 3 CSR generation failed (exit " + csrExit + ")");
        pqcCsrFile = new File(s3Out, "pqc_ee_csr.pem");
        if (!pqcCsrFile.exists()) throw new RuntimeException("@BeforeClass: pqc_ee_csr.pem not created");

        // 4. Plain RSA CSR (no relatedCertRequest attribute) for negative tests
        File plainOut = Files.createTempDirectory("pqcli_s4_plain").toFile();
        int plainExit = new CommandLine(new CSRCommand()).execute(
                "-nk",   "RSA:3072",
                "-subj", "CN=Plain-EE-Stage4",
                "-out",  new File(plainOut, "plain").getAbsolutePath()
        );
        if (plainExit != 0) throw new RuntimeException("@BeforeClass: plain CSR generation failed (exit " + plainExit + ")");
        plainCsrFile = new File(plainOut, "plain_csr.pem");
        if (!plainCsrFile.exists()) throw new RuntimeException("@BeforeClass: plain_csr.pem not created");
    }

    /**
     * Full end-to-end Stage 4 compliant issuance:
     * - Sign PQC CSR with relatedCertRequest attribute using --related-cert.
     * - Assert issued cert carries RelatedCertificate extension.
     * - Assert verify --related-cert passes.
     */
    @Test
    public void positiveEndToEndCompliantIssuance() throws Exception {
        File outDir = Files.createTempDirectory("pqcli_s4_issued").toFile();
        int exitCode = new CommandLine(new SignCommand()).execute(
                "-csr",           pqcCsrFile.getAbsolutePath(),
                "-CAcert",        signCaCertFile.getAbsolutePath(),
                "-CAkey",         signCaKeyFile.getAbsolutePath(),
                "--related-cert", refCertFile.getAbsolutePath(),
                "-out",           new File(outDir, "issued").getAbsolutePath()
        );
        assertEquals("Stage 4 compliant issuance must exit 0", 0, exitCode);

        File issuedCertFile = new File(outDir, "issued_certificate.pem");
        assertTrue("issued_certificate.pem must exist", issuedCertFile.exists());

        X509Certificate issued = ViewCommand.loadCertificate(issuedCertFile.getAbsolutePath());
        X509CertificateHolder holder = new X509CertificateHolder(issued.getEncoded());
        assertNotNull("RelatedCertificate extension (OID 1.3.6.1.5.5.7.1.36) must be in issued cert",
                holder.getExtensions().getExtension(OID_RELATED_CERT));

        // Hash binding must verify via Stage 2 verify path
        int verifyExit = new CommandLine(new VerifyCommand()).execute(
                "-in",            issuedCertFile.getAbsolutePath(),
                "--related-cert", refCertFile.getAbsolutePath()
        );
        assertEquals("verify --related-cert must pass for Stage 4 issued cert", 0, verifyExit);
    }

    /** CSR has relatedCertRequest attribute but --related-cert is absent → exit 1. */
    @Test
    public void csrHasAttributeButNoRelatedCertFlagFails() {
        ByteArrayOutputStream errBuf = new ByteArrayOutputStream();
        PrintStream origErr = System.err;
        System.setErr(new PrintStream(errBuf));
        int exitCode;
        try {
            exitCode = new CommandLine(new SignCommand()).execute(
                    "-csr",    pqcCsrFile.getAbsolutePath(),
                    "-CAcert", signCaCertFile.getAbsolutePath(),
                    "-CAkey",  signCaKeyFile.getAbsolutePath()
                    // --related-cert intentionally absent
            );
        } finally {
            System.setErr(origErr);
        }
        assertEquals("Missing --related-cert for CSR with attribute must exit 1", 1, exitCode);
        String err = errBuf.toString();
        assertTrue("stderr must mention --related-cert or relatedCertRequest; got: " + err,
                err.contains("--related-cert") || err.contains("relatedCertRequest"));
    }

    /** --related-cert provided but CSR has no relatedCertRequest attribute → exit 1. */
    @Test
    public void relatedCertFlagWithoutCsrAttributeFails() {
        ByteArrayOutputStream errBuf = new ByteArrayOutputStream();
        PrintStream origErr = System.err;
        System.setErr(new PrintStream(errBuf));
        int exitCode;
        try {
            exitCode = new CommandLine(new SignCommand()).execute(
                    "-csr",           plainCsrFile.getAbsolutePath(),
                    "-CAcert",        signCaCertFile.getAbsolutePath(),
                    "-CAkey",         signCaKeyFile.getAbsolutePath(),
                    "--related-cert", refCertFile.getAbsolutePath()
                    // plainCsrFile has no relatedCertRequest attribute
            );
        } finally {
            System.setErr(origErr);
        }
        assertEquals("--related-cert on CSR without attribute must exit 1", 1, exitCode);
        String err = errBuf.toString();
        assertTrue("stderr must mention attribute or 1.2.840; got: " + err,
                err.contains("1.2.840.113549.1.9.16.2.60") || err.contains("relatedCertRequest")
                        || err.contains("attribute"));
    }

    /** Wrong --related-cert (certID mismatch) → exit 1. */
    @Test
    public void wrongRelatedCertFailsCertIdOrPopCheck() throws Exception {
        // Generate a completely different cert — certID (issuer+serial) will not match
        AlgorithmSet wrongAlgo = new AlgorithmSet("EC:secp256r1");
        KeyPair wrongKP = KeyGenerator.generateKeyPair(wrongAlgo.getAlgorithms());
        java.lang.reflect.Method genCert = CertificateGenerator.class.getDeclaredMethod(
                "generateCertificate",
                AlgorithmSet.class, KeyPair.class, KeyPair.class, String.class, double.class);
        genCert.setAccessible(true);
        X509Certificate wrongCertObj = (X509Certificate) genCert.invoke(
                null, wrongAlgo, wrongKP, null, "CN=WrongCert-Stage4", 1.0);
        File wrongCertFile = writeCertFile(wrongCertObj);

        ByteArrayOutputStream errBuf = new ByteArrayOutputStream();
        PrintStream origErr = System.err;
        System.setErr(new PrintStream(errBuf));
        int exitCode;
        try {
            exitCode = new CommandLine(new SignCommand()).execute(
                    "-csr",           pqcCsrFile.getAbsolutePath(),
                    "-CAcert",        signCaCertFile.getAbsolutePath(),
                    "-CAkey",         signCaKeyFile.getAbsolutePath(),
                    "--related-cert", wrongCertFile.getAbsolutePath()
            );
        } finally {
            System.setErr(origErr);
        }
        assertEquals("Wrong --related-cert must exit 1 (certID mismatch)", 1, exitCode);
        String err = errBuf.toString();
        assertTrue("stderr must mention mismatch or PoP failure; got: " + err,
                err.contains("certID") || err.contains("does not match")
                        || err.contains("PoP") || err.contains("mismatch"));
    }

    /** --related-cert and --related-cert-test-extension cannot be combined → exit 1. */
    @Test
    public void conflictBetweenStage2AndStage4Fails() {
        ByteArrayOutputStream errBuf = new ByteArrayOutputStream();
        PrintStream origErr = System.err;
        System.setErr(new PrintStream(errBuf));
        int exitCode;
        try {
            exitCode = new CommandLine(new SignCommand()).execute(
                    "-csr",                          pqcCsrFile.getAbsolutePath(),
                    "-CAcert",                       signCaCertFile.getAbsolutePath(),
                    "-CAkey",                        signCaKeyFile.getAbsolutePath(),
                    "--related-cert",                refCertFile.getAbsolutePath(),
                    "--related-cert-test-extension", refCertFile.getAbsolutePath()
            );
        } finally {
            System.setErr(origErr);
        }
        assertEquals("Combining Stage 2 and Stage 4 options must exit 1", 1, exitCode);
        String err = errBuf.toString();
        assertTrue("stderr must mention conflict or 'cannot be combined'; got: " + err,
                err.contains("cannot be combined") || err.contains("Stage 4") || err.contains("Stage 2"));
    }

    /** --related-cert with --profile intermediate-ca → exit 1. */
    @Test
    public void nonLeafProfileWithRelatedCertFails() {
        ByteArrayOutputStream errBuf = new ByteArrayOutputStream();
        PrintStream origErr = System.err;
        System.setErr(new PrintStream(errBuf));
        int exitCode;
        try {
            exitCode = new CommandLine(new SignCommand()).execute(
                    "-csr",           pqcCsrFile.getAbsolutePath(),
                    "-CAcert",        signCaCertFile.getAbsolutePath(),
                    "-CAkey",         signCaKeyFile.getAbsolutePath(),
                    "--related-cert", refCertFile.getAbsolutePath(),
                    "--profile",      "intermediate-ca"
            );
        } finally {
            System.setErr(origErr);
        }
        assertEquals("--related-cert with intermediate-ca profile must exit 1", 1, exitCode);
        String err = errBuf.toString();
        assertTrue("stderr must mention leaf/profile/CA restriction; got: " + err,
                err.contains("leaf") || err.contains("profile") || err.contains("CA certificates"));
    }

    // --- File helpers ---

    private static File writeCertFile(X509Certificate cert) throws Exception {
        File f = File.createTempFile("pqcli_s4_cert", ".pem");
        f.deleteOnExit();
        CertificateGenerator.saveCertificateToFile(f.getAbsolutePath(), cert);
        return f;
    }

    private static File writeKeyFile(java.security.PrivateKey key) throws Exception {
        File f = File.createTempFile("pqcli_s4_key", ".pem");
        f.deleteOnExit();
        KeyGenerator.saveKeyToFile(f.getAbsolutePath(), key);
        return f;
    }
}
