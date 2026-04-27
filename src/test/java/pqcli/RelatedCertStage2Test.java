package pqcli;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.cert.X509CertificateHolder;
import org.junit.BeforeClass;
import org.junit.Test;
import picocli.CommandLine;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.PrintStream;
import java.nio.file.Files;
import java.security.KeyPair;
import java.security.cert.X509Certificate;

import static org.junit.Assert.*;

/**
 * RFC 9763 Stage 2 tests: RelatedCertificate test-mode extension generation and hash-binding check.
 *
 * Stage 2 is NOT RFC 9763-compliant issuance — no relatedCertRequest PoP is verified.
 * These tests cover the --related-cert-test-extension (sign) and --related-cert (verify) paths only.
 */
public class RelatedCertStage2Test {

    private static final ASN1ObjectIdentifier OID_RELATED_CERT =
            new ASN1ObjectIdentifier("1.3.6.1.5.5.7.1.36");

    static {
        ProviderSetup.setupProvider();
    }

    // Shared fixture: RSA CA cert + PQC EE cert with RelatedCertificate extension
    private static File rsaCaCertFile;
    private static File rsaCaKeyFile;
    private static File pqcEeCertFile;

    @BeforeClass
    public static void buildFixture() throws Exception {
        // 1. Build RSA:3072 self-signed CA cert
        AlgorithmSet caAlgo = new AlgorithmSet("RSA:3072");
        KeyPair caKeyPair = KeyGenerator.generateKeyPair(caAlgo.getAlgorithms());
        java.lang.reflect.Method genCert = CertificateGenerator.class.getDeclaredMethod(
                "generateCertificate",
                AlgorithmSet.class, KeyPair.class, KeyPair.class, String.class, double.class);
        genCert.setAccessible(true);
        X509Certificate caCert = (X509Certificate) genCert.invoke(
                null, caAlgo, caKeyPair, null, "CN=TestCA-Stage2", 1.0);
        rsaCaCertFile = writeCertFile(caCert);
        rsaCaKeyFile  = writeKeyFile(caKeyPair.getPrivate());

        // 2. Build ML-DSA:65 CSR
        AlgorithmSet eeAlgo = new AlgorithmSet("ML-DSA:65");
        KeyPair eeKeyPair = KeyGenerator.generateKeyPair(eeAlgo.getAlgorithms());
        String eeSigAlgo = CertificateGenerator.getSuitableSignatureAlgorithm(eeAlgo.getAlgorithms()[0]);
        org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder csrBuilder =
                new org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder(
                        new org.bouncycastle.asn1.x500.X500Name("CN=PQC-EE-Stage2"),
                        eeKeyPair.getPublic());
        org.bouncycastle.operator.ContentSigner eeSigner =
                new org.bouncycastle.operator.jcajce.JcaContentSignerBuilder(eeSigAlgo)
                        .setProvider("BC").build(eeKeyPair.getPrivate());
        org.bouncycastle.pkcs.PKCS10CertificationRequest eeCsr = csrBuilder.build(eeSigner);
        File eeCsrFile = writeCsrFile(eeCsr);

        // 3. Sign EE cert with --related-cert-test-extension pointing at the RSA CA cert
        File outDir = Files.createTempDirectory("pqcli_rc_stage2").toFile();
        int exitCode = new CommandLine(new SignCommand()).execute(
                "-csr",    eeCsrFile.getAbsolutePath(),
                "-CAcert", rsaCaCertFile.getAbsolutePath(),
                "-CAkey",  rsaCaKeyFile.getAbsolutePath(),
                "--related-cert-test-extension", rsaCaCertFile.getAbsolutePath(),
                "-out",    new File(outDir, "pqc_ee").getAbsolutePath()
        );
        if (exitCode != 0) {
            throw new RuntimeException("@BeforeClass: sign --related-cert-test-extension failed (exit " + exitCode + ")");
        }
        pqcEeCertFile = new File(outDir, "pqc_ee_certificate.pem");
        if (!pqcEeCertFile.exists()) {
            throw new RuntimeException("@BeforeClass: pqc_ee_certificate.pem not created");
        }
    }

    /** Issued PQC EE cert must carry the RelatedCertificate extension OID 1.3.6.1.5.5.7.1.36. */
    @Test
    public void issuedCertHasRelatedCertExtension() throws Exception {
        X509Certificate cert = ViewCommand.loadCertificate(pqcEeCertFile.getAbsolutePath());
        X509CertificateHolder holder = new X509CertificateHolder(cert.getEncoded());
        assertNotNull("RelatedCertificate extension (OID 1.3.6.1.5.5.7.1.36) must be present",
                holder.getExtensions().getExtension(OID_RELATED_CERT));
    }

    /** verify --related-cert against the correct referenced cert must exit 0. */
    @Test
    public void hashBindingVerifiesOk() {
        int exitCode = new CommandLine(new VerifyCommand()).execute(
                "-in",            pqcEeCertFile.getAbsolutePath(),
                "--related-cert", rsaCaCertFile.getAbsolutePath()
        );
        assertEquals("Binding check against the correct cert must exit 0", 0, exitCode);
    }

    /** verify --related-cert against a different cert must exit 1 (hash mismatch). */
    @Test
    public void hashBindingFailsForWrongCert() throws Exception {
        // Build a different cert (EC key → different DER → different hash)
        AlgorithmSet otherAlgo = new AlgorithmSet("EC:secp256r1");
        KeyPair otherKey = KeyGenerator.generateKeyPair(otherAlgo.getAlgorithms());
        java.lang.reflect.Method genCert = CertificateGenerator.class.getDeclaredMethod(
                "generateCertificate",
                AlgorithmSet.class, KeyPair.class, KeyPair.class, String.class, double.class);
        genCert.setAccessible(true);
        X509Certificate otherCert = (X509Certificate) genCert.invoke(
                null, otherAlgo, otherKey, null, "CN=OtherCert-Stage2", 1.0);
        File otherCertFile = writeCertFile(otherCert);

        int exitCode = new CommandLine(new VerifyCommand()).execute(
                "-in",            pqcEeCertFile.getAbsolutePath(),
                "--related-cert", otherCertFile.getAbsolutePath()
        );
        assertEquals("Binding check against a different cert must exit 1", 1, exitCode);
    }

    /** --related-cert-test-extension must be rejected for intermediate-ca profile (EE-only rule). */
    @Test
    public void testExtensionRejectedForIntermediateCaProfile() throws Exception {
        AlgorithmSet eeAlgo = new AlgorithmSet("ML-DSA:65");
        KeyPair eeKeyPair = KeyGenerator.generateKeyPair(eeAlgo.getAlgorithms());
        String eeSigAlgo = CertificateGenerator.getSuitableSignatureAlgorithm(eeAlgo.getAlgorithms()[0]);
        org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder csrBuilder =
                new org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder(
                        new org.bouncycastle.asn1.x500.X500Name("CN=ShouldFail-Stage2"),
                        eeKeyPair.getPublic());
        org.bouncycastle.operator.ContentSigner eeSigner =
                new org.bouncycastle.operator.jcajce.JcaContentSignerBuilder(eeSigAlgo)
                        .setProvider("BC").build(eeKeyPair.getPrivate());
        File csrFile = writeCsrFile(csrBuilder.build(eeSigner));

        ByteArrayOutputStream errBuf = new ByteArrayOutputStream();
        PrintStream origErr = System.err;
        System.setErr(new PrintStream(errBuf));
        int exitCode;
        try {
            exitCode = new CommandLine(new SignCommand()).execute(
                    "-csr",    csrFile.getAbsolutePath(),
                    "-CAcert", rsaCaCertFile.getAbsolutePath(),
                    "-CAkey",  rsaCaKeyFile.getAbsolutePath(),
                    "--profile", "intermediate-ca",
                    "--related-cert-test-extension", rsaCaCertFile.getAbsolutePath()
            );
        } finally {
            System.setErr(origErr);
        }
        assertEquals("sign must exit 1 when --related-cert-test-extension is used with intermediate-ca profile",
                1, exitCode);
        String err = errBuf.toString();
        assertTrue("stderr must mention leaf or CA restriction; got: " + err,
                err.contains("leaf") || err.contains("end-entity") || err.contains("CA certificates"));
    }

    // --- File helpers ---

    private static File writeCertFile(X509Certificate cert) throws Exception {
        File f = File.createTempFile("pqcli_rc2_cert", ".pem");
        f.deleteOnExit();
        CertificateGenerator.saveCertificateToFile(f.getAbsolutePath(), cert);
        return f;
    }

    private static File writeKeyFile(java.security.PrivateKey key) throws Exception {
        File f = File.createTempFile("pqcli_rc2_key", ".pem");
        f.deleteOnExit();
        KeyGenerator.saveKeyToFile(f.getAbsolutePath(), key);
        return f;
    }

    private static File writeCsrFile(org.bouncycastle.pkcs.PKCS10CertificationRequest csr) throws Exception {
        File f = File.createTempFile("pqcli_rc2_csr", ".pem");
        f.deleteOnExit();
        try (FileOutputStream os = new FileOutputStream(f)) {
            os.write("-----BEGIN CERTIFICATE REQUEST-----\n".getBytes());
            os.write(KeyGenerator.wrapBase64(csr.getEncoded()).getBytes());
            os.write("-----END CERTIFICATE REQUEST-----\n".getBytes());
        }
        return f;
    }
}
