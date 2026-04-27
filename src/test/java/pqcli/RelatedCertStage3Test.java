package pqcli;

import org.bouncycastle.asn1.ASN1BitString;
import org.bouncycastle.asn1.ASN1IA5String;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.pkcs.Attribute;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.junit.BeforeClass;
import org.junit.Test;
import picocli.CommandLine;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.PrintStream;
import java.nio.file.Files;
import java.security.KeyPair;
import java.security.cert.X509Certificate;

import static org.junit.Assert.*;

/**
 * RFC 9763 Stage 3 tests: relatedCertRequest CSR attribute generation with PoP.
 *
 * Stage 3 creates the CSR attribute only. Stage 4 CA-side parsing, PoP verification,
 * and compliant issuance of the RelatedCertificate extension are NOT implemented yet.
 */
public class RelatedCertStage3Test {

    private static final ASN1ObjectIdentifier OID_RELATED_CERT_REQUEST =
            new ASN1ObjectIdentifier("1.2.840.113549.1.9.16.2.60");

    static {
        ProviderSetup.setupProvider();
    }

    // Shared fixture
    private static File refCertFile;   // RSA cert — the one being referenced
    private static File refKeyFile;    // RSA private key for the referenced cert
    private static PKCS10CertificationRequest csr; // CSR with relatedCertRequest attribute

    @BeforeClass
    public static void buildFixture() throws Exception {
        // 1. Build RSA:3072 self-signed cert (the referenced cert)
        AlgorithmSet caAlgo = new AlgorithmSet("RSA:3072");
        KeyPair caKP = KeyGenerator.generateKeyPair(caAlgo.getAlgorithms());
        java.lang.reflect.Method genCert = CertificateGenerator.class.getDeclaredMethod(
                "generateCertificate",
                AlgorithmSet.class, KeyPair.class, KeyPair.class, String.class, double.class);
        genCert.setAccessible(true);
        X509Certificate refCert = (X509Certificate) genCert.invoke(
                null, caAlgo, caKP, null, "CN=RefCert-Stage3", 1.0);
        refCertFile = writeCertFile(refCert);
        refKeyFile  = writeKeyFile(caKP.getPrivate());

        // 2. Generate a CSR (RSA:3072) with relatedCertRequest pointing at refCert
        File outDir = Files.createTempDirectory("pqcli_rc_s3").toFile();
        int exitCode = new CommandLine(new CSRCommand()).execute(
                "-nk",                "RSA:3072",
                "-subj",              "CN=EE-Stage3",
                "--related-cert",     refCertFile.getAbsolutePath(),
                "--related-cert-key", refKeyFile.getAbsolutePath(),
                "--related-cert-url", "https://example.com/refcert.pem",
                "-out",               new File(outDir, "ee").getAbsolutePath()
        );
        if (exitCode != 0) {
            throw new RuntimeException("@BeforeClass: CSR with relatedCertRequest failed (exit " + exitCode + ")");
        }
        File csrFile = new File(outDir, "ee_csr.pem");
        if (!csrFile.exists()) {
            throw new RuntimeException("@BeforeClass: ee_csr.pem not created");
        }
        csr = loadCsr(csrFile);
    }

    /** The relatedCertRequest attribute OID 1.2.840.113549.1.9.16.2.60 must be present. */
    @Test
    public void relatedCertRequestAttributeIsPresent() {
        Attribute[] attrs = csr.getAttributes(OID_RELATED_CERT_REQUEST);
        assertNotNull("relatedCertRequest attribute (OID 1.2.840.113549.1.9.16.2.60) must be present", attrs);
        assertTrue("Must have at least one attribute value", attrs.length > 0);
    }

    /** RequesterCertificate must be a SEQUENCE with exactly four elements. */
    @Test
    public void requesterCertificateHasFourElements() {
        Attribute[] attrs = csr.getAttributes(OID_RELATED_CERT_REQUEST);
        assertNotNull(attrs);
        ASN1Sequence seq = ASN1Sequence.getInstance(attrs[0].getAttrValues().getObjectAt(0));
        assertEquals("RequesterCertificate SEQUENCE must have exactly 4 elements", 4, seq.size());
    }

    /**
     * locationInfo (element 2) must be a single IA5String, not a SEQUENCE.
     * RFC 9763 body text specifies a single URI; Appendix A is inconsistent
     * and overridden by Errata ID 8750.
     */
    @Test
    public void locationInfoIsIA5StringNotSequence() {
        Attribute[] attrs = csr.getAttributes(OID_RELATED_CERT_REQUEST);
        assertNotNull(attrs);
        ASN1Sequence seq = ASN1Sequence.getInstance(attrs[0].getAttrValues().getObjectAt(0));
        assertFalse("locationInfo must NOT be a SEQUENCE (single URI per RFC body text + Errata 8750)",
                seq.getObjectAt(2) instanceof ASN1Sequence);
        ASN1IA5String uri = ASN1IA5String.getInstance(seq.getObjectAt(2));
        assertNotNull("locationInfo must be an IA5String", uri);
        assertEquals("URI value must match --related-cert-url input",
                "https://example.com/refcert.pem", uri.getString());
    }

    /** Element 3 must be a non-empty BIT STRING (the PoP signature). */
    @Test
    public void signatureElementIsBitStringWithContent() {
        Attribute[] attrs = csr.getAttributes(OID_RELATED_CERT_REQUEST);
        assertNotNull(attrs);
        ASN1Sequence seq = ASN1Sequence.getInstance(attrs[0].getAttrValues().getObjectAt(0));
        ASN1BitString sig = ASN1BitString.getInstance(seq.getObjectAt(3));
        assertNotNull("Element 3 must be a BIT STRING (PoP signature)", sig);
        assertTrue("PoP signature must be non-empty", sig.getBytes().length > 0);
    }

    /** requestTime (element 1) must be an INTEGER (BinaryTime: seconds since epoch). */
    @Test
    public void requestTimeIsInteger() {
        Attribute[] attrs = csr.getAttributes(OID_RELATED_CERT_REQUEST);
        assertNotNull(attrs);
        ASN1Sequence seq = ASN1Sequence.getInstance(attrs[0].getAttrValues().getObjectAt(0));
        ASN1Integer requestTime = ASN1Integer.getInstance(seq.getObjectAt(1));
        assertNotNull("requestTime (element 1) must be an ASN.1 INTEGER (BinaryTime)", requestTime);
        // Sanity: epoch seconds should be a reasonable value (after 2020-01-01 = 1577836800)
        assertTrue("requestTime must be a plausible epoch-seconds value",
                requestTime.getValue().longValue() > 1577836800L);
    }

    /** Providing only --related-cert (missing --related-cert-key and --related-cert-url) must exit 1. */
    @Test
    public void missingRelatedCertKeyAndUrlFails() throws Exception {
        ByteArrayOutputStream errBuf = new ByteArrayOutputStream();
        PrintStream origErr = System.err;
        System.setErr(new PrintStream(errBuf));
        int exitCode;
        try {
            exitCode = new CommandLine(new CSRCommand()).execute(
                    "-nk",           "RSA:3072",
                    "--related-cert", refCertFile.getAbsolutePath()
                    // --related-cert-key and --related-cert-url intentionally absent
            );
        } finally {
            System.setErr(origErr);
        }
        assertEquals("Partial related-cert options must exit 1", 1, exitCode);
        String err = errBuf.toString();
        assertTrue("stderr must mention missing options; got: " + err,
                err.contains("must all be provided") || err.contains("--related-cert-key"));
    }

    /** Providing only --related-cert-key (without --related-cert and --related-cert-url) must exit 1. */
    @Test
    public void onlyRelatedCertKeyFails() throws Exception {
        ByteArrayOutputStream errBuf = new ByteArrayOutputStream();
        PrintStream origErr = System.err;
        System.setErr(new PrintStream(errBuf));
        int exitCode;
        try {
            exitCode = new CommandLine(new CSRCommand()).execute(
                    "-nk",                "RSA:3072",
                    "--related-cert-key", refKeyFile.getAbsolutePath()
                    // --related-cert and --related-cert-url intentionally absent
            );
        } finally {
            System.setErr(origErr);
        }
        assertEquals("Only --related-cert-key without the others must exit 1", 1, exitCode);
        String err = errBuf.toString();
        assertTrue("stderr must mention missing options; got: " + err,
                err.contains("must all be provided") || err.contains("--related-cert"));
    }

    /** Using --related-cert with a hybrid CSR (-nk RSA:3072,ML-DSA:65) must exit 1. */
    @Test
    public void relatedCertWithHybridCsrFails() throws Exception {
        ByteArrayOutputStream errBuf = new ByteArrayOutputStream();
        PrintStream origErr = System.err;
        System.setErr(new PrintStream(errBuf));
        int exitCode;
        try {
            exitCode = new CommandLine(new CSRCommand()).execute(
                    "-nk",                "RSA:3072,ML-DSA:65",
                    "--related-cert",     refCertFile.getAbsolutePath(),
                    "--related-cert-key", refKeyFile.getAbsolutePath(),
                    "--related-cert-url", "https://example.com/cert.pem"
            );
        } finally {
            System.setErr(origErr);
        }
        assertEquals("--related-cert with hybrid CSR must exit 1", 1, exitCode);
        String err = errBuf.toString();
        assertTrue("stderr must mention hybrid restriction; got: " + err,
                err.contains("hybrid") || err.contains("composite") || err.contains("Stage 3"));
    }

    // --- File helpers ---

    private static File writeCertFile(X509Certificate cert) throws Exception {
        File f = File.createTempFile("pqcli_s3_cert", ".pem");
        f.deleteOnExit();
        CertificateGenerator.saveCertificateToFile(f.getAbsolutePath(), cert);
        return f;
    }

    private static File writeKeyFile(java.security.PrivateKey key) throws Exception {
        File f = File.createTempFile("pqcli_s3_key", ".pem");
        f.deleteOnExit();
        KeyGenerator.saveKeyToFile(f.getAbsolutePath(), key);
        return f;
    }

    private static PKCS10CertificationRequest loadCsr(File f) throws Exception {
        try (PEMParser pem = new PEMParser(new FileReader(f))) {
            Object obj = pem.readObject();
            if (obj instanceof PKCS10CertificationRequest) return (PKCS10CertificationRequest) obj;
            if (obj instanceof org.bouncycastle.asn1.pkcs.CertificationRequest)
                return new PKCS10CertificationRequest(
                        (org.bouncycastle.asn1.pkcs.CertificationRequest) obj);
            throw new IllegalArgumentException("Not a CSR: " + (obj == null ? "null" : obj.getClass().getName()));
        }
    }
}
