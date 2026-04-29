package pqcli;

import org.junit.Test;

import java.io.File;
import java.io.FileOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.util.List;

import static org.junit.Assert.*;

public class PemBundleParserTest {

    static {
        ProviderSetup.setupProvider();
    }

    @Test
    public void singleCertFile() throws Exception {
        X509Certificate cert = makeSelfSigned("RSA:3072");
        File f = writePemBundle(cert);
        List<X509Certificate> loaded = ViewCommand.loadCertificates(f.getAbsolutePath());
        assertEquals(1, loaded.size());
        assertArrayEquals(cert.getEncoded(), loaded.get(0).getEncoded());
    }

    @Test
    public void multiCertBundle() throws Exception {
        X509Certificate c1 = makeSelfSigned("RSA:3072");
        X509Certificate c2 = makeSelfSigned("EC:secp256r1");
        X509Certificate c3 = makeSelfSigned("ML-DSA:65");
        File f = writePemBundle(c1, c2, c3);
        List<X509Certificate> loaded = ViewCommand.loadCertificates(f.getAbsolutePath());
        assertEquals(3, loaded.size());
        assertArrayEquals(c1.getEncoded(), loaded.get(0).getEncoded());
        assertArrayEquals(c2.getEncoded(), loaded.get(1).getEncoded());
        assertArrayEquals(c3.getEncoded(), loaded.get(2).getEncoded());
    }

    @Test
    public void emptyFileReturnsEmptyList() throws Exception {
        File f = File.createTempFile("empty_bundle", ".pem");
        f.deleteOnExit();
        try (FileOutputStream out = new FileOutputStream(f)) { /* empty */ }
        List<X509Certificate> result = ViewCommand.loadCertificates(f.getAbsolutePath());
        assertTrue("Empty file must return empty list", result.isEmpty());
    }

    @Test
    public void keyFileThrows() throws Exception {
        AlgorithmSet as = new AlgorithmSet("RSA:3072");
        KeyPair kp = KeyGenerator.generateKeyPair(as.getAlgorithms());
        File keyFile = File.createTempFile("rsa_key", ".pem");
        keyFile.deleteOnExit();
        KeyGenerator.saveKeyToFile(keyFile.getAbsolutePath(), kp.getPrivate());
        // BC's CertificateFactory throws CertificateException ("malformed PEM data") for a key file
        try {
            ViewCommand.loadCertificates(keyFile.getAbsolutePath());
            fail("Expected exception for key file");
        } catch (Exception e) {
            // Any exception is acceptable; the call must not silently return certs
        }
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    private static X509Certificate makeSelfSigned(String algo) throws Exception {
        AlgorithmSet as = new AlgorithmSet(algo);
        KeyPair kp = KeyGenerator.generateKeyPair(as.getAlgorithms());
        return CertificateGenerator.generateCertificate(as, kp, null, "CN=Test-" + algo, 1.0);
    }

    static File writePemBundle(X509Certificate... certs) throws Exception {
        File f = File.createTempFile("pem_bundle", ".pem");
        f.deleteOnExit();
        try (FileOutputStream out = new FileOutputStream(f)) {
            for (X509Certificate cert : certs) {
                out.write("-----BEGIN CERTIFICATE-----\n".getBytes(StandardCharsets.US_ASCII));
                out.write(KeyGenerator.wrapBase64(cert.getEncoded()).getBytes(StandardCharsets.US_ASCII));
                out.write("-----END CERTIFICATE-----\n".getBytes(StandardCharsets.US_ASCII));
            }
        }
        return f;
    }
}
