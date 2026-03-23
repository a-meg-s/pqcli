package pqcli;

import org.bouncycastle.asn1.pkcs.CertificationRequest;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;

import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

import java.io.FileReader;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.concurrent.Callable;

@Command(name = "sign", description = "Sign a CSR with a CA key to produce a chain-of-trust certificate")
public class SignCommand implements Callable<Integer> {

    @Option(names = {"-csr"}, required = true, description = "PKCS#10 CSR file (PEM)")
    private String csrFile;

    @Option(names = {"-CAcert"}, required = true, description = "CA certificate file (PEM)")
    private String caCertFile;

    @Option(names = {"-CAkey"}, required = true, description = "CA private key file (PEM, PKCS#8 or PKCS#1)")
    private String caKeyFile;

    @Option(names = {"-days", "-d"}, defaultValue = "365",
            description = "Certificate validity in days (default: 365)")
    private int days;

    @Option(names = {"-out", "-o"}, defaultValue = "",
            description = "Output filename prefix (e.g. 'signed' → signed_certificate.pem)")
    private String outPrefix;

    @Option(names = "--timing", defaultValue = "false",
            description = "Print signing timing")
    private boolean printTiming;

    private String prefixed(String name) {
        return outPrefix.isEmpty() ? name : outPrefix + "_" + name;
    }

    @Override
    public Integer call() throws Exception {
        ProviderSetup.setupProvider();
        try {
            // Load CA cert
            X509Certificate caCert = ViewCommand.loadCertificate(caCertFile);

            // Load CA private key (supports PKCS#8 and PKCS#1 via BC PEMParser)
            PrivateKey caPrivateKey;
            try (PEMParser pem = new PEMParser(new FileReader(caKeyFile))) {
                Object obj = pem.readObject();
                JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider("BC");
                if (obj instanceof org.bouncycastle.openssl.PEMKeyPair) {
                    caPrivateKey = converter.getKeyPair((PEMKeyPair) obj).getPrivate();
                } else if (obj instanceof org.bouncycastle.pkcs.PKCS8EncryptedPrivateKeyInfo) {
                    throw new IllegalArgumentException("Encrypted PKCS#8 keys are not supported. Use unencrypted private key.");
                } else if (obj instanceof org.bouncycastle.asn1.pkcs.PrivateKeyInfo) {
                    caPrivateKey = converter.getPrivateKey((org.bouncycastle.asn1.pkcs.PrivateKeyInfo) obj);
                } else {
                    throw new IllegalArgumentException("Unrecognized PEM object type: " + (obj == null ? "null" : obj.getClass().getName()));
                }
            }

            // Load CSR
            PKCS10CertificationRequest csr;
            try (PEMParser pem = new PEMParser(new FileReader(csrFile))) {
                Object obj = pem.readObject();
                if (obj instanceof PKCS10CertificationRequest) {
                    csr = (PKCS10CertificationRequest) obj;
                } else if (obj instanceof CertificationRequest) {
                    csr = new PKCS10CertificationRequest((CertificationRequest) obj);
                } else {
                    throw new IllegalArgumentException("Not a CSR: " + (obj == null ? "null" : obj.getClass().getName()));
                }
            }

            // Derive signing algorithm from CA cert
            String sigAlgo = caCert.getSigAlgName();

            // Build certificate
            long t0 = System.currentTimeMillis();
            Date notBefore = new Date();
            Date notAfter = new Date(notBefore.getTime() + (long) days * 86400000L);

            X500Name issuer = new X500Name(caCert.getSubjectX500Principal().getName("RFC1779"));
            X500Name subject = csr.getSubject();

            X509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
                    issuer,
                    BigInteger.valueOf(System.currentTimeMillis()),
                    notBefore,
                    notAfter,
                    subject,
                    new JcaPEMKeyConverter().setProvider("BC")
                            .getPublicKey(csr.getSubjectPublicKeyInfo())
            );

            ContentSigner signer = new JcaContentSignerBuilder(sigAlgo).setProvider("BC").build(caPrivateKey);
            X509Certificate certificate = new JcaX509CertificateConverter()
                    .setProvider("BC")
                    .getCertificate(certBuilder.build(signer));
            long signMs = System.currentTimeMillis() - t0;

            CertificateGenerator.saveCertificateToFile(prefixed("certificate.pem"), certificate);

            System.out.println("Signed certificate saved successfully!");
            System.out.println("  Subject:    " + subject);
            System.out.println("  Issuer:     " + issuer);
            System.out.println("  Sig Alg:    " + sigAlgo);
            System.out.println("  Valid until:" + notAfter);
            System.out.println("  File:       " + prefixed("certificate.pem"));
            if (printTiming) {
                System.out.println("  Sign time:  " + signMs + " ms");
            }
            System.out.println(certificate);
            return 0;

        } catch (Exception e) {
            System.err.println("Error during signing: " + e.getMessage());
            return 1;
        }
    }
}
