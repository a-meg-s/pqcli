package pqcli;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.SubjectAltPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jcajce.CompositePrivateKey;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.concurrent.Callable;
import java.util.Date;
import java.util.regex.*;

@Command(name="cert", description="Generates an X.509 v3 certificate with a public/private key pair")
public class CertificateGenerator implements Callable<Integer> {

    @Option(names = { "-sig", "-s" }, description = "Signature algorithm override. Auto-derived from key algorithm if omitted.")
    private String signatureAlgorithm;

    @Option(names = { "-newkey", "-nk" }, required = true, description = {
        "Key algorithm. Single: RSA:3072, EC:secp256r1, DSA:2048, Ed25519, Ed448,",
        "  ML-DSA:44/65/87, SLH-DSA:128s/128f/192s/192f/256s/256f,",
        "  SLH-DSA:shake-128s/shake-128f/shake-192s/shake-192f/shake-256s/shake-256f.",
        "  Hybrid (comma): RSA:3072,ML-DSA:65.  Composite (underscore): RSA:3072_ML-DSA:65."
    })
    private String keyAlgorithm;

    @Option(names = { "-days", "-d" }, description = "Certificate validity in days", required = false, defaultValue = "365")
    private String validityDays;

    @Option(names = { "-subj", "-subject" }, description = "Certificate subject in OpenSSL format", required = false, defaultValue = "CN=PQCLI Test Certificate, C=DE")
    private String subject;

    @Option(names = { "-out", "-o" }, description = "Output filename prefix (e.g. 'rsa3072' → rsa3072_certificate.pem)", defaultValue = "")
    private String outPrefix;

    @Option(names = "--timing", description = "Print key generation and certificate signing timing", defaultValue = "false")
    private boolean printTiming;

    private String prefixed(String name) {
        return outPrefix.isEmpty() ? name : outPrefix + "_" + name;
    }

	//public static void main(String[] args) {
    public Integer call() throws Exception {
        ProviderSetup.setupProvider();
        try {
            double validityDaysD = 0;
            try {
                validityDaysD = Double.parseDouble(validityDays);
            }
            finally {
                if (validityDaysD < 0.04) {
                    System.err.println("Error: Invalid validity period specified! Must be at least 0.04 days.");
                    return 1;
                }
            }
            subject = dnOpensslToX500(subject);

            AlgorithmSet algorithmSet = new AlgorithmSet(keyAlgorithm);

            // Generate key pair(s) for the public key(s) of the certificate
            long t0 = System.currentTimeMillis();
            KeyPair keyPair = KeyGenerator.generateKeyPair(algorithmSet.getAlgorithms());
            long keyGenMs = System.currentTimeMillis() - t0;

            KeyPair altKeyPair = null;
            if (algorithmSet.isHybrid()) {
                altKeyPair = KeyGenerator.generateKeyPair(algorithmSet.getAltAlgorithms());
            }

            // Always self-signed. -sig is reserved for a future non-self-signed path but has no effect currently.
            KeyPair signatureKeyPair = keyPair;
            KeyPair altSignatureKeyPair = algorithmSet.isHybrid() ? altKeyPair : null;
            AlgorithmSet signatureAlgorithmSet = algorithmSet;

            // Create X.509 certificate
            long t1 = System.currentTimeMillis();
            X509Certificate certificate;
            certificate = generateCertificate(signatureAlgorithmSet, signatureKeyPair, altSignatureKeyPair, subject, validityDaysD);
            long certGenMs = System.currentTimeMillis() - t1;

            // Save certificate and key(s) to files
            KeyGenerator.saveKeyToFile(prefixed("private_key.pem"), keyPair.getPrivate());
            KeyGenerator.saveKeyToFile(prefixed("public_key.pem"), keyPair.getPublic());
            if (algorithmSet.isHybrid()) {
                KeyGenerator.saveKeyToFile(prefixed("alt_private_key.pem"), altKeyPair.getPrivate());
                KeyGenerator.saveKeyToFile(prefixed("alt_public_key.pem"), altKeyPair.getPublic());
            }
            saveCertificateToFile(prefixed("certificate.pem"), certificate);

            System.out.println("Certificate and key saved successfully!");
            System.out.println("  Subject:    " + certificate.getSubjectX500Principal().getName());
            System.out.println("  Algorithm:  " + certificate.getSigAlgName());
            System.out.println("  Valid until:" + certificate.getNotAfter());
            if (printTiming) {
                System.out.println("  Key gen time:  " + keyGenMs + " ms");
                System.out.println("  Cert gen time: " + certGenMs + " ms");
            }
            System.out.println();
            System.out.println(certificate);

        } catch (Exception e) {
            System.err.println("Error during certificate generation: " + e.getMessage());
            e.printStackTrace();
            return 1;
        }
        return 0;
	}
	
	static String getSuitableSignatureAlgorithm(AlgorithmWithParameters keyAlgorithm) {
        String name = keyAlgorithm.algorithm;
        String params = keyAlgorithm.keySizeOrCurve;

        if (name.contains("rsa")) {
            boolean rsaPss = false;
            if (params.endsWith("-pss")) {
                rsaPss = true;
                params = params.substring(0, params.length() - 4);
            }
            String sigAlgo = "SHA256withRSA";
            int keySize = Integer.parseInt(params);
            if (keySize >= 4096) {
                sigAlgo = "SHA512withRSA";
            } else if (keySize >= 3072) {
                sigAlgo = "SHA384withRSA";
            }
            if (rsaPss) sigAlgo = sigAlgo + "andMGF1";
            return sigAlgo;
        } else if (name.contains("ec")) {
            int curveSize = 256;

            // This simply takes the first number in the curve name as the curve size
            // which should be fine for all common curves but is technically hacky
            Pattern pattern = Pattern.compile("\\d+"); // One or more digits
            Matcher matcher = pattern.matcher(params);
            if (matcher.find()) {
                curveSize = Integer.parseInt(matcher.group());
            }

            // RFC 5656 section 6.2.1:
            if (curveSize > 384) {
                return "SHA512withECDSA";
            } else if (curveSize > 256) {
                return "SHA384withECDSA";
            }
            return "SHA256withECDSA";
        } else if (name.contains("ed25519")) {
            return "Ed25519";
        } else if (name.contains("ed448")) {
            return "Ed448";
        } else if (name.contains("dilithium-bcpqc")) {
            throw new IllegalArgumentException("Signature with BCPQC Dilithium key no longer supported, use ML-DSA.");
            //return "Dilithium"; // BC 1.79+ uses this as an alias for ML-DSA, that however does not recognize the Dilithium private key
        } else if (name.contains("mldsa")) {
            return "ML-DSA-" + params;
        } else if (name.contains("slh-dsa")) {
            if (params.startsWith("shake-")) {
                return "SLH-DSA-SHAKE-" + params.substring(6);
            }
            return "SLH-DSA-SHA2-" + params;
        } else if (name.contains("dsa")) { // ensure DSA is last as to not match ML-DSA or ECDSA etc.
            return "SHA256withDSA";
        }

        throw new IllegalArgumentException("No signature algorithm known for key algorithm: " + name);
    }


    /**
     * Generate a self-signed X.509 certificate.
     */
    static X509Certificate generateCertificate(AlgorithmSet algorithmSet, KeyPair keyPair, KeyPair altKeyPair,
                                               String subject, double validityDays)
            throws Exception {

        /* Certificate fields */
        X500Name subjectName;
        try {
            subjectName = new X500Name(subject);
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("Invalid subject name: " + e.getMessage());
        }
        X500Name issuerName = subjectName;
        BigInteger serialNumber = generateSerial();
        Date notBefore = new Date(System.currentTimeMillis() - 24 * 60 * 60 * 1000); // Current time - 1 day
        Date notAfter = new Date(System.currentTimeMillis() + 1000L * (long)(validityDays * 60.0 * 60.0 * 24.0)); // Current time + validityDays

        /* Subject Public Key */
        X509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
                issuerName, serialNumber, notBefore, notAfter, subjectName, keyPair.getPublic());

        // Add SubjectAltPublicKeyInfo extension for the alternative public key
        if (altKeyPair != null) {
            SubjectAltPublicKeyInfo altKeyInfo = SubjectAltPublicKeyInfo.getInstance(altKeyPair.getPublic().getEncoded());
            certBuilder.addExtension(org.bouncycastle.asn1.x509.Extension.subjectAltPublicKeyInfo, false, altKeyInfo);
        }

        /* Extensions */
        certBuilder.addExtension(org.bouncycastle.asn1.x509.Extension.basicConstraints, true, new BasicConstraints(true));
        certBuilder.addExtension(org.bouncycastle.asn1.x509.Extension.keyUsage, true, new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign));
        JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();
        certBuilder.addExtension(org.bouncycastle.asn1.x509.Extension.subjectKeyIdentifier, false,
                extUtils.createSubjectKeyIdentifier(keyPair.getPublic()));
        // Self-signed: AKID keyIdentifier = own public key hash (same as SKID)
        certBuilder.addExtension(org.bouncycastle.asn1.x509.Extension.authorityKeyIdentifier, false,
                extUtils.createAuthorityKeyIdentifier(
                        org.bouncycastle.asn1.x509.SubjectPublicKeyInfo.getInstance(keyPair.getPublic().getEncoded())));

        /* Signing */
        ContentSigner contentSigner = getSigner(algorithmSet.getAlgorithms(), keyPair);
        
        X509CertificateHolder certHolder;
        if (altKeyPair != null && algorithmSet.isHybrid()) { // alternative signature algorithm is given
            ContentSigner altContentSigner = getSigner(algorithmSet.getAltAlgorithms(), altKeyPair);
            certHolder = certBuilder.build(contentSigner, false, altContentSigner);
        } else {
            certHolder = certBuilder.build(contentSigner);
        }

        return new JcaX509CertificateConverter().setProvider("BC").getCertificate(certHolder);
    }

    /**
     * Generate a self-signed X.509 certificate with a single signature algorithm.
     */
    private static X509Certificate generateCertificate(AlgorithmSet algorithmSet, KeyPair keyPair, String subject, double validityDays) throws Exception {
        return generateCertificate(algorithmSet, keyPair, null, subject, validityDays);
    }

    static ContentSigner getSigner(AlgorithmWithParameters[] algos, KeyPair signingPair)
            throws OperatorCreationException {
        if (algos == null || algos.length == 0) {
            throw new IllegalArgumentException("No signature algorithm specified");
        }
        if (algos.length == 1) {
            String sigAlgo = getSuitableSignatureAlgorithm(algos[0]);
            return new JcaContentSignerBuilder(sigAlgo).setProvider("BC").build(signingPair.getPrivate());
        }
        // length > 1: composite signature — use named-combination path.
        // BC 1.84 named signer emits PKIX-arc OIDs (1.3.6.1.5.5.7.6.*) for supported combos.
        String namedCombo = AlgorithmSet.resolveNamedComposite(algos);
        if (namedCombo == null) {
            throw new IllegalArgumentException(
                "Unsupported composite combination for signing. " +
                "Only draft-ietf-lamps-pq-composite-sigs named combinations are supported.");
        }
        if (!(signingPair.getPrivate() instanceof CompositePrivateKey)) {
            throw new IllegalArgumentException("Composite signing requires a CompositePrivateKey");
        }
        return new JcaContentSignerBuilder(namedCombo).setProvider("BC").build(signingPair.getPrivate());
    }

    static void saveCertificateToFile(String fileName, X509Certificate certificate) throws IOException, CertificateEncodingException {
        try (OutputStream os = new FileOutputStream(fileName)) {
            os.write(("-----BEGIN CERTIFICATE-----\n").getBytes());
            os.write(KeyGenerator.wrapBase64(certificate.getEncoded()).getBytes());
            os.write(("-----END CERTIFICATE-----\n").getBytes());
        }
    }

    /**
     * Generates a positive non-zero random serial number with 128 bits of entropy.
     * RFC 5280 §4.1.2.2: serial must be positive, ≤ 20 octets DER-encoded.
     * BigInteger(128, rng) is non-negative; the loop excludes zero (probability 1/2^128).
     * Maximum value 2^128-1 encodes as 17 bytes (with DER leading 0x00), within the 20-octet limit.
     */
    static BigInteger generateSerial() {
        SecureRandom rng = new SecureRandom();
        BigInteger s;
        do {
            s = new BigInteger(128, rng);
        } while (s.signum() == 0);
        return s;
    }

    /**
     * Build a RelatedCertificate extension (OID 1.3.6.1.5.5.7.1.36, RFC 9763) containing
     * a hash of the DER encoding of {@code relatedCert}.
     *
     * This is a TEST-MODE helper. The resulting extension carries only a hash binding.
     * No relatedCertRequest PoP has been verified. Do NOT claim RFC 9763-compliant
     * issuance when using this helper without Stage 4 CA-side PoP verification.
     *
     * Supported hashAlg values: "SHA-256" (OID 2.16.840.1.101.3.4.2.1),
     *                            "SHA-384" (OID 2.16.840.1.101.3.4.2.2).
     */
    static Extension buildRelatedCertExtension(java.security.cert.X509Certificate relatedCert,
                                               String hashAlg) throws Exception {
        ASN1ObjectIdentifier hashAlgOid;
        switch (hashAlg.toUpperCase().replace("-", "")) {
            case "SHA256": hashAlgOid = new ASN1ObjectIdentifier("2.16.840.1.101.3.4.2.1"); break;
            case "SHA384": hashAlgOid = new ASN1ObjectIdentifier("2.16.840.1.101.3.4.2.2"); break;
            default:
                throw new IllegalArgumentException(
                    "Unsupported hash algorithm for RelatedCertificate extension: " + hashAlg
                    + ". Supported: SHA-256, SHA-384.");
        }
        byte[] hashValue = MessageDigest.getInstance(hashAlg).digest(relatedCert.getEncoded());
        ASN1EncodableVector seq = new ASN1EncodableVector();
        seq.add(new AlgorithmIdentifier(hashAlgOid));
        seq.add(new DEROctetString(hashValue));
        return new Extension(
            new ASN1ObjectIdentifier("1.3.6.1.5.5.7.1.36"),
            false,
            new DERSequence(seq).getEncoded()
        );
    }

    // Convert OpenSSL DN (/CN=Test/C=DE) to X.500 format (CN=Test,C=DE)
    private static String dnOpensslToX500(String dn) {
        String x500Dn = dn.replace('/', ',');
        x500Dn = x500Dn.trim();
        // remove leading comma
        if (x500Dn.startsWith(",")) {
            x500Dn = x500Dn.substring(1);
        }
        return x500Dn;
    }
}
