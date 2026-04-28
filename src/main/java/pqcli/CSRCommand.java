package pqcli;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.cms.IssuerAndSerialNumber;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.ContentVerifier;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;

import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.OutputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.concurrent.Callable;

// RFC 2986 (PKCS#10) defines a standard CSR format with one primary subjectPublicKeyInfo,
// one primary outer signature, and an optional attribute field.
//
// Composite CSR: the composite public key encodes into the standard primary
// subjectPublicKeyInfo. Algorithm identifiers and encoding are draft/BC-internal;
// non-BC tooling may not understand the resulting CSR.
//
// Hybrid CSR: Bouncy Castle 1.80 provides a non-standard extended builder path via
// the 3-arg build() method. It injects an alt public key and alt signature into the
// CSR attribute field. This is BC-specific and not defined by RFC 2986 or any
// widely adopted standard. Interoperability with non-BC tooling is not guaranteed.
// Parsers that do not implement this BC extension will ignore the alt content.
@Command(name = "csr", description = "Generate a PKCS#10 certificate signing request", mixinStandardHelpOptions = true)
public class CSRCommand implements Callable<Integer> {

    @Option(names = {"-newkey", "-nk"}, required = true, description = {
        "Key algorithm. Single: RSA:3072, EC:secp256r1, ML-DSA:65, SLH-DSA:128f, Ed25519.",
        "Composite (underscore): RSA:3072_ML-DSA:65.",
        "Hybrid (comma): RSA:3072,ML-DSA:65 (BC-specific encoding, not broadly standardized)."
    })
    private String keyAlgorithm;

    @Option(names = {"-subj", "-subject"}, defaultValue = "CN=PQCLI CSR",
            description = "Subject DN in OpenSSL format (e.g. /CN=Test/C=DE)")
    private String subject;

    @Option(names = {"-out", "-o"}, defaultValue = "",
            description = "Output filename prefix (e.g. 'ee' → ee_csr.pem, ee_private_key.pem)")
    private String outPrefix;

    @Option(names = "--timing", defaultValue = "false",
            description = "Print key generation and CSR signing timing")
    private boolean printTiming;

    @Option(names = "--related-cert",
            description = {
                "RFC 9763 Stage 3: adds relatedCertRequest attribute (OID 1.2.840.113549.1.9.16.2.60) to the CSR.",
                "Requires --related-cert-key and --related-cert-url. Not valid with composite or hybrid CSR."
            })
    private String relatedCertFile;

    @Option(names = "--related-cert-key",
            description = "Private key corresponding to --related-cert. Required when --related-cert is used.")
    private String relatedCertKeyFile;

    @Option(names = "--related-cert-url",
            description = "Single URI identifying the referenced certificate. " +
                "Encoded as IA5String per RFC 9763 body text (Errata ID 8750). " +
                "Required when --related-cert is used.")
    private String relatedCertUrl;

    private String prefixed(String name) {
        return outPrefix.isEmpty() ? name : outPrefix + "_" + name;
    }

    @Override
    public Integer call() throws Exception {
        ProviderSetup.setupProvider();
        try {
            AlgorithmSet algorithmSet = new AlgorithmSet(keyAlgorithm);

            // === Stage 3: validate relatedCertRequest options ===
            boolean anyRelated = relatedCertFile != null || relatedCertKeyFile != null || relatedCertUrl != null;
            boolean allRelated = relatedCertFile != null && relatedCertKeyFile != null && relatedCertUrl != null;
            if (anyRelated && !allRelated) {
                System.err.println("Error: --related-cert, --related-cert-key, and --related-cert-url must all be provided together.");
                System.err.println("       Missing:"
                    + (relatedCertFile    == null ? " --related-cert"     : "")
                    + (relatedCertKeyFile == null ? " --related-cert-key" : "")
                    + (relatedCertUrl     == null ? " --related-cert-url" : ""));
                return 1;
            }
            if (allRelated && (algorithmSet.isHybrid() || algorithmSet.isComposite())) {
                System.err.println("Error: --related-cert is not supported with hybrid or composite CSR in Stage 3.");
                System.err.println("       Use a single-algorithm CSR when adding a relatedCertRequest attribute.");
                return 1;
            }

            // Load and validate referenced cert/key early (fail fast before key generation)
            X509Certificate refCert = null;
            PrivateKey refKey = null;
            X500Name refIssuerName = null;
            BigInteger refSerial = null;
            if (allRelated) {
                try {
                    refCert = ViewCommand.loadCertificate(relatedCertFile);
                } catch (Exception e) {
                    System.err.println("Error loading --related-cert: " + e.getMessage());
                    return 1;
                }
                try {
                    refKey = loadRelatedPrivKey(relatedCertKeyFile);
                } catch (Exception e) {
                    System.err.println("Error loading --related-cert-key: " + e.getMessage());
                    return 1;
                }
                // Verify key correspondence: sign-then-verify over a test message
                String refSigAlgo = SignCommand.deriveSigAlgoFromCaKey(refCert);
                try {
                    ContentSigner testSigner = new JcaContentSignerBuilder(refSigAlgo)
                            .setProvider("BC").build(refKey);
                    testSigner.getOutputStream().write(
                            "pqcli-rc-pop-key-check".getBytes(StandardCharsets.UTF_8));
                    byte[] testSig = testSigner.getSignature();
                    ContentVerifierProvider testCVP = new JcaContentVerifierProviderBuilder()
                            .setProvider("BC").build(refCert.getPublicKey());
                    ContentVerifier cv = testCVP.get(testSigner.getAlgorithmIdentifier());
                    cv.getOutputStream().write(
                            "pqcli-rc-pop-key-check".getBytes(StandardCharsets.UTF_8));
                    if (!cv.verify(testSig)) {
                        System.err.println("Error: --related-cert-key does not correspond to the public key in --related-cert.");
                        return 1;
                    }
                } catch (Exception e) {
                    System.err.println("Error: --related-cert-key does not correspond to the public key in --related-cert: "
                            + e.getMessage());
                    return 1;
                }
                X509CertificateHolder refHolder = new X509CertificateHolder(refCert.getEncoded());
                refIssuerName = refHolder.getIssuer();
                refSerial     = refCert.getSerialNumber();
            }

            String x500Subject = subject.replace('/', ',').replaceAll("^,", "");

            long t0 = System.currentTimeMillis();
            KeyPair keyPair = KeyGenerator.generateKeyPair(algorithmSet.getAlgorithms());
            long keyGenMs = System.currentTimeMillis() - t0;

            JcaPKCS10CertificationRequestBuilder builder =
                    new JcaPKCS10CertificationRequestBuilder(new X500Name(x500Subject), keyPair.getPublic());

            // === Stage 3: build RequesterCertificate and inject relatedCertRequest attribute ===
            if (allRelated) {
                // certID: IssuerAndSerialNumber identifies the referenced certificate
                IssuerAndSerialNumber certID = new IssuerAndSerialNumber(refIssuerName, refSerial);
                // requestTime: BinaryTime (seconds since Unix epoch) as ASN.1 INTEGER
                ASN1Integer requestTime = new ASN1Integer(BigInteger.valueOf(System.currentTimeMillis() / 1000L));
                // locationInfo: single URI as IA5String per RFC 9763 body text (Errata ID 8750)
                DERIA5String locationInfo = new DERIA5String(relatedCertUrl);

                // PoP signature over DER(certID) || DER(requestTime) using the referenced cert's private key
                String popSigAlgo = SignCommand.deriveSigAlgoFromCaKey(refCert);
                byte[] certIdDer    = certID.toASN1Primitive().getEncoded("DER");
                byte[] reqTimeDer   = requestTime.getEncoded("DER");
                byte[] popInput     = new byte[certIdDer.length + reqTimeDer.length];
                System.arraycopy(certIdDer,  0, popInput, 0,                certIdDer.length);
                System.arraycopy(reqTimeDer, 0, popInput, certIdDer.length, reqTimeDer.length);

                ContentSigner popSigner = new JcaContentSignerBuilder(popSigAlgo)
                        .setProvider("BC").build(refKey);
                popSigner.getOutputStream().write(popInput);
                byte[] sigBytes = popSigner.getSignature();

                // RequesterCertificate ::= SEQUENCE { certID, requestTime, locationInfo, signature }
                ASN1EncodableVector v = new ASN1EncodableVector();
                v.add(certID);
                v.add(requestTime);
                v.add(locationInfo);
                v.add(new DERBitString(sigBytes));

                builder.addAttribute(
                        new ASN1ObjectIdentifier("1.2.840.113549.1.9.16.2.60"),
                        new DERSequence(v));
            }

            PKCS10CertificationRequest csr;
            long t1 = System.currentTimeMillis();

            if (algorithmSet.isHybrid()) {
                // Hybrid: generate alt key pair and use BC's 3-arg build() method.
                // The alt public key and alt signature are injected into the PKCS#10 attribute
                // field by BC. This encoding is BC-specific and not broadly standardized.
                KeyPair altKeyPair = KeyGenerator.generateKeyPair(algorithmSet.getAltAlgorithms());
                ContentSigner primarySigner = CertificateGenerator.getSigner(algorithmSet.getAlgorithms(), keyPair);
                ContentSigner altSigner = CertificateGenerator.getSigner(algorithmSet.getAltAlgorithms(), altKeyPair);
                csr = builder.build(primarySigner, altKeyPair.getPublic(), altSigner);

                // Save alt key pair using the same naming convention as CertificateGenerator
                KeyGenerator.saveKeyToFile(prefixed("alt_private_key.pem"), altKeyPair.getPrivate());
                KeyGenerator.saveKeyToFile(prefixed("alt_public_key.pem"), altKeyPair.getPublic());
            } else {
                // Single or composite: getSigner handles both cases.
                // For composite, keyPair contains a CompositePublicKey and getSigner
                // builds a CompositeAlgorithmSpec signer automatically.
                ContentSigner signer = CertificateGenerator.getSigner(algorithmSet.getAlgorithms(), keyPair);
                csr = builder.build(signer);
            }

            long csrGenMs = System.currentTimeMillis() - t1;

            KeyGenerator.saveKeyToFile(prefixed("private_key.pem"), keyPair.getPrivate());
            KeyGenerator.saveKeyToFile(prefixed("public_key.pem"), keyPair.getPublic());
            saveCsrToFile(prefixed("csr.pem"), csr);

            System.out.println("CSR and key saved successfully!");
            System.out.println("  Subject:    " + x500Subject);

            if (algorithmSet.isHybrid()) {
                System.out.println("  Type:       Hybrid CSR");
                System.out.println("  Primary:    " + CertificateGenerator.getSuitableSignatureAlgorithm(algorithmSet.getAlgorithms()[0]));
                System.out.println("  Alt algo:   " + CertificateGenerator.getSuitableSignatureAlgorithm(algorithmSet.getAltAlgorithms()[0]));
                System.out.println("  Files:      " + prefixed("csr.pem") + ", " + prefixed("private_key.pem") + ", " + prefixed("alt_private_key.pem"));
                System.out.println("  NOTE: Hybrid CSR uses BC-specific alt-* attribute encoding.");
                System.out.println("        No widely adopted standard defines this format.");
                System.out.println("        Parsers without BC hybrid support may ignore the alt content.");
            } else if (algorithmSet.isComposite()) {
                System.out.println("  Type:       Composite CSR");
                System.out.println("  Files:      " + prefixed("csr.pem") + ", " + prefixed("private_key.pem"));
                System.out.println("  NOTE: Uses draft-ietf-lamps-pq-composite-sigs named-combination OIDs");
                System.out.println("        (PKIX arc 1.3.6.1.5.5.7.6.*). Draft, not yet RFC.");
            } else {
                System.out.println("  Algorithm:  " + CertificateGenerator.getSuitableSignatureAlgorithm(algorithmSet.getAlgorithms()[0]));
                System.out.println("  Files:      " + prefixed("csr.pem") + ", " + prefixed("private_key.pem"));
            }

            if (allRelated) {
                System.out.println("relatedCertRequest attribute added (RFC 9763 Stage 3)");
                System.out.println("  OID:    1.2.840.113549.1.9.16.2.60");
                System.out.println("  certID: issuer=" + refIssuerName
                        + "  serial=" + refSerial.toString(16).toUpperCase());
                System.out.println("  URI:    " + relatedCertUrl);
                System.out.println("  PoP:    included");
                System.out.println("NOTE: CA-side PoP verification and compliant issuance are Stage 4 and are not implemented in this stage.");
            }
            if (printTiming) {
                System.out.println("  Key gen time: " + keyGenMs + " ms");
                System.out.println("  CSR gen time: " + csrGenMs + " ms");
            }
            return 0;
        } catch (Exception e) {
            System.err.println("Error during CSR generation: " + e.getMessage());
            return 1;
        }
    }

    static void saveCsrToFile(String fileName, PKCS10CertificationRequest csr) throws Exception {
        try (OutputStream os = new FileOutputStream(fileName)) {
            os.write("-----BEGIN CERTIFICATE REQUEST-----\n".getBytes());
            os.write(KeyGenerator.wrapBase64(csr.getEncoded()).getBytes());
            os.write("-----END CERTIFICATE REQUEST-----\n".getBytes());
        }
    }

    private static PrivateKey loadRelatedPrivKey(String keyFile) throws Exception {
        try (PEMParser pem = new PEMParser(new FileReader(keyFile))) {
            Object obj = pem.readObject();
            JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider("BC");
            if (obj instanceof PEMKeyPair) {
                return converter.getKeyPair((PEMKeyPair) obj).getPrivate();
            } else if (obj instanceof org.bouncycastle.pkcs.PKCS8EncryptedPrivateKeyInfo) {
                throw new IllegalArgumentException("Encrypted PKCS#8 keys are not supported. Use unencrypted private key.");
            } else if (obj instanceof org.bouncycastle.asn1.pkcs.PrivateKeyInfo) {
                return converter.getPrivateKey((org.bouncycastle.asn1.pkcs.PrivateKeyInfo) obj);
            }
            throw new IllegalArgumentException("Unrecognized PEM object type: "
                    + (obj == null ? "null" : obj.getClass().getName()));
        }
    }
}
