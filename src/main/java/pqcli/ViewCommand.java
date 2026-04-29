package pqcli;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.SubjectAltPublicKeyInfo;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.jcajce.CompositePublicKey;

import picocli.CommandLine.Command;
import picocli.CommandLine.Option;
import picocli.CommandLine.Parameters;

import java.io.ByteArrayInputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collection;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.stream.Collectors;

@Command(name = "view", description = "Display structured details of an X.509 certificate (subject, issuer, public key, extensions, OIDs)",
    mixinStandardHelpOptions = true)
public class ViewCommand implements Callable<Integer> {
    @Parameters(index = "0", description = "Certificate file to view (PEM)")
    private String certificateFile;

    @Option(names = "--full",
            description = "Also print the full raw Bouncy Castle certificate dump after the structured view.")
    private boolean fullDump;

    @Override
    public Integer call() {
        ProviderSetup.setupProvider();
        try {
            X509Certificate cert = loadCertificate(certificateFile);
            X509CertificateHolder holder = new X509CertificateHolder(cert.getEncoded());
            printCertInfo(cert, holder);
            if (fullDump) {
                System.out.println();
                System.out.println("--- Full Certificate Dump ---");
                System.out.println(cert);
            }
        } catch (Exception e) {
            System.err.println("Error during certificate loading: " + e.getMessage());
            return 1;
        }
        return 0;
    }

    private static void printCertInfo(X509Certificate cert, X509CertificateHolder holder) {
        SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss z");

        System.out.println("=== Certificate ===");
        System.out.println("Subject:     " + cert.getSubjectX500Principal().getName());
        System.out.println("Issuer:      " + cert.getIssuerX500Principal().getName());
        System.out.println("Serial:      " + cert.getSerialNumber().toString(16).toUpperCase());
        System.out.println("Not Before:  " + sdf.format(cert.getNotBefore()));
        System.out.println("Not After:   " + sdf.format(cert.getNotAfter()));

        String sigAlgOid = cert.getSigAlgOID();
        System.out.println("Sig Alg:     " + oidToName(sigAlgOid) + "  (OID: " + sigAlgOid + ")");

        System.out.println();
        System.out.println("--- Public Key ---");
        printPublicKeyInfo(cert.getPublicKey(), holder.getSubjectPublicKeyInfo());

        Extensions extensions = holder.getExtensions();
        if (extensions != null) {
            ASN1ObjectIdentifier[] oids = extensions.getExtensionOIDs();
            if (oids != null && oids.length > 0) {
                System.out.println();
                System.out.println("--- Extensions (" + oids.length + ") ---");
                for (ASN1ObjectIdentifier oid : oids) {
                    Extension ext = extensions.getExtension(oid);
                    String marker = ext.isCritical() ? "[critical]" : "[        ]";
                    printExtension(marker, oid, ext, cert);
                }
            }
        }
    }

    private static void printPublicKeyInfo(PublicKey publicKey, SubjectPublicKeyInfo spki) {
        if (publicKey instanceof CompositePublicKey) {
            CompositePublicKey compositeKey = (CompositePublicKey) publicKey;
            String compOid = spki.getAlgorithm().getAlgorithm().getId();
            System.out.println("  Type:       Composite  (OID: " + compOid + ")");
            List<PublicKey> components = compositeKey.getPublicKeys();
            System.out.println("  Components: " + components.size());
            for (int i = 0; i < components.size(); i++) {
                PublicKey comp = components.get(i);
                System.out.println("    [" + i + "] " + comp.getAlgorithm() + "  — " + keyDetails(comp));
            }
        } else {
            String algoOid = spki.getAlgorithm().getAlgorithm().getId();
            System.out.println("  Algorithm:  " + oidToName(algoOid) + "  (OID: " + algoOid + ")");
            System.out.println("  Details:    " + keyDetails(publicKey));
        }
    }

    private static String keyDetails(PublicKey key) {
        if (key instanceof RSAPublicKey) {
            return ((RSAPublicKey) key).getModulus().bitLength() + " bits";
        }
        if (key instanceof ECPublicKey) {
            ECPublicKey ecKey = (ECPublicKey) key;
            if (ecKey.getParams() instanceof org.bouncycastle.jce.spec.ECNamedCurveSpec) {
                return "curve=" + ((org.bouncycastle.jce.spec.ECNamedCurveSpec) ecKey.getParams()).getName();
            }
            return "~" + ecKey.getW().getAffineX().bitLength() + " bits";
        }
        // PQC / unknown: show encoded length as rough indicator
        byte[] enc = key.getEncoded();
        return "encoded " + (enc != null ? enc.length : "?") + " bytes";
    }

    private static void printExtension(String marker, ASN1ObjectIdentifier oid, Extension ext, X509Certificate cert) {
        if (oid.equals(Extension.basicConstraints)) {
            String decoded;
            try {
                decoded = "CA:" + BasicConstraints.getInstance(ext.getParsedValue()).isCA();
            } catch (Exception e) {
                decoded = "(parse error)";
            }
            System.out.println(marker + " Basic Constraints: " + decoded);

        } else if (oid.equals(Extension.keyUsage)) {
            System.out.println(marker + " Key Usage: " + decodeKeyUsage(cert));

        } else if (oid.equals(Extension.subjectAltPublicKeyInfo)) {
            System.out.println(marker + " Subject Alt Public Key Info  (OID: " + oid.getId() + ")");
            try {
                SubjectAltPublicKeyInfo altKeyInfo = SubjectAltPublicKeyInfo.getInstance(ext.getParsedValue());
                AlgorithmIdentifier algoId = altKeyInfo.getAlgorithm();
                String algoOid = algoId.getAlgorithm().getId();
                System.out.println("             Algorithm: " + oidToName(algoOid) + "  (OID: " + algoOid + ")");
            } catch (Exception e) {
                System.out.println("             (parse error: " + e.getMessage() + ")");
            }

        } else if (oid.equals(Extension.altSignatureAlgorithm)) {
            System.out.println(marker + " Alt Signature Algorithm  (OID: " + oid.getId() + ")");
            try {
                AlgorithmIdentifier algoId = AlgorithmIdentifier.getInstance(ext.getParsedValue());
                String algoOid = algoId.getAlgorithm().getId();
                System.out.println("             Algorithm: " + oidToName(algoOid) + "  (OID: " + algoOid + ")");
            } catch (Exception e) {
                System.out.println("             (parse error: " + e.getMessage() + ")");
            }

        } else if (oid.equals(Extension.altSignatureValue)) {
            System.out.println(marker + " Alt Signature Value  (OID: " + oid.getId() + ")");

        } else if (oid.getId().equals("1.3.6.1.5.5.7.1.36")) {
            // RFC 9763: RelatedCertificate ::= SEQUENCE { hashAlgorithm DigestAlgorithmIdentifier, hashValue OCTET STRING }
            System.out.println(marker + " Related Certificate (RFC 9763 id-pe-relatedCert)  (OID: " + oid.getId() + ")");
            try {
                ASN1Sequence seq = ASN1Sequence.getInstance(ext.getParsedValue());
                AlgorithmIdentifier hashAlg = AlgorithmIdentifier.getInstance(seq.getObjectAt(0));
                byte[] hashValue = ASN1OctetString.getInstance(seq.getObjectAt(1)).getOctets();
                String algOid = hashAlg.getAlgorithm().getId();
                System.out.println("             Hash Alg:  " + oidToName(algOid) + "  (OID: " + algOid + ")");
                System.out.println("             Hash:       " + bytesToHex(hashValue) + "  (" + hashValue.length + " bytes)");
            } catch (Exception e) {
                System.out.println("             (parse error: " + e.getMessage() + ")");
            }

        } else {
            System.out.println(marker + " " + oidToName(oid.getId()) + "  (OID: " + oid.getId() + ")");
        }
    }

    private static String decodeKeyUsage(X509Certificate cert) {
        boolean[] usage = cert.getKeyUsage();
        if (usage == null) return "(none)";
        String[] names = {
            "digitalSignature", "nonRepudiation", "keyEncipherment",
            "dataEncipherment", "keyAgreement", "keyCertSign",
            "cRLSign", "encipherOnly", "decipherOnly"
        };
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < usage.length && i < names.length; i++) {
            if (usage[i]) {
                if (sb.length() > 0) sb.append(", ");
                sb.append(names[i]);
            }
        }
        return sb.length() > 0 ? sb.toString() : "(none)";
    }

    /** Resolve well-known OIDs to human-readable algorithm names. */
    static String oidToName(String oid) {
        switch (oid) {
            // RSA key / sig
            case "1.2.840.113549.1.1.1":  return "RSA";
            case "1.2.840.113549.1.1.11": return "SHA256withRSA";
            case "1.2.840.113549.1.1.12": return "SHA384withRSA";
            case "1.2.840.113549.1.1.13": return "SHA512withRSA";
            // ECDSA
            case "1.2.840.10045.2.1":     return "EC";
            case "1.2.840.10045.4.3.2":   return "SHA256withECDSA";
            case "1.2.840.10045.4.3.3":   return "SHA384withECDSA";
            case "1.2.840.10045.4.3.4":   return "SHA512withECDSA";
            // EdDSA
            case "1.3.101.112":           return "Ed25519";
            case "1.3.101.113":           return "Ed448";
            // ML-DSA (FIPS 204, NIST final)
            case "2.16.840.1.101.3.4.3.17": return "ML-DSA-44";
            case "2.16.840.1.101.3.4.3.18": return "ML-DSA-65";
            case "2.16.840.1.101.3.4.3.19": return "ML-DSA-87";
            // SLH-DSA SHA2 (FIPS 205)
            case "2.16.840.1.101.3.4.3.20": return "SLH-DSA-SHA2-128s";
            case "2.16.840.1.101.3.4.3.21": return "SLH-DSA-SHA2-128f";
            case "2.16.840.1.101.3.4.3.22": return "SLH-DSA-SHA2-192s";
            case "2.16.840.1.101.3.4.3.23": return "SLH-DSA-SHA2-192f";
            case "2.16.840.1.101.3.4.3.24": return "SLH-DSA-SHA2-256s";
            case "2.16.840.1.101.3.4.3.25": return "SLH-DSA-SHA2-256f";
            // SLH-DSA SHAKE (FIPS 205)
            case "2.16.840.1.101.3.4.3.26": return "SLH-DSA-SHAKE-128s";
            case "2.16.840.1.101.3.4.3.27": return "SLH-DSA-SHAKE-128f";
            case "2.16.840.1.101.3.4.3.28": return "SLH-DSA-SHAKE-192s";
            case "2.16.840.1.101.3.4.3.29": return "SLH-DSA-SHAKE-192f";
            case "2.16.840.1.101.3.4.3.30": return "SLH-DSA-SHAKE-256s";
            case "2.16.840.1.101.3.4.3.31": return "SLH-DSA-SHAKE-256f";
            // Composite signatures — named-combination OIDs from draft-ietf-lamps-pq-composite-sigs
            // PKIX arc 1.3.6.1.5.5.7.6.* — OIDs verified against draft-18 and BC 1.84 empirical output (2026-04-17)
            case "1.3.6.1.5.5.7.6.37": return "MLDSA44-RSA2048-PSS-SHA256";
            case "1.3.6.1.5.5.7.6.38": return "MLDSA44-RSA2048-PKCS15-SHA256";
            case "1.3.6.1.5.5.7.6.39": return "MLDSA44-Ed25519-SHA512";
            case "1.3.6.1.5.5.7.6.40": return "MLDSA44-ECDSA-P256-SHA256";
            case "1.3.6.1.5.5.7.6.41": return "MLDSA65-RSA3072-PSS-SHA512";
            case "1.3.6.1.5.5.7.6.42": return "MLDSA65-RSA3072-PKCS15-SHA512";
            case "1.3.6.1.5.5.7.6.43": return "MLDSA65-RSA4096-PSS-SHA512";
            case "1.3.6.1.5.5.7.6.44": return "MLDSA65-RSA4096-PKCS15-SHA512";
            case "1.3.6.1.5.5.7.6.45": return "MLDSA65-ECDSA-P256-SHA512";
            case "1.3.6.1.5.5.7.6.46": return "MLDSA65-ECDSA-P384-SHA512";
            case "1.3.6.1.5.5.7.6.47": return "MLDSA65-ECDSA-brainpoolP256r1-SHA512";
            case "1.3.6.1.5.5.7.6.48": return "MLDSA65-Ed25519-SHA512";
            case "1.3.6.1.5.5.7.6.49": return "MLDSA87-ECDSA-P384-SHA512";
            case "1.3.6.1.5.5.7.6.50": return "MLDSA87-ECDSA-brainpoolP384r1-SHA512";
            case "1.3.6.1.5.5.7.6.51": return "MLDSA87-Ed448-SHAKE256";
            case "1.3.6.1.5.5.7.6.52": return "MLDSA87-RSA3072-PSS-SHA512";
            case "1.3.6.1.5.5.7.6.53": return "MLDSA87-RSA4096-PSS-SHA512";
            case "1.3.6.1.5.5.7.6.54": return "MLDSA87-ECDSA-P521-SHA512";
            // Legacy BC/generic composite draft-era OIDs (no longer generated; kept for viewing old artifacts)
            case "1.3.6.1.4.1.18227.2.1":   return "Composite-Sig (legacy BC/generic draft-era OID — not draft-aligned)";
            case "2.16.840.1.114027.80.4.1": return "Composite-Sig (legacy BC/generic draft-era OID — not draft-aligned)";
            // Standard X.509 extensions
            case "2.5.29.14": return "Subject Key Identifier";
            case "2.5.29.15": return "Key Usage";
            case "2.5.29.17": return "Subject Alt Name";
            case "2.5.29.19": return "Basic Constraints";
            case "2.5.29.35": return "Authority Key Identifier";
            case "2.5.29.72": return "Subject Alt Public Key Info";
            case "2.5.29.73": return "Alt Signature Algorithm";
            case "2.5.29.74": return "Alt Signature Value";
            // SHA-2 digest algorithm OIDs (NIST FIPS 180-4)
            case "2.16.840.1.101.3.4.2.1": return "SHA-256";
            case "2.16.840.1.101.3.4.2.2": return "SHA-384";
            case "2.16.840.1.101.3.4.2.3": return "SHA-512";
            // RFC 9763 (Proposed Standard, June 2025): dual-certificate binding
            case "1.3.6.1.5.5.7.1.36": return "Related Certificate (RFC 9763 id-pe-relatedCert)";
            case "1.2.840.113549.1.9.16.2.60": return "relatedCertRequest (RFC 9763 id-aa-relatedCertRequest)";
            default: return oid;
        }
    }

    static X509Certificate loadCertificate(String pemFilePath) throws Exception {
        List<String> lines = Files.readAllLines(Paths.get(pemFilePath));

        if (lines.get(0).contains("KEY---")) {
            throw new IllegalArgumentException("Viewing key data is not yet supported");
        }
        if (!lines.get(0).contains("CERTIFICATE---")) {
            throw new IllegalArgumentException("File does not appear to be a PEM-encoded certificate");
        }

        String pemContent = lines.stream()
                                 .filter(line -> !line.startsWith("-----"))
                                 .collect(Collectors.joining());

        byte[] decoded = Base64.getDecoder().decode(pemContent);
        CertificateFactory certFactory = CertificateFactory.getInstance("X.509", "BC");
        return (X509Certificate) certFactory.generateCertificate(new ByteArrayInputStream(decoded));
    }

    static List<X509Certificate> loadCertificates(String pemFilePath) throws Exception {
        byte[] fileBytes = Files.readAllBytes(Paths.get(pemFilePath));
        CertificateFactory certFactory = CertificateFactory.getInstance("X.509", "BC");
        Collection<? extends java.security.cert.Certificate> raw =
                certFactory.generateCertificates(new ByteArrayInputStream(fileBytes));
        List<X509Certificate> certs = new ArrayList<>(raw.size());
        for (java.security.cert.Certificate c : raw) {
            certs.add((X509Certificate) c);
        }
        return certs; // empty list if no cert blocks present
    }

    static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) sb.append(String.format("%02x", b));
        return sb.toString();
    }
}
