package pqcli;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;

import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

import java.io.FileOutputStream;
import java.io.OutputStream;
import java.security.KeyPair;
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
@Command(name = "csr", description = "Generate a PKCS#10 certificate signing request")
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

    private String prefixed(String name) {
        return outPrefix.isEmpty() ? name : outPrefix + "_" + name;
    }

    @Override
    public Integer call() throws Exception {
        ProviderSetup.setupProvider();
        try {
            AlgorithmSet algorithmSet = new AlgorithmSet(keyAlgorithm);

            String x500Subject = subject.replace('/', ',').replaceAll("^,", "");

            long t0 = System.currentTimeMillis();
            KeyPair keyPair = KeyGenerator.generateKeyPair(algorithmSet.getAlgorithms());
            long keyGenMs = System.currentTimeMillis() - t0;

            JcaPKCS10CertificationRequestBuilder builder =
                    new JcaPKCS10CertificationRequestBuilder(new X500Name(x500Subject), keyPair.getPublic());

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
                System.out.println("  NOTE: Composite algorithm identifiers are draft/BC-internal.");
                System.out.println("        Non-BC tooling may not understand this CSR.");
            } else {
                System.out.println("  Algorithm:  " + CertificateGenerator.getSuitableSignatureAlgorithm(algorithmSet.getAlgorithms()[0]));
                System.out.println("  Files:      " + prefixed("csr.pem") + ", " + prefixed("private_key.pem"));
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
}
