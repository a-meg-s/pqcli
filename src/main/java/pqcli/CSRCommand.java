package pqcli;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;

import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

import java.io.FileOutputStream;
import java.io.OutputStream;
import java.security.KeyPair;
import java.util.concurrent.Callable;

@Command(name = "csr", description = "Generate a PKCS#10 certificate signing request")
public class CSRCommand implements Callable<Integer> {

    @Option(names = {"-newkey", "-nk"}, required = true, description = {
        "Key algorithm (single only; hybrid/composite not supported for CSR).",
        "Examples: RSA:3072, EC:secp256r1, ML-DSA:65, SLH-DSA:128f, Ed25519"
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
            if (algorithmSet.isHybrid()) {
                System.err.println("Error: Hybrid keys are not supported for CSR generation." +
                        " PKCS#10 has no standard alt-key extension. Use a single algorithm.");
                return 1;
            }

            String x500Subject = subject.replace('/', ',').replaceAll("^,", "");

            long t0 = System.currentTimeMillis();
            KeyPair keyPair = KeyGenerator.generateKeyPair(algorithmSet.getAlgorithms());
            long keyGenMs = System.currentTimeMillis() - t0;

            String sigAlgo = CertificateGenerator.getSuitableSignatureAlgorithm(algorithmSet.getAlgorithms()[0]);

            long t1 = System.currentTimeMillis();
            JcaPKCS10CertificationRequestBuilder builder =
                    new JcaPKCS10CertificationRequestBuilder(new X500Name(x500Subject), keyPair.getPublic());
            ContentSigner signer = new JcaContentSignerBuilder(sigAlgo).setProvider("BC").build(keyPair.getPrivate());
            PKCS10CertificationRequest csr = builder.build(signer);
            long csrGenMs = System.currentTimeMillis() - t1;

            KeyGenerator.saveKeyToFile(prefixed("private_key.pem"), keyPair.getPrivate());
            KeyGenerator.saveKeyToFile(prefixed("public_key.pem"), keyPair.getPublic());
            saveCsrToFile(prefixed("csr.pem"), csr);

            System.out.println("CSR and key saved successfully!");
            System.out.println("  Subject:    " + x500Subject);
            System.out.println("  Algorithm:  " + sigAlgo);
            System.out.println("  Files:      " + prefixed("csr.pem") + ", " + prefixed("private_key.pem"));
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
