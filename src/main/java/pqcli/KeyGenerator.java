package pqcli;

import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.NamedParameterSpec;
import java.util.Base64;
import java.util.concurrent.Callable;

import org.bouncycastle.jcajce.spec.MLDSAParameterSpec;
import org.bouncycastle.pqc.jcajce.spec.DilithiumParameterSpec;
import org.bouncycastle.jcajce.spec.SLHDSAParameterSpec;

import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

@Command(name="key", description="Generates a public/private key pair")
public class KeyGenerator implements Callable<Integer> {
    @Option(names = { "-newkey", "-nk", "-new", "-t" }, required = true, description = {
        "Key algorithm. Single: RSA:3072, EC:secp256r1, DSA:2048, Ed25519, Ed448,",
        "  ML-DSA:44/65/87, SLH-DSA:128s/128f/192s/192f/256s/256f,",
        "  SLH-DSA:shake-128s/shake-128f/shake-192s/shake-192f/shake-256s/shake-256f.",
        "  Hybrid (comma): RSA:3072,ML-DSA:65.  Composite (underscore): RSA:3072_ML-DSA:65."
    })
    private String keyAlgorithm;

    @Option(names = { "-out", "-o" }, description = {
        "Output filename prefix. E.g. 'rsa3072' produces:",
        "  rsa3072_private_key.pem, rsa3072_public_key.pem.",
        "  Hybrid also adds: rsa3072_alt_private_key.pem, rsa3072_alt_public_key.pem."
    }, defaultValue = "")
    private String outPrefix;

    @Option(names = "--timing", description = "Print key generation timing", defaultValue = "false")
    private boolean printTiming;

    private String prefixed(String name) {
        return outPrefix.isEmpty() ? name : outPrefix + "_" + name;
    }

    public Integer call() throws Exception {
        ProviderSetup.setupProvider();
        try {
            AlgorithmSet algorithmSet = new AlgorithmSet(keyAlgorithm);

            long t0 = System.currentTimeMillis();
            KeyPair keyPair = generateKeyPair(algorithmSet.getAlgorithms());
            long keyGenMs = System.currentTimeMillis() - t0;

            saveKeyToFile(prefixed("private_key.pem"), keyPair.getPrivate());
            saveKeyToFile(prefixed("public_key.pem"), keyPair.getPublic());
            System.out.println("Key pair saved successfully!");
            System.out.println("  Algorithm:    " + keyPair.getPublic().getAlgorithm());
            System.out.println("  Public key:   " + keyPair.getPublic().getClass().getSimpleName()
                    + " (" + keyPair.getPublic().getEncoded().length + " bytes encoded)");
            System.out.println("  Private key:  " + keyPair.getPrivate().getClass().getSimpleName()
                    + " (" + keyPair.getPrivate().getEncoded().length + " bytes encoded)");
            if (printTiming) System.out.println("  Key gen time: " + keyGenMs + " ms");
            System.out.println(keyPair);

            if (algorithmSet.isHybrid()) {
                long t1 = System.currentTimeMillis();
                KeyPair altKeyPair = generateKeyPair(algorithmSet.getAltAlgorithms());
                long altKeyGenMs = System.currentTimeMillis() - t1;

                saveKeyToFile(prefixed("alt_private_key.pem"), altKeyPair.getPrivate());
                saveKeyToFile(prefixed("alt_public_key.pem"), altKeyPair.getPublic());
                System.out.println("Alternative key pair saved successfully!");
                System.out.println("  Algorithm:    " + altKeyPair.getPublic().getAlgorithm());
                System.out.println("  Public key:   " + altKeyPair.getPublic().getClass().getSimpleName()
                        + " (" + altKeyPair.getPublic().getEncoded().length + " bytes encoded)");
                System.out.println("  Private key:  " + altKeyPair.getPrivate().getClass().getSimpleName()
                        + " (" + altKeyPair.getPrivate().getEncoded().length + " bytes encoded)");
                if (printTiming) System.out.println("  Key gen time: " + altKeyGenMs + " ms");
                System.out.println(altKeyPair);
            }

            return 0;
        } catch (Exception e) {
            System.err.println("Error during key generation: " + e.getMessage());
            return 1;
        }
    }

    public static KeyPair generateKeyPair(AlgorithmWithParameters[] algorithms)
            throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {
        if (algorithms == null || algorithms.length == 0) {
            throw new IllegalArgumentException("No algorithm specified for key generation.");
        }
        if (algorithms.length == 1) {
            return generateKeyPair(algorithms[0]);
        }
        // Composite key: use named-combination path (draft-ietf-lamps-pq-composite-sigs aligned).
        // BC 1.84 named composite KPG emits PKIX-arc OIDs (1.3.6.1.5.5.7.6.*) for supported combos.
        // Unsupported combinations throw rather than falling back to legacy generic OIDs.
        String namedCombo = AlgorithmSet.resolveNamedComposite(algorithms);
        if (namedCombo == null) {
            throw new IllegalArgumentException(
                "Unsupported composite combination. Only draft-ietf-lamps-pq-composite-sigs " +
                "named combinations are supported (ML-DSA 44/65/87 with RSA/ECDSA/EdDSA per draft). " +
                "Examples: ML-DSA:65_RSA:3072, ML-DSA:65_EC:secp256r1, ML-DSA:87_Ed448.");
        }
        KeyPairGenerator namedKpg = KeyPairGenerator.getInstance(namedCombo, "BC");
        return namedKpg.generateKeyPair();
    }

    public static KeyPair generateKeyPair(AlgorithmWithParameters algorithm) 
            throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {
        return generateKeyPair(algorithm.algorithm, algorithm.keySizeOrCurve);
    }

    /**
     * Generates a key pair based on the given algorithm and key length.
     */
    public static KeyPair generateKeyPair(String algorithm, String curveOrKeyLength) 
            throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {

        // Remove this if there is no reason to use raw Dilithium keys over ML-DSA
        if (algorithm.equals("dilithium-bcpqc")) {
            // Initialisation for PQC Algorithm CRYSTALS-Dilithium (ML-DSA / FIPS 204 is based on Dilithium)
            // Note: The Dilitium implementation in the BCPQC provider outputs a private key BC 1.79+ can no longer use for signing.
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("Dilithium", "BCPQC");

            // Dilithium security level (2, 3, 5 available)
            int level = Integer.parseInt(curveOrKeyLength);
            DilithiumParameterSpec spec;
            switch (level) {
                case 2:
                    spec = DilithiumParameterSpec.dilithium2;
                    break;
                case 3:
                    spec = DilithiumParameterSpec.dilithium3;
                    break;
                case 5:
                    spec = DilithiumParameterSpec.dilithium5;
                    break;
                default:
                    throw new IllegalArgumentException("Invalid Dilithium security level " + level + ". Choose 2, 3 or 5.");
            }

            keyPairGenerator.initialize(spec, new SecureRandom());
            return keyPairGenerator.generateKeyPair();
        }

        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(algorithm, "BC");

        if (algorithm.equals("ec")) {
            // Initialisierung mit der angegebenen Kurve (z. B. prime256v1)
            keyPairGenerator.initialize(new ECGenParameterSpec(curveOrKeyLength), new SecureRandom());
        }
        else if (algorithm.equals("rsa")) {
            // Initialisation for RSA with the given key length
            if (curveOrKeyLength.endsWith("-pss")) { // PSS is not relevant for key generation
                curveOrKeyLength = curveOrKeyLength.substring(0, curveOrKeyLength.length() - 4);
            }
            int keyLength = Integer.parseInt(curveOrKeyLength);
            if (keyLength < 1024) {
                throw new IllegalArgumentException("RSA key length must be at least 1024 bit.");
            }
            if (keyLength % 2 != 0) {
                // enforce even key length as BC will hang unable to generate primes on odd key lengths
                throw new IllegalArgumentException("RSA key length must be an even number.");
            }
            if (keyLength > 8192) {
                // arbitrary limit, but ensures no crazy key lengths are used
                throw new IllegalArgumentException("RSA key length must be at most 8192 bit.");
            }
            if (keyLength < 2048) {
                System.out.println("Warning: RSA key length is less than 2048 bit. Consider using a stronger key length.");
            }
            keyPairGenerator.initialize(keyLength, new SecureRandom());
        }
        else if (algorithm.equals("dsa")) {
            // Initialisation for DSA with the given key length
            int keyLength = Integer.parseInt(curveOrKeyLength);
            if (keyLength < 1024 || keyLength > 4096 || keyLength % 1024 != 0) {
                throw new IllegalArgumentException("DSA key length must be either 1024, 2048, 3072, or 4096.");
            }
            keyPairGenerator.initialize(keyLength, new SecureRandom());   
        } 
        else if (algorithm.equals("mldsa")) {
            // Initialisation for PQC Algorithm ML-DSA (based on Dilithium)
            keyPairGenerator = KeyPairGenerator.getInstance("ML-DSA", "BC");

            // Dilithium security level (2, 3, 5 available)
            int level = Integer.parseInt(curveOrKeyLength);
            MLDSAParameterSpec spec;
            switch (level) {
                case 2:
                case 44:
                    spec = MLDSAParameterSpec.ml_dsa_44;
                    break;
                case 3:
                case 65:
                    spec = MLDSAParameterSpec.ml_dsa_65;
                    break;
                case 5:
                case 87:
                    spec = MLDSAParameterSpec.ml_dsa_87; // TODO: Check if ml_dsa_87_with_sha512 should be used
                    break;
                default:
                    throw new IllegalArgumentException("Invalid ML-DSA parameter spec " + level + ". Choose 44, 65 or 87.");
            }

            keyPairGenerator.initialize(spec, new SecureRandom());
        }
        else if (algorithm.equals("slh-dsa")) {
            // Initialisation for PQC Algorithm SLH-DSA / FIPS 205 (based on SPHINCS+)
            keyPairGenerator = KeyPairGenerator.getInstance("SLH-DSA", "BC");

            // SHA2 variants: 128s, 128f, 192s, 192f, 256s, 256f (default when no prefix)
            // SHAKE variants: shake-128s, shake-128f, shake-192s, shake-192f, shake-256s, shake-256f
            String level = curveOrKeyLength;
            SLHDSAParameterSpec spec;
            switch (level) {
                case "128":
                case "128s":
                    spec = SLHDSAParameterSpec.slh_dsa_sha2_128s;
                    break;
                case "128f":
                    spec = SLHDSAParameterSpec.slh_dsa_sha2_128f;
                    break;
                case "192":
                case "192s":
                    spec = SLHDSAParameterSpec.slh_dsa_sha2_192s;
                    break;
                case "192f":
                    spec = SLHDSAParameterSpec.slh_dsa_sha2_192f;
                    break;
                case "256":
                case "256s":
                    spec = SLHDSAParameterSpec.slh_dsa_sha2_256s;
                    break;
                case "256f":
                    spec = SLHDSAParameterSpec.slh_dsa_sha2_256f;
                    break;
                case "shake-128s":
                    spec = SLHDSAParameterSpec.slh_dsa_shake_128s;
                    break;
                case "shake-128f":
                    spec = SLHDSAParameterSpec.slh_dsa_shake_128f;
                    break;
                case "shake-192s":
                    spec = SLHDSAParameterSpec.slh_dsa_shake_192s;
                    break;
                case "shake-192f":
                    spec = SLHDSAParameterSpec.slh_dsa_shake_192f;
                    break;
                case "shake-256s":
                    spec = SLHDSAParameterSpec.slh_dsa_shake_256s;
                    break;
                case "shake-256f":
                    spec = SLHDSAParameterSpec.slh_dsa_shake_256f;
                    break;
                default:
                    throw new IllegalArgumentException("Invalid SLH-DSA parameter " + level
                        + ". SHA2 variants: 128s, 128f, 192s, 192f, 256s, 256f."
                        + " SHAKE variants: shake-128s, shake-128f, shake-192s, shake-192f, shake-256s, shake-256f.");
            }

            keyPairGenerator.initialize(spec, new SecureRandom());
        }
        else if (algorithm.equals("ed25519") || algorithm.equals("ed448")) {
            // Initialisation for EdDSA
            keyPairGenerator.initialize(new NamedParameterSpec(algorithm), new SecureRandom());

        } else {
            throw new IllegalArgumentException("Algorithm not supported: " + algorithm);
        }

        return keyPairGenerator.generateKeyPair();
    }

    public static void saveKeyToFile(String fileName, Key key) throws IOException {
        try (OutputStream os = new FileOutputStream(fileName)) {
            String header = (key instanceof PrivateKey) ? "PRIVATE KEY" : "PUBLIC KEY";
            os.write(("-----BEGIN " + header + "-----\n").getBytes());
            os.write(wrapBase64(key.getEncoded()).getBytes());
            os.write(("-----END " + header + "-----\n").getBytes());
        }
    }

    static String wrapBase64(byte[] data) {
        String encoded = Base64.getEncoder().encodeToString(data);
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < encoded.length(); i += 64) {
            sb.append(encoded, i, Math.min(i + 64, encoded.length()));
            sb.append('\n');
        }
        return sb.toString();
    }
}
