package pqcli;

import java.util.Arrays;

/* The AlgorithmSet is capable of representing single and composite certificates.
 * Hybrid certificates are supported by the altAlgorithms field.
 * Although unlikely to be used in practice, the hybrid altSignature could be composite too.
 */
public class AlgorithmSet {
    final AlgorithmWithParameters[] algorithms;
    final AlgorithmWithParameters[] altAlgorithms;

    public AlgorithmSet(AlgorithmWithParameters[] algorithms, AlgorithmWithParameters[] altAlgorithms) {
        this.algorithms = algorithms;
        this.altAlgorithms = altAlgorithms;
    }

    public AlgorithmSet(AlgorithmWithParameters[] algorithms) {
        this(algorithms, null);
    }

    public AlgorithmSet(String algorithmStr) {
        String[] parts = algorithmStr.split(",");
        parts = Arrays.stream(parts)
            .filter(s -> !s.trim().isEmpty()) // Remove empty and whitespace-only strings
            .toArray(String[]::new);

        if (parts.length == 0) {
            throw new IllegalArgumentException("No algorithms specified");
        }

        if (parts.length > 2) {
            throw new IllegalArgumentException("Hybrid certificates cannot contain more than one alternative algorithm.");
        }

        this.algorithms = getComponents(parts[0]);
        if (parts.length == 2) {
            this.altAlgorithms = getComponents(parts[1]);
        } else {
            this.altAlgorithms = null;
        }
    }

    private static AlgorithmWithParameters[] getComponents(String componentStr) {
        String[] components = componentStr.split("_");
        components = Arrays.stream(components)
            .filter(s -> !s.trim().isEmpty()) // Remove empty and whitespace-only strings
            .toArray(String[]::new);
        AlgorithmWithParameters[] algos = new AlgorithmWithParameters[components.length];
        for (int i = 0; i < components.length; i++) {
            algos[i] = new AlgorithmWithParameters(components[i]);
        }
        return algos;
    }

    public boolean isComposite() {
        return algorithms.length > 1;
    }

    public boolean isAltComposite() {
        return altAlgorithms != null && altAlgorithms.length > 1;
    }

    public boolean isHybrid() {
        return altAlgorithms != null && altAlgorithms.length > 0;
    }

    public int numAlgorithms() {
        return algorithms.length;
    }

    public AlgorithmWithParameters getAlgorithm(int index) {
        if (index < 0 || index >= algorithms.length) {
            throw new IllegalArgumentException("Invalid index for algorithm set: " + index);
        }
        return algorithms[index];
    }

    public AlgorithmWithParameters getAlgorithm() {
        if (algorithms.length == 0) {
            throw new IllegalStateException("Set is empty");
        }
        return algorithms[0];
    }

    public AlgorithmWithParameters[] getAlgorithms() {
        return algorithms;
    }

    public AlgorithmWithParameters getAltAlgorithm(int index) {
        if (!isHybrid()) {
            throw new IllegalStateException("Not a hybrid algorithm");
        }
        if (index < 0 || index >= altAlgorithms.length) {
            throw new IllegalArgumentException("Invalid index for alt algorithm set: " + index);
        }
        return altAlgorithms[index];
    }

    public AlgorithmWithParameters getAltAlgorithm() {
        if (!isHybrid()) {
            throw new IllegalStateException("Not a hybrid algorithm");
        }
        return altAlgorithms[0];
    }

    public AlgorithmWithParameters[] getAltAlgorithms() {
        return altAlgorithms;
    }

    /**
     * Attempt to resolve a 2-algorithm composite array to a BC named-combination
     * algorithm string aligned with draft-ietf-lamps-pq-composite-sigs.
     *
     * Only ML-DSA-based named combinations from the active draft are supported.
     * The component order in the array is normalised — either (ML-DSA, X) or (X, ML-DSA).
     * RSA combinations use the PSS variant by default.
     *
     * OIDs verified against draft-ietf-lamps-pq-composite-sigs-18 and BC 1.84 empirical output
     * on 2026-04-17. BC 1.84 emits PKIX-arc OIDs (1.3.6.1.5.5.7.6.*) for all these names.
     *
     * Returns null if no draft-aligned named combination exists for the given pair.
     */
    public static String resolveNamedComposite(AlgorithmWithParameters[] algos) {
        if (algos.length != 2) return null;

        AlgorithmWithParameters a = algos[0];
        AlgorithmWithParameters b = algos[1];

        // Exactly one must be mldsa
        AlgorithmWithParameters mldsa = null;
        AlgorithmWithParameters other = null;
        if (a.algorithm.equals("mldsa") && !b.algorithm.equals("mldsa")) {
            mldsa = a; other = b;
        } else if (b.algorithm.equals("mldsa") && !a.algorithm.equals("mldsa")) {
            mldsa = b; other = a;
        } else {
            return null; // Both ML-DSA or neither — no named combo exists
        }

        String level = mldsa.keySizeOrCurve;   // "44", "65", or "87"
        String otherAlgo = other.algorithm;
        // Strip the "-pss" suffix if present: RSA composite always uses the PSS variant
        // (named draft combos have a fixed scheme; the "-pss" hint from key syntax is redundant)
        String otherParam = other.keySizeOrCurve.endsWith("-pss")
                ? other.keySizeOrCurve.substring(0, other.keySizeOrCurve.length() - 4)
                : other.keySizeOrCurve;

        switch (level) {
            case "44":
                if (otherAlgo.equals("rsa") && otherParam.equals("2048"))
                    return "MLDSA44-RSA2048-PSS-SHA256";
                if (otherAlgo.equals("ec") && otherParam.equals("secp256r1"))
                    return "MLDSA44-ECDSA-P256-SHA256";
                if (otherAlgo.equals("ed25519"))
                    return "MLDSA44-Ed25519-SHA512";
                break;
            case "65":
                if (otherAlgo.equals("rsa") && otherParam.equals("3072"))
                    return "MLDSA65-RSA3072-PSS-SHA512";
                if (otherAlgo.equals("rsa") && otherParam.equals("4096"))
                    return "MLDSA65-RSA4096-PSS-SHA512";
                if (otherAlgo.equals("ec") && otherParam.equals("secp256r1"))
                    return "MLDSA65-ECDSA-P256-SHA512";
                if (otherAlgo.equals("ec") && otherParam.equals("secp384r1"))
                    return "MLDSA65-ECDSA-P384-SHA512";
                if (otherAlgo.equals("ed25519"))
                    return "MLDSA65-Ed25519-SHA512";
                break;
            case "87":
                if (otherAlgo.equals("rsa") && otherParam.equals("3072"))
                    return "MLDSA87-RSA3072-PSS-SHA512";
                if (otherAlgo.equals("rsa") && otherParam.equals("4096"))
                    return "MLDSA87-RSA4096-PSS-SHA512";
                if (otherAlgo.equals("ec") && otherParam.equals("secp384r1"))
                    return "MLDSA87-ECDSA-P384-SHA512";
                if (otherAlgo.equals("ec") && otherParam.equals("secp521r1"))
                    return "MLDSA87-ECDSA-P521-SHA512";
                if (otherAlgo.equals("ed448"))
                    return "MLDSA87-Ed448-SHAKE256";
                break;
        }
        return null; // No named draft combination for this pair
    }
}
