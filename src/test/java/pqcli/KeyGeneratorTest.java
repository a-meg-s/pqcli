package pqcli;

import org.bouncycastle.jcajce.CompositePublicKey;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.junit.Test;

import java.security.KeyPair;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.RSAPublicKey;

import static org.junit.Assert.*;

public class KeyGeneratorTest {

    static {
        ProviderSetup.setupProvider();
    }

    // --- RSA ---

    @Test
    public void rsaKeyPairHasCorrectModulusLength() throws Exception {
        KeyPair kp = KeyGenerator.generateKeyPair("rsa", "3072");
        assertTrue(kp.getPublic() instanceof RSAPublicKey);
        int bits = ((RSAPublicKey) kp.getPublic()).getModulus().bitLength();
        assertTrue("Expected ~3072 bit modulus", bits >= 3000 && bits <= 3072);
    }

    @Test
    public void rsaKeyPairPssStrippedBeforeGeneration() throws Exception {
        // -pss suffix must be stripped; key generation should succeed
        KeyPair kp = KeyGenerator.generateKeyPair("rsa", "2048-pss");
        assertTrue(kp.getPublic() instanceof RSAPublicKey);
    }

    @Test(expected = IllegalArgumentException.class)
    public void rsaTooShortThrows() throws Exception {
        KeyGenerator.generateKeyPair("rsa", "512");
    }

    @Test(expected = IllegalArgumentException.class)
    public void rsaOddLengthThrows() throws Exception {
        KeyGenerator.generateKeyPair("rsa", "3071");
    }

    @Test(expected = IllegalArgumentException.class)
    public void rsaTooLongThrows() throws Exception {
        KeyGenerator.generateKeyPair("rsa", "8194");
    }

    // --- EC ---

    @Test
    public void ecSecp256r1KeyPair() throws Exception {
        KeyPair kp = KeyGenerator.generateKeyPair("ec", "secp256r1");
        assertEquals("EC", kp.getPublic().getAlgorithm());
        assertTrue(kp.getPublic().getEncoded().length > 0);
    }

    @Test
    public void ecSecp384r1KeyPair() throws Exception {
        KeyPair kp = KeyGenerator.generateKeyPair("ec", "secp384r1");
        assertEquals("EC", kp.getPublic().getAlgorithm());
    }

    @Test
    public void ecSecp521r1KeyPair() throws Exception {
        KeyPair kp = KeyGenerator.generateKeyPair("ec", "secp521r1");
        assertEquals("EC", kp.getPublic().getAlgorithm());
    }

    // --- DSA ---

    @Test
    public void dsa2048KeyPair() throws Exception {
        KeyPair kp = KeyGenerator.generateKeyPair("dsa", "2048");
        assertTrue(kp.getPublic() instanceof DSAPublicKey);
        assertEquals(2048, ((DSAPublicKey) kp.getPublic()).getParams().getP().bitLength());
    }

    @Test(expected = IllegalArgumentException.class)
    public void dsaInvalidLengthThrows() throws Exception {
        KeyGenerator.generateKeyPair("dsa", "1500");
    }

    // --- EdDSA ---

    @Test
    public void ed25519KeyPair() throws Exception {
        KeyPair kp = KeyGenerator.generateKeyPair("ed25519", "");
        assertEquals("Ed25519", kp.getPublic().getAlgorithm());
    }

    @Test
    public void ed448KeyPair() throws Exception {
        KeyPair kp = KeyGenerator.generateKeyPair("ed448", "");
        assertEquals("Ed448", kp.getPublic().getAlgorithm());
    }

    // --- ML-DSA ---

    @Test
    public void mlDsa44KeyPair() throws Exception {
        KeyPair kp = KeyGenerator.generateKeyPair("mldsa", "44");
        assertTrue(kp.getPublic().getAlgorithm().startsWith("ML-DSA"));
        assertTrue(kp.getPublic().getEncoded().length > 0);
    }

    @Test
    public void mlDsa65KeyPair() throws Exception {
        KeyPair kp = KeyGenerator.generateKeyPair("mldsa", "65");
        assertTrue(kp.getPublic().getAlgorithm().startsWith("ML-DSA"));
    }

    @Test
    public void mlDsa87KeyPair() throws Exception {
        KeyPair kp = KeyGenerator.generateKeyPair("mldsa", "87");
        assertTrue(kp.getPublic().getAlgorithm().startsWith("ML-DSA"));
    }

    @Test(expected = IllegalArgumentException.class)
    public void mlDsaInvalidLevelThrows() throws Exception {
        KeyGenerator.generateKeyPair("mldsa", "99");
    }

    // --- SLH-DSA SHA2 ---

    @Test
    public void slhDsaSha2_128sKeyPair() throws Exception {
        KeyPair kp = KeyGenerator.generateKeyPair("slh-dsa", "128s");
        assertNotNull(kp.getPublic().getEncoded());
        assertTrue(kp.getPublic().getEncoded().length > 0);
    }

    @Test
    public void slhDsaSha2_128fKeyPair() throws Exception {
        KeyPair kp = KeyGenerator.generateKeyPair("slh-dsa", "128f");
        assertNotNull(kp.getPublic().getEncoded());
    }

    @Test
    public void slhDsaSha2_192sKeyPair() throws Exception {
        KeyPair kp = KeyGenerator.generateKeyPair("slh-dsa", "192s");
        assertNotNull(kp.getPublic().getEncoded());
    }

    @Test
    public void slhDsaSha2_192fKeyPair() throws Exception {
        KeyPair kp = KeyGenerator.generateKeyPair("slh-dsa", "192f");
        assertNotNull(kp.getPublic().getEncoded());
    }

    @Test
    public void slhDsaSha2_256sKeyPair() throws Exception {
        KeyPair kp = KeyGenerator.generateKeyPair("slh-dsa", "256s");
        assertNotNull(kp.getPublic().getEncoded());
    }

    @Test
    public void slhDsaSha2_256fKeyPair() throws Exception {
        KeyPair kp = KeyGenerator.generateKeyPair("slh-dsa", "256f");
        assertNotNull(kp.getPublic().getEncoded());
    }

    // --- SLH-DSA SHAKE ---

    @Test
    public void slhDsaShake128sKeyPair() throws Exception {
        KeyPair kp = KeyGenerator.generateKeyPair("slh-dsa", "shake-128s");
        assertNotNull(kp.getPublic().getEncoded());
    }

    @Test
    public void slhDsaShake128fKeyPair() throws Exception {
        KeyPair kp = KeyGenerator.generateKeyPair("slh-dsa", "shake-128f");
        assertNotNull(kp.getPublic().getEncoded());
    }

    @Test
    public void slhDsaShake192sKeyPair() throws Exception {
        KeyPair kp = KeyGenerator.generateKeyPair("slh-dsa", "shake-192s");
        assertNotNull(kp.getPublic().getEncoded());
    }

    @Test
    public void slhDsaShake192fKeyPair() throws Exception {
        KeyPair kp = KeyGenerator.generateKeyPair("slh-dsa", "shake-192f");
        assertNotNull(kp.getPublic().getEncoded());
    }

    @Test
    public void slhDsaShake256sKeyPair() throws Exception {
        KeyPair kp = KeyGenerator.generateKeyPair("slh-dsa", "shake-256s");
        assertNotNull(kp.getPublic().getEncoded());
    }

    @Test
    public void slhDsaShake256fKeyPair() throws Exception {
        KeyPair kp = KeyGenerator.generateKeyPair("slh-dsa", "shake-256f");
        assertNotNull(kp.getPublic().getEncoded());
    }

    @Test(expected = IllegalArgumentException.class)
    public void slhDsaInvalidVariantThrows() throws Exception {
        KeyGenerator.generateKeyPair("slh-dsa", "999x");
    }

    // --- Composite ---

    @Test
    public void compositeKeyPairHasTwoComponents() throws Exception {
        AlgorithmWithParameters[] algos = new AlgorithmSet("RSA:3072_ML-DSA:65").getAlgorithms();
        KeyPair kp = KeyGenerator.generateKeyPair(algos);
        assertTrue(kp.getPublic() instanceof CompositePublicKey);
        assertEquals(2, ((CompositePublicKey) kp.getPublic()).getPublicKeys().size());
    }

    @Test
    public void compositeEdDsaKeyPairGenerates() throws Exception {
        AlgorithmWithParameters[] algos = new AlgorithmSet("Ed25519_ML-DSA:44").getAlgorithms();
        KeyPair kp = KeyGenerator.generateKeyPair(algos);
        assertTrue(kp.getPublic() instanceof CompositePublicKey);
    }

    // --- Hybrid (two separate key pairs) ---

    @Test
    public void hybridAlgorithmSetGeneratesTwoKeyPairs() throws Exception {
        AlgorithmSet as = new AlgorithmSet("RSA:3072,ML-DSA:65");
        assertTrue(as.isHybrid());
        KeyPair primary = KeyGenerator.generateKeyPair(as.getAlgorithms());
        KeyPair alt = KeyGenerator.generateKeyPair(as.getAltAlgorithms());
        assertEquals("RSA", primary.getPublic().getAlgorithm());
        assertTrue(alt.getPublic().getAlgorithm().startsWith("ML-DSA"));
    }

    // --- Unknown algorithm ---

    @Test
    public void unknownAlgorithmThrowsNoSuchAlgorithm() {
        try {
            KeyGenerator.generateKeyPair("unknownalgo", "");
            fail("Expected exception for unknown algorithm");
        } catch (IllegalArgumentException | java.security.NoSuchAlgorithmException
                | java.security.NoSuchProviderException
                | java.security.InvalidAlgorithmParameterException e) {
            // acceptable: unknown algo not in the known-dispatch list
        }
    }

    // --- wrapBase64 ---

    @Test
    public void base64LineWrapAt64Chars() {
        byte[] data = new byte[100];
        for (int i = 0; i < data.length; i++) data[i] = (byte) i;
        String wrapped = KeyGenerator.wrapBase64(data);
        for (String line : wrapped.split("\n")) {
            assertTrue("Line exceeds 64 chars: " + line.length(), line.length() <= 64);
        }
    }
}
