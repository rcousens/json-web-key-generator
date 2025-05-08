package io.swyftx.jwk;

import com.google.common.base.Strings;
import com.nimbusds.jose.Algorithm;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.KeyType;
import com.nimbusds.jose.jwk.KeyUse;

/**
 * Helper class to generate Json Web Keys of different types
 */
public class KeyGenerator {

    /**
     * Creates a JWK based on the specified parameters
     * @param size Key size (required for RSA keys)
     * @param kid Key ID generator
     * @param keyUse Key usage (signing, encryption)
     * @param keyAlg Algorithm for the key
     * @return The generated JWK
     */
    public static JWK makeKey(String size, KeyIdGenerator kid, KeyUse keyUse, Algorithm keyAlg) {
        return makeRsaKey(size, kid, keyUse, keyAlg);
    }

    /**
     * Creates an RSA JWK with the specified parameters
     * @param size Key size in bits
     * @param kid Key ID generator
     * @param keyUse Key usage (signing, encryption)
     * @param keyAlg Algorithm for the key
     * @return The generated RSA JWK
     */
    private static JWK makeRsaKey(String size, KeyIdGenerator kid, KeyUse keyUse, Algorithm keyAlg) {
        if (Strings.isNullOrEmpty(size)) {
            throw new IllegalArgumentException("Key size (in bits) is required for key type " + KeyType.RSA);
        }

        // Parse the key size
        Integer keySize = Integer.decode(size);
        if (keySize % 8 != 0) {
            throw new IllegalArgumentException("Key size (in bits) must be divisible by 8, got " + keySize);
        }

        return RSAKeyMaker.make(keySize, keyUse, keyAlg, kid);
    }
}
