package com.example.secure;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.generators.X25519KeyPairGenerator;
import org.bouncycastle.crypto.params.X25519KeyGenerationParameters;
import org.bouncycastle.crypto.params.X25519PublicKeyParameters;

import java.security.SecureRandom;

public final class CryptoUtils {

    private CryptoUtils() {}

    public static AsymmetricCipherKeyPair generateX25519KeyPair() {
        X25519KeyPairGenerator generator = new X25519KeyPairGenerator();
        generator.init(new X25519KeyGenerationParameters(new SecureRandom()));
        return generator.generateKeyPair();
    }

    public static byte[] encodePublicKey(AsymmetricCipherKeyPair keyPair) {
        return ((X25519PublicKeyParameters) keyPair.getPublic()).getEncoded();
    }

    public static X25519PublicKeyParameters decodePublicKey(byte[] encoded) {
        return new X25519PublicKeyParameters(encoded);
    }
}
