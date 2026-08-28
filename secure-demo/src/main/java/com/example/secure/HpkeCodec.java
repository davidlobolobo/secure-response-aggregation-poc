package com.example.secure;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.hpke.HPKE;
import org.bouncycastle.crypto.hpke.HPKEContext;
import org.bouncycastle.crypto.hpke.HPKEContextWithEncapsulation;
import org.bouncycastle.crypto.params.X25519PublicKeyParameters;

/**
 * Fixed suite: DHKEM(X25519, HKDF-SHA256) + HKDF-SHA256 + AES-256-GCM,
 * base mode (no PSK, no sender authentication at the HPKE layer — that
 * identity is provided by mTLS at the transport layer instead).
 */
public final class HpkeCodec {

    private HpkeCodec() {}

    private static HPKE newSuite() {
        return new HPKE(
            HPKE.mode_base,
            HPKE.kem_X25519_SHA256,
            HPKE.kdf_HKDF_SHA256,
            HPKE.aead_AES_GCM256
        );
    }

    public record Sealed(byte[] enc, byte[] ciphertext) {}

    public static Sealed seal(
            X25519PublicKeyParameters recipientPublicKey,
            byte[] info,
            byte[] aad,
            byte[] plaintext) throws Exception {

        HPKEContextWithEncapsulation ctx =
            newSuite().setupBaseS(recipientPublicKey, info);

        // NOTE: HPKEContext's real signature is seal(aad, data), not
        // seal(data, aad) as some javadoc summaries suggest. Verified
        // against the actual bytecode (org.bouncycastle.crypto.hpke.AEAD.process).
        byte[] ciphertext = ctx.seal(aad, plaintext);
        byte[] enc = ctx.getEncapsulation();

        return new Sealed(enc, ciphertext);
    }

    public static byte[] open(
            byte[] enc,
            AsymmetricCipherKeyPair recipientKeyPair,
            byte[] info,
            byte[] aad,
            byte[] ciphertext) throws Exception {

        HPKEContext ctx =
            newSuite().setupBaseR(enc, recipientKeyPair, info);

        return ctx.open(aad, ciphertext);
    }
}
