package com.example.secure;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.hpke.HPKE;
import org.bouncycastle.crypto.hpke.HPKEContext;
import org.bouncycastle.crypto.hpke.HPKEContextWithEncapsulation;
import org.bouncycastle.crypto.params.X25519PublicKeyParameters;

/**
 * Suite fija: DHKEM(X25519, HKDF-SHA256) + HKDF-SHA256 + AES-256-GCM,
 * modo base (sin PSK ni autenticacion de sender a nivel HPKE; esa
 * identidad la aporta mTLS en el transporte, ver seccion 4 del documento).
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

        // OJO: la firma real de HPKEContext es seal(aad, data), no
        // seal(data, aad) como sugieren algunos resumenes del javadoc.
        // Verificado por bytecode (org.bouncycastle.crypto.hpke.AEAD.process).
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
