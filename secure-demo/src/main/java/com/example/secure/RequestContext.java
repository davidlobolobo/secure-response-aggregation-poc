package com.example.secure;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;

import java.time.Instant;

/**
 * Estado efimero que vive unicamente en el servicio requester
 * (seccion 7.1 / 16 del documento). La keyPair completa -incluida
 * la privada- nunca sale de este objeto.
 */
public record RequestContext(
    String requestId,
    String requester,
    AsymmetricCipherKeyPair keyPair,
    Instant issuedAt,
    Instant expiresAt
) {
    public byte[] publicKeyBytes() {
        return CryptoUtils.encodePublicKey(keyPair);
    }
}
