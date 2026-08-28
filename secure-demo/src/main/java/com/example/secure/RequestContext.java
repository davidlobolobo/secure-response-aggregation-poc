package com.example.secure;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;

import java.time.Instant;

/**
 * Ephemeral state that lives only in the requester service. The full
 * key pair — including the private key — never leaves this object.
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
