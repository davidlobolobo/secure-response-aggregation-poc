package com.example.secure;

/**
 * The envelope format that travels through the aggregator. "ts" travels
 * in the clear alongside the ciphertext because it is part of the AAD:
 * the requester needs it to reconstruct the exact same authenticated
 * bytes when decrypting.
 */
public record EncryptedEnvelope(
    String rid,
    String src,
    long ts,
    byte[] enc,
    byte[] ct
) {}
