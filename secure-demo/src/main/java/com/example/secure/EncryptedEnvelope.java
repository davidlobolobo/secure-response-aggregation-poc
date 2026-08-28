package com.example.secure;

/**
 * Formato de envelope que viaja a traves del aggregator (seccion 7.3 / 12
 * del documento). "ts" viaja en claro junto al ciphertext porque forma
 * parte del AAD: el requester lo necesita para reconstruir exactamente
 * los mismos bytes autenticados al descifrar.
 */
public record EncryptedEnvelope(
    String rid,
    String src,
    long ts,
    byte[] enc,
    byte[] ct
) {}
