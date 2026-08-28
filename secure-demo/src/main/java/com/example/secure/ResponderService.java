package com.example.secure;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.bouncycastle.crypto.params.X25519PublicKeyParameters;

import java.nio.charset.StandardCharsets;
import java.time.Instant;

/**
 * Simula un servicio downstream (B, C, D o E): recibe la clave publica
 * del requester y un payload de negocio, y devuelve el envelope cifrado
 * (seccion 7.3 del documento). Nunca ve ni necesita la clave privada.
 */
public final class ResponderService {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final byte[] INFO = "secure-demo/v1".getBytes(StandardCharsets.UTF_8);

    private final String serviceName;

    public ResponderService(String serviceName) {
        this.serviceName = serviceName;
    }

    public EncryptedEnvelope handle(
            String requestId,
            String requester,
            byte[] requesterPublicKeyBytes,
            Object payload) throws Exception {

        X25519PublicKeyParameters requesterPublicKey =
            CryptoUtils.decodePublicKey(requesterPublicKeyBytes);

        byte[] json = MAPPER.writeValueAsBytes(payload);
        long ts = Instant.now().getEpochSecond();

        byte[] aad = AadCodec.build(requestId, serviceName, requester, ts);

        HpkeCodec.Sealed sealed =
            HpkeCodec.seal(requesterPublicKey, INFO, aad, json);

        System.out.printf(
            "[%s] JSON original: %s%n",
            serviceName,
            new String(json, StandardCharsets.UTF_8)
        );

        return new EncryptedEnvelope(requestId, serviceName, ts, sealed.enc(), sealed.ciphertext());
    }
}
