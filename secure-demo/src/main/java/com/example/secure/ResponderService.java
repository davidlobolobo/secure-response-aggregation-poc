package com.example.secure;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.bouncycastle.crypto.params.X25519PublicKeyParameters;

import java.nio.charset.StandardCharsets;
import java.time.Instant;

/**
 * Simulates a downstream service (B, C, D or E): receives the requester's
 * public key and a business payload, and returns the encrypted envelope.
 * It never sees or needs the private key.
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
            "[%s] original JSON: %s%n",
            serviceName,
            new String(json, StandardCharsets.UTF_8)
        );

        return new EncryptedEnvelope(requestId, serviceName, ts, sealed.enc(), sealed.ciphertext());
    }
}
