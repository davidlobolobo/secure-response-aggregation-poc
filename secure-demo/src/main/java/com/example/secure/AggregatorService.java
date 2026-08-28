package com.example.secure;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

/**
 * Simula el intermediario/aggregator (secciones 20-21 del documento):
 * hace fan-out en paralelo con Virtual Threads y agrega los envelopes
 * cifrados. Notese que esta clase JAMAS recibe un AsymmetricCipherKeyPair
 * ni ninguna clave privada -no hay forma estructural de que descifre.
 */
public final class AggregatorService {

    private final Map<String, ResponderService> responders;

    public AggregatorService(Map<String, ResponderService> responders) {
        this.responders = responders;
    }

    public List<EncryptedEnvelope> fanOut(
            String requestId,
            String requester,
            byte[] requesterPublicKeyBytes,
            Map<String, Object> payloadsByService) throws Exception {

        System.out.printf(
            "[aggregator] requestId=%s -- reenviando publicKey a %d responders (sin retener clave privada)%n",
            requestId, responders.size()
        );

        List<EncryptedEnvelope> envelopes = new ArrayList<>();

        try (ExecutorService executor = Executors.newVirtualThreadPerTaskExecutor()) {
            List<Future<EncryptedEnvelope>> futures = new ArrayList<>();

            for (var entry : responders.entrySet()) {
                String name = entry.getKey();
                ResponderService responder = entry.getValue();
                Object payload = payloadsByService.get(name);

                futures.add(executor.submit(() ->
                    responder.handle(requestId, requester, requesterPublicKeyBytes, payload)
                ));
            }

            for (Future<EncryptedEnvelope> f : futures) {
                envelopes.add(f.get());
            }
        }

        for (EncryptedEnvelope e : envelopes) {
            System.out.printf(
                "[aggregator] requestId=%s src=%s ciphertext(hex, primeros 16 bytes)=%s ... -- NO puede descifrar%n",
                e.rid(), e.src(), hexPrefix(e.ct(), 16)
            );
        }

        return envelopes;
    }

    private static String hexPrefix(byte[] data, int n) {
        StringBuilder sb = new StringBuilder();
        int limit = Math.min(n, data.length);
        for (int i = 0; i < limit; i++) {
            sb.append(String.format("%02X ", data[i]));
        }
        return sb.toString().trim();
    }
}
