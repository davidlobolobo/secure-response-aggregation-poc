package com.example.secure;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

/**
 * Simulates the intermediary/aggregator: fans requests out in parallel
 * with Virtual Threads and collects the encrypted envelopes. Note that
 * this class NEVER receives an AsymmetricCipherKeyPair or any private
 * key — there is no structural way for it to decrypt anything.
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
            "[aggregator] requestId=%s -- forwarding public key to %d responders (holding no private key)%n",
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
                "[aggregator] requestId=%s src=%s ciphertext(hex, first 16 bytes)=%s ... -- CANNOT decrypt%n",
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
