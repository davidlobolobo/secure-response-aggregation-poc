package com.example.secure;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * End-to-end PoC: the requester generates an X25519 key pair, the
 * aggregator fans requests out without ever knowing the private key,
 * each responder encrypts with real HPKE (Bouncy Castle), the requester
 * decrypts, and the three negative cases are demonstrated. Exits with a
 * non-zero status if any negative test unexpectedly succeeds, so it can
 * double as a CI smoke test.
 */
public final class Demo {

    private static final byte[] INFO = "secure-demo/v1".getBytes(StandardCharsets.UTF_8);
    private static final String REQUESTER = "service-a";

    public static void main(String[] args) throws Exception {
        System.out.println("=== Phase 1: original request ===");
        RequestContext ctx = newRequestContext();

        Map<String, ResponderService> responders = Map.of(
            "service-b", new ResponderService("service-b"),
            "service-c", new ResponderService("service-c"),
            "service-d", new ResponderService("service-d"),
            "service-e", new ResponderService("service-e")
        );

        Map<String, Object> payloads = Map.of(
            "service-b", Map.of("customerId", 12567, "status", "ACTIVE", "balance", 15234.22),
            "service-c", Map.of("orderId", 987, "status", "SHIPPED"),
            "service-d", Map.of("riskScore", 0.12, "flag", false),
            "service-e", Map.of("inventory", 42, "warehouse", "MX-01")
        );

        AggregatorService aggregator = new AggregatorService(responders);

        List<EncryptedEnvelope> envelopes = aggregator.fanOut(
            ctx.requestId(), ctx.requester(), ctx.publicKeyBytes(), payloads
        );

        System.out.println();
        System.out.println("=== Phase 2: requester decrypts ===");
        for (EncryptedEnvelope e : envelopes) {
            byte[] aad = AadCodec.build(e.rid(), e.src(), ctx.requester(), e.ts());
            byte[] plaintext = HpkeCodec.open(e.enc(), ctx.keyPair(), INFO, aad, e.ct());
            System.out.printf("[requester] decrypted from %s: %s%n",
                e.src(), new String(plaintext, StandardCharsets.UTF_8));
        }

        System.out.println();
        System.out.println("=== Negative test 1: tampered ciphertext ===");
        negativeTamperedCiphertext(ctx, envelopes.get(0));

        System.out.println();
        System.out.println("=== Negative test 2: request_id substitution via AAD ===");
        negativeWrongAad(ctx, envelopes.get(0));

        System.out.println();
        System.out.println("=== Negative test 3: aggregator attempting to decrypt ===");
        negativeWrongKey(envelopes.get(0));

        System.out.println();
        System.out.println("=== The aggregator aggregated 4 encrypted responses without ever reading their content ===");
    }

    private static RequestContext newRequestContext() {
        AsymmetricCipherKeyPair keyPair = CryptoUtils.generateX25519KeyPair();
        String requestId = UUID.randomUUID().toString();
        Instant now = Instant.now();

        System.out.printf(
            "[requester] requestId=%s -- public key generated, private key kept in local memory only%n",
            requestId
        );

        return new RequestContext(requestId, REQUESTER, keyPair, now, now.plusSeconds(60));
    }

    private static void negativeTamperedCiphertext(RequestContext ctx, EncryptedEnvelope original) {
        byte[] tampered = original.ct().clone();
        tampered[10] ^= 0x01;

        byte[] aad = AadCodec.build(original.rid(), original.src(), ctx.requester(), original.ts());

        try {
            HpkeCodec.open(original.enc(), ctx.keyPair(), INFO, aad, tampered);
            throw new AssertionError("decrypting a tampered ciphertext should not have succeeded");
        } catch (AssertionError ex) {
            throw ex;
        } catch (Exception ex) {
            System.out.printf("[OK] decryption rejected as expected: %s%n", ex.getClass().getSimpleName());
        }
    }

    private static void negativeWrongAad(RequestContext ctx, EncryptedEnvelope original) {
        byte[] forgedAad = AadCodec.build(
            "request-999-attack", original.src(), ctx.requester(), original.ts()
        );

        try {
            HpkeCodec.open(original.enc(), ctx.keyPair(), INFO, forgedAad, original.ct());
            throw new AssertionError("a response should not have been transferable to another requestId");
        } catch (AssertionError ex) {
            throw ex;
        } catch (Exception ex) {
            System.out.printf("[OK] response not transferable to another requestId: %s%n", ex.getClass().getSimpleName());
        }
    }

    private static void negativeWrongKey(EncryptedEnvelope original) {
        AsymmetricCipherKeyPair attackerKeyPair = CryptoUtils.generateX25519KeyPair();
        byte[] aad = AadCodec.build(original.rid(), original.src(), REQUESTER, original.ts());

        try {
            HpkeCodec.open(original.enc(), attackerKeyPair, INFO, aad, original.ct());
            throw new AssertionError("the aggregator should not have been able to decrypt with the wrong key");
        } catch (AssertionError ex) {
            throw ex;
        } catch (Exception ex) {
            System.out.printf("[OK] aggregator cannot decrypt: %s%n", ex.getClass().getSimpleName());
        }
    }
}
