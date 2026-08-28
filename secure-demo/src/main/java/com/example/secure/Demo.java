package com.example.secure;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * PoC de extremo a extremo (secciones 39-50 del documento):
 * requester genera X25519, el aggregator hace fan-out sin conocer
 * la clave privada, cada responder cifra con HPKE real (Bouncy Castle),
 * el requester descifra, y se demuestran los tres casos negativos.
 */
public final class Demo {

    private static final byte[] INFO = "secure-demo/v1".getBytes(StandardCharsets.UTF_8);
    private static final String REQUESTER = "service-a";

    public static void main(String[] args) throws Exception {
        System.out.println("=== Fase 1: peticion original ===");
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
        System.out.println("=== Fase 2: requester descifra ===");
        for (EncryptedEnvelope e : envelopes) {
            byte[] aad = AadCodec.build(e.rid(), e.src(), ctx.requester(), e.ts());
            byte[] plaintext = HpkeCodec.open(e.enc(), ctx.keyPair(), INFO, aad, e.ct());
            System.out.printf("[requester] decrypted from %s: %s%n",
                e.src(), new String(plaintext, StandardCharsets.UTF_8));
        }

        System.out.println();
        System.out.println("=== Prueba negativa 1: manipulacion de ciphertext (seccion 47) ===");
        negativeTamperedCiphertext(ctx, envelopes.get(0));

        System.out.println();
        System.out.println("=== Prueba negativa 2: sustitucion de requestId via AAD (seccion 48) ===");
        negativeWrongAad(ctx, envelopes.get(0));

        System.out.println();
        System.out.println("=== Prueba negativa 3: intento de descifrado del aggregator (seccion 49) ===");
        negativeWrongKey(envelopes.get(0));

        System.out.println();
        System.out.println("=== El aggregator agrego 4 respuestas cifradas sin conocer su contenido ===");
    }

    private static RequestContext newRequestContext() {
        AsymmetricCipherKeyPair keyPair = CryptoUtils.generateX25519KeyPair();
        String requestId = UUID.randomUUID().toString();
        Instant now = Instant.now();

        System.out.printf(
            "[requester] requestId=%s -- publicKey generada, privateKey solo en memoria local%n",
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
            System.out.println("[FALLO] el descifrado no debio tener exito");
        } catch (Exception ex) {
            System.out.printf("[OK] descifrado rechazado como se esperaba: %s%n", ex.getClass().getSimpleName());
        }
    }

    private static void negativeWrongAad(RequestContext ctx, EncryptedEnvelope original) {
        byte[] forgedAad = AadCodec.build(
            "request-999-attack", original.src(), ctx.requester(), original.ts()
        );

        try {
            HpkeCodec.open(original.enc(), ctx.keyPair(), INFO, forgedAad, original.ct());
            System.out.println("[FALLO] el descifrado no debio tener exito");
        } catch (Exception ex) {
            System.out.printf("[OK] respuesta no trasladable a otro requestId: %s%n", ex.getClass().getSimpleName());
        }
    }

    private static void negativeWrongKey(EncryptedEnvelope original) {
        AsymmetricCipherKeyPair attackerKeyPair = CryptoUtils.generateX25519KeyPair();
        byte[] aad = AadCodec.build(original.rid(), original.src(), REQUESTER, original.ts());

        try {
            HpkeCodec.open(original.enc(), attackerKeyPair, INFO, aad, original.ct());
            System.out.println("[FALLO] el aggregator no debio poder descifrar");
        } catch (Exception ex) {
            System.out.printf("[OK] aggregator no puede descifrar: %s%n", ex.getClass().getSimpleName());
        }
    }
}
