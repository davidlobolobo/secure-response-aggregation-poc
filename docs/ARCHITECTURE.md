# Architecture

## 1. Problem

A set of services exchange information through an intermediary/aggregator:

1. An origin service sends a request to the intermediary.
2. The intermediary fans the request out to several downstream services.
3. Each downstream service processes the request and produces a JSON response.
4. Each response is returned to the intermediary.
5. The intermediary aggregates the responses.
6. The intermediary returns the aggregated result to the origin service.

**Requirement:** the intermediary must be able to transport and aggregate the responses, but must never be able to read their content.

## 2. Core idea

> Each request generates a temporary public key. Downstream services use that public key to encrypt their responses, but only the service that originated the request holds the private key needed to decrypt them.

The intermediary never receives that private key. It sees every response, but only as ciphertext.

### Who knows which keys

Say `service-a` initiates a request. It generates an ephemeral X25519 key pair:

```text
privateKey_A_request-123   (stays in service-a's memory only)
publicKey_A_request-123    (travels with the request)
```

The public key travels through the intermediary to `service-b`, `service-c`, etc. Each of them encrypts its response for that public key. The intermediary only ever observes:

```text
ciphertext_B
ciphertext_C
...
```

and never possesses the private key needed to decrypt them.

### What the intermediary can and cannot see

The intermediary can legitimately see operational metadata:

- request id, origin service, responding service
- HTTP status, response time, response size
- timeouts, transport errors

It cannot see:

- JSON payload contents, business fields, sensitive values
- personal or financial data
- tokens embedded in the payload

Even if the intermediary is compromised, an attacker does not automatically gain access to response content. The intermediary is a transport/aggregation component, not a cryptographic trust boundary.

## 3. Trust model

**Trusted per-service:**

- each service's permanent identity private keys
- each service's ephemeral private keys
- process memory, keystore/secret store, mTLS credentials

**The intermediary is trusted for:**

- routing, availability, correlation, aggregation, error handling

**The intermediary is *not* trusted for confidentiality.** That is the point of this design.

```text
Public keys may be distributed.
Private keys are never distributed.
Downstream services encrypt with the public key.
Only the requester decrypts, with the private key.
```

## 4. Cryptographic protocol

### Transport

- **TLS 1.3** protects data in transit.
- **mTLS** authenticates both ends of every hop.

mTLS is necessary but not sufficient: without end-to-end encryption, the intermediary can read plaintext at the TLS termination point. Hence the HPKE layer below.

### Message encryption

```text
HPKE
DHKEM(X25519, HKDF-SHA256)
HKDF-SHA256
AES-256-GCM
```

- **X25519** — key encapsulation. Small keys, fast, well supported, suitable for high request volume.
- **HKDF-SHA256** — derives independent keying material from the X25519 shared secret.
- **AES-256-GCM** — authenticated encryption of the JSON payload: confidentiality, integrity, and ciphertext authentication with strong hardware acceleration on modern CPUs.

### Why not encrypt directly with RSA

Asymmetric crypto should establish or wrap a symmetric key, not encrypt bulk JSON directly — RSA is slow for large payloads and has strict size limits. The correct shape is hybrid encryption:

```text
X25519 -> shared secret -> HKDF -> AES key -> AES-GCM(JSON)
```

AES does the actual content encryption because it is dramatically more efficient at scale.

## 5. Request/response flow

```text
┌───────────────┐
│  Requester    │  generates an ephemeral X25519 key pair
└───────┬───────┘
        │ privateKey  [stays local, never leaves this service]
        │ publicKey   [travels with the request, ideally signed]
        ▼
┌──────────────────────────────┐
│         Aggregator           │  sees: request_id, publicKey
│   never holds a private key  │  sees on the way back: ciphertext only
└─────────────┬─────────────────┘
              │ fan-out
     ┌────────┼────────┬────────┐
     ▼        ▼        ▼        ▼
    Svc B    Svc C    Svc D    Svc E
     │        │        │        │
     │  each produces its own JSON, then HPKE-encrypts it
     │  for the requester's public key
     ▼        ▼        ▼        ▼
 CipherB  CipherC  CipherD  CipherE
     └────────┴────┬───┴────────┘
                    ▼
              Aggregator
        assembles ciphertexts, still cannot read them
                    │
                    ▼
              Requester
      decrypts every response in parallel with its
      own private key + HPKE
```

## 6. AAD — binding a response to its context

AES-GCM lets you authenticate additional data (AAD) without encrypting it. This binds each response to the exact request it belongs to:

```text
AAD = request_id | source_service | destination_service | timestamp | schema_version
```

This defeats a substitution attack: an attacker cannot take the (still-encrypted) response for `request-123` and replay it as the response for `request-999` — the AEAD tag verification fails, because the AAD used to authenticate the ciphertext no longer matches.

## 7. Anti-replay

Every request should carry:

```text
request_id
timestamp
expires
nonce
```

Services must reject expired requests, duplicate `request_id`s, reused nonces, and timestamps outside an acceptance window (a `TTL` of 30–60 seconds is a reasonable starting point, tuned to the operational needs).

## 8. Authenticating the requester's public key

A critical gap if left unaddressed: nothing stops the intermediary from swapping the requester's public key for one it controls, then decrypting every response itself.

```text
requester sends:        publicKey_A
intermediary swaps in:  publicKey_Attacker
downstream services encrypt for publicKey_Attacker instead
```

**Mitigation:** the request metadata (`request_id`, `requester`, `response_public_key`, `timestamp`, `expires`, `nonce`) should be signed by the requester using **Ed25519**. Downstream services already know the requester's long-lived identity public key and can verify the signature before trusting the embedded ephemeral public key.

## 9. Security profiles

**Profile 1 — maximum throughput (default recommendation):**

```text
mTLS + HPKE + AES-GCM + AAD
```

Maximum efficiency, strong transport identity, end-to-end confidentiality, ciphertext integrity.

**Profile 2 — cryptographic auditability:**

```text
mTLS + HPKE + AES-GCM + AAD + Ed25519 signature per message
```

Lets you prove cryptographically which service produced each ciphertext, at the cost of extra signing/verification work per message — evaluate whether that's actually needed at your target throughput before adopting it by default.

## 10. Aggregated envelope format

```json
{
  "rid": "f729f500-02f1-4cb1-8956-2bb97ce1a7ce",
  "responses": [
    { "src": "service-b", "enc": "<hpke-encapsulation>", "ct": "<ciphertext>" },
    { "src": "service-c", "enc": "<hpke-encapsulation>", "ct": "<ciphertext>" }
  ]
}
```

The aggregator can assemble and forward this structure without ever understanding its content.

## 11. Reference implementation notes (Java 21)

This architecture is platform-agnostic — it is defined by standard primitives (X25519, HKDF-SHA256, AES-256-GCM, HPKE/RFC 9180, TLS 1.3/mTLS), not by any language feature. [`secure-demo/`](../secure-demo) is the Java 21 reference PoC.

The JDK does not ship a native HPKE implementation. `KeyPairGenerator.getInstance("X25519")` and `Cipher.getInstance("AES/GCM/NoPadding")` are available natively, but real HPKE (encapsulation, `info` binding, base/auth/psk modes) requires a library. This PoC uses **Bouncy Castle** (`org.bouncycastle.crypto.hpke.HPKE`, `bcprov-jdk18on`), which implements RFC 9180 for exactly the suite recommended above: `DHKEM(X25519, HKDF-SHA256) + HKDF-SHA256 + AES-256-GCM`.

## 12. Production checklist

This PoC validates the core cryptographic mechanism. Before taking it to production:

- [ ] Real TLS 1.3 / mTLS on the wire (the PoC runs everything in a single process, with no network).
- [ ] Sign request metadata with Ed25519 so the aggregator cannot substitute the requester's public key (section 8).
- [ ] Real anti-replay: reject duplicate `request_id`s, enforce an expiration window, track nonces (section 7).
- [ ] Services as independent processes/containers communicating over HTTP/2, not in-memory calls.
- [ ] Load testing at your target RPS, with p95/p99 latency, CPU, and GC measured on real hardware — throughput and CPU cost scale with payload size and fan-out factor, so model those for your actual workload rather than assuming the numbers from a different deployment.
- [ ] Decide whether Profile 2 (per-message Ed25519 signatures) is required for your compliance/audit needs, given its throughput cost.
