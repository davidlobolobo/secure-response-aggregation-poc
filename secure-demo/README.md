# secure-demo

A Java 21 proof of concept for an end-to-end encryption protocol for secure response aggregation between microservices: an intermediary fans requests out and aggregates encrypted responses without ever being able to read their content. See [`../docs/ARCHITECTURE.md`](../docs/ARCHITECTURE.md) for the full design.

It simulates, in a single process, the complete flow:

1. `service-a` (the requester) generates an ephemeral X25519 key pair. The private key never leaves its memory.
2. An `AggregatorService` receives only the public key and fans out in parallel (Virtual Threads) to four `ResponderService` instances (`service-b`, `service-c`, `service-d`, `service-e`).
3. Each responder encrypts its JSON with **real HPKE (RFC 9180)** using that public key — via Bouncy Castle, suite `DHKEM(X25519, HKDF-SHA256) + HKDF-SHA256 + AES-256-GCM`.
4. The aggregator collects the four encrypted envelopes **without being able to decrypt them** (it never receives or holds a private key).
5. `service-a` decrypts all four responses.
6. Three negative tests run: a tampered ciphertext, a substituted `request_id` (fails AAD verification), and a decryption attempt with the wrong key pair (simulating the aggregator itself trying to peek).

## Requirements

- Java 21
- Maven 3.9+

## Build and run

```bash
mvn compile exec:java
```

or build the classes and run manually:

```bash
mvn package
java -cp target/classes:$(find ~/.m2 -name 'bcprov-jdk18on-*.jar' -o -name 'jackson-*.jar' | tr '\n' ':') com.example.secure.Demo
```

## Expected output

```
=== Phase 1: original request ===
[requester] requestId=... -- public key generated, private key kept in local memory only
[aggregator] requestId=... -- forwarding public key to 4 responders (holding no private key)
[service-b] original JSON: {"customerId":12567,"status":"ACTIVE","balance":15234.22}
...
[aggregator] requestId=... src=service-b ciphertext(hex, first 16 bytes)=... -- CANNOT decrypt

=== Phase 2: requester decrypts ===
[requester] decrypted from service-b: {"customerId":12567,"status":"ACTIVE","balance":15234.22}
...

=== Negative test 1: tampered ciphertext ===
[OK] decryption rejected as expected: InvalidCipherTextException

=== Negative test 2: request_id substitution via AAD ===
[OK] response not transferable to another requestId: InvalidCipherTextException

=== Negative test 3: aggregator attempting to decrypt ===
[OK] aggregator cannot decrypt: InvalidCipherTextException
```

The process exits with a non-zero status if any negative test unexpectedly succeeds — `Demo` doubles as a smoke test wired into CI (see `.github/workflows/build.yml`).

## Structure

| Class | Role |
|---|---|
| `CryptoUtils` | X25519 key generation and (de)serialization (Bouncy Castle's lightweight API) |
| `HpkeCodec` | Wrapper around `org.bouncycastle.crypto.hpke.HPKE` for the protocol's fixed suite |
| `AadCodec` | Builds the AAD (`requestId\|src\|dst\|ts\|schema_version`) binding each response to its request |
| `RequestContext` | The requester's ephemeral state, including the private key |
| `EncryptedEnvelope` | The wire format that crosses the aggregator |
| `ResponderService` | Simulates a downstream service encrypting its response |
| `AggregatorService` | Simulates the intermediary: fan-out and aggregation, with no access to any private key |
| `Demo` | Orchestrates the full flow and the negative tests |

## Important note about the Bouncy Castle API

`HPKEContext.seal` / `.open` take their arguments as **`(aad, data)`**, not `(data, aad)` — easy to get backwards since it doesn't match the usual order of other Java AEAD APIs. Getting it backwards makes the AAD get encrypted as if it were the plaintext, and decryption then fails with `InvalidCipherTextException` ("data too short" or "mac check failed" depending on size). Verified against the real bytecode of `bcprov-jdk18on` 1.79 and 1.85.2.

## What's missing for production

This PoC validates the core cryptographic mechanism, but **is not production-ready as-is**. Before deploying it in a real environment:

- Real TLS 1.3 / mTLS on the wire (everything here runs in a single process, with no network).
- Sign the request metadata (Ed25519) so the aggregator cannot substitute the requester's public key.
- Real anti-replay: reject duplicate `request_id`s, enforce an expiration window, track nonces.
- Services as independent processes/containers communicating over HTTP/2, not in-memory calls.
- Load testing (1k/5k/10k RPS) with p95/p99 latency, CPU, and GC measured.

See the full checklist in [`../docs/ARCHITECTURE.md`](../docs/ARCHITECTURE.md#12-production-checklist).
