# End-to-End Encryption for Secure Response Aggregation

A proof of concept (PoC) for an end-to-end encryption architecture that lets an intermediary/aggregator service route and collect responses from multiple microservices **without ever being able to read their content**.

- **[docs/ARCHITECTURE.md](./docs/ARCHITECTURE.md)** — the design: trust model, cryptographic protocol (X25519 + HKDF-SHA256 + AES-256-GCM via HPKE / RFC 9180), AAD binding, anti-replay, and the production checklist.
- **[secure-demo/](./secure-demo)** — a working Java 21 PoC that implements the protocol with real HPKE (via Bouncy Castle) and demonstrates the design's security properties, including negative tests.

## Core idea

> Each request generates a temporary public key (X25519). Downstream services encrypt their responses with that public key; only the service that originated the request holds the private key needed to decrypt them. The intermediary transports and aggregates ciphertext, but can never read it.

## Protocol

- X25519 for key encapsulation
- HKDF-SHA256 for key derivation
- AES-256-GCM for authenticated encryption of the payload
- HPKE (RFC 9180) as the standard envelope for the three primitives above
- Ephemeral per-request keys — the private key never leaves the service that generated it

## Scope

The architecture is platform-agnostic. Java 21 is used here as the reference platform for the PoC and concept validation; an implementation on another platform is out of scope for this repository for now.

## Status

Proof of concept — not production-ready as-is. See the production checklist in [`docs/ARCHITECTURE.md`](./docs/ARCHITECTURE.md#12-production-checklist) (real TLS 1.3/mTLS, signed request metadata, real anti-replay, load testing).

## Contributing

See [CONTRIBUTING.md](./CONTRIBUTING.md). For security issues, see [SECURITY.md](./SECURITY.md) instead of opening a public issue.

## License

[MIT](./LICENSE)
