# Security Policy

This repository contains a **proof of concept (PoC)** of an end-to-end encryption protocol. It is not hardened for production (see the checklist in [`docs/ARCHITECTURE.md`](./docs/ARCHITECTURE.md#12-production-checklist)) and should not be deployed as-is against real data.

## Reporting a vulnerability

If you find a security issue in the code or in the protocol design — for example, a flaw in how HPKE/AES-GCM is used, a weakness in how the AAD is constructed, or a way for the aggregator to recover plaintext — please report it privately:

- Via [GitHub Security Advisories](../../security/advisories/new) for this repository (preferred), or
- By email to **david.academica@gmail.com**.

Please do not open a public issue for a vulnerability until it has been assessed.

Include, if possible:

- A description of the issue and its impact.
- Steps to reproduce it (or a minimal PoC).
- The affected version/commit.

This is a personal project with no formal response SLA, but reports will be triaged as promptly as possible.

## Scope

Out of scope: reports that the PoC "has no TLS/mTLS", "has no real anti-replay", or "runs everything in a single process" — these are known, documented limitations of the PoC, not vulnerabilities. In scope: any flaw in the part the PoC does implement — the use of HPKE/X25519/AES-GCM and the integrity check via AAD.
