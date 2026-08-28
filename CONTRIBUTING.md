# Contributing

Thanks for your interest in this project. It's a small proof of concept, so the process is informal:

## Requirements

- Java 21
- Maven 3.9+

## Build and run

```bash
cd secure-demo
mvn compile exec:java
```

See [`secure-demo/README.md`](./secure-demo/README.md) for more detail on what the demo does and how to read its output.

## Before opening a Pull Request

1. Verify that `mvn compile exec:java` runs without errors and that all three negative tests in `Demo` finish with `[OK]` (if one succeeded when it shouldn't have, the process fails with an `AssertionError` — that's the signal something broke).
2. If you add a class or change the protocol, update `secure-demo/README.md` and/or `docs/ARCHITECTURE.md` accordingly.
3. If your change touches key generation, AAD, or HPKE usage, explain in the PR description which security property you're preserving or changing — this is a cryptography project, so that context matters more than in a typical change.

## Code style

- No comments explaining *what* the code does; only when the *why* isn't obvious (a non-obvious constraint, a detail of an external API such as Bouncy Castle's argument order).
- Descriptive commit messages explaining the motivation for the change.

## Reporting bugs or proposing features

Use the repository's issue templates. For security vulnerabilities, see [`SECURITY.md`](./SECURITY.md) instead of opening a public issue.
