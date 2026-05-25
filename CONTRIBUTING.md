# Contributing

Thanks for considering a contribution to deny.sh. This guide covers the operational basics. The substantive design conversation happens in issues.

## Before you start

1. Read [DCO.md](./DCO.md). Every commit must be DCO-signed (`git commit -s`). Pull requests with unsigned commits fail CI.
2. Check open issues and the project [STATE.md](https://github.com/deny-sh-crypto/deny-sh) (if accessible) for ongoing work on the area you want to touch.
3. For non-trivial changes (anything beyond a typo fix or a documented bug), open an issue first to align on scope. We'd rather front-load that conversation than ask you to throw work away.

## Scope of this repo

This is one of the public mirror repositories for the deny.sh project. The canonical source for SDK and primitive code is the public mirror you are looking at; the private monorepo (`deny-sh-crypto/deny-sh`) carries the server, web, browser-extension, MCP server, and CI infrastructure on top.

If your contribution targets a different surface (e.g. browser extension UI, server-side API), please open an issue here first — we'll route you to the right place.

## What we welcome

- Bug fixes with a reproduction test
- Documentation improvements
- Cross-SDK byte-compat regression tests (additions to the locked KAT suite)
- Threat-model reviews and challenges
- Side-channel safety improvements with a measurement methodology

## What we don't accept

- Algorithm-level changes to the cryptographic primitive (KDF, cipher, mode, composition). These need a coordinated change across all five SDKs + a bump of the wire-format version byte + cross-SDK byte-compat KAT regeneration. Open an issue first.
- Dependencies that bring in transitive supply-chain risk. Vetting overhead exceeds the benefit for an encryption library.
- Major refactors without prior discussion.

## How to submit

1. Fork the repo.
2. Create a branch from `main` (or whichever default branch this repo uses).
3. Make your changes. Commits must be DCO-signed (`-s`).
4. Run the local test suite for this language and confirm clean.
5. Open a pull request describing the change, the rationale, and any decisions you made.

## Licensing

By contributing to this repository, you agree that your contribution is licensed under the project's existing licence (see `LICENSE` in this repo's root). The DCO sign-off is your affirmation of that.

## Code of conduct

Be kind. Disagree on substance, never on people. If something feels off, email hello@deny.sh.
