# deny-sh

Deniable encryption. One ciphertext, two passwords, two completely different plaintexts. Both mathematically valid. No way to prove which one is real.

**[deny.sh](https://deny.sh)** · [Whitepaper](https://deny.sh/whitepaper) · [Verify it yourself](https://deny.sh/verify) · [Other SDKs](https://deny.sh/sdks)

## What this is

The TypeScript / Node.js SDK + CLI for deny.sh.

```bash
npm install deny-sh
```

8.4KB. Zero runtime dependencies. Just `node:crypto` under the hood.

## How it works

```
plaintext + password1 + password2 → ciphertext + control_data

ciphertext + control_data + passwords → original plaintext  ✓
ciphertext + fake_control + passwords → decoy plaintext     ✓
```

Both decryptions succeed. Both produce valid output. There is no mathematical marker, no hidden flag, no forensic trace that distinguishes one from the other. The attacker got *a* plaintext. They can never prove it wasn't *the* plaintext.

Under the hood:

1. Key derivation via **scrypt** (N=16384, r=8, p=1) from two passwords
2. 4-byte LE length prefix + plaintext, XORed with random control data
3. **AES-256-CTR** encryption
4. Output: `salt (32B) | IV (16B) | ciphertext`

Creating a decoy is just running the maths in reverse with different plaintext. New control data falls out. Same ciphertext. Different truth.

## Quick start

```typescript
import { encrypt, decrypt, generateDeniableControl } from 'deny-sh';

const real    = Buffer.from('the actual secret');
const decoy   = Buffer.from('a plausible cover story');
const realPw  = 'real password';
const decoyPw = 'duress password';

// Encrypt the real plaintext, generate a decoy control file
const { ciphertext, control: realControl } = encrypt(real, realPw);
const decoyControl = generateDeniableControl(ciphertext, decoy, decoyPw);

// Both decryptions succeed
const out1 = decrypt(ciphertext, realControl,  realPw);   // → real
const out2 = decrypt(ciphertext, decoyControl, decoyPw);  // → decoy
```

The `realControl` and `decoyControl` blobs are indistinguishable. Whoever holds the ciphertext can be presented with either control file plus the matching password and will decrypt to a valid plaintext. There is no way for them to know which one came first.

## CLI

```bash
deny-sh protect <file> --decoy <decoy-file>   # encrypt with a decoy
deny-sh verify  <file>                         # check a ciphertext+control pair
deny-sh init                                   # set up .deny/ in cwd
deny-sh backup ...                             # backup helpers (S3, rclone)
deny-sh vault  ...                             # local vault management
deny-sh env    ...                             # encrypted .env handling
deny-sh status                                 # show current .deny/ state
```

Run `deny-sh --help` for the full surface.

## Other languages

| Language     | Package        | Repo |
|--------------|---------------|------|
| TypeScript   | `deny-sh`     | [deny-sh-crypto/deny-js](https://github.com/deny-sh-crypto/deny-js) (this repo) |
| Python       | `deny-sh`     | [deny-sh-crypto/deny-python](https://github.com/deny-sh-crypto/deny-python) |
| Rust         | `deny-sh`     | [deny-sh-crypto/deny-rs](https://github.com/deny-sh-crypto/deny-rs) |
| Go           | `deny-go`     | [deny-sh-crypto/deny-go](https://github.com/deny-sh-crypto/deny-go) |

All four are algorithm-compatible: a ciphertext produced by one decrypts cleanly under the others.

## Verify the deniability claim

```bash
git clone https://github.com/deny-sh-crypto/deny-js
cd deny-js
npm install
npm run build
npm run verify
```

`run-verification.mjs` runs the cryptographic verification suite end-to-end and prints results. The full mathematical argument is in the [whitepaper](https://deny.sh/whitepaper).

## Threat model

deny.sh defends against **passive ciphertext leak** scenarios: someone obtains your encrypted file (cloud breach, lost laptop, seized device) and tries to read it.

It is **not** designed to resist an adaptive adversary who can compel you to perform multiple decryptions, demand additional passwords iteratively, or run forensic side-channel analysis on your decryption hardware. See the [whitepaper §5](https://deny.sh/whitepaper) for the full threat model.

## License

Dual-licensed:

- **AGPL-3.0-or-later** for open-source use. See [LICENSE](LICENSE).
- **Commercial license** available for proprietary integrations. See [COMMERCIAL-LICENSE.md](COMMERCIAL-LICENSE.md) and email `licensing@deny.sh`.

## Audit status

External cryptographic audit in scoping for Q3 2026. Results will be published when complete. Until then: read the code, run the verification suite, read the whitepaper, draw your own conclusions.
