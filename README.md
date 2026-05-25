# deny-sh

Deniable encryption. One ciphertext, two passwords, two completely different plaintexts. Both mathematically valid. When the bytes leak, what leaks is the decoy.

**[deny.sh](https://deny.sh)** · [Whitepaper](https://deny.sh/whitepaper) · [Verify it yourself](https://deny.sh/verify) · [Other SDKs](https://deny.sh/sdks)

## What this is

The TypeScript / Node.js SDK + CLI for deny.sh, the [deniability infrastructure](https://deny.sh). This package is the **Encrypt pillar**: the cryptographic primitive, Apache 2.0, free for any use, embeddable in any product, proprietary or open.

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

1. Key derivation via **Argon2id** (t=3, m=64 MiB, p=1, v=0x13) from two passwords
2. 4-byte LE length prefix + plaintext, XORed with random control data
3. **AES-256-CTR** encryption
4. Output: `salt (32B) | IV (16B) | ciphertext`

Creating a decoy is just running the maths in reverse with different plaintext. New control data falls out. Same ciphertext. Different truth.

## Quick start

```typescript
import {
  encrypt,
  decrypt,
  generateDeniableControl,
  generateControlData,
} from 'deny-sh';

const real  = new TextEncoder().encode('the actual secret');
const decoy = new TextEncoder().encode('a plausible cover story');
const password1 = 'real password';
const password2 = 'duress password';

// 1. Allocate random control data sized to the inner payload (plaintext + 4 bytes)
const controlData = generateControlData(real.length + 4);

// 2. Encrypt the real plaintext
const { ciphertext } = encrypt(real, { password1, password2, controlData });

// 3. Derive a decoy control file that decrypts the SAME ciphertext to the decoy
const { controlData: decoyControl } = generateDeniableControl(
  ciphertext,
  password1,
  password2,
  decoy
);

// Both decryptions succeed
const { plaintext: outReal  } = decrypt(ciphertext, { password1, password2, controlData });
const { plaintext: outDecoy } = decrypt(ciphertext, { password1, password2, controlData: decoyControl });
```

The `controlData` and `decoyControl` blobs are indistinguishable. Whoever holds the ciphertext can be presented with either control file plus the matching passwords and will decrypt to a valid plaintext. There is no way for them to know which one came first.

The primitive is intentionally unauthenticated. Wrong passwords return garbage, not an error. Add a caller-side integrity check (magic bytes plus a SHA-256 fingerprint on the plaintext) if you need decryption to fail loudly on the wrong inputs. See <https://deny.sh/security> for the construction write-up.

## CLI

```bash
deny-sh protect                                # interactive seed-phrase protection wizard
deny-sh init                                   # set up .deny/ in cwd
deny-sh env protect .env                       # encrypt a .env file -> .env.deny
deny-sh env restore .env.deny                  # restore an encrypted .env file
deny-sh vault set|get|list|delete KEY [value]  # local encrypted key-value store
deny-sh 1p push|pull|list|status               # 1Password integration
deny-sh bw push|pull|list|status               # Bitwarden integration
deny-sh backup push|pull|list|config|auto      # cloud backup helpers (S3, rclone)
deny-sh verify                                 # run encryption/deniability test suite
deny-sh status                                 # show .deny/ state and version info
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

**Apache License 2.0**. See [LICENSE](LICENSE).

Free for commercial and proprietary use. No copyleft, no attribution beyond the standard Apache notice, no legal review required for embedding in closed-source projects.

The deny.sh application layer (vault, dead-man's switch, MCP server, hosted API, web UI) remains under AGPL-3.0. The cryptographic primitive in this SDK is Apache 2.0. See [deny.sh/licensing](https://deny.sh/licensing) for the full split.

## Audit status

External cryptographic audit is on the roadmap. Firm and scope will be announced once engaged. Until then: read the code, run the verification suite, read the whitepaper, draw your own conclusions.

## Reporting vulnerabilities

Found a bug in the crypto, the SDK, or the CLI? Email security@deny.sh (PGP fingerprint and disclosure policy at [deny.sh/disclosure](https://deny.sh/disclosure)). Please give us a reasonable window before public disclosure.
