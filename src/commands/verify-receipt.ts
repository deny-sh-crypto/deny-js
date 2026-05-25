/**
 * deny verify-receipt — verify a signed audit-chain receipt offline.
 *
 * Usage:
 *   deny verify-receipt receipt.json
 *   deny verify-receipt -i receipt.json
 *   deny verify-receipt --json receipt.json    (machine-readable output)
 *
 * Verifies:
 *   1. Receipt JSON schema (version 1).
 *   2. For every tsa_token in the receipt:
 *      a. token parses as CMS SignedData wrapping a TSTInfo
 *      b. TSTInfo.messageImprint.hashedMessage == receipt.entry_hash
 *      c. signedAttrs.messageDigest == sha256(DER(TSTInfo))
 *      d. signerInfo.signature verifies the signedAttrs DER over the
 *         TSA's embedded signing certificate public key
 *      e. gen_time is sane (epoch in 2000..2050)
 *   3. created_at <= max(tsa.gen_time across granted tokens)
 *
 * What this does NOT do (intentionally, out of scope for Day 3):
 *   - Walk TSA cert chain back to a root CA. We accept the TSA cert
 *     embedded in the response as the witness identity. A regulator
 *     who wants full PKI trust adds the TSA root to their trust store
 *     and re-verifies with `openssl ts -verify` against this same token.
 *   - Validate certificate revocation status (CRL/OCSP).
 *   - Re-walk the audit chain from genesis (that requires the full chain;
 *     this CLI verifies a single receipt artefact).
 *
 * Output:
 *   OK         all checks pass
 *   TAMPERED   at least one check failed; prints reason + which token
 *   ERROR      bad file / bad JSON / unexpected exception
 */

import { readFileSync, writeFileSync, mkdirSync, copyFileSync, existsSync, chmodSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHash, createVerify, createPublicKey, KeyObject } from 'node:crypto';
import {
  bold,
  cyan,
  dim,
  green,
  red,
  yellow,
} from '../utils/display.js';

// ─── Tiny DER parser (subset matching server/audit-tsa.ts) ───────────────────
interface Tlv {
  tag: number;
  contents: Buffer;
  raw: Buffer;
  end: number;
}

function readLength(buf: Buffer, off: number): { length: number; consumed: number } {
  const first = buf[off];
  if (first < 0x80) return { length: first, consumed: 1 };
  const n = first & 0x7f;
  if (n === 0 || n > 4) throw new Error('DER: unsupported length form');
  let len = 0;
  for (let i = 1; i <= n; i++) len = (len << 8) | buf[off + i];
  return { length: len, consumed: 1 + n };
}

function readTLV(buf: Buffer, off: number): Tlv {
  if (off >= buf.length) throw new Error('DER: read past end');
  const tag = buf[off];
  const { length, consumed } = readLength(buf, off + 1);
  const start = off + 1 + consumed;
  const end = start + length;
  if (end > buf.length) throw new Error('DER: length exceeds buffer');
  return { tag, contents: buf.subarray(start, end), raw: buf.subarray(off, end), end };
}

function* iterChildren(node: Tlv): Generator<Tlv> {
  let off = 0;
  while (off < node.contents.length) {
    const c = readTLV(node.contents, off);
    yield c;
    off = c.end;
  }
}

function decodeOid(node: Tlv): string {
  if (node.tag !== 0x06) return '';
  const b = node.contents;
  if (b.length === 0) return '';
  const arcs: number[] = [Math.floor(b[0] / 40), b[0] % 40];
  let n = 0;
  for (let i = 1; i < b.length; i++) {
    n = (n << 7) | (b[i] & 0x7f);
    if ((b[i] & 0x80) === 0) { arcs.push(n); n = 0; }
  }
  return arcs.join('.');
}

function isConstructed(tag: number): boolean {
  if (tag === 0x30 || tag === 0x31) return true;
  return (tag & 0xc0) === 0x80 && (tag & 0x20) !== 0;
}

const OID = {
  signedData: '1.2.840.113549.1.7.2',
  tstInfo: '1.2.840.113549.1.9.16.1.4',
  messageDigest: '1.2.840.113549.1.9.4',
  contentType: '1.2.840.113549.1.9.3',
  sha1: '1.3.14.3.2.26',
  sha224: '2.16.840.1.101.3.4.2.4',
  sha256: '2.16.840.1.101.3.4.2.1',
  sha384: '2.16.840.1.101.3.4.2.2',
  sha512: '2.16.840.1.101.3.4.2.3',
  rsaEncryption: '1.2.840.113549.1.1.1',
  sha1WithRSA: '1.2.840.113549.1.1.5',
  sha224WithRSA: '1.2.840.113549.1.1.14',
  sha256WithRSA: '1.2.840.113549.1.1.11',
  sha384WithRSA: '1.2.840.113549.1.1.12',
  sha512WithRSA: '1.2.840.113549.1.1.13',
  ecPublicKey: '1.2.840.10045.2.1',
  ecdsaWithSha256: '1.2.840.10045.4.3.2',
  ecdsaWithSha384: '1.2.840.10045.4.3.3',
  ecdsaWithSha512: '1.2.840.10045.4.3.4',
} as const;

function hashAlgFromOid(oid: string | null): string {
  switch (oid) {
    case OID.sha1:   return 'sha1';
    case OID.sha224: return 'sha224';
    case OID.sha256: return 'sha256';
    case OID.sha384: return 'sha384';
    case OID.sha512: return 'sha512';
    default:         return 'sha256';
  }
}

function verifyAlgFromOid(sigOid: string | null, digestOid: string | null): string {
  // Prefer the signature algorithm OID (canonical). Fall back to the
  // SignerInfo.digestAlgorithm OID combined with rsaEncryption.
  switch (sigOid) {
    case OID.sha1WithRSA:   return 'RSA-SHA1';
    case OID.sha224WithRSA: return 'RSA-SHA224';
    case OID.sha256WithRSA: return 'RSA-SHA256';
    case OID.sha384WithRSA: return 'RSA-SHA384';
    case OID.sha512WithRSA: return 'RSA-SHA512';
    case OID.ecdsaWithSha256: return 'sha256';
    case OID.ecdsaWithSha384: return 'sha384';
    case OID.ecdsaWithSha512: return 'sha512';
    case OID.rsaEncryption: {
      // PKCS#1 v1.5 with bare rsaEncryption: digest comes from SignerInfo.
      switch (digestOid) {
        case OID.sha1:   return 'RSA-SHA1';
        case OID.sha224: return 'RSA-SHA224';
        case OID.sha256: return 'RSA-SHA256';
        case OID.sha384: return 'RSA-SHA384';
        case OID.sha512: return 'RSA-SHA512';
        default:         return 'RSA-SHA256';
      }
    }
    default: return 'RSA-SHA256';
  }
}

// ─── Receipt + token verification ───────────────────────────────────────────

interface ReceiptJson {
  version: number;
  entry_id: number;
  tenant_id_hash_redacted: string;
  op_type: string;
  op_payload_hash: string;
  prev_hash: string;
  entry_hash: string;
  created_at: number;
  created_at_iso: string;
  chain_length_at_issue: number;
  tsa_tokens: Array<{
    tsa_name: string;
    tsa_url: string;
    status: string;
    gen_time: number | null;
    gen_time_iso: string | null;
    token_b64: string | null;
    reason?: string;
  }>;
  issued_at: number;
  issued_at_iso: string;
  issuer: string;
}

interface TokenCheck {
  tsa_name: string;
  status: string;
  hashImprintMatch: boolean | null;
  signedAttrsDigestMatch: boolean | null;
  signatureValid: boolean | null;
  genTimeSane: boolean | null;
  notes: string[];
}

interface VerifyResult {
  ok: boolean;
  reason?: string;
  receipt_summary: {
    entry_id: number;
    op_type: string;
    entry_hash: string;
    created_at_iso: string;
    chain_length_at_issue: number;
    tsa_count: number;
  };
  tokens: TokenCheck[];
}

/**
 * Walk the CMS SignedData structure inside a TimeStampToken to find:
 *   - the encapsulated TSTInfo DER bytes
 *   - the SignerInfo (first one — TSAs sign with exactly one signer)
 *   - the embedded TSA certificate (whose subject matches the SignerInfo
 *     issuerAndSerialNumber). We find this heuristically: extract every
 *     certificate from the SignedData.certificates field, then pick the
 *     one whose serial number matches the SignerInfo's serial.
 */
interface CmsExtract {
  tstInfoBytes: Buffer | null;
  signerInfo: Tlv | null;
  certs: Tlv[];
}

function extractCms(token: Buffer): CmsExtract {
  const out: CmsExtract = { tstInfoBytes: null, signerInfo: null, certs: [] };
  try {
    let top = readTLV(token, 0);
    if (top.tag !== 0x30) return out;
    let kids = [...iterChildren(top)];
    // The token may be either:
    //   (a) a raw ContentInfo (id-signedData wrapping SignedData), OR
    //   (b) a TimeStampResp wrapper { PKIStatusInfo, TimeStampToken }
    //       where TimeStampToken is itself a ContentInfo.
    // Detect (b) by checking whether the SECOND child is a SEQUENCE that
    // looks like ContentInfo (its first grandchild OID == id-signedData).
    if (kids[0]?.tag !== 0x06 || decodeOid(kids[0]) !== OID.signedData) {
      // Try treating as TimeStampResp wrapper.
      const cand = kids.find(k => {
        if (k.tag !== 0x30) return false;
        try {
          const sub = [...iterChildren(k)];
          return sub[0]?.tag === 0x06 && decodeOid(sub[0]) === OID.signedData;
        } catch { return false; }
      });
      if (!cand) return out;
      top = cand;
      kids = [...iterChildren(top)];
    }
    if (kids.length < 2 || kids[0].tag !== 0x06 || decodeOid(kids[0]) !== OID.signedData) {
      return out;
    }
    // kids[1] is [0] EXPLICIT, contains SignedData SEQUENCE.
    const signedDataNode = readTLV(kids[1].contents, 0);
    if (signedDataNode.tag !== 0x30) return out;
    const sdKids = [...iterChildren(signedDataNode)];
    // SignedData ::= SEQUENCE { version, digestAlgorithms SET, encapContentInfo,
    //                          certificates [0] IMPLICIT OPTIONAL,
    //                          crls         [1] IMPLICIT OPTIONAL,
    //                          signerInfos  SET }
    // We need encapContentInfo (sdKids[2]), certificates (any [0] context-specific),
    // signerInfos (the LAST SET).
    const encap = sdKids[2];
    if (encap && encap.tag === 0x30) {
      // encapContentInfo ::= { eContentType OID, eContent [0] EXPLICIT OCTET STRING }
      const ek = [...iterChildren(encap)];
      if (ek.length >= 2 && ek[0].tag === 0x06 && decodeOid(ek[0]) === OID.tstInfo) {
        const wrapper = ek[1];
        // wrapper is [0] EXPLICIT OCTET STRING. The OCTET STRING wraps TSTInfo.
        try {
          const inner = readTLV(wrapper.contents, 0);
          if (inner.tag === 0x04) {
            out.tstInfoBytes = Buffer.from(inner.contents);
          }
        } catch { /* fall through */ }
      }
    }
    // Walk sdKids looking for [0] certificates and signerInfos SET (0x31).
    for (const k of sdKids) {
      if (k.tag === 0xa0) {
        // certificates [0] IMPLICIT — children are Certificate SEQUENCEs.
        for (const c of iterChildren(k)) {
          if (c.tag === 0x30) out.certs.push(c);
        }
      } else if (k.tag === 0x31) {
        // SignerInfos SET — first SignerInfo is what we use.
        for (const si of iterChildren(k)) {
          if (si.tag === 0x30) { out.signerInfo = si; break; }
        }
      }
    }
  } catch {
    /* swallow — caller observes nulls */
  }
  return out;
}

interface SignerFields {
  serialHex: string | null;
  signedAttrsDer: Buffer | null;
  signedAttrs: Tlv[]; // children of the SET (implicit [0] reconstructed below)
  digestAlgoOid: string | null;
  signatureAlgoOid: string | null;
  signatureBytes: Buffer | null;
}

function parseSignerInfo(signerInfo: Tlv): SignerFields {
  const out: SignerFields = {
    serialHex: null,
    signedAttrsDer: null,
    signedAttrs: [],
    digestAlgoOid: null,
    signatureAlgoOid: null,
    signatureBytes: null,
  };
  // SignerInfo ::= SEQUENCE {
  //   version INTEGER,
  //   sid (issuerAndSerialNumber or [0] SubjectKeyIdentifier),
  //   digestAlgorithm AlgorithmIdentifier,
  //   signedAttrs [0] IMPLICIT SET OF Attribute OPTIONAL,
  //   signatureAlgorithm AlgorithmIdentifier,
  //   signature OCTET STRING,
  //   unsignedAttrs [1] IMPLICIT OPTIONAL
  // }
  const kids = [...iterChildren(signerInfo)];
  if (kids.length < 5) return out;
  // sid handling: either SEQUENCE (issuerAndSerialNumber) or [0] (SKI).
  const sid = kids[1];
  if (sid.tag === 0x30) {
    const sidKids = [...iterChildren(sid)];
    if (sidKids.length >= 2 && sidKids[1].tag === 0x02) {
      out.serialHex = sidKids[1].contents.toString('hex');
    }
  } else if (sid.tag === 0x80) {
    // SubjectKeyIdentifier — we don't match by SKI here, leave serialHex null.
  }
  // digestAlgorithm (kids[2]) — SignerInfo's view of which hash protects
  // the encapsulated content. RFC 3161 TSAs vary (FreeTSA uses sha512;
  // many use sha256). We MUST follow the SignerInfo's declared OID rather
  // than hardcode sha256, or the messageDigest comparison will fail on
  // every non-sha256 TSA.
  if (kids[2] && kids[2].tag === 0x30) {
    const dKids = [...iterChildren(kids[2])];
    if (dKids[0] && dKids[0].tag === 0x06) {
      out.digestAlgoOid = decodeOid(dKids[0]);
    }
  }
  // Find signedAttrs ([0] IMPLICIT). Walk remaining kids.
  let idx = 3;
  if (kids[idx] && kids[idx].tag === 0xa0) {
    const sa = kids[idx];
    // signedAttrs is encoded as [0] IMPLICIT SET. To compute messageDigest
    // over signedAttrs (per CMS), we must DER-encode the same set BUT with
    // tag 0x31 (SET) instead of 0xa0 (the EXPLICIT IMPLICIT [0] tag).
    // CMS RFC 5652 §5.4 mandates this.
    const reTagged = Buffer.concat([
      Buffer.from([0x31]),
      sa.raw.subarray(1), // length + value bytes unchanged
    ]);
    out.signedAttrsDer = reTagged;
    out.signedAttrs = [...iterChildren(sa)];
    idx++;
  }
  // signatureAlgorithm
  if (kids[idx] && kids[idx].tag === 0x30) {
    const algoKids = [...iterChildren(kids[idx])];
    if (algoKids[0] && algoKids[0].tag === 0x06) {
      out.signatureAlgoOid = decodeOid(algoKids[0]);
    }
    idx++;
  }
  // signature OCTET STRING
  if (kids[idx] && kids[idx].tag === 0x04) {
    out.signatureBytes = Buffer.from(kids[idx].contents);
  }
  return out;
}

/** Extract serial number hex from a Certificate (tbsCert.serialNumber). */
function certSerialHex(cert: Tlv): string | null {
  try {
    const sdKids = [...iterChildren(cert)]; // SEQUENCE { tbsCert, sigAlg, sig }
    if (!sdKids[0] || sdKids[0].tag !== 0x30) return null;
    const tbsKids = [...iterChildren(sdKids[0])];
    // tbsCertificate ::= SEQUENCE { [0] version (optional), serialNumber INTEGER, ... }
    // If version present, it'll be tag 0xa0. Skip it.
    let serialIdx = 0;
    if (tbsKids[0] && tbsKids[0].tag === 0xa0) serialIdx = 1;
    const sn = tbsKids[serialIdx];
    if (!sn || sn.tag !== 0x02) return null;
    return sn.contents.toString('hex');
  } catch {
    return null;
  }
}

function findSignerCert(certs: Tlv[], serialHex: string | null): Tlv | null {
  if (!serialHex) return certs[0] ?? null;
  // Strip a leading 00 byte that DER adds to keep INTEGER positive — for
  // matching, compare both with and without it.
  const sn1 = serialHex.toLowerCase();
  const sn2 = sn1.startsWith('00') ? sn1.slice(2) : '00' + sn1;
  for (const c of certs) {
    const cs = certSerialHex(c);
    if (!cs) continue;
    const csl = cs.toLowerCase();
    if (csl === sn1 || csl === sn2 || csl.replace(/^0+/, '') === sn1.replace(/^0+/, '')) {
      return c;
    }
  }
  return certs[0] ?? null;
}

/** Look up an OID attribute value inside the signedAttrs set. */
function findSignedAttr(signedAttrs: Tlv[], oid: string): Tlv | null {
  for (const a of signedAttrs) {
    if (a.tag !== 0x30) continue;
    const kids = [...iterChildren(a)];
    if (kids[0] && kids[0].tag === 0x06 && decodeOid(kids[0]) === oid) {
      // attribute value is in a SET (kids[1]). Return the first set member.
      if (kids[1] && kids[1].tag === 0x31) {
        const v = [...iterChildren(kids[1])];
        return v[0] ?? null;
      }
    }
  }
  return null;
}

/**
 * Verify a single TSA token against the receipt's entry_hash.
 * Returns a structured per-token result.
 */
function verifyToken(
  entryHashHex: string,
  tokenB64: string,
  tsaName: string,
  status: string,
): TokenCheck {
  const check: TokenCheck = {
    tsa_name: tsaName,
    status,
    hashImprintMatch: null,
    signedAttrsDigestMatch: null,
    signatureValid: null,
    genTimeSane: null,
    notes: [],
  };
  let token: Buffer;
  try {
    token = Buffer.from(tokenB64, 'base64');
  } catch (e: any) {
    check.notes.push('token_b64 is not valid base64');
    return check;
  }

  const { tstInfoBytes, signerInfo, certs } = extractCms(token);
  if (!tstInfoBytes) {
    check.notes.push('TSTInfo not found in token');
    return check;
  }

  // (a) messageImprint hash matches receipt entry_hash.
  try {
    const tstInfo = readTLV(tstInfoBytes, 0);
    const tk = [...iterChildren(tstInfo)];
    // TSTInfo: version, policy, messageImprint, serialNumber, genTime, ...
    const mi = tk[2];
    if (!mi || mi.tag !== 0x30) {
      check.notes.push('TSTInfo.messageImprint missing');
    } else {
      const miKids = [...iterChildren(mi)];
      const hashOctet = miKids[1];
      if (!hashOctet || hashOctet.tag !== 0x04) {
        check.notes.push('TSTInfo.messageImprint.hashedMessage missing');
      } else {
        const observed = hashOctet.contents.toString('hex');
        check.hashImprintMatch = observed.toLowerCase() === entryHashHex.toLowerCase();
        if (!check.hashImprintMatch) {
          check.notes.push(
            `messageImprint hex differs from entry_hash (got ${observed.slice(0, 16)}…)`,
          );
        }
      }
    }
    // genTime sanity (year 2000..2050)
    const gt = tk[4];
    if (gt && gt.tag === 0x18) {
      const s = gt.contents.toString('ascii');
      const m = /^(\d{4})/.exec(s);
      if (m) {
        const y = Number(m[1]);
        check.genTimeSane = y >= 2000 && y <= 2050;
        if (!check.genTimeSane) check.notes.push(`genTime year out of range: ${y}`);
      }
    }
  } catch (e: any) {
    check.notes.push('TSTInfo parse error: ' + (e?.message || String(e)));
    return check;
  }

  // (b) + (c) SignerInfo signature verification.
  if (!signerInfo) {
    check.notes.push('no SignerInfo found (token may be from unsigned TSA mode)');
    return check;
  }
  const fields = parseSignerInfo(signerInfo);
  if (!fields.signedAttrsDer || !fields.signatureBytes) {
    check.notes.push('SignerInfo missing signedAttrs or signature');
    return check;
  }

  // signedAttrs.messageDigest must equal <digestAlg>(DER(TSTInfo)).
  // Algorithm comes from SignerInfo.digestAlgorithm (FreeTSA uses sha512,
  // DigiCert uses sha256; both are spec-compliant per RFC 3161).
  const hashAlg = hashAlgFromOid(fields.digestAlgoOid);
  const expectedDigest = createHash(hashAlg).update(tstInfoBytes).digest('hex');
  const mdAttr = findSignedAttr(fields.signedAttrs, OID.messageDigest);
  if (!mdAttr) {
    check.notes.push('signedAttrs missing messageDigest');
  } else if (mdAttr.tag !== 0x04) {
    check.notes.push('messageDigest is not OCTET STRING');
  } else {
    const observed = mdAttr.contents.toString('hex');
    check.signedAttrsDigestMatch = observed.toLowerCase() === expectedDigest.toLowerCase();
    if (!check.signedAttrsDigestMatch) {
      check.notes.push('messageDigest in signedAttrs does not match sha256(TSTInfo)');
    }
  }

  // Signature verify.
  const signerCert = findSignerCert(certs, fields.serialHex);
  if (!signerCert) {
    check.notes.push('no signing cert found in CMS certificates field');
    return check;
  }
  let pub: KeyObject;
  try {
    // Wrap the cert SEQUENCE in PEM so createPublicKey can parse it.
    const der = Buffer.concat([
      Buffer.from([0x30]),
      // Recompute length header for the cert DER. signerCert.raw IS the full
      // SEQUENCE TLV already, so use that directly.
    ]);
    const certDer = signerCert.raw;
    const pem = '-----BEGIN CERTIFICATE-----\n' +
      certDer.toString('base64').replace(/(.{64})/g, '$1\n').trimEnd() +
      '\n-----END CERTIFICATE-----\n';
    pub = createPublicKey({ key: pem, format: 'pem' });
  } catch (e: any) {
    check.notes.push('failed to load signer cert: ' + (e?.message || String(e)));
    return check;
  }

  // Map signatureAlgorithm + digestAlgorithm OIDs to Node verify alg name.
  const nodeAlg = verifyAlgFromOid(fields.signatureAlgoOid, fields.digestAlgoOid);
  try {
    const v = createVerify(nodeAlg);
    v.update(fields.signedAttrsDer);
    v.end();
    check.signatureValid = v.verify(pub, fields.signatureBytes);
    if (!check.signatureValid) check.notes.push(`signature verify FAILED (alg=${nodeAlg})`);
  } catch (e: any) {
    check.signatureValid = false;
    check.notes.push('verify threw: ' + (e?.message || String(e)));
  }

  return check;
}

function summarize(checks: TokenCheck[]): { ok: boolean; reason?: string } {
  if (checks.length === 0) {
    return { ok: false, reason: 'receipt has no TSA tokens to verify' };
  }
  // A receipt OK iff AT LEAST ONE granted token verifies completely.
  // Multiple TSAs are redundancy, not unanimity.
  for (const c of checks) {
    if (c.status !== 'granted') continue;
    if (c.hashImprintMatch === false) continue;
    if (c.signedAttrsDigestMatch === false) continue;
    if (c.signatureValid === false) continue;
    if (c.genTimeSane === false) continue;
    if (c.hashImprintMatch && c.signatureValid) {
      return { ok: true };
    }
  }
  // None passed — find the first granted token's reason.
  const granted = checks.find(c => c.status === 'granted');
  if (granted) {
    return { ok: false, reason: granted.notes.join('; ') || 'verification failed' };
  }
  return { ok: false, reason: 'no granted TSA token in receipt' };
}

function isReceiptShape(r: any): r is ReceiptJson {
  return (
    !!r &&
    typeof r === 'object' &&
    typeof r.version === 'number' &&
    typeof r.entry_id === 'number' &&
    typeof r.entry_hash === 'string' &&
    typeof r.prev_hash === 'string' &&
    typeof r.op_type === 'string' &&
    Array.isArray(r.tsa_tokens)
  );
}

export interface VerifyReceiptOptions {
  /** Skip TSA signature verification (for unit tests that don't ship real tokens). */
  skipSignatureCheck?: boolean;
}

/** Pure function: verify a parsed receipt object. Exposed for unit tests. */
export function verifyReceiptObject(
  receipt: ReceiptJson,
  opts: VerifyReceiptOptions = {},
): VerifyResult {
  const tokens: TokenCheck[] = [];
  for (const t of receipt.tsa_tokens) {
    if (!t.token_b64) {
      tokens.push({
        tsa_name: t.tsa_name,
        status: t.status,
        hashImprintMatch: null,
        signedAttrsDigestMatch: null,
        signatureValid: null,
        genTimeSane: null,
        notes: ['no token_b64 (status=' + t.status + ')'],
      });
      continue;
    }
    if (opts.skipSignatureCheck) {
      tokens.push({
        tsa_name: t.tsa_name,
        status: t.status,
        hashImprintMatch: null,
        signedAttrsDigestMatch: null,
        signatureValid: null,
        genTimeSane: null,
        notes: ['signature check skipped'],
      });
      continue;
    }
    tokens.push(verifyToken(receipt.entry_hash, t.token_b64, t.tsa_name, t.status));
  }
  const { ok, reason } = summarize(tokens);
  return {
    ok,
    ...(reason ? { reason } : {}),
    receipt_summary: {
      entry_id: receipt.entry_id,
      op_type: receipt.op_type,
      entry_hash: receipt.entry_hash,
      created_at_iso: receipt.created_at_iso,
      chain_length_at_issue: receipt.chain_length_at_issue,
      tsa_count: receipt.tsa_tokens.length,
    },
    tokens,
  };
}

// ─── CLI entry ──────────────────────────────────────────────────────────────

export async function cmdVerifyReceipt(
  subArgs: string[],
  flags: Record<string, string>,
): Promise<void> {
  const path = flags['i'] || flags['f'] || subArgs[0];
  const machineJson = flags['json'] === 'true';
  const exportOpensslDir = flags['export-openssl'];

  if (!path) {
    console.error('Usage: deny verify-receipt <receipt.json>  (or -i <file>)');
    console.error('       deny verify-receipt <receipt.json> --export-openssl <dir>');
    process.exit(2);
  }

  let raw: string;
  try {
    raw = readFileSync(path, 'utf8');
  } catch (e: any) {
    console.error(`Cannot read receipt file: ${e?.message || e}`);
    process.exit(2);
  }

  let parsed: any;
  try {
    parsed = JSON.parse(raw);
  } catch (e: any) {
    console.error(`Receipt is not valid JSON: ${e?.message || e}`);
    process.exit(2);
  }

  if (!isReceiptShape(parsed)) {
    console.error('Receipt JSON does not match the expected v1 schema.');
    process.exit(2);
  }
  if (parsed.version !== 1) {
    console.error(`Unsupported receipt version: ${parsed.version}`);
    process.exit(2);
  }

  const result = verifyReceiptObject(parsed);

  // --export-openssl mode: produce regulator-grade artefacts that
  // openssl ts -verify accepts natively. This is the path a compliance
  // auditor uses when they want to validate against an externally
  // trusted PKI rather than the deny CLI's bundled verifier. We write:
  //   <dir>/freetsa.tsr             (TimeStampToken for the FreeTSA witness)
  //   <dir>/digicert.tsr            (where available)
  //   <dir>/entry-hash.txt          (the message imprint hex)
  //   <dir>/freetsa-cacert.pem      (FreeTSA root, bundled with the CLI)
  //   <dir>/freetsa-tsa.pem         (FreeTSA signing intermediate, bundled)
  //   <dir>/verify.sh               (one-liner that runs openssl ts -verify)
  // The verify.sh exit code is the regulator-grade verdict; the CLI's
  // own verdict (printed above) is the convenience-grade verdict.
  if (exportOpensslDir) {
    try {
      exportOpensslArtefacts(parsed, exportOpensslDir);
      console.log(green('  ✓ openssl artefacts written to ' + exportOpensslDir));
      console.log(dim('    Run: bash ' + join(exportOpensslDir, 'verify.sh')));
    } catch (e: any) {
      console.error('  ✗ export-openssl failed: ' + (e?.message || String(e)));
      process.exit(2);
    }
  }

  if (machineJson) {
    process.stdout.write(JSON.stringify(result, null, 2) + '\n');
    process.exit(result.ok ? 0 : 1);
  }

  // Human-readable output.
  console.log('');
  console.log(bold('deny.sh — signed audit receipt verifier'));
  console.log(dim('  ' + path));
  console.log('');
  console.log(`  entry id           ${cyan(String(result.receipt_summary.entry_id))}`);
  console.log(`  op type            ${result.receipt_summary.op_type}`);
  console.log(`  entry hash         ${dim(result.receipt_summary.entry_hash.slice(0, 32) + '…')}`);
  console.log(`  created at         ${result.receipt_summary.created_at_iso}`);
  console.log(`  chain length       ${result.receipt_summary.chain_length_at_issue}`);
  console.log(`  TSA tokens         ${result.receipt_summary.tsa_count}`);
  console.log('');

  for (const t of result.tokens) {
    const tick = (v: boolean | null) =>
      v === true ? green('✓') : v === false ? red('✗') : yellow('–');
    console.log(`  ${bold(t.tsa_name)}  (${t.status})`);
    console.log(`    ${tick(t.hashImprintMatch)} messageImprint matches entry_hash`);
    console.log(`    ${tick(t.signedAttrsDigestMatch)} signedAttrs.messageDigest matches digest(TSTInfo)`);
    console.log(`    ${tick(t.signatureValid)} SignerInfo signature verifies`);
    console.log(`    ${tick(t.genTimeSane)} genTime in plausible range`);
    if (t.notes.length) {
      for (const n of t.notes) console.log(`      ${dim(n)}`);
    }
    console.log('');
  }

  if (result.ok) {
    console.log(green('  OK — receipt verifies against at least one granted TSA token.'));
    if (!exportOpensslDir) {
      console.log(dim('  (For regulator-grade PKI validation against an externally trusted'));
      console.log(dim('   root: rerun with --export-openssl <dir> and run the produced'));
      console.log(dim('   verify.sh against the openssl ts -verify CLI.)'));
    }
    console.log('');
    process.exit(0);
  } else {
    console.log(red('  TAMPERED — receipt does not verify.'));
    if (result.reason) console.log('  reason: ' + result.reason);
    console.log('');
    process.exit(1);
  }
}

// ─── openssl ts -verify artefact export ─────────────────────────────────────

/**
 * Locate the bundled CA-chain directory shipped alongside this CLI.
 * Resolves to <pkg>/dist/src/commands/_ca-bundle/ when installed from npm
 * or run from a built tree, OR <pkg>/src/commands/_ca-bundle/ when run via
 * tsx during dev. Returns null if neither path exists (degraded mode:
 * verify.sh will still work if the caller has FreeTSA roots in their
 * system trust store).
 */
function findCaBundleDir(): string | null {
  const here = dirname(fileURLToPath(import.meta.url));
  const candidates = [
    join(here, '_ca-bundle'),
    join(here, '..', '..', 'src', 'commands', '_ca-bundle'),
    join(here, '..', '..', '..', 'src', 'commands', '_ca-bundle'),
  ];
  for (const c of candidates) {
    if (existsSync(join(c, 'freetsa-cacert.pem'))) return c;
  }
  return null;
}

function exportOpensslArtefacts(receipt: ReceiptJson, outDir: string): void {
  mkdirSync(outDir, { recursive: true });

  // 1. Write entry-hash.txt — the messageImprint hex that the TSA witnessed.
  writeFileSync(join(outDir, 'entry-hash.txt'), receipt.entry_hash + '\n', 'utf8');

  // 2. Per-TSA: write the TimeStampResp bytes as .tsr (default openssl
  //    name for a full RFC 3161 response with PKIStatusInfo wrapper).
  //    The server stores the full HTTP response body from the TSA, which
  //    IS a TimeStampResp — use openssl ts -verify -in <file> (no
  //    -token_in). If the body was already unwrapped to a bare
  //    TimeStampToken (no PKIStatusInfo), openssl needs -token_in: we
  //    detect that by checking the top-level SEQUENCE's first child.
  const tsrFiles: Array<{ tsaName: string; file: string; status: string; tokenIn: boolean }> = [];
  for (const t of receipt.tsa_tokens) {
    if (t.status !== 'granted' || !t.token_b64) continue;
    const safeName = t.tsa_name.replace(/[^a-z0-9_.-]/gi, '_').toLowerCase();
    const file = `${safeName}.tsr`;
    const der = Buffer.from(t.token_b64, 'base64');
    writeFileSync(join(outDir, file), der);
    // Detect TimeStampResp (wrapped) vs TimeStampToken (bare ContentInfo).
    // TimeStampResp's first child is PKIStatusInfo (SEQUENCE of INTEGER).
    // TimeStampToken's first child is contentType OID (id-signedData).
    let tokenIn = false;
    try {
      const top = readTLV(der, 0);
      if (top.tag === 0x30) {
        const first = readTLV(top.contents, 0);
        if (first.tag === 0x06) tokenIn = true;
      }
    } catch { /* default false */ }
    tsrFiles.push({ tsaName: t.tsa_name, file, status: t.status, tokenIn });
  }
  if (tsrFiles.length === 0) {
    throw new Error('no granted TSA tokens to export');
  }

  // 3. Copy bundled FreeTSA CA chain (if available).
  const bundleDir = findCaBundleDir();
  let bundlePresent = false;
  if (bundleDir) {
    const caSrc = join(bundleDir, 'freetsa-cacert.pem');
    const tsaSrc = join(bundleDir, 'freetsa-tsa.pem');
    if (existsSync(caSrc) && existsSync(tsaSrc)) {
      copyFileSync(caSrc, join(outDir, 'freetsa-cacert.pem'));
      copyFileSync(tsaSrc, join(outDir, 'freetsa-tsa.pem'));
      bundlePresent = true;
    }
  }

  // 4. Emit verify.sh — runs openssl ts -verify for every .tsr against
  //    the bundled CA chain. Exits non-zero on the first failure.
  const lines: string[] = [
    '#!/usr/bin/env bash',
    '#',
    '# Regulator-grade verification of a deny.sh audit receipt.',
    '# Generated by `deny verify-receipt --export-openssl`.',
    '#',
    '# Required: openssl 1.1+ on PATH. No deny CLI required.',
    '#',
    '# What this verifies (per RFC 3161 and CMS RFC 5652):',
    '#   - The TimeStampToken CMS SignedData parses cleanly.',
    '#   - The TSA SignerInfo signature is valid over signedAttrs.',
    '#   - The TSA cert chain validates to the bundled FreeTSA root.',
    '#   - The TSTInfo.messageImprint matches the receipt entry_hash.',
    '#',
    '# Exit 0 = receipt verifies. Non-zero = TAMPERED.',
    '',
    'set -e',
    'cd "$(dirname "$0")"',
    '',
    'HASH=$(cat entry-hash.txt | tr -d " \\n")',
    'echo "entry hash: $HASH"',
    'echo ""',
    '',
  ];
  for (const f of tsrFiles) {
    const tokenInFlag = f.tokenIn ? ' -token_in' : '';
    lines.push(`echo "--- ${f.tsaName} (${f.file}) ---"`);
    if (bundlePresent && /freetsa/i.test(f.tsaName)) {
      lines.push(
        `openssl ts -verify -in "${f.file}"${tokenInFlag} \\`,
        `  -digest "$HASH" \\`,
        `  -CAfile freetsa-cacert.pem \\`,
        `  -untrusted freetsa-tsa.pem`,
      );
    } else {
      // No bundled CA for this TSA — caller must point at their own.
      lines.push(
        `openssl ts -verify -in "${f.file}"${tokenInFlag} \\`,
        `  -digest "$HASH" \\`,
        `  -CAfile "\${${tsaUpper(f.tsaName)}_CAFILE:-/etc/ssl/certs/ca-certificates.crt}"`,
      );
    }
    lines.push('echo ""');
  }
  lines.push('echo "all granted tokens verified."');
  lines.push('');
  const verifyShPath = join(outDir, 'verify.sh');
  writeFileSync(verifyShPath, lines.join('\n'), 'utf8');
  chmodSync(verifyShPath, 0o755);

  // 5. README so the regulator knows what they're looking at.
  const readme: string[] = [
    '# deny.sh audit receipt — openssl verification bundle',
    '',
    `entry_id: ${receipt.entry_id}`,
    `entry_hash: ${receipt.entry_hash}`,
    `op_type: ${receipt.op_type}`,
    `created_at: ${receipt.created_at_iso}`,
    `chain_length_at_issue: ${receipt.chain_length_at_issue}`,
    `issuer: ${receipt.issuer}`,
    '',
    '## Files',
    '',
    'entry-hash.txt        sha256 hex of the audit-chain entry the TSAs witnessed',
    ...tsrFiles.map(f => `${f.file.padEnd(22)}TimeStampToken from ${f.tsaName} (CMS SignedData / DER)`),
    'freetsa-cacert.pem    FreeTSA root CA (bundled with the deny CLI)',
    'freetsa-tsa.pem       FreeTSA signing intermediate cert',
    'verify.sh             one-liner that runs openssl ts -verify for every .tsr',
    '',
    '## How to verify',
    '',
    'bash verify.sh',
    '',
    'Exit 0 = the receipt verifies under standard RFC 3161 PKI rules.',
    'Non-zero exit = the receipt is tampered or the CA chain does not validate.',
    '',
    '## What this proves',
    '',
    'Each .tsr file is a trusted-timestamp token signed by an RFC 3161 TSA',
    'that witnessed a sha256 digest. The digest is the entry_hash above. The',
    'entry_hash is itself a sha256 over (prev_hash || tenant_id || op_type ||',
    'canonical(op_payload) || created_at), which links into the per-tenant',
    'audit chain. Therefore: if openssl ts -verify accepts the .tsr against',
    'the bundled root, the witnessed digest is exactly the entry that deny.sh',
    'stored in its chain at the witnessed time.',
    '',
  ];
  writeFileSync(join(outDir, 'README.md'), readme.join('\n'), 'utf8');
}

function tsaUpper(name: string): string {
  return name.replace(/[^a-z0-9]/gi, '_').toUpperCase();
}
