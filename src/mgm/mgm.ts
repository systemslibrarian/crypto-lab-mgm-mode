/**
 * Multilinear Galois Mode — RFC 9058 sections 4.1 and 4.2, over any
 * BlockCipher with n = 64 (Magma) or n = 128 (Kuznyechik).
 *
 * The one idea the lab exists to show:
 *
 *   GCM authenticates with ONE hash key H = E_K(0^128); the tag is a polynomial
 *   in that single H.
 *   MGM derives a DISTINCT authentication coefficient for every block,
 *   H_i = E_K(Z_i), from a counter Z that starts at E_K(1 || ICN) and steps its
 *   LEFT half, while the encryption counter Y starts at E_K(0 || ICN) and steps
 *   its RIGHT half. The tag is a multilinear function of the blocks, and its
 *   value is then ENCRYPTED: T = MSB_S(E_K(sum)).
 *
 * Everything below returns its whole trace, because the page shows every Y_i,
 * E_K(Y_i), Z_i, H_i and running sum, and the tests compare each one with the
 * values RFC 9058 Appendix A prints — not only the final tag.
 */
import type { BlockCipher } from '../cipher/types';
import { bytesToBigInt, bigIntToBytes, equalBytes, xorBytes } from '../cipher/bytes';
import { gfMul } from './gf';

export interface MgmTrace {
  /** n / 8. */
  blockBytes: number;
  /** 0^1 || ICN and 1^1 || ICN, the two counter seeds before encryption. */
  encSeed: Uint8Array;
  authSeed: Uint8Array;
  /** Y_1..Y_q and E_K(Y_1)..E_K(Y_q). */
  y: Uint8Array[];
  keystream: Uint8Array[];
  /** Z_1..Z_{h+q+1} and H_1..H_{h+q+1}. */
  z: Uint8Array[];
  h: Uint8Array[];
  /** The padded blocks each H_i multiplies: A_1..A_h then C_1..C_q. */
  authBlocks: { kind: 'A' | 'C'; index: number; block: Uint8Array }[];
  /** sum after each A_i and C_j term, in order. */
  runningSum: Uint8Array[];
  /** len(A) || len(C), lengths in BITS. */
  lengthBlock: Uint8Array;
  /** sum xor (H_{h+q+1} (x) (len(A) || len(C))) — the value that gets encrypted. */
  finalSum: Uint8Array;
  /** E_K(finalSum) before truncation. */
  fullTag: Uint8Array;
}

export interface MgmResult {
  ciphertext: Uint8Array;
  tag: Uint8Array;
  trace: MgmTrace;
}

export class MgmInputError extends Error {}

/** incr_r: add 1 to the right half, mod 2^{n/2}. */
export function incrR(block: Uint8Array): Uint8Array {
  const half = block.length / 2;
  const out = block.slice();
  const r = (bytesToBigInt(block.subarray(half)) + 1n) & ((1n << BigInt(half * 8)) - 1n);
  out.set(bigIntToBytes(r, half), half);
  return out;
}

/** incr_l: add 1 to the left half, mod 2^{n/2}. */
export function incrL(block: Uint8Array): Uint8Array {
  const half = block.length / 2;
  const out = block.slice();
  const l = (bytesToBigInt(block.subarray(0, half)) + 1n) & ((1n << BigInt(half * 8)) - 1n);
  out.set(bigIntToBytes(l, half), 0);
  return out;
}

function splitBlocks(data: Uint8Array, n: number): Uint8Array[] {
  const blocks: Uint8Array[] = [];
  for (let i = 0; i < data.length; i += n) {
    const piece = data.subarray(i, Math.min(i + n, data.length));
    const padded = new Uint8Array(n); // A_h = A*_h || 0^{n-t}
    padded.set(piece);
    blocks.push(padded);
  }
  return blocks;
}

/**
 * Fail closed on everything RFC 9058 forbids rather than computing something.
 * The ICN is n-1 bits; it is passed as an n-byte block whose top bit must be 0,
 * the form RFC 9058's own vectors print ("0^1 || ICN").
 */
function validate(cipher: BlockCipher, icn: Uint8Array, aad: Uint8Array, body: Uint8Array, tagBytes: number) {
  const n = cipher.blockBytes;
  if (icn.length !== n) throw new MgmInputError(`ICN must be ${n} bytes for ${cipher.name}, got ${icn.length}`);
  if (icn[0] & 0x80) {
    throw new MgmInputError('ICN is n-1 bits: its top bit must be 0, because MGM sets that bit itself to separate the two counters');
  }
  if (aad.length === 0 && body.length === 0) {
    // RFC 9058 section 6: with both empty the tag no longer depends on the nonce.
    throw new MgmInputError('MGM must not process empty associated data and empty plaintext together (RFC 9058 section 6)');
  }
  const limitBits = 2n ** BigInt(n * 4); // 2^{n/2}
  if (BigInt(aad.length + body.length) * 8n >= limitBits) {
    throw new MgmInputError(`|A| + |P| must be under 2^${n * 4} bits`);
  }
  if (!Number.isInteger(tagBytes) || tagBytes < 4 || tagBytes > n) {
    throw new MgmInputError(`tag length must be 4..${n} bytes (32 <= S <= n bits)`);
  }
}

/** The shared tag computation of 4.1 step 3 and 4.2 step 2. */
function computeTag(cipher: BlockCipher, icn: Uint8Array, aad: Uint8Array, ct: Uint8Array, tagBytes: number) {
  const n = cipher.blockBytes;
  const authSeed = icn.slice();
  authSeed[0] |= 0x80; // 1^1 || ICN
  const aBlocks = splitBlocks(aad, n);
  const cBlocks = splitBlocks(ct, n);
  const authBlocks = [
    ...aBlocks.map((block, i) => ({ kind: 'A' as const, index: i + 1, block })),
    ...cBlocks.map((block, i) => ({ kind: 'C' as const, index: i + 1, block })),
  ];
  const z: Uint8Array[] = [cipher.encryptBlock(authSeed)];
  const h: Uint8Array[] = [];
  const runningSum: Uint8Array[] = [];
  let sum = new Uint8Array(n);
  for (const { block } of authBlocks) {
    const hi = cipher.encryptBlock(z[z.length - 1]);
    h.push(hi);
    sum = xorBytes(sum, gfMul(hi, block));
    runningSum.push(sum);
    z.push(incrL(z[z.length - 1]));
  }
  const hLast = cipher.encryptBlock(z[z.length - 1]);
  h.push(hLast);
  const half = n / 2;
  const lengthBlock = new Uint8Array(n);
  lengthBlock.set(bigIntToBytes(BigInt(aad.length) * 8n, half), 0);
  lengthBlock.set(bigIntToBytes(BigInt(ct.length) * 8n, half), half);
  const finalSum = xorBytes(sum, gfMul(hLast, lengthBlock));
  const fullTag = cipher.encryptBlock(finalSum);
  return {
    tag: fullTag.slice(0, tagBytes),
    parts: { authSeed, z, h, authBlocks, runningSum, lengthBlock, finalSum, fullTag },
  };
}

/** The counter-mode half of 4.1 step 1 / 4.2 step 3. */
function ctr(cipher: BlockCipher, icn: Uint8Array, input: Uint8Array) {
  const n = cipher.blockBytes;
  const encSeed = icn.slice(); // 0^1 || ICN
  const y: Uint8Array[] = [];
  const keystream: Uint8Array[] = [];
  const out = new Uint8Array(input.length);
  if (input.length > 0) {
    y.push(cipher.encryptBlock(encSeed));
    for (let off = 0; off < input.length; off += n) {
      if (off > 0) y.push(incrR(y[y.length - 1]));
      const ks = cipher.encryptBlock(y[y.length - 1]);
      keystream.push(ks);
      for (let i = 0; i < n && off + i < input.length; i++) out[off + i] = input[off + i] ^ ks[i]; // MSB_u on the last block
    }
  }
  return { out, encSeed, y, keystream };
}

export function mgmEncrypt(cipher: BlockCipher, icn: Uint8Array, aad: Uint8Array, plaintext: Uint8Array,
  tagBytes: number = cipher.blockBytes): MgmResult {
  validate(cipher, icn, aad, plaintext, tagBytes);
  const { out: ciphertext, encSeed, y, keystream } = ctr(cipher, icn, plaintext);
  const { tag, parts } = computeTag(cipher, icn, aad, ciphertext, tagBytes);
  return { ciphertext, tag, trace: { blockBytes: cipher.blockBytes, encSeed, y, keystream, ...parts } };
}

export type MgmOpenResult =
  | { ok: true; plaintext: Uint8Array; trace: MgmTrace }
  | { ok: false; expectedTag: Uint8Array; trace: MgmTrace };

/**
 * RFC 9058 4.2: verify FIRST, decrypt only if the tag matches. A failure
 * returns no plaintext at all — not a partial one, not a "best effort" one.
 */
export function mgmDecrypt(cipher: BlockCipher, icn: Uint8Array, aad: Uint8Array, ciphertext: Uint8Array,
  tag: Uint8Array): MgmOpenResult {
  validate(cipher, icn, aad, ciphertext, tag.length);
  const { tag: expected, parts } = computeTag(cipher, icn, aad, ciphertext, tag.length);
  const base = { blockBytes: cipher.blockBytes, encSeed: icn.slice(), y: [] as Uint8Array[], keystream: [] as Uint8Array[], ...parts };
  if (!equalBytes(expected, tag)) return { ok: false, expectedTag: expected, trace: base };
  const { out, y, keystream } = ctr(cipher, icn, ciphertext);
  return { ok: true, plaintext: out, trace: { ...base, y, keystream } };
}
