/**
 * Why a 64-bit block needs a much shorter key life than a 128-bit one — derived
 * from published numbers, never asserted.
 *
 * 1. RFC 9058 section 6 gives MGM's security bounds for a random permutation
 *    (from [SEC-MGM]). For an adversary making q encryption queries totalling s
 *    blocks of plaintext and associated data, and a forgery of l blocks:
 *
 *        CA <= 3(s + 4q)^2 / 2^n
 *        IA <= 3(s + 4q + l + 3)^2 / 2^n + 2 / 2^S
 *
 *    Same formula, n = 64 versus n = 128: the 2^n denominator is the whole story.
 *
 * 2. RFC 9367 (GOST cipher suites for TLS 1.3) re-keys inside a connection with
 *    TLSTREE: the key for record `seqnum` depends on seqnum & C_3, so a leaf key
 *    lasts 2^(trailing zero bits of C_3) records. The constants are the RFC's
 *    Table 1; the record counts are computed from them here, not copied.
 */

export interface AdvantageInput {
  /** block size in bits */
  n: 64 | 128;
  /** total blocks of plaintext + associated data under one key */
  s: number;
  /** number of encryption queries (messages) */
  q: number;
}

/** log2 of the confidentiality-advantage bound 3(s + 4q)^2 / 2^n. */
export function log2ConfidentialityBound({ n, s, q }: AdvantageInput): number {
  return Math.log2(3) + 2 * Math.log2(s + 4 * q) - n;
}

/** log2 of the integrity-advantage bound, with an l-block forgery and an S-bit tag. */
export function log2IntegrityBound({ n, s, q }: AdvantageInput, l: number, tagBits: number): number {
  const birthday = Math.log2(3) + 2 * Math.log2(s + 4 * q + l + 3) - n;
  const guess = 1 - tagBits; // 2 / 2^S
  // log2(2^a + 2^b), computed without overflow.
  const hi = Math.max(birthday, guess);
  return hi + Math.log2(1 + 2 ** (Math.min(birthday, guess) - hi));
}

/**
 * The largest s (blocks under one key) that keeps the confidentiality bound at
 * or below 2^-target, for q messages: s = sqrt(2^(n - target) / 3) - 4q.
 */
export function maxBlocksForBound(n: 64 | 128, targetBits: number, q: number): number {
  return Math.sqrt(2 ** (n - targetBits) / 3) - 4 * q;
}

export interface TlsTreeSuite {
  suite: string;
  cipher: 'Kuznyechik' | 'Magma';
  c1: bigint; c2: bigint; c3: bigint;
  /** SNMAX, RFC 9367 Table 2, as log2(SNMAX + 1). */
  snmaxLog2: number;
}

/** RFC 9367 Tables 1 and 2, verbatim. */
export const TLSTREE_SUITES: readonly TlsTreeSuite[] = [
  { suite: 'TLS_GOSTR341112_256_WITH_KUZNYECHIK_MGM_L', cipher: 'Kuznyechik',
    c1: 0xf800000000000000n, c2: 0xfffffff000000000n, c3: 0xffffffffffffe000n, snmaxLog2: 64 },
  { suite: 'TLS_GOSTR341112_256_WITH_MAGMA_MGM_L', cipher: 'Magma',
    c1: 0xffe0000000000000n, c2: 0xffffffffc0000000n, c3: 0xffffffffffffff80n, snmaxLog2: 64 },
  { suite: 'TLS_GOSTR341112_256_WITH_KUZNYECHIK_MGM_S', cipher: 'Kuznyechik',
    c1: 0xffffffffe0000000n, c2: 0xffffffffffff0000n, c3: 0xfffffffffffffff8n, snmaxLog2: 42 },
  { suite: 'TLS_GOSTR341112_256_WITH_MAGMA_MGM_S', cipher: 'Magma',
    c1: 0xfffffffffc000000n, c2: 0xffffffffffffe000n, c3: 0xffffffffffffffffn, snmaxLog2: 39 },
];

export function trailingZeroBits(v: bigint): number {
  if (v === 0n) return 64;
  let z = 0;
  while ((v & 1n) === 0n) { v >>= 1n; z++; }
  return z;
}

/** Records encrypted under one TLSTREE leaf key: 2^(trailing zeros of C_3). */
export function recordsPerLeafKey(s: TlsTreeSuite): number {
  return 2 ** trailingZeroBits(s.c3);
}
