/**
 * Magma — GOST R 34.12-2015, 64-bit block, 256-bit key (RFC 8891).
 *
 * A 32-round Feistel network. Each round adds a 32-bit round key mod 2^32,
 * pushes the result through eight 4-bit S-boxes, and rotates left by 11.
 *
 * Magma IS GOST 28147-89 with three things pinned down (RFC 8891 Appendix B):
 *   1. the S-boxes are fixed to id-tc26-gost-28147-param-Z (RFC 7836 App. C),
 *   2. the key is read as one big-endian integer,
 *   3. data blocks are read as big-endian integers.
 * GOST 28147-89 itself defined no S-boxes at all — RFC 5830 section 4: "the
 * standard doesn't define any S-boxes" — so before 2015 "GOST" named a family
 * of ciphers, one per S-box set. SBOX_PARAM_Z below is the one that won.
 */
import type { BlockCipher } from './types';

/** Pi'_0 .. Pi'_7 of RFC 8891 section 4.1, verbatim. Pi'_i substitutes nibble i
 * (nibble 0 is the least significant). */
export const SBOX_PARAM_Z: readonly (readonly number[])[] = [
  [12, 4, 6, 2, 10, 5, 11, 9, 14, 8, 13, 7, 0, 3, 15, 1],
  [6, 8, 2, 3, 9, 10, 5, 12, 1, 14, 4, 7, 11, 13, 0, 15],
  [11, 3, 5, 8, 2, 15, 10, 13, 14, 1, 7, 4, 12, 9, 6, 0],
  [12, 8, 2, 1, 13, 4, 15, 6, 7, 0, 10, 5, 3, 14, 9, 11],
  [7, 15, 5, 10, 8, 1, 6, 13, 0, 9, 3, 14, 11, 4, 2, 12],
  [5, 13, 15, 6, 9, 2, 12, 10, 11, 7, 8, 1, 4, 3, 14, 0],
  [8, 14, 2, 5, 6, 9, 1, 12, 15, 4, 11, 0, 13, 10, 3, 7],
  [1, 7, 14, 13, 0, 5, 8, 3, 4, 15, 10, 6, 9, 12, 11, 2],
];

/** t: V_32 -> V_32, the eight parallel 4-bit substitutions (RFC 8891 4.2). */
export function magmaT(a: number): number {
  let out = 0;
  for (let i = 0; i < 8; i++) {
    const nibble = (a >>> (4 * i)) & 0xf;
    out |= SBOX_PARAM_Z[i][nibble] << (4 * i);
  }
  return out >>> 0;
}

/** g[k](a) = t(a [+] k) <<< 11 (RFC 8891 4.2). */
export function magmaG(k: number, a: number): number {
  const s = magmaT((a + k) >>> 0);
  return ((s << 11) | (s >>> 21)) >>> 0;
}

/** K_1..K_32 from the 256-bit key, big-endian (RFC 8891 4.3): K_1..K_8 three
 * times forward, then once in reverse. */
export function magmaRoundKeys(key: Uint8Array): number[] {
  if (key.length !== 32) throw new Error(`Magma needs a 32-byte key, got ${key.length}`);
  const k: number[] = [];
  for (let i = 0; i < 8; i++) {
    k.push(((key[4 * i] << 24) | (key[4 * i + 1] << 16) | (key[4 * i + 2] << 8) | key[4 * i + 3]) >>> 0);
  }
  return [...k, ...k, ...k, ...k.slice().reverse()];
}

function readHalves(block: Uint8Array): [number, number] {
  if (block.length !== 8) throw new Error(`Magma blocks are 8 bytes, got ${block.length}`);
  const hi = ((block[0] << 24) | (block[1] << 16) | (block[2] << 8) | block[3]) >>> 0;
  const lo = ((block[4] << 24) | (block[5] << 16) | (block[6] << 8) | block[7]) >>> 0;
  return [hi, lo];
}

function writeHalves(hi: number, lo: number): Uint8Array {
  return new Uint8Array([hi >>> 24, (hi >>> 16) & 0xff, (hi >>> 8) & 0xff, hi & 0xff,
    lo >>> 24, (lo >>> 16) & 0xff, (lo >>> 8) & 0xff, lo & 0xff]);
}

/**
 * Run the 32 rounds over (a_1, a_0) with the given key order. Returns every
 * intermediate (a_1, a_0) pair so the page — and the tests — can compare each
 * round with RFC 8891 Appendix A.4/A.5 rather than only the final block.
 */
export function magmaRounds(roundKeys: readonly number[], block: Uint8Array): {
  out: Uint8Array;
  trace: [number, number][];
} {
  let [a1, a0] = readHalves(block);
  const trace: [number, number][] = [];
  // G[K_1] .. G[K_31]: (a_1, a_0) -> (a_0, g[k](a_0) xor a_1)
  for (let i = 0; i < 31; i++) {
    const next = (magmaG(roundKeys[i], a0) ^ a1) >>> 0;
    a1 = a0;
    a0 = next;
    trace.push([a1, a0]);
  }
  // G*[K_32]: (a_1, a_0) -> (g[k](a_0) xor a_1) || a_0 — no final swap.
  const last = (magmaG(roundKeys[31], a0) ^ a1) >>> 0;
  return { out: writeHalves(last, a0), trace };
}

export class Magma implements BlockCipher {
  readonly name = 'Magma' as const;
  readonly blockBytes = 8 as const;
  readonly roundKeys: readonly number[];
  private readonly reversed: readonly number[];

  constructor(key: Uint8Array) {
    this.roundKeys = magmaRoundKeys(key);
    this.reversed = this.roundKeys.slice().reverse();
  }

  encryptBlock(block: Uint8Array): Uint8Array {
    return magmaRounds(this.roundKeys, block).out;
  }

  decryptBlock(block: Uint8Array): Uint8Array {
    // D = G*[K_1] G[K_2] ... G[K_32]: the same network with the keys reversed.
    return magmaRounds(this.reversed, block).out;
  }
}
