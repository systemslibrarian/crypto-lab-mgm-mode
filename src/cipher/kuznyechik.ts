/**
 * Kuznyechik — GOST R 34.12-2015, 128-bit block, 256-bit key (RFC 7801).
 *
 * A 9-round SPN: X[K] (xor the round key), S (the 8-bit substitution pi),
 * L (a linear map over GF(2^8)), then a final key xor. MGM over Kuznyechik is
 * the 128-bit instantiation; it exists in this lab so the 64-bit Magma one can
 * be set beside it with everything else held equal.
 *
 * Indexing: a 16-byte block is a_15 || ... || a_0 with a_15 the FIRST byte,
 * exactly as RFC 7801 writes its hex examples.
 */
import type { BlockCipher } from './types';

/** Pi' of RFC 7801 section 4.1, verbatim. */
export const PI: readonly number[] = [
  252, 238, 221, 17, 207, 110, 49, 22, 251, 196, 250, 218, 35, 197, 4, 77,
  233, 119, 240, 219, 147, 46, 153, 186, 23, 54, 241, 187, 20, 205, 95, 193,
  249, 24, 101, 90, 226, 92, 239, 33, 129, 28, 60, 66, 139, 1, 142, 79,
  5, 132, 2, 174, 227, 106, 143, 160, 6, 11, 237, 152, 127, 212, 211, 31,
  235, 52, 44, 81, 234, 200, 72, 171, 242, 42, 104, 162, 253, 58, 206, 204,
  181, 112, 14, 86, 8, 12, 118, 18, 191, 114, 19, 71, 156, 183, 93, 135,
  21, 161, 150, 41, 16, 123, 154, 199, 243, 145, 120, 111, 157, 158, 178, 177,
  50, 117, 25, 61, 255, 53, 138, 126, 109, 84, 198, 128, 195, 189, 13, 87,
  223, 245, 36, 169, 62, 168, 67, 201, 215, 121, 214, 246, 124, 34, 185, 3,
  224, 15, 236, 222, 122, 148, 176, 188, 220, 232, 40, 80, 78, 51, 10, 74,
  167, 151, 96, 115, 30, 0, 98, 68, 26, 184, 56, 130, 100, 159, 38, 65,
  173, 69, 70, 146, 39, 94, 85, 47, 140, 163, 165, 125, 105, 213, 149, 59,
  7, 88, 179, 64, 134, 172, 29, 247, 48, 55, 107, 228, 136, 217, 231, 137,
  225, 27, 131, 73, 76, 63, 248, 254, 141, 83, 170, 144, 202, 216, 133, 97,
  32, 113, 103, 164, 45, 43, 9, 91, 203, 155, 37, 208, 190, 229, 108, 82,
  89, 166, 116, 210, 230, 244, 180, 192, 209, 102, 175, 194, 57, 75, 99, 182,
];

/** Pi^-1, computed rather than transcribed; the tests check it against the
 * table RFC 7801 prints. */
export const PI_INV: readonly number[] = (() => {
  const inv = new Array<number>(256);
  PI.forEach((v, i) => { inv[v] = i; });
  return inv;
})();

/** Multiplication in Q = GF(2)[x]/(x^8 + x^7 + x^6 + x + 1) (RFC 7801 3.2). */
export function gf256Mul(a: number, b: number): number {
  let r = 0;
  for (let i = 0; i < 8; i++) {
    if (b & 1) r ^= a;
    const carry = a & 0x80;
    a = (a << 1) & 0xff;
    if (carry) a ^= 0xc3; // x^8 = x^7 + x^6 + x + 1
    b >>= 1;
  }
  return r;
}

/**
 * Coefficients of l for (a_15, ..., a_0). RFC 7801 section 4.2 prints the
 * second term as "32*delta(a_15)"; it is a_14, as the palindromic pattern and
 * the RFC's own section 5.2-5.3 examples require. The tests check R and L
 * against those examples, so a wrong reading here cannot pass silently.
 */
const L_COEFF = [148, 32, 133, 16, 194, 192, 1, 251, 1, 192, 194, 16, 133, 32, 148, 1];

/** l(a_15, ..., a_0); `bytes[0]` is a_15. */
function lFunc(bytes: ArrayLike<number>): number {
  let acc = 0;
  for (let i = 0; i < 16; i++) acc ^= gf256Mul(bytes[i], L_COEFF[i]);
  return acc;
}

/** R(a_15||...||a_0) = l(a_15, ..., a_0) || a_15 || ... || a_1. */
export function kuzR(a: Uint8Array): Uint8Array {
  const out = new Uint8Array(16);
  out[0] = lFunc(a);
  out.set(a.subarray(0, 15), 1);
  return out;
}

/** R^-1(a_15||...||a_0) = a_14 || ... || a_0 || l(a_14, ..., a_0, a_15). */
export function kuzRInv(a: Uint8Array): Uint8Array {
  const shifted = new Uint8Array(16);
  shifted.set(a.subarray(1), 0);
  shifted[15] = a[0];
  const out = new Uint8Array(16);
  out.set(a.subarray(1), 0);
  out[15] = lFunc(shifted);
  return out;
}

export function kuzL(a: Uint8Array): Uint8Array {
  let x = a;
  for (let i = 0; i < 16; i++) x = kuzR(x);
  return x;
}

export function kuzLInv(a: Uint8Array): Uint8Array {
  let x = a;
  for (let i = 0; i < 16; i++) x = kuzRInv(x);
  return x;
}

export function kuzS(a: Uint8Array): Uint8Array {
  return a.map((b) => PI[b]);
}

function kuzSInv(a: Uint8Array): Uint8Array {
  return a.map((b) => PI_INV[b]);
}

function xor16(a: Uint8Array, b: Uint8Array): Uint8Array {
  const out = new Uint8Array(16);
  for (let i = 0; i < 16; i++) out[i] = a[i] ^ b[i];
  return out;
}

/** C_i = L(Vec_128(i)), i = 1..32 (RFC 7801 4.4). */
export const ROUND_CONSTANTS: readonly Uint8Array[] = Array.from({ length: 32 }, (_, i) => {
  const v = new Uint8Array(16);
  v[15] = i + 1;
  return kuzL(v);
});

/** F[k](a_1, a_0) = (LSX[k](a_1) xor a_0, a_1). */
function feistelStep(k: Uint8Array, a1: Uint8Array, a0: Uint8Array): [Uint8Array, Uint8Array] {
  return [xor16(kuzL(kuzS(xor16(k, a1))), a0), a1];
}

/** K_1..K_10 (RFC 7801 4.4). */
export function kuzRoundKeys(key: Uint8Array): Uint8Array[] {
  if (key.length !== 32) throw new Error(`Kuznyechik needs a 32-byte key, got ${key.length}`);
  const keys: Uint8Array[] = [key.slice(0, 16), key.slice(16, 32)];
  let a1 = keys[0];
  let a0 = keys[1];
  for (let i = 0; i < 4; i++) {
    for (let j = 0; j < 8; j++) [a1, a0] = feistelStep(ROUND_CONSTANTS[8 * i + j], a1, a0);
    keys.push(a1, a0);
  }
  return keys;
}

export class Kuznyechik implements BlockCipher {
  readonly name = 'Kuznyechik' as const;
  readonly blockBytes = 16 as const;
  readonly roundKeys: readonly Uint8Array[];

  constructor(key: Uint8Array) {
    this.roundKeys = kuzRoundKeys(key);
  }

  encryptBlock(block: Uint8Array): Uint8Array {
    if (block.length !== 16) throw new Error(`Kuznyechik blocks are 16 bytes, got ${block.length}`);
    let x = block;
    for (let i = 0; i < 9; i++) x = kuzL(kuzS(xor16(this.roundKeys[i], x)));
    return xor16(this.roundKeys[9], x);
  }

  decryptBlock(block: Uint8Array): Uint8Array {
    if (block.length !== 16) throw new Error(`Kuznyechik blocks are 16 bytes, got ${block.length}`);
    let x = xor16(this.roundKeys[9], block);
    for (let i = 8; i >= 0; i--) x = xor16(this.roundKeys[i], kuzSInv(kuzLInv(x)));
    return x;
  }
}
