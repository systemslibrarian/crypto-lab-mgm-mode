/**
 * The (x) operation of RFC 9058 section 3: multiplication in GF(2^n).
 *
 * A block X = (x_{n-1}, ..., x_0) is the polynomial x_{n-1} w^{n-1} + ... + x_0,
 * with x_{n-1} the most significant bit of the first byte — the natural
 * big-endian reading. That is NOT GCM's convention, which reflects the bits;
 * reading MGM's blocks the GCM way gives wrong answers, and the RFC vectors
 * catch it.
 *
 *   n = 64:  f(w) = w^64 + w^4 + w^3 + w + 1      reduction constant 0x1b
 *   n = 128: f(w) = w^128 + w^7 + w^2 + w + 1     reduction constant 0x87
 */
import { bigIntToBytes, bytesToBigInt } from '../cipher/bytes';

const REDUCTION: Record<8 | 16, bigint> = { 8: 0x1bn, 16: 0x87n };

export function gfMul(x: Uint8Array, y: Uint8Array): Uint8Array {
  const n = x.length;
  if ((n !== 8 && n !== 16) || y.length !== n) {
    throw new Error(`GF(2^n) multiplication needs two 8- or 16-byte blocks, got ${x.length} and ${y.length}`);
  }
  const bits = BigInt(n * 8);
  const top = 1n << (bits - 1n);
  const mask = (1n << bits) - 1n;
  const red = REDUCTION[n as 8 | 16];
  let a = bytesToBigInt(x);
  let b = bytesToBigInt(y);
  let r = 0n;
  // Shift-and-add, reducing a by f(w) each time it overflows the degree.
  while (b > 0n) {
    if (b & 1n) r ^= a;
    b >>= 1n;
    const carry = a & top;
    a = (a << 1n) & mask;
    if (carry) a ^= red;
  }
  return bigIntToBytes(r, n);
}
