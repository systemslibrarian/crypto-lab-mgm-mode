/**
 * The side-by-side the lab is built around: where each block's authentication
 * coefficient comes from.
 *
 *   GCM (SP 800-38D): GHASH multiplies the blocks by powers of ONE hash subkey
 *   H = E_K(0^128). Block i of m is weighted by H^(m - i + 1), so recovering H
 *   recovers every coefficient at once.
 *
 *   MGM (RFC 9058): block i is weighted by H_i = E_K(Z_i), a fresh block-cipher
 *   output per position. No coefficient is a function of another.
 *
 * The GCM-shaped column is computed with the SAME cipher and the SAME field
 * MGM uses (f(w) from RFC 9058), because the point is the structure, not the
 * algorithm. It is NOT AES-GCM — GCM is defined for 128-bit AES with a
 * bit-reflected field convention — and the page says so beside it.
 */
import type { BlockCipher } from '../cipher/types';
import { bytesToHex } from '../cipher/bytes';
import { gfMul } from './gf';
import type { MgmTrace } from './mgm';

export interface CoefficientRow {
  label: string;
  mgm: string;
  gcmShape: string;
  /** For GCM: the power of the single H this position is weighted by. */
  power: number;
}

export function coefficientRows(cipher: BlockCipher, trace: MgmTrace): { rows: CoefficientRow[]; h: string } {
  const n = cipher.blockBytes;
  const h = cipher.encryptBlock(new Uint8Array(n)); // H = E_K(0^n)
  const labels = [...trace.authBlocks.map((b) => `${b.kind}${b.index}`), 'len'];
  const m = labels.length;
  const powers: Uint8Array[] = [h];
  for (let i = 1; i < m; i++) powers.push(gfMul(powers[i - 1], h));
  const rows = labels.map((label, i) => ({
    label,
    mgm: bytesToHex(trace.h[i]),
    power: m - i,
    gcmShape: bytesToHex(powers[m - i - 1]),
  }));
  return { rows, h: bytesToHex(h) };
}

/** True when no two MGM coefficients in the trace are equal. */
export function allDistinct(hexes: string[]): boolean {
  return new Set(hexes).size === hexes.length;
}
