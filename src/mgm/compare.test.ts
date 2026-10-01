import { describe, expect, it } from 'vitest';
import { Kuznyechik } from '../cipher/kuznyechik';
import { Magma, SBOX_PARAM_Z } from '../cipher/magma';
import { bytesToHex, hexToBytes, xorBytes } from '../cipher/bytes';
import { gfMul } from './gf';
import { mgmEncrypt } from './mgm';
import { allDistinct, coefficientRows } from './compare';
import { reuseIcn } from './misuse';
import { RFC9058_VECTORS } from './vectors';

const enc = new TextEncoder();

describe('coefficients: one H versus one H_i per block', () => {
  const v = RFC9058_VECTORS[2]; // Magma example 1: 6 A blocks (41 bytes), 9 C blocks (67 bytes), 1 length block
  const cipher = new Magma(hexToBytes(v.key));
  const r = mgmEncrypt(cipher, hexToBytes(v.icn), hexToBytes(v.aad), hexToBytes(v.plaintext));
  const { rows, h } = coefficientRows(cipher, r.trace);

  it('one row per authenticated block plus the length block', () => {
    expect(rows.map((x) => x.label)).toEqual(['A1', 'A2', 'A3', 'A4', 'A5', 'A6',
      'C1', 'C2', 'C3', 'C4', 'C5', 'C6', 'C7', 'C8', 'C9', 'len']);
  });
  it('the MGM column is the RFC H_i sequence', () => expect(rows.map((x) => x.mgm)).toEqual(v.h));
  it('every MGM coefficient is distinct', () => expect(allDistinct(rows.map((x) => x.mgm))).toBe(true));
  it('every GCM-shaped coefficient is a power of the single H = E_K(0^n)', () => {
    expect(h).toBe(bytesToHex(cipher.encryptBlock(new Uint8Array(8))));
    // Re-derived independently: multiply H by itself power-1 times.
    for (const row of rows) {
      let acc = hexToBytes(h);
      for (let i = 1; i < row.power; i++) acc = gfMul(acc, hexToBytes(h));
      expect(row.gcmShape).toBe(bytesToHex(acc));
    }
    // Knowing H gives the coefficient of the last block directly.
    expect(rows.at(-1)!.gcmShape).toBe(h);
  });
});

describe('a repeated ICN: verified, and leaked', () => {
  for (const cipher of [new Magma(hexToBytes(RFC9058_VECTORS[2].key)), new Kuznyechik(hexToBytes(RFC9058_VECTORS[0].key))]) {
    it(`${cipher.name}: both verify, and C1 xor C2 equals P1 xor P2`, () => {
      const icn = new Uint8Array(cipher.blockBytes); icn[1] = 0x42;
      const p1 = enc.encode('Transfer 100 to account 4417, ref A');
      const p2 = enc.encode('Transfer 999 to account 9001, ref B');
      const d = reuseIcn(cipher, icn, enc.encode('hdr'), p1, p2);
      expect(d.verified1 && d.verified2).toBe(true);
      expect(d.leaks).toBe(true);
      // Re-derived without the module: knowing p1, the attacker recovers p2.
      expect(new TextDecoder().decode(xorBytes(xorBytes(d.c1, d.c2), p1))).toBe('Transfer 999 to account 9001, ref B');
    });
  }
  it('with distinct ICNs the xor relation does not hold', () => {
    const cipher = new Magma(hexToBytes(RFC9058_VECTORS[2].key));
    const p = enc.encode('same plaintext twice');
    const a = mgmEncrypt(cipher, hexToBytes('0000000000000001'), new Uint8Array(0), p);
    const b = mgmEncrypt(cipher, hexToBytes('0000000000000002'), new Uint8Array(0), p);
    expect(bytesToHex(xorBytes(a.ciphertext, b.ciphertext))).not.toBe(bytesToHex(new Uint8Array(p.length)));
  });
});

describe('Magma S-box: two RFCs, one table', () => {
  it('RFC 7836 Appendix C (param-Z, columns K1..K8) equals RFC 8891 Pi\'_0..Pi\'_7', () => {
    // Transcribed from RFC 7836 Appendix C, row x, columns K1..K8.
    const rows = ['c6bc7581', '4838fde7', '62525f2e', '2381a65d', 'a92d8960', '5af41295', 'b5af6c18', '9cd6dac3',
      'e1e70bf4', '8e10974f', 'd47a38ba', '7745e106', '0bc3b4d9', '3d9e43ac', 'f0692e3b', '1f0bc072'];
    for (let col = 0; col < 8; col++) {
      expect(rows.map((r) => parseInt(r[col], 16))).toEqual(SBOX_PARAM_Z[col]);
    }
  });
});
