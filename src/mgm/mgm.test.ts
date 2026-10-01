import { describe, expect, it } from 'vitest';
import { Kuznyechik } from '../cipher/kuznyechik';
import { Magma } from '../cipher/magma';
import { bytesToHex, hexToBytes } from '../cipher/bytes';
import type { BlockCipher } from '../cipher/types';
import { MgmInputError, incrL, incrR, mgmDecrypt, mgmEncrypt } from './mgm';
import { gfMul } from './gf';
import { RFC9058_VECTORS } from './vectors';

const make = (name: string, key: Uint8Array): BlockCipher => (name === 'Magma' ? new Magma(key) : new Kuznyechik(key));
const hx = (a: Uint8Array[]) => a.map(bytesToHex);

describe('RFC 9058 Appendix A: every intermediate value', () => {
  it('extracted four examples, two per cipher', () => {
    expect(RFC9058_VECTORS.map((v) => `${v.cipher} ${v.example}`)).toEqual(
      ['Kuznyechik 1', 'Kuznyechik 2', 'Magma 1', 'Magma 2']);
  });

  for (const v of RFC9058_VECTORS) {
    describe(`${v.cipher} example ${v.example}`, () => {
      const cipher = make(v.cipher, hexToBytes(v.key));
      const r = mgmEncrypt(cipher, hexToBytes(v.icn), hexToBytes(v.aad), hexToBytes(v.plaintext));

      it('encryption counter Y_i and keystream E_K(Y_i)', () => {
        expect(hx(r.trace.y)).toEqual(v.y);
        expect(hx(r.trace.keystream)).toEqual(v.keystream);
      });
      it('ciphertext', () => expect(bytesToHex(r.ciphertext)).toBe(v.ciphertext ?? ''));
      it('authentication counter Z_i and coefficients H_i', () => {
        expect(hx(r.trace.z)).toEqual(v.z);
        expect(hx(r.trace.h)).toEqual(v.h);
      });
      it('the running sum after every block', () => expect(hx(r.trace.runningSum)).toEqual(v.runningSum));
      it('len(A) || len(C), the encrypted sum and the tag', () => {
        expect(bytesToHex(r.trace.lengthBlock)).toBe(v.lengthBlock);
        expect(bytesToHex(r.trace.finalSum)).toBe(v.finalSum);
        expect(bytesToHex(r.tag)).toBe(v.tag);
      });
      it('decrypts and verifies', () => {
        const o = mgmDecrypt(cipher, hexToBytes(v.icn), hexToBytes(v.aad), r.ciphertext, r.tag);
        expect(o.ok).toBe(true);
        if (o.ok) expect(bytesToHex(o.plaintext)).toBe(v.plaintext);
      });
    });
  }

  it('Kuznyechik example 1: Y_1 is the RFC 7801 test ciphertext, because the key and 0||ICN are that test', () => {
    // An independent cross-check between two RFCs: RFC 9058 reuses RFC 7801's
    // key and plaintext, so E_K(0^1 || ICN) must equal RFC 7801 section 5.5's b.
    const v = RFC9058_VECTORS[0];
    expect(v.y[0]).toBe('7f679d90bebc24305a468d42b9d4edcd');
  });
});

describe('the counters and the field', () => {
  it('incr_r steps only the right half and wraps', () => {
    expect(bytesToHex(incrR(hexToBytes('00000000ffffffff')))).toBe('0000000000000000');
    expect(bytesToHex(incrR(hexToBytes('12345678000000ff')))).toBe('1234567800000100');
  });
  it('incr_l steps only the left half and wraps', () => {
    expect(bytesToHex(incrL(hexToBytes('ffffffff00000001')))).toBe('0000000000000001');
    expect(bytesToHex(incrL(hexToBytes('000000ff12345678')))).toBe('0000010012345678');
  });
  it('(x) is commutative, has identity 1, and reduces by f(w)', () => {
    const one8 = hexToBytes('0000000000000001');
    const a = hexToBytes('8000000000000000'); // w^63
    const w = hexToBytes('0000000000000002'); // w
    expect(bytesToHex(gfMul(a, one8))).toBe(bytesToHex(a));
    expect(bytesToHex(gfMul(a, w))).toBe(bytesToHex(gfMul(w, a)));
    // w^63 * w = w^64 = w^4 + w^3 + w + 1 = 0x1b
    expect(bytesToHex(gfMul(a, w))).toBe('000000000000001b');
    const a16 = hexToBytes('80000000000000000000000000000000');
    const w16 = hexToBytes('00000000000000000000000000000002');
    expect(bytesToHex(gfMul(a16, w16))).toBe('00000000000000000000000000000087');
  });
});

describe('verification fails closed', () => {
  const v = RFC9058_VECTORS[2]; // Magma example 1
  const cipher = new Magma(hexToBytes(v.key));
  const icn = hexToBytes(v.icn);
  const aad = hexToBytes(v.aad);
  const sealed = mgmEncrypt(cipher, icn, aad, hexToBytes(v.plaintext));
  const flip = (b: Uint8Array, i: number) => { const c = b.slice(); c[i] ^= 0x01; return c; };

  it('one flipped ciphertext bit, anywhere, is rejected', () => {
    for (let i = 0; i < sealed.ciphertext.length; i++) {
      expect(mgmDecrypt(cipher, icn, aad, flip(sealed.ciphertext, i), sealed.tag).ok).toBe(false);
    }
  });
  it('one flipped associated-data bit is rejected', () => {
    for (let i = 0; i < aad.length; i++) expect(mgmDecrypt(cipher, icn, flip(aad, i), sealed.ciphertext, sealed.tag).ok).toBe(false);
  });
  it('one flipped tag bit is rejected', () => {
    for (let i = 0; i < sealed.tag.length; i++) expect(mgmDecrypt(cipher, icn, aad, sealed.ciphertext, flip(sealed.tag, i)).ok).toBe(false);
  });
  it('a different ICN is rejected', () => {
    expect(mgmDecrypt(cipher, flip(icn, 7), aad, sealed.ciphertext, sealed.tag).ok).toBe(false);
  });
  it('moving bytes between A and C is rejected, because the lengths are authenticated', () => {
    const joined = new Uint8Array([...aad, ...sealed.ciphertext]);
    const aad2 = joined.subarray(0, aad.length + 1);
    const ct2 = joined.subarray(aad.length + 1);
    expect(mgmDecrypt(cipher, icn, aad2, ct2, sealed.tag).ok).toBe(false);
  });
  it('a rejected message yields no plaintext at all', () => {
    const o = mgmDecrypt(cipher, icn, aad, flip(sealed.ciphertext, 0), sealed.tag);
    expect(o.ok).toBe(false);
    expect('plaintext' in o).toBe(false);
  });
  it('a truncated tag still verifies at its own length and only there', () => {
    const short = mgmEncrypt(cipher, icn, aad, hexToBytes(v.plaintext), 4);
    expect(bytesToHex(short.tag)).toBe(v.tag.slice(0, 8)); // MSB_S of the full tag
    expect(mgmDecrypt(cipher, icn, aad, short.ciphertext, short.tag).ok).toBe(true);
  });
});

describe('inputs RFC 9058 forbids are refused, not computed', () => {
  const m = new Magma(hexToBytes(RFC9058_VECTORS[2].key));
  const icn = hexToBytes('12def06b3c130a59');
  it('empty A and empty P together (RFC 9058 section 6)', () => {
    expect(() => mgmEncrypt(m, icn, new Uint8Array(0), new Uint8Array(0))).toThrow(MgmInputError);
  });
  it('an ICN with its top bit set', () => {
    expect(() => mgmEncrypt(m, hexToBytes('92def06b3c130a59'), new Uint8Array(1), new Uint8Array(1))).toThrow(/top bit/);
  });
  it('an ICN of the wrong width', () => {
    expect(() => mgmEncrypt(m, new Uint8Array(16), new Uint8Array(1), new Uint8Array(1))).toThrow(/8 bytes/);
  });
  it('a tag shorter than 32 bits or longer than n', () => {
    expect(() => mgmEncrypt(m, icn, new Uint8Array(1), new Uint8Array(1), 3)).toThrow(/tag length/);
    expect(() => mgmEncrypt(m, icn, new Uint8Array(1), new Uint8Array(1), 9)).toThrow(/tag length/);
  });
});
