import { describe, expect, it } from 'vitest';
import { Magma, magmaG, magmaRoundKeys, magmaRounds, magmaT } from './magma';
import { bytesToHex, hexToBytes } from './bytes';

// Every value below is copied from RFC 8891 Appendix A.
const KEY = hexToBytes('ffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff');

describe('Magma, RFC 8891 Appendix A', () => {
  it('A.1 transformation t', () => {
    expect(magmaT(0xfdb97531).toString(16)).toBe('2a196f34');
    expect(magmaT(0x2a196f34).toString(16)).toBe('ebd9f03a');
    expect(magmaT(0xebd9f03a).toString(16)).toBe('b039bb3d');
    expect(magmaT(0xb039bb3d).toString(16)).toBe('68695433');
  });

  it('A.2 transformation g', () => {
    expect(magmaG(0x87654321, 0xfedcba98).toString(16)).toBe('fdcbc20c');
    expect(magmaG(0xfdcbc20c, 0x87654321).toString(16)).toBe('7e791a4b');
    expect(magmaG(0x7e791a4b, 0xfdcbc20c).toString(16)).toBe('c76549ec');
    expect(magmaG(0xc76549ec, 0x7e791a4b).toString(16)).toBe('9791c849');
  });

  it('A.3 key schedule: forward three times, then reversed', () => {
    const k = magmaRoundKeys(KEY).map((x) => x.toString(16).padStart(8, '0'));
    expect(k.slice(0, 8)).toEqual(['ffeeddcc', 'bbaa9988', '77665544', '33221100',
      'f0f1f2f3', 'f4f5f6f7', 'f8f9fafb', 'fcfdfeff']);
    expect(k.slice(8, 16)).toEqual(k.slice(0, 8));
    expect(k.slice(16, 24)).toEqual(k.slice(0, 8));
    expect(k.slice(24)).toEqual(['fcfdfeff', 'f8f9fafb', 'f4f5f6f7', 'f0f1f2f3',
      '33221100', '77665544', 'bbaa9988', 'ffeeddcc']);
  });

  it('A.4 every one of the 31 G rounds, then the ciphertext', () => {
    const expected = [
      '76543210 28da3b14', '28da3b14 b14337a5', 'b14337a5 633a7c68', '633a7c68 ea89c02c',
      'ea89c02c 11fe726d', '11fe726d ad0310a4', 'ad0310a4 37d97f25', '37d97f25 46324615',
      '46324615 ce995f2a', 'ce995f2a 93c1f449', '93c1f449 4811c7ad', '4811c7ad c4b3edca',
      'c4b3edca 44ca5ce1', '44ca5ce1 fef51b68', 'fef51b68 2098cd86', '2098cd86 4f15b0bb',
      '4f15b0bb e32805bc', 'e32805bc e7116722', 'e7116722 89cadf21', '89cadf21 bac8444d',
      'bac8444d 11263a21', '11263a21 625434c3', '625434c3 8025c0a5', '8025c0a5 b0d66514',
      'b0d66514 47b1d5f4', '47b1d5f4 c78e6d50', 'c78e6d50 80251e99', '80251e99 2b96eca6',
      '2b96eca6 05ef4401', '05ef4401 239a4577', '239a4577 c2d8ca3d',
    ];
    const { out, trace } = magmaRounds(magmaRoundKeys(KEY), hexToBytes('fedcba9876543210'));
    expect(trace.map(([a, b]) => `${a.toString(16).padStart(8, '0')} ${b.toString(16).padStart(8, '0')}`))
      .toEqual(expected);
    expect(bytesToHex(out)).toBe('4ee901e5c2d8ca3d');
  });

  it('A.5 decryption returns the plaintext', () => {
    expect(bytesToHex(new Magma(KEY).decryptBlock(hexToBytes('4ee901e5c2d8ca3d')))).toBe('fedcba9876543210');
  });

  it('round-trips arbitrary blocks', () => {
    const m = new Magma(KEY);
    for (let i = 0; i < 64; i++) {
      const b = Uint8Array.from({ length: 8 }, (_, j) => (i * 37 + j * 11) & 0xff);
      expect(bytesToHex(m.decryptBlock(m.encryptBlock(b)))).toBe(bytesToHex(b));
    }
  });

  it('rejects a wrong-length key or block', () => {
    expect(() => new Magma(new Uint8Array(16))).toThrow(/32-byte key/);
    expect(() => new Magma(KEY).encryptBlock(new Uint8Array(16))).toThrow(/8 bytes/);
  });
});
