import { describe, expect, it } from 'vitest';
import { Kuznyechik, PI_INV, ROUND_CONSTANTS, kuzL, kuzR, kuzS } from './kuznyechik';
import { bytesToHex, hexToBytes } from './bytes';

// Every value below is copied from RFC 7801.
const KEY = hexToBytes('8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef');
const hex = (s: string) => hexToBytes(s);

describe('Kuznyechik, RFC 7801', () => {
  it('section 4.1: the computed pi^-1 equals the table the RFC prints', () => {
    const printed = [165, 45, 50, 143, 14, 48, 56, 192, 84, 230, 158, 57, 85, 126, 82, 145,
      100, 3, 87, 90, 28, 96, 7, 24, 33, 114, 168, 209, 41, 198, 164, 63, 224, 39, 141, 12,
      130, 234, 174, 180, 154, 99, 73, 229, 66, 228, 21, 183, 200, 6, 112, 157, 65, 117, 25,
      201, 170, 252, 77, 191, 42, 115, 132, 213, 195, 175, 43, 134, 167, 177, 178, 91, 70, 211,
      159, 253, 212, 15, 156, 47, 155, 67, 239, 217, 121, 182, 83, 127, 193, 240, 35, 231, 37,
      94, 181, 30, 162, 223, 166, 254, 172, 34, 249, 226, 74, 188, 53, 202, 238, 120, 5, 107,
      81, 225, 89, 163, 242, 113, 86, 17, 106, 137, 148, 101, 140, 187, 119, 60, 123, 40, 171,
      210, 49, 222, 196, 95, 204, 207, 118, 44, 184, 216, 46, 54, 219, 105, 179, 20, 149, 190,
      98, 161, 59, 22, 102, 233, 92, 108, 109, 173, 55, 97, 75, 185, 227, 186, 241, 160, 133,
      131, 218, 71, 197, 176, 51, 250, 150, 111, 110, 194, 246, 80, 255, 93, 169, 142, 23, 27,
      151, 125, 236, 88, 247, 31, 251, 124, 9, 13, 122, 103, 69, 135, 220, 232, 79, 29, 78, 4,
      235, 248, 243, 62, 61, 189, 138, 136, 221, 205, 11, 19, 152, 2, 147, 128, 144, 208, 36,
      52, 203, 237, 244, 206, 153, 16, 68, 64, 146, 58, 1, 38, 18, 26, 72, 104, 245, 129, 139,
      199, 214, 32, 10, 8, 0, 76, 215, 116];
    expect(PI_INV).toEqual(printed);
  });

  it('5.1 transformation S', () => {
    expect(bytesToHex(kuzS(hex('ffeeddccbbaa99881122334455667700')))).toBe('b66cd8887d38e8d77765aeea0c9a7efc');
    expect(bytesToHex(kuzS(hex('b66cd8887d38e8d77765aeea0c9a7efc')))).toBe('559d8dd7bd06cbfe7e7b262523280d39');
    expect(bytesToHex(kuzS(hex('559d8dd7bd06cbfe7e7b262523280d39')))).toBe('0c3322fed531e4630d80ef5c5a81c50b');
    expect(bytesToHex(kuzS(hex('0c3322fed531e4630d80ef5c5a81c50b')))).toBe('23ae65633f842d29c5df529c13f5acda');
  });

  it('5.2 transformation R', () => {
    expect(bytesToHex(kuzR(hex('00000000000000000000000000000100')))).toBe('94000000000000000000000000000001');
    expect(bytesToHex(kuzR(hex('94000000000000000000000000000001')))).toBe('a5940000000000000000000000000000');
    expect(bytesToHex(kuzR(hex('a5940000000000000000000000000000')))).toBe('64a59400000000000000000000000000');
    expect(bytesToHex(kuzR(hex('64a59400000000000000000000000000')))).toBe('0d64a594000000000000000000000000');
  });

  it('5.3 transformation L', () => {
    expect(bytesToHex(kuzL(hex('64a59400000000000000000000000000')))).toBe('d456584dd0e3e84cc3166e4b7fa2890d');
    expect(bytesToHex(kuzL(hex('d456584dd0e3e84cc3166e4b7fa2890d')))).toBe('79d26221b87b584cd42fbc4ffea5de9a');
    expect(bytesToHex(kuzL(hex('79d26221b87b584cd42fbc4ffea5de9a')))).toBe('0e93691a0cfc60408b7b68f66b513c13');
    expect(bytesToHex(kuzL(hex('0e93691a0cfc60408b7b68f66b513c13')))).toBe('e6a8094fee0aa204fd97bcb0b44b8580');
  });

  it('5.4 round constants and round keys', () => {
    expect(bytesToHex(ROUND_CONSTANTS[0])).toBe('6ea276726c487ab85d27bd10dd849401');
    expect(bytesToHex(ROUND_CONSTANTS[7])).toBe('f6593616e6055689adfba18027aa2a08');
    expect(new Kuznyechik(KEY).roundKeys.map(bytesToHex)).toEqual([
      '8899aabbccddeeff0011223344556677', 'fedcba98765432100123456789abcdef',
      'db31485315694343228d6aef8cc78c44', '3d4553d8e9cfec6815ebadc40a9ffd04',
      '57646468c44a5e28d3e59246f429f1ac', 'bd079435165c6432b532e82834da581b',
      '51e640757e8745de705727265a0098b1', '5a7925017b9fdd3ed72a91a22286f984',
      'bb44e25378c73123a5f32f73cdb6e517', '72e9dd7416bcf45b755dbaa88e4a4043',
    ]);
  });

  it('5.5 encryption and 5.6 decryption', () => {
    const k = new Kuznyechik(KEY);
    expect(bytesToHex(k.encryptBlock(hex('1122334455667700ffeeddccbbaa9988')))).toBe('7f679d90bebc24305a468d42b9d4edcd');
    expect(bytesToHex(k.decryptBlock(hex('7f679d90bebc24305a468d42b9d4edcd')))).toBe('1122334455667700ffeeddccbbaa9988');
  });

  it('round-trips arbitrary blocks', () => {
    const k = new Kuznyechik(KEY);
    for (let i = 0; i < 32; i++) {
      const b = Uint8Array.from({ length: 16 }, (_, j) => (i * 53 + j * 29) & 0xff);
      expect(bytesToHex(k.decryptBlock(k.encryptBlock(b)))).toBe(bytesToHex(b));
    }
  });
});
