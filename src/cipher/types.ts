/** The only thing MGM asks of a block cipher: a keyed permutation of n-bit
 * blocks. RFC 9058 never decrypts with the cipher — MGM is "inverse free" —
 * so decryptBlock exists here only so the cipher pages can show a round trip. */
export interface BlockCipher {
  /** Human name, as the RFCs spell it. */
  readonly name: 'Magma' | 'Kuznyechik';
  /** n / 8: 8 for Magma, 16 for Kuznyechik. */
  readonly blockBytes: 8 | 16;
  encryptBlock(block: Uint8Array): Uint8Array;
  decryptBlock(block: Uint8Array): Uint8Array;
}

export type CipherName = BlockCipher['name'];
