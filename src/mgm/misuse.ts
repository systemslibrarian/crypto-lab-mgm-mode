/**
 * What a repeated ICN costs, demonstrated rather than warned about.
 *
 * RFC 9058 section 6: "Using the same ICN values for two different messages
 * encrypted with the same key eliminates the security properties of this mode."
 * The part of that this lab can SHOW, with the real mode and nothing faked:
 * the encryption counter Y depends only on the key and the ICN, so two messages
 * under one ICN get the same keystream, and C1 xor C2 = P1 xor P2 — an
 * eavesdropper learns the xor of the two plaintexts without the key.
 *
 * Both messages still decrypt and verify. That is the negative claim this lab
 * makes (template section 4.1d): every check the receiver performs reports
 * success, and confidentiality is gone anyway. MGM has no code it can raise
 * here, because nothing it checks is violated.
 *
 * What this module does NOT claim: a tag forgery. GCM's nonce reuse famously
 * leaks H (Joux's "forbidden attack"); MGM encrypts its sum before output, and
 * this lab demonstrates no forgery against it. Saying otherwise would be
 * inventing a result.
 */
import type { BlockCipher } from '../cipher/types';
import { equalBytes, xorBytes } from '../cipher/bytes';
import { mgmDecrypt, mgmEncrypt } from './mgm';

export interface ReuseDemo {
  c1: Uint8Array; c2: Uint8Array; t1: Uint8Array; t2: Uint8Array;
  /** Over the common prefix length. */
  xorCiphertexts: Uint8Array;
  xorPlaintexts: Uint8Array;
  /** The receiver's own verdicts on each message. */
  verified1: boolean;
  verified2: boolean;
  /** C1 xor C2 equals P1 xor P2 byte for byte. */
  leaks: boolean;
}

export function reuseIcn(cipher: BlockCipher, icn: Uint8Array, aad: Uint8Array, p1: Uint8Array, p2: Uint8Array): ReuseDemo {
  const a = mgmEncrypt(cipher, icn, aad, p1);
  const b = mgmEncrypt(cipher, icn, aad, p2);
  const len = Math.min(p1.length, p2.length);
  const xorCiphertexts = xorBytes(a.ciphertext.subarray(0, len), b.ciphertext.subarray(0, len));
  const xorPlaintexts = xorBytes(p1.subarray(0, len), p2.subarray(0, len));
  return {
    c1: a.ciphertext, c2: b.ciphertext, t1: a.tag, t2: b.tag,
    xorCiphertexts, xorPlaintexts,
    verified1: mgmDecrypt(cipher, icn, aad, a.ciphertext, a.tag).ok,
    verified2: mgmDecrypt(cipher, icn, aad, b.ciphertext, b.tag).ok,
    leaks: equalBytes(xorCiphertexts, xorPlaintexts),
  };
}
