import { describe, expect, it } from 'vitest';
import {
  TLSTREE_SUITES, exceedsInputLimit, log2ConfidentialityBound, log2IntegrityBound,
  maxBlocksForBound, maxInputBits, recordsPerLeafKey, trailingZeroBits,
} from './limits';

describe('RFC 9058 section 6 bounds', () => {
  it('at 2^32 blocks the 64-bit bound is already near 1, the 128-bit one negligible', () => {
    // 3 * (2^32 + 4)^2 / 2^64 is about 3; / 2^128 is about 2^-62.4.
    const s = 2 ** 32;
    expect(log2ConfidentialityBound({ n: 64, s, q: 1 })).toBeCloseTo(Math.log2(3), 3);
    expect(log2ConfidentialityBound({ n: 128, s, q: 1 })).toBeCloseTo(Math.log2(3) - 64, 3);
  });
  it('the same data costs exactly 64 bits more advantage at n = 64', () => {
    for (const s of [1e3, 1e6, 1e9]) {
      const d = log2ConfidentialityBound({ n: 64, s, q: 10 }) - log2ConfidentialityBound({ n: 128, s, q: 10 });
      expect(d).toBeCloseTo(64, 9);
    }
  });
  it('maxBlocksForBound inverts the confidentiality bound', () => {
    for (const n of [64, 128] as const) {
      const s = maxBlocksForBound(n, 30, 1);
      expect(log2ConfidentialityBound({ n, s, q: 1 })).toBeCloseTo(-30, 6);
    }
  });
  it('the integrity bound never drops below the tag-guessing term 2/2^S', () => {
    expect(log2IntegrityBound({ n: 128, s: 1, q: 1 }, 1, 64)).toBeGreaterThanOrEqual(1 - 64 - 1e-9);
    expect(log2IntegrityBound({ n: 64, s: 2 ** 20, q: 1 }, 1, 64)).toBeGreaterThan(log2ConfidentialityBound({ n: 64, s: 2 ** 20, q: 1 }));
  });
});

describe('RFC 9367 TLSTREE re-keying, derived from Table 1', () => {
  it('records per leaf key come from the trailing zeros of C_3', () => {
    expect(trailingZeroBits(0xffffffffffffe000n)).toBe(13);
    expect(Object.fromEntries(TLSTREE_SUITES.map((s) => [s.suite, recordsPerLeafKey(s)]))).toEqual({
      TLS_GOSTR341112_256_WITH_KUZNYECHIK_MGM_L: 8192,
      TLS_GOSTR341112_256_WITH_MAGMA_MGM_L: 128,
      TLS_GOSTR341112_256_WITH_KUZNYECHIK_MGM_S: 8,
      TLS_GOSTR341112_256_WITH_MAGMA_MGM_S: 1,
    });
  });
  it('in each pair the Magma suite re-keys at least as often as the Kuznyechik one', () => {
    const [kl, ml, ks, ms] = TLSTREE_SUITES.map(recordsPerLeafKey);
    expect(ml).toBeLessThan(kl);
    expect(ms).toBeLessThan(ks);
    expect(TLSTREE_SUITES[3].snmaxLog2).toBeLessThan(TLSTREE_SUITES[2].snmaxLog2);
  });
});

/**
 * RFC 9058 section 4.1, quoted from the RFC rather than read off this code:
 *
 *   "Associated authenticated data A, 0 <= |A| < 2^{n/2}."
 *   "Plaintext P, 0 <= |P| < 2^{n/2}."
 *   "The length of the associated data A and of the plaintext P MUST be such
 *    that 0 < |A| + |P| < 2^{n/2}."
 *
 * Lengths are in bits. Every expected value below is that clause arithmetic --
 * 2^32 bits is 512 MiB, 2^64 bits is 2 EiB -- and none of it was taken from
 * what the implementation returns.
 *
 * Section 4.1c mutation, run 2026-11-17: in exceedsInputLimit, relax `>=` to
 * `>` (making the exclusive ceiling inclusive). Tests (a) and (b) both fail on
 * the at-the-limit case. Dropping the `* 8` instead -- comparing bytes against
 * a bit count -- fails (a), (b) and the boundary test. The mutation is on the
 * limit check itself, not on the display flag in src/ui/exhibits.ts.
 */
describe('RFC 9058 section 4.1 input-length limit', () => {
  it('(a) a Magma message at or above the RFC limit is flagged invalid', () => {
    // n = 64, so the ceiling is 2^32 bits = 2^29 bytes = 512 MiB, EXCLUSIVE.
    expect(maxInputBits(64)).toBe(2 ** 32);
    expect(exceedsInputLimit(64, 512 * 1024 * 1024)).toBe(true);
    expect(exceedsInputLimit(64, 32 * 1024 * 1024 * 1024)).toBe(true); // the old 32 GiB default
    expect(exceedsInputLimit(64, 512 * 1024 * 1024 - 1)).toBe(false);
    expect(exceedsInputLimit(64, 0)).toBe(true); // "0 < |A| + |P|"
  });

  it('(b) Kuznyechik carries a different limit, and 512 MiB is legal there', () => {
    // n = 128, so the ceiling is 2^64 bits = 2^61 bytes = 2 EiB.
    expect(maxInputBits(128)).toBe(2 ** 64);
    expect(maxInputBits(128) / maxInputBits(64)).toBe(2 ** 32);
    expect(exceedsInputLimit(128, 512 * 1024 * 1024)).toBe(false);
    expect(exceedsInputLimit(128, 32 * 1024 * 1024 * 1024)).toBe(false);
    expect(exceedsInputLimit(128, 2 ** 61)).toBe(true);
    expect(exceedsInputLimit(128, 2 ** 61 - 1024)).toBe(false);
  });

  it('(c) changing the message count changes the bound', () => {
    // Section 6 counts s over every message, so splitting a fixed total across
    // more queries leaves s alone and raises 4q: the bound gets slightly worse,
    // not better. Splitting is what makes each message a legal INPUT.
    const s = 2 ** 32;
    const one = log2ConfidentialityBound({ n: 64, s, q: 1 });
    const many = log2ConfidentialityBound({ n: 64, s, q: 2 ** 20 });
    expect(many).toBeGreaterThan(one);
    // 3(s + 4q)^2 / 2^n, computed from the RFC formula here.
    expect(many).toBeCloseTo(Math.log2(3 * (2 ** 32 + 4 * 2 ** 20) ** 2) - 64, 6);
    // And the same split is what brings one Magma message inside section 4.1.
    const total = 32 * 1024 * 1024 * 1024;
    expect(exceedsInputLimit(64, total / 1)).toBe(true);
    expect(exceedsInputLimit(64, total / 128)).toBe(false);
  });

  it('the exhibit default sits inside the valid region for both ciphers', () => {
    // index.html ships lm-volume = 2^35 bytes split across 2^7 messages.
    const perMessage = 2 ** 35 / 2 ** 7;
    expect(exceedsInputLimit(64, perMessage)).toBe(false);
    expect(exceedsInputLimit(128, perMessage)).toBe(false);
  });
});
