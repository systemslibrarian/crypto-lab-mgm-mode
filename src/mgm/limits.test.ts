import { describe, expect, it } from 'vitest';
import {
  TLSTREE_SUITES, log2ConfidentialityBound, log2IntegrityBound, maxBlocksForBound,
  recordsPerLeafKey, trailingZeroBits,
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
