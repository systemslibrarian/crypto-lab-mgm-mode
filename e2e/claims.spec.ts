import { expect, test, type Page } from '@playwright/test';
import { RFC9058_VECTORS } from '../src/mgm/vectors';

/**
 * Does the page tell the truth (audits/_MASTER-TEMPLATE.md 4.1b and 4.1d)?
 *
 * Every claim is checked against something the page did not compute: the RFC
 * text (via the extracted vectors), arithmetic re-derived here by a different
 * route than src/ takes, or the inputs the test itself typed.
 */

const enc = new TextEncoder();
const dec = new TextDecoder();
const hexOf = (s: string) => s.replace(/[^0-9a-f]/gi, '').toLowerCase();
const bytes = (hex: string) => Uint8Array.from(hexOf(hex).match(/../g) ?? [], (b) => parseInt(b, 16));
const toHex = (b: Uint8Array) => Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');

/**
 * GF(2^n) multiplication, written independently of src/mgm/gf.ts: that one
 * shifts BigInts; this one works byte arrays bit by bit, MSB first, and
 * reduces with f(w) as RFC 9058 section 3 states it.
 */
function gfMulIndependent(x: Uint8Array, y: Uint8Array): Uint8Array {
  const n = x.length;
  const reduction = n === 8 ? 0x1b : 0x87;
  let acc: Uint8Array = new Uint8Array(n);
  for (let byte = 0; byte < n; byte++) {
    for (let bit = 7; bit >= 0; bit--) {
      // acc = acc * w  (shift left one bit, reduce on carry out)
      const carry = acc[0] & 0x80;
      const shifted = new Uint8Array(n);
      for (let i = 0; i < n; i++) shifted[i] = ((acc[i] << 1) | (i + 1 < n ? acc[i + 1] >> 7 : 0)) & 0xff;
      if (carry) shifted[n - 1] ^= reduction;
      acc = shifted;
      if ((y[byte] >> bit) & 1) for (let i = 0; i < n; i++) acc[i] ^= x[i];
    }
  }
  return acc;
}

async function open(page: Page) {
  await page.goto('.');
  await expect(page.locator('#wb-status')).toHaveAttribute('data-verdict', 'sealed');
}

test.describe('Exhibit 3: the page agrees with RFC 9058, value by value', () => {
  for (const [i, v] of RFC9058_VECTORS.entries()) {
    test(`${v.cipher} example ${v.example}: every computed value equals the RFC's`, async ({ page }) => {
      await open(page);
      await page.selectOption('#rfc-example', String(i));
      await page.getByRole('button', { name: 'Run and compare' }).click();
      const rows = page.locator('#rfc-table-body tr');
      const expected = [...v.y, ...v.keystream, ...(v.plaintext ? [v.ciphertext] : []), ...v.z, ...v.h, ...v.runningSum,
        v.lengthBlock, v.finalSum, v.tag];
      await expect(rows).toHaveCount(expected.length);
      // The "computed here" column, against the RFC text — not against the
      // page's own "RFC prints" column, which would only check the page agrees
      // with itself.
      const computed = await rows.locator('td:nth-child(3)').allTextContents();
      expect(computed).toEqual(expected);
      await expect(page.locator('#rfc-verdict')).toHaveAttribute('data-verdict', 'rfc-all-match');
      await expect(page.locator('#rfc-verdict')).toContainText(`${expected.length} of ${expected.length}`);
    });
  }
});

test.describe('Exhibit 2: one H versus one H_i per block', () => {
  test('the GCM column is powers of the single H, re-derived here', async ({ page }) => {
    await open(page);
    const summary = await page.locator('#cf-summary').textContent();
    const h = bytes(/H = ([0-9a-f]+)/.exec(summary ?? '')![1]);
    const cells = await page.locator('#cf-table-body td.gcm').allTextContents();
    expect(cells.length).toBeGreaterThan(3);
    for (const cell of cells) {
      const [, k, value] = /H\^(\d+) = ([0-9a-f]+)/.exec(cell)!;
      let acc: Uint8Array = h;
      for (let j = 1; j < Number(k); j++) acc = gfMulIndependent(acc, h);
      expect(value).toBe(toHex(acc));
    }
  });

  test('the MGM column is all distinct, as the summary says', async ({ page }) => {
    await open(page);
    const mgm = (await page.locator('#cf-table-body td.mgm').allTextContents()).map((c) => c.split('= ')[1]);
    expect(new Set(mgm).size).toBe(mgm.length);
    await expect(page.locator('#cf-summary')).toContainText(`all ${mgm.length} coefficients are distinct`);
  });

  test('each step of the walk: H_i (x) block and the running sum, re-derived here', async ({ page }) => {
    await open(page);
    await page.getByRole('button', { name: 'Show the whole tag computation' }).click();
    const lines = await page.locator('#cf-walk-list li').allTextContents();
    const blocks = await page.locator('#cf-table-body tr td:nth-child(2)').allTextContents();
    let sum = new Uint8Array(8);
    let checked = 0;
    for (const line of lines) {
      const m = /H_(\d+) = E_K\(Z_\d+\) = ([0-9a-f]+);\s+H_\d+ ⊗ \S+ = ([0-9a-f]+);\s+sum = ([0-9a-f]+)/.exec(line);
      if (!m) continue;
      const idx = Number(m[1]) - 1;
      const product = gfMulIndependent(bytes(m[2]), bytes(blocks[idx]));
      expect(m[3]).toBe(toHex(product));
      sum = sum.map((b, j) => b ^ product[j]);
      expect(m[4]).toBe(toHex(sum));
      checked++;
    }
    expect(checked).toBe(blocks.length - 1); // every block but the length block
    await expect(page.locator('#cf-walk [data-verdict="walk-matches"]')).toHaveCount(1);
  });

  test('the length block encodes |A| and |C| in bits, from what the test typed', async ({ page }) => {
    await open(page);
    const aad = await page.locator('#wb-aad').inputValue();
    const pt = await page.locator('#wb-pt').inputValue();
    const len = (await page.locator('#cf-table-body tr').last().locator('td').first().textContent())!;
    expect(parseInt(len.slice(0, 8), 16)).toBe(enc.encode(aad).length * 8);
    expect(parseInt(len.slice(8), 16)).toBe(enc.encode(pt).length * 8);
  });
});

test.describe('Exhibit 1: seal, open, tamper', () => {
  test('verify and open returns exactly the plaintext that was typed', async ({ page }) => {
    await open(page);
    await page.fill('#wb-pt', 'a fresh message for the round trip');
    await page.getByRole('button', { name: 'Seal with MGM' }).click();
    await page.getByRole('button', { name: 'Verify and open' }).click();
    await expect(page.locator('#rx-verdict')).toHaveAttribute('data-verdict', 'verified');
    await expect(page.locator('#rx-plain')).toHaveText('P = "a fresh message for the round trip"');
  });

  for (const [btn, part] of [['Flip one bit of C', 'C'], ['Flip one bit of A', 'A'], ['Flip one bit of T', 'T']]) {
    test(`one flipped bit of ${part} is rejected and releases no plaintext`, async ({ page }) => {
      await open(page);
      const before = { ct: await page.locator('#rx-ct').inputValue(), tag: await page.locator('#rx-tag').inputValue() };
      await page.getByRole('button', { name: btn }).click();
      const after = { ct: await page.locator('#rx-ct').inputValue(), tag: await page.locator('#rx-tag').inputValue() };
      if (part === 'C') expect(hexOf(after.ct)).not.toBe(hexOf(before.ct));
      if (part === 'T') expect(after.tag).not.toBe(before.tag);
      await page.getByRole('button', { name: 'Verify and open' }).click();
      await expect(page.locator('#rx-verdict')).toHaveAttribute('data-verdict', 'rejected');
      await expect(page.locator('#rx-verdict')).toContainText('No plaintext is released');
      await expect(page.locator('#rx-plain')).toHaveText('');
    });
  }

  test('the empty-A-and-empty-P input RFC 9058 forbids is refused, and says why', async ({ page }) => {
    await open(page);
    await page.fill('#wb-aad', '');
    await page.fill('#wb-pt', '');
    await page.getByRole('button', { name: 'Seal with MGM' }).click();
    await expect(page.locator('#wb-status')).toHaveAttribute('data-verdict', 'refused');
    await expect(page.locator('#wb-status')).toContainText('RFC 9058 section 6');
    await expect(page.locator('#wb-out')).toBeHidden();
  });

  test('an ICN with its top bit set is refused', async ({ page }) => {
    await open(page);
    await page.fill('#wb-icn', '92def06b3c130a59');
    await page.getByRole('button', { name: 'Seal with MGM' }).click();
    await expect(page.locator('#wb-status')).toHaveAttribute('data-verdict', 'refused');
    await expect(page.locator('#wb-status')).toContainText('top bit');
  });

  test('editing an input retires the seal and says so; re-choosing the same tag length does not', async ({ page }) => {
    await open(page);
    const tagLen = await page.locator('#wb-taglen').inputValue();
    await page.selectOption('#wb-taglen', tagLen); // no-op guard
    await expect(page.locator('#wb-status')).toHaveAttribute('data-verdict', 'sealed');
    await page.locator('#wb-pt').press('End');
    await page.locator('#wb-pt').pressSequentially('!');
    await expect(page.locator('#wb-status')).toHaveAttribute('data-verdict', 'retired');
    await expect(page.locator('#wb-status')).toContainText('retired');
    await expect(page.locator('#wb-out')).toBeHidden();
  });
});

test.describe('Exhibit 4, the negative claim: VERIFIED — AND LEAKED', () => {
  test('both messages verify, the limitation is on screen, and message 2 is read without the key', async ({ page }) => {
    await open(page);
    const p1 = await page.locator('#ru-p1').inputValue();
    const p2 = await page.locator('#ru-p2').inputValue();
    await page.getByRole('button', { name: 'Encrypt both' }).click();
    // 1. the fixture is reached
    await expect(page.locator('#ru-verdict')).toHaveAttribute('data-verdict', 'verified-and-leaked');
    // 2. every check the page renders reports success
    await expect(page.locator('#ru-v1')).toHaveText('✓ message 1 verifies');
    await expect(page.locator('#ru-v2')).toHaveText('✓ message 2 verifies');
    // 3. the limitation is visible in this state, not in a README
    await expect(page.locator('#ru-claim')).toBeVisible();
    await expect(page.locator('#ru-claim')).toContainText('confidentiality for two messages that share an ICN');
    // and the leak itself, re-derived here: (C1 xor C2) xor P1 = P2
    const xc = bytes((await page.locator('#ru-xc').textContent())!);
    const recovered = dec.decode(xc.map((b, i) => b ^ enc.encode(p1)[i]));
    expect(recovered).toBe(p2.slice(0, recovered.length));
    await expect(page.locator('#ru-recovered')).toHaveText(`"${recovered}"`);
  });

  test('the control: with distinct ICNs the xor relation is gone', async ({ page }) => {
    await open(page);
    await page.locator('#ru-distinct').check();
    await page.getByRole('button', { name: 'Encrypt both' }).click();
    await expect(page.locator('#ru-verdict')).toHaveAttribute('data-verdict', 'no-leak');
    const xc = await page.locator('#ru-xc').textContent();
    const xp = await page.locator('#ru-xp').textContent();
    expect(xc).not.toBe(xp);
  });

  test('the [hidden] probe: the reuse result is genuinely not painted before a run', async ({ page }) => {
    await open(page);
    const box = await page.locator('#ru-result').boundingBox();
    expect(box).toBeNull();
  });
});

test.describe('Exhibit 5: the limits are the RFC formulas, not prose', () => {
  test('the displayed bounds equal 3(s + 4q)^2 / 2^n recomputed here', async ({ page }) => {
    await open(page);
    const log2Bytes = Number(await page.locator('#lm-volume').inputValue());
    for (const [id, n] of [['#lm-magma', 64], ['#lm-kuz', 128]] as const) {
      const s = 2 ** log2Bytes / (n / 8);
      const expected = Math.log2(3 * (s + 4) ** 2) - n;
      const shown = Number(await page.locator(id).getAttribute('data-log2'));
      expect(Math.abs(shown - expected)).toBeLessThan(0.01);
    }
  });

  test('records per TLSTREE key equal 2^(trailing zeros of the C_3 printed beside them)', async ({ page }) => {
    await open(page);
    const rows = page.locator('#lm-tls-body tr');
    await expect(rows).toHaveCount(4);
    for (let i = 0; i < 4; i++) {
      const c3 = BigInt((await rows.nth(i).locator('td').nth(1).textContent())!);
      let z = 0; let v = c3;
      while ((v & 1n) === 0n) { v >>= 1n; z++; }
      expect(Number(await rows.nth(i).locator('td').nth(2).getAttribute('data-records'))).toBe(2 ** z);
    }
    // RFC 9367 Table 1 is public: the Magma L suite's C_3 is 0xffffffffffffff80.
    await expect(rows.nth(1).locator('td').nth(1)).toHaveText('0xffffffffffffff80');
  });
});

test.describe('Exhibit 6: a different S-box is a different cipher', () => {
  test('the reference is RFC 8891 A.4, and a swap changes the ciphertext', async ({ page }) => {
    await open(page);
    await expect(page.locator('#sb-reference')).toHaveText('4ee901e5c2d8ca3d');
    await page.getByRole('button', { name: 'Swap and encrypt' }).click();
    const variant = await page.locator('#sb-variant').textContent();
    expect(variant).toMatch(/^[0-9a-f]{16}$/);
    expect(variant).not.toBe('4ee901e5c2d8ca3d');
    await expect(page.locator('#sb-verdict')).toHaveAttribute('data-verdict', 'different-cipher');
  });
});

test.describe('honest scoping is on the page', () => {
  test('the Independent Submission status and the not-AES-GCM note are visible', async ({ page }) => {
    await open(page);
    await expect(page.locator('.caveat')).toContainText('Independent Submission');
    await expect(page.locator('#ex-coeff')).toContainText('not AES-GCM');
    await expect(page.locator('#ex-reuse')).toContainText('claims no forgery');
  });
});
