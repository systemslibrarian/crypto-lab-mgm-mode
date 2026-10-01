import AxeBuilder from '@axe-core/playwright';
import { expect, type Page } from '@playwright/test';
import { auditContrast, formatContrastFailures } from './contrast';
import { auditNonText } from './nontext';
import { NONTEXT_BASELINE } from './nontext-baseline';

export const TAGS = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa'];

/** A phone-width viewport, for the WCAG 1.4.10 reflow half of the gate. */
export const NARROW = { width: 380, height: 800 };

/**
 * The WCAG gate for MGM Mode.
 *
 * The machinery (settle, the two-run axe scan, the incomplete bucket, the
 * arithmetic contrast walks, the non-text ratchet, reflow, scroller and
 * invisible-focus checks) is crypto-lab-schnorr-forge's gate at 21f668ba8232,
 * the one audits/_MASTER-TEMPLATE.md section 4.1 names, with its function
 * bodies unchanged. What is this lab's own is what the gate is told about the
 * page: `boot()` and `driveAllStates()`.
 *
 * What this page paints, and therefore what the oracles have to cover:
 *   - one long scrolling page of six exhibits, no tabs and no hidden panels;
 *   - verdict lines in four tones (`.verdict-ok/-bad/-warn/-idle`), each an
 *     icon glyph + words + colour, the glyph `aria-hidden`;
 *   - four scrolling `.table-wrap` regions (coefficients, RFC comparison,
 *     TLSTREE, S-box), each `role="region"` + `aria-label` + `tabindex="0"`;
 *   - long hex in `.mono`, wrapped with `overflow-wrap: anywhere`;
 *   - a range input, radios, a checkbox and styled `<select>`s.
 *
 * Nothing is injected into the page before a scan, nothing is revealed from
 * script, every state is reached by clicking the control a reader clicks, and
 * the defaults are asserted rather than assumed.
 */

/**
 * Wait for every running animation and transition to drain: six quiet frames,
 * bounded by a budget, ignoring infinite animations (this lab has none). Under
 * reduced motion this page runs no transitions at all — `style.css` declares
 * its only one inside `prefers-reduced-motion: no-preference` — so this is
 * normally six frames.
 */
export async function settle(page: Page, budgetMs = 4000): Promise<void> {
  await page.waitForFunction(
    (budget: number) => {
      const w = window as unknown as { __quietFrames?: number; __settleStart?: number };
      if (w.__settleStart === undefined) w.__settleStart = performance.now();
      const done = (): boolean => {
        w.__quietFrames = 0;
        w.__settleStart = undefined;
        return true;
      };
      const running = document.getAnimations().filter((a) => {
        if (a.playState !== 'running') return false;
        const timing = a.effect?.getComputedTiming?.();
        return timing?.iterations !== Infinity;
      });
      w.__quietFrames = running.length === 0 ? (w.__quietFrames ?? 0) + 1 : 0;
      if (w.__quietFrames >= 6) return done();
      if (performance.now() - (w.__settleStart ?? 0) > budget) return done();
      return false;
    },
    budgetMs,
    { timeout: 20_000, polling: 'raf' }
  );
}

/** No visible text may render at opacity 0 (aria-hidden glyphs excluded). */
async function expectNotBlank(page: Page, label: string): Promise<void> {
  const invisible = await page.evaluate(() => {
    const out: string[] = [];
    for (const el of Array.from(document.querySelectorAll('body *'))) {
      const own = Array.from(el.childNodes)
        .filter((n) => n.nodeType === Node.TEXT_NODE)
        .map((n) => n.textContent ?? '')
        .join('')
        .trim();
      if (!own) continue;
      if (!(el as HTMLElement).checkVisibility?.({ checkVisibilityCSS: true })) continue;
      if (el.closest('[aria-hidden="true"]')) continue;
      let effective = 1;
      let node: Element | null = el;
      while (node) {
        effective *= parseFloat(getComputedStyle(node).opacity);
        node = node.parentElement;
      }
      if (effective === 0) {
        out.push(`${el.tagName.toLowerCase()}.${(el.getAttribute('class') ?? '').trim()}`);
      }
    }
    return Array.from(new Set(out));
  });
  expect(invisible, `no visible text may render at opacity 0 in state: ${label}`).toEqual([]);
}

/** Uncaught page errors and console errors. Attach before `boot`, assert after the drive. */
export function watchPageErrors(page: Page): string[] {
  const errors: string[] = [];
  page.on('pageerror', (e) => errors.push(`pageerror: ${e.message}`));
  page.on('console', (m) => {
    if (m.type() === 'error') errors.push(`console.error: ${m.text()}`);
  });
  return errors;
}

/** Exactly one banner landmark: the shared top bar. The hero is a `<div>`. */
export async function assertSingleBanner(page: Page): Promise<void> {
  const banners = await page.evaluate(() => {
    const scoped = new Set(['MAIN', 'ARTICLE', 'ASIDE', 'NAV', 'SECTION']);
    const isBanner = (el: Element): boolean => {
      if (el.getAttribute('role') === 'banner') return true;
      if (el.tagName !== 'HEADER') return false;
      if (el.getAttribute('role')) return false;
      for (let p = el.parentElement; p; p = p.parentElement) if (scoped.has(p.tagName)) return false;
      return true;
    };
    return [...document.querySelectorAll('header,[role="banner"]')].filter(isBanner).length;
  });
  expect(banners, 'exactly one banner landmark').toBe(1);
}

/** Any explicit role on a list must be `list`, and never on an empty list. */
export async function assertListSemantics(page: Page): Promise<void> {
  const broken = await page.$$eval('ul[role], ol[role]', (els) =>
    els
      .filter((e) => e.getAttribute('role') !== 'list' || e.children.length === 0)
      .map((e) => `${e.tagName.toLowerCase()}[role=${e.getAttribute('role')}] with ${e.children.length} children`)
  );
  expect(broken, 'an explicit non-list role on a list deletes its semantics').toEqual([]);
}

/**
 * Load the page with reduced motion in effect and assert the defaults.
 *
 * `os` is the visitor's colour-scheme preference. Dark is the only theme, so
 * the page must be dark under either; the light-preference run is what proves
 * the pin ignores it.
 *
 * The workbench seals its default message at mount, so first paint must
 * already show a sealed result and a full coefficient table: a renderer that
 * threw would leave those empty, and an empty table is exactly what a scan
 * reports as perfectly accessible.
 */
export async function boot(page: Page, os: 'dark' | 'light'): Promise<void> {
  page.setDefaultTimeout(20_000);
  await page.emulateMedia({ reducedMotion: 'reduce', colorScheme: os });
  await page.goto('.');
  expect(
    await page.evaluate(() => matchMedia('(prefers-reduced-motion: reduce)').matches),
    'reduced-motion emulation must actually be in effect'
  ).toBe(true);
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'dark');
  await assertSingleBanner(page);
  await assertListSemantics(page);

  await expect(page.locator('main')).toHaveCount(1);
  await expect(page.locator('a.cl-skip-link')).toHaveAttribute('href', '#app');
  await expect(page.locator('#app')).toHaveCount(1);
  await expect(
    page.locator('#theme-toggle, #themeToggle, .theme-toggle, .theme-toggle-btn, [data-theme-toggle], #cl-theme-toggle')
  ).toHaveCount(0);

  // Six exhibits, in order.
  await expect(page.locator('section.exhibit h2 .num')).toHaveText(['1', '2', '3', '4', '5', '6']);

  // Shipped defaults: Magma, RFC 9058 A.2.1's key and ICN, full-block tag.
  await expect(page.locator('input[name="wb-cipher"][value="Magma"]')).toBeChecked();
  await expect(page.locator('#wb-key')).toHaveValue('ffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff');
  await expect(page.locator('#wb-icn')).toHaveValue('12def06b3c130a59');
  await expect(page.locator('#wb-taglen')).toHaveValue('8');

  // Sealed at mount: verdict, receiver panel and coefficient table present.
  await expect(page.locator('#wb-status')).toHaveAttribute('data-verdict', 'sealed');
  await expect(page.locator('#wb-out')).toBeVisible();
  await expect(page.locator('#rx-verdict')).toHaveAttribute('data-verdict', 'pending');
  await expect(page.locator('#cf-table-body tr')).not.toHaveCount(0);
  await expect(page.locator('#cf-summary')).toHaveAttribute('data-verdict', 'distinct');
  await expect(page.locator('#cf-progress')).toHaveText(/^0 of \d+ positions/);

  // Exhibits 3, 4 and 6 have not been run; the reuse result is hidden.
  await expect(page.locator('#rfc-table-body tr')).toHaveCount(0);
  await expect(page.locator('#rfc-table-wrap')).toBeHidden();
  await expect(page.locator('#ru-result')).toBeHidden();
  await expect(page.locator('#sb-variant')).toHaveText('—');

  await settle(page);
  await expectNotBlank(page, `${os}-OS first paint`);
}

/** WCAG 1.4.10: the document must not scroll sideways. Names the widest culprit. */
export async function expectNoHorizontalOverflow(page: Page, label: string): Promise<void> {
  const overflow = await page.evaluate(() => {
    const doc = document.documentElement;
    if (doc.scrollWidth <= doc.clientWidth) return null;
    const clipped = (el: Element): boolean => {
      let n = el.parentElement;
      while (n && n !== doc) {
        const ox = getComputedStyle(n).overflowX;
        if (ox === 'auto' || ox === 'scroll' || ox === 'hidden' || ox === 'clip') return true;
        n = n.parentElement;
      }
      return false;
    };
    const over = Array.from(document.querySelectorAll('body *'))
      .map((el) => ({ el, r: el.getBoundingClientRect() }))
      .filter((x) => x.r.width > 0 && x.r.right > doc.clientWidth + 1)
      .sort((a, b) => b.r.right - a.r.right);
    const widest = over.filter((x) => !clipped(x.el))[0] ?? over[0];
    return {
      scrollWidth: doc.scrollWidth,
      clientWidth: doc.clientWidth,
      widest: widest
        ? `${clipped(widest.el) ? '[clipped] ' : ''}${widest.el.tagName.toLowerCase()}${widest.el.id ? '#' + widest.el.id : ''}` +
          `${widest.el.getAttribute('class') ? '.' + widest.el.getAttribute('class')!.trim().split(/\s+/).join('.') : ''}` +
          ` @${Math.round(widest.r.width)}px right=${Math.round(widest.r.right)}`
        : '(none identified)',
    };
  });
  expect(overflow, `page must not scroll horizontally in state: ${label}`).toBeNull();
}

/**
 * Every scrolling container must be keyboard-operable (WCAG 2.1.1). This page
 * has four `.table-wrap` scrollers on purpose, so here the check is never
 * vacuous: each carries `tabindex="0"`, and this fails the day one does not.
 */
export async function expectScrollersReachable(page: Page, label: string): Promise<void> {
  const unreachable = await page.evaluate(() => {
    const FOCUSABLE = 'a[href],button,input,select,textarea,summary,[tabindex]:not([tabindex="-1"])';
    return Array.from(document.querySelectorAll<HTMLElement>('body *'))
      .filter((el) => el.scrollWidth > el.clientWidth + 1 || el.scrollHeight > el.clientHeight + 1)
      .filter((el) => {
        const cs = getComputedStyle(el);
        return ['auto', 'scroll'].includes(cs.overflowX) || ['auto', 'scroll'].includes(cs.overflowY);
      })
      .filter((el) => el.tabIndex < 0 && !el.querySelector(FOCUSABLE))
      .map((el) => `${el.tagName.toLowerCase()}.${(el.getAttribute('class') ?? '').trim()} (${el.scrollWidth}x${el.scrollHeight} in ${el.clientWidth}x${el.clientHeight})`);
  });
  expect(Array.from(new Set(unreachable)), `scrolling regions with no keyboard route in state: ${label}`).toEqual([]);
}

/** Nothing may be focusable while it paints nothing (WCAG 2.4.3 / 2.4.7). */
export async function expectNoInvisibleFocusTargets(page: Page, label: string): Promise<void> {
  const bad = await page.evaluate(() => {
    const FOCUSABLE = 'a[href],button,input,select,textarea,summary,[tabindex]:not([tabindex="-1"])';
    const out: string[] = [];
    for (const el of Array.from(document.querySelectorAll<HTMLElement>(FOCUSABLE))) {
      if (el.tabIndex < 0) continue;
      if (!el.checkVisibility?.({ checkVisibilityCSS: true })) continue;
      let effective = 1;
      for (let n: Element | null = el; n; n = n.parentElement) effective *= parseFloat(getComputedStyle(n).opacity);
      const r = el.getBoundingClientRect();
      if (effective !== 0 && r.width > 0 && r.height > 0) continue;
      const before = document.activeElement;
      el.focus();
      const took = document.activeElement === el;
      (before as HTMLElement | null)?.focus?.();
      if (took) out.push(`${el.tagName.toLowerCase()}${el.id ? '#' + el.id : ''} (opacity ${effective}, ${Math.round(r.width)}x${Math.round(r.height)})`);
    }
    return Array.from(new Set(out));
  });
  expect(bad, `focusable elements that paint nothing in state: ${label}`).toEqual([]);
}

/** `A11Y_COLLECT=1`: record failures instead of throwing, then fail at the end. Never set in CI. */
const COLLECTING = !!process.env.A11Y_COLLECT;
const collected: string[] = [];

function record(entry: string): void {
  collected.push(entry);
  console.log(`\n[A11Y_COLLECT #${collected.length}] ${entry}`);
}

export function softExpect(actual: unknown, message: string, expected: unknown): void {
  if (!COLLECTING) {
    expect(actual, message).toEqual(expected);
    return;
  }
  try {
    expect(actual, message).toEqual(expected);
  } catch {
    record(`${message}\n  ${JSON.stringify(actual, null, 2)}`);
  }
}

export function reportCollected(): void {
  if (!COLLECTING) return;
  expect(collected, `A11Y_COLLECT recorded ${collected.length} failure(s)`).toEqual([]);
}

async function soft(fn: () => Promise<void>): Promise<void> {
  if (!COLLECTING) return fn();
  try {
    await fn();
  } catch (e) {
    record(String(e).slice(0, 6000));
  }
}

/**
 * WCAG 1.4.11 and generated content, ratcheted against `nontext-baseline.ts`:
 * a finding not listed fails, a listed finding that got worse fails, and a
 * listed finding that was fixed fails until its entry is deleted. Called from
 * `scan()` on every state, strict or collecting.
 */
const nonTextSeen = new Set<string>();

export async function expectNoNewNonTextFailures(page: Page, label: string): Promise<void> {
  const found = await auditNonText(page);
  if (process.env.NT_BASELINE_CAPTURE) {
    for (const f of found) console.log(`NTCAP|${f.kind}|${f.selector}|${f.ratio}|${f.required}|${/POSITIONED/.test(f.detail)}`);
    return;
  }
  const problems: string[] = [];
  for (const f of found) {
    const key = `${f.kind}|${f.selector}`;
    nonTextSeen.add(key);
    const base = NONTEXT_BASELINE[key];
    if (!base) problems.push(`NEW ${f.ratio}:1 (needs ${f.required}:1) [${f.kind}] ${f.selector} — ${f.detail}`);
    else if (f.ratio < base.ratio - 0.01) problems.push(`WORSE ${f.selector}: ${f.ratio}:1, baseline recorded ${base.ratio}:1`);
  }
  expect(problems, `new or worsened non-text contrast in state: ${label}`).toEqual([]);
}

export function expectBaselineNotStale(): void {
  const unseen = Object.keys(NONTEXT_BASELINE).filter((k) => !nonTextSeen.has(k));
  expect(unseen, 'baselined non-text findings that no longer appear — delete them from nontext-baseline.ts').toEqual([]);
}

/**
 * Scan the page as it stands: reduced-motion end state, axe WCAG rules AND the
 * four landmark best-practice rules as two separate runs (chaining withTags
 * and withRules silently replaces the first), axe's `incomplete` bucket
 * (only `color-contrast` may remain, because it is measured arithmetically
 * next), the contrast walk with and without the aria-hidden exemption,
 * non-text contrast, scroller reachability, invisible focus targets, reflow.
 */
export async function scan(page: Page, label: string): Promise<void> {
  await settle(page);
  await expectNotBlank(page, label);
  const wcag = await new AxeBuilder({ page }).withTags(TAGS).analyze();
  const landmarks = await new AxeBuilder({ page })
    .withRules(['landmark-no-duplicate-banner', 'landmark-unique', 'landmark-one-main', 'landmark-complementary-is-top-level'])
    .analyze();
  const results = {
    violations: [...wcag.violations, ...landmarks.violations],
    incomplete: [...wcag.incomplete, ...landmarks.incomplete],
  };
  const violations = results.violations.map((v) => ({
    state: label, id: v.id, impact: v.impact, help: v.help,
    nodes: v.nodes.map((n) => n.target.join(' ')).slice(0, 8),
  }));
  softExpect(violations, `axe violations in state: ${label}`, []);
  const unexplainedIncomplete = results.incomplete
    .filter((v) => v.id !== 'color-contrast')
    .map((v) => ({ state: label, id: v.id, nodes: v.nodes.map((n) => n.target.join(' ')).slice(0, 8) }));
  softExpect(unexplainedIncomplete, `axe incomplete results in state: ${label}`, []);
  const contrast = Array.from(new Set(formatContrastFailures(await auditContrast(page))));
  softExpect(contrast, `measured contrast failures in state: ${label}`, []);
  const hiddenContrast = Array.from(new Set(formatContrastFailures(
    await auditContrast(page, '[aria-hidden="true"], [aria-hidden="true"] *', true))));
  softExpect(hiddenContrast, `measured aria-hidden contrast failures in state: ${label}`, []);
  await soft(() => expectNoNewNonTextFailures(page, label));
  await soft(() => expectScrollersReachable(page, label));
  await soft(() => expectNoInvisibleFocusTargets(page, label));
  await soft(() => expectNoHorizontalOverflow(page, label));
}

/**
 * Drive every state the lab renders, scanning each: arrival; the skip link
 * focused; each tamper and its rejection; a refused input; the restored and
 * verified message; Kuznyechik; the coefficient walk partly and fully folded;
 * the RFC comparison; nonce reuse and its control; the limits slider at both
 * ends; the S-box swap, a no-op swap and the restore; hover and focus.
 * Every wait is on a real DOM signal, never a fixed timeout.
 */
export async function driveAllStates(page: Page, label: string): Promise<void> {
  const scanAt = (s: string): Promise<void> => scan(page, `${label} / ${s}`);

  await scanAt('arrival: sealed under RFC 9058 A.2.1 inputs, nothing verified yet');

  await page.evaluate(() => (document.activeElement as HTMLElement | null)?.blur?.());
  await page.keyboard.press('Tab');
  await expect(page.locator('a.cl-skip-link')).toBeFocused();
  await scanAt('the skip link focused');

  // ── Exhibit 1: open, tamper, refuse ─────────────────────────────────────
  await page.getByRole('button', { name: 'Verify and open' }).click();
  await expect(page.locator('#rx-verdict')).toHaveAttribute('data-verdict', 'verified');
  await scanAt('Seal: verified and opened');

  for (const [btn, what] of [['Flip one bit of C', 'C'], ['Flip one bit of A', 'A'], ['Flip one bit of T', 'T']] as const) {
    await page.getByRole('button', { name: btn }).click();
    await expect(page.locator('#rx-verdict')).toHaveAttribute('data-verdict', 'pending');
    await page.getByRole('button', { name: 'Verify and open' }).click();
    await expect(page.locator('#rx-verdict')).toHaveAttribute('data-verdict', 'rejected');
    await expect(page.locator('#rx-plain')).toHaveText('');
    await scanAt(`Seal: one bit of ${what} flipped, rejected`);
  }
  await page.getByRole('button', { name: 'Restore what was sent' }).click();
  await page.getByRole('button', { name: 'Verify and open' }).click();
  await expect(page.locator('#rx-verdict')).toHaveAttribute('data-verdict', 'verified');

  await page.fill('#wb-icn', 'ffff');
  await expect(page.locator('#wb-status')).toHaveAttribute('data-verdict', 'retired');
  await scanAt('Seal: an input edited, the previous seal retired');
  await page.getByRole('button', { name: 'Seal with MGM' }).click();
  await expect(page.locator('#wb-status')).toHaveAttribute('data-verdict', 'refused');
  await scanAt('Seal: a malformed ICN refused');

  await page.locator('input[name="wb-cipher"][value="Kuznyechik"]').check();
  await page.getByRole('button', { name: 'Seal with MGM' }).click();
  await expect(page.locator('#wb-status')).toHaveAttribute('data-verdict', 'sealed');
  await expect(page.locator('#wb-icn')).toHaveValue('1122334455667700ffeeddccbbaa9988');
  await scanAt('Seal: Kuznyechik, sealed');

  // ── Exhibit 2: the coefficient walk ─────────────────────────────────────
  await page.getByRole('button', { name: 'Fold in the next block' }).click();
  await page.getByRole('button', { name: 'Fold in the next block' }).click();
  await expect(page.locator('#cf-progress')).toHaveText(/^2 of /);
  await scanAt('Coefficients: two blocks folded in');
  await page.getByRole('button', { name: 'Show the whole tag computation' }).click();
  await expect(page.locator('#cf-walk [data-verdict="walk-matches"]')).toHaveCount(1);
  await expect(page.getByRole('button', { name: 'Fold in the next block' })).toBeDisabled();
  await scanAt('Coefficients: the whole tag computed, Next disabled');

  // ── Exhibit 3: RFC 9058 ─────────────────────────────────────────────────
  await page.getByRole('button', { name: 'Run and compare' }).click();
  await expect(page.locator('#rfc-verdict')).toHaveAttribute('data-verdict', 'rfc-all-match');
  await scanAt('RFC: Kuznyechik example 1, every value matching');
  await page.selectOption('#rfc-example', '3');
  await expect(page.locator('#rfc-verdict')).toHaveAttribute('data-verdict', 'retired');
  await page.getByRole('button', { name: 'Run and compare' }).click();
  await expect(page.locator('#rfc-verdict')).toHaveAttribute('data-verdict', 'rfc-all-match');
  await scanAt('RFC: Magma example 2 after a retired verdict');

  // ── Exhibit 4: nonce reuse ──────────────────────────────────────────────
  await page.getByRole('button', { name: 'Encrypt both' }).click();
  await expect(page.locator('#ru-verdict')).toHaveAttribute('data-verdict', 'verified-and-leaked');
  await scanAt('Reuse: verified and leaked');
  await page.locator('#ru-distinct').check();
  await page.getByRole('button', { name: 'Encrypt both' }).click();
  await expect(page.locator('#ru-verdict')).toHaveAttribute('data-verdict', 'no-leak');
  await scanAt('Reuse: the distinct-ICN control');

  // ── Exhibit 5: limits at both ends ──────────────────────────────────────
  await page.locator('#lm-volume').focus();
  await page.keyboard.press('End');
  await expect(page.locator('#lm-kuz')).toHaveClass('bad-text');
  await scanAt('Limits: 2^70 bytes, both bounds vacuous');
  await page.keyboard.press('Home');
  await expect(page.locator('#lm-magma')).toHaveClass('ok-text');
  await scanAt('Limits: 1 KiB, both bounds small');

  // ── Exhibit 6: the S-box ────────────────────────────────────────────────
  await page.getByRole('button', { name: 'Swap and encrypt' }).click();
  await expect(page.locator('#sb-verdict')).toHaveAttribute('data-verdict', 'different-cipher');
  await expect(page.locator('#sb-table-body td.swapped')).toHaveCount(2);
  await scanAt('S-box: two entries swapped, a different cipher');
  await page.selectOption('#sb-b', '0');
  await page.getByRole('button', { name: 'Swap and encrypt' }).click();
  await expect(page.locator('#sb-verdict')).toHaveAttribute('data-verdict', 'noop');
  await scanAt('S-box: an entry swapped with itself, refused as a no-op');
  await page.getByRole('button', { name: 'Restore param-Z' }).click();
  await expect(page.locator('#sb-table-body td.swapped')).toHaveCount(0);

  // ── Hover and focus ─────────────────────────────────────────────────────
  await page.getByRole('button', { name: 'Seal with MGM' }).hover();
  await scanAt('a primary button hovered');
  await page.getByRole('button', { name: 'New random key' }).hover();
  await scanAt('a secondary button hovered');
  await page.locator('.cl-topbar .cl-btn').first().hover();
  await scanAt('a top bar control hovered');
  await page.locator('#wb-pt').focus();
  await scanAt('a textarea focused');
  await page.locator('.table-wrap').first().focus();
  await scanAt('a scrolling table region focused');
}
