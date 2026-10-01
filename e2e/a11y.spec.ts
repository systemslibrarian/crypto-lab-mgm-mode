import { expect, test } from '@playwright/test';
import { boot, driveAllStates, expectBaselineNotStale, NARROW, reportCollected, watchPageErrors } from './gate';

/**
 * WCAG 2.1 A/AA gate. Every state `driveAllStates` reaches is scanned, at
 * desktop and phone width, under a dark-preference and a light-preference OS.
 * The page is dark under both: dark is the fleet's only theme, and the
 * light-OS runs are the proof the pin ignores the preference.
 */
for (const os of ['dark', 'light'] as const) {
  test(`no WCAG A/AA violations, ${os}-preference OS`, async ({ page }) => {
    test.setTimeout(900_000);
    const errors = watchPageErrors(page);
    await boot(page, os);
    await driveAllStates(page, `${os}-OS`);
    expect(errors, errors.join('\n')).toEqual([]);
    expectBaselineNotStale();
    reportCollected();
  });

  test(`no WCAG A/AA violations, ${os}-preference OS, at 380px`, async ({ page }) => {
    test.setTimeout(900_000);
    const errors = watchPageErrors(page);
    await page.setViewportSize(NARROW);
    await boot(page, os);
    await driveAllStates(page, `${os}-OS @380px`);
    expect(errors, errors.join('\n')).toEqual([]);
    expectBaselineNotStale();
    reportCollected();
  });
}
