import { defineConfig, devices } from '@playwright/test';

/**
 * E2E runs against the production build served by `vite preview`, so what
 * passes here is what ships. Two suites:
 *   - a11y.spec.ts   — the axe WCAG gate, Chromium only.
 *   - claims.spec.ts — does the page tell the truth; desktop Chromium and a phone.
 *
 * Port 4659 is unique to this lab across the fleet (never the Vite default 4173),
 * checked against every sibling playwright.config.ts on 2026-10-01.
 */
export default defineConfig({
  testDir: './e2e',
  fullyParallel: true,
  timeout: 90_000,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 1 : 0,
  reporter: process.env.CI ? 'list' : [['list'], ['html', { open: 'never' }]],
  use: {
    baseURL: 'http://localhost:4714/crypto-lab-mgm-mode/',
    colorScheme: 'dark',
    // Only for local runs in an environment whose Playwright browser build does
    // not match this package's version. CI never sets it.
    launchOptions: process.env.PW_CHROMIUM_PATH ? { executablePath: process.env.PW_CHROMIUM_PATH } : {},
  },
  projects: [
    { name: 'a11y', testMatch: /a11y\.spec\.ts/, use: { ...devices['Desktop Chrome'] } },
    { name: 'claims-chromium', testMatch: /claims\.spec\.ts/, use: { ...devices['Desktop Chrome'] } },
    { name: 'claims-mobile', testMatch: /claims\.spec\.ts/, use: { ...devices['Pixel 5'] } },
  ],
  webServer: {
    // Build before serving: `vite preview` serves whatever is already in dist/,
    // so without this a failing build passes green against the previous bundle.
    command: 'npm run build && npm run preview -- --port 4714 --strictPort',
    url: 'http://localhost:4714/crypto-lab-mgm-mode/',
    reuseExistingServer: !process.env.CI,
    timeout: 120_000,
  },
});
