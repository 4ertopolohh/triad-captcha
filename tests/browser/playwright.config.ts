import { defineConfig, devices } from '@playwright/test';

export default defineConfig({
  testDir: '.',
  testMatch: 'security-contract.spec.ts',
  fullyParallel: false,
  forbidOnly: true,
  retries: 0,
  workers: 1,
  timeout: 30_000,
  expect: { timeout: 10_000 },
  reporter: [['list']],
  use: {
    ...devices['Desktop Chrome'],
    baseURL: process.env.TRIADCAPTCHA_BROWSER_DEMO_URL ?? 'http://localhost:8080',
    browserName: 'chromium',
    headless: true,
    ignoreHTTPSErrors: true,
    launchOptions: {
      args: [
        '--host-resolver-rules=MAP *.triad.test 127.0.0.1, MAP *.other.test 127.0.0.1',
        '--no-proxy-server',
      ],
      ...(process.env.TRIADCAPTCHA_BROWSER_EXECUTABLE
        ? { executablePath: process.env.TRIADCAPTCHA_BROWSER_EXECUTABLE }
        : {}),
    },
  },
  webServer: {
    command: 'node server.mjs',
    url: 'https://127.0.0.1:9443/health',
    ignoreHTTPSErrors: true,
    reuseExistingServer: false,
    timeout: 20_000,
  },
});
