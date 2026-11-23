import {defineConfig} from '@playwright/test';

export const viewports = [
  {name: '1440x900', width: 1440, height: 900, gating: false},
  {name: '1280x800', width: 1280, height: 800, gating: true},
  {name: '1024x768', width: 1024, height: 768, gating: false},
  {name: '768x1024', width: 768, height: 1024, gating: false},
  {name: '390x844', width: 390, height: 844, gating: true},
];
export const themes = ['light', 'dark'] as const;

const only = process.env.UX_GATING_ONLY === '1';

export default defineConfig({
  testDir: 'tests',
  timeout: 60_000,
  globalTimeout: 115_000,
  fullyParallel: true,
  reporter: [['list']],
  use: {
    baseURL: process.env.UX_BASE_URL ?? 'https://beyond10x.github.io',
    reducedMotion: 'reduce',
  },
  projects: viewports
    .filter((v) => !only || v.gating)
    .flatMap((v) =>
      themes.map((theme) => ({
        name: `${v.name}-${theme}`,
        metadata: {viewport: v.name, theme, gating: v.gating},
        use: {viewport: {width: v.width, height: v.height}, colorScheme: theme},
      })),
    ),
});
