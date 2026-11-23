import {test, expect, type Page} from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';
import {mkdirSync, readFileSync, writeFileSync} from 'node:fs';
import path from 'node:path';

const here = path.dirname(new URL(import.meta.url).pathname);
const uxRoot = path.resolve(here, '..');
const scenario = JSON.parse(readFileSync(path.join(uxRoot, 'scenarios/identity-docs/tasks.json'), 'utf8'));
const tasks: Array<{id: string; label: string; target: unknown; keywords: string}> = scenario.tasks;
const out = path.resolve(uxRoot, process.env.UX_OUT ?? 'rounds/current');
const gate = process.env.UX_GATE === '1';
const AXE_TAGS = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa', 'wcag22aa'];
const MAX_TABS = 300;
const MAX_ACTIONS = 30;

declare global {
  interface Window {
    __ux: any;
  }
}

async function open(page: Page, theme: string) {
  await page.goto(scenario.page, {waitUntil: 'load'});
  await page.waitForFunction(() => !!window.__ux && !!document.querySelector('article'));
  const actual = await page.evaluate(() => document.documentElement.dataset.theme);
  expect(actual, 'theme applied').toBe(theme);
  await page.evaluate((ts) => ts.forEach((t: unknown) => window.__ux.resolve(t)), tasks);
}

async function settle(page: Page) {
  await page.evaluate(() => new Promise<void>((done) => {
    let last = -1;
    const started = performance.now();
    let still = 0;
    const tick = () => {
      if (window.scrollY === last) still++;
      else { still = 0; last = window.scrollY; }
      if (still >= 6 || performance.now() - started > 1500) done();
      else requestAnimationFrame(tick);
    };
    requestAnimationFrame(tick);
  }));
}

async function frame(page: Page) {
  await page.waitForTimeout(750);
  return page.screenshot();
}

test('identity docs page: layout, always-visible, axe, keyboard, screen-only', async ({page}, info) => {
  const meta = info.project.metadata as {viewport: string; theme: string; gating: boolean};
  await page.addInitScript({path: path.join(uxRoot, 'lib/inpage.js')});

  await open(page, meta.theme);
  const resolved = await page.evaluate((ts) => ts.map((t: any) => ({id: t.id, ...window.__ux.resolve(t)})), tasks);
  const layout = await page.evaluate(() => window.__ux.layout());
  const states: Array<{state: string; misses: number; items: unknown}> = [];
  const top = await page.evaluate(() => window.__ux.alwaysVisible());
  states.push({state: 'top', misses: top.misses, items: top.items});
  const frames: Array<{label: string; png: Buffer}> = [{label: 'top', png: await frame(page)}];

  // Two axe passes: as loaded, and with every disclosure open. A rule counts with its larger node count.
  const serious = (v: {impact?: string | null}) => v.impact === 'serious' || v.impact === 'critical';
  const axeClosed = await new AxeBuilder({page}).withTags(AXE_TAGS).analyze();
  const opened = await page.evaluate(() => window.__ux.openAll());
  await page.waitForTimeout(300);
  const axeOpen = await new AxeBuilder({page}).withTags(AXE_TAGS).analyze();
  const byRule = new Map<string, {id: string; impact: string | null | undefined; nodes: number; sample?: string; pass: string}>();
  for (const [pass, res] of [['closed', axeClosed], ['open', axeOpen]] as const) {
    for (const v of res.violations) {
      const prev = byRule.get(v.id);
      if (!prev || v.nodes.length > prev.nodes) byRule.set(v.id, {id: v.id, impact: v.impact, nodes: v.nodes.length, sample: v.nodes[0]?.target.join(' '), pass});
    }
  }
  const axeSerious = [...byRule.values()].filter(serious);
  const axeOther = [...byRule.values()].filter((v) => !serious(v));
  const axeIncomplete = axeClosed.incomplete.map((v) => ({id: v.id, nodes: v.nodes.length}));

  // Keyboard: Tab from the top; expand a collapsed on-page TOC once when focus reaches it.
  await open(page, meta.theme);
  const ids = tasks.map((t) => t.id);
  const keyboard: Record<string, number | null> = Object.fromEntries(ids.map((id) => [id, null]));
  let presses = 0;
  let obscured = 0;
  let stops = 0;
  let first: string | null = null;
  for (let i = 0; i < MAX_TABS && Object.values(keyboard).some((v) => v === null); i++) {
    await page.keyboard.press('Tab');
    presses++;
    const f = await page.evaluate((ids) => window.__ux.focusInfo(ids), ids);
    if (!f.desc) continue;
    if (first === null) first = f.desc;
    else if (f.desc === first && i > 5) break;
    stops++;
    if (f.obscured) obscured++;
    for (const id of f.reached) if (keyboard[id] === null) keyboard[id] = presses;
    if (f.expandable) {
      await page.keyboard.press('Enter');
      presses++;
    }
  }

  // Screen-only user: one task at a time, from the top of the page.
  const screenOnly: Array<Record<string, unknown>> = [];
  let dirty = true;
  for (const t of tasks) {
    if (dirty) await open(page, meta.theme);
    else {
      await page.evaluate(() => { history.replaceState(null, '', location.pathname); window.scrollTo(0, 0); (document.activeElement as HTMLElement | null)?.blur(); });
      await settle(page);
    }
    dirty = false;
    await page.evaluate((ts) => ts.forEach((x: unknown) => window.__ux.resolve(x)), tasks);
    let actions = 0;
    let looks = 1;
    const path: string[] = [];
    let glance: number = await page.evaluate((id) => window.__ux.glanceOf(window.__ux.target(id)), t.id);
    const inView = () => page.evaluate((id) => window.__ux.inView(window.__ux.target(id)), t.id);
    if (glance === 3) {
      for (let step = 0; step < 2 && !(await inView()); step++) {
        const control = await page.evaluate((k) => window.__ux.findControl(k), t.keywords);
        if (!control) break;
        await page.locator('[data-ux-control]').first().click();
        await settle(page);
        actions++;
        looks++;
        path.push(`${control.kind}: ${control.desc}`);
        if (control.kind === 'disclosure') dirty = true;
        glance = 2;
        if (control.kind === 'link') break;
      }
      while (!(await inView()) && actions < MAX_ACTIONS) {
        const {key, moved} = await page.evaluate((id) => window.__ux.pageStep(window.__ux.target(id)), t.id);
        if (!moved) break;
        actions++;
        looks++;
        glance = 3;
        if (path[path.length - 1] !== key) path.push(key);
      }
    }
    const done = await inView();
    const av = await page.evaluate(() => window.__ux.alwaysVisible());
    states.push({state: `after ${t.id}`, misses: av.misses, items: av.items});
    frames.push({label: t.id, png: await frame(page)});
    screenOnly.push({task: t.id, completed: done, actions, looks, glance, path});
  }

  const result = {
    project: info.project.name,
    viewport: meta.viewport,
    theme: meta.theme,
    gating: meta.gating,
    url: page.url().split('#')[0],
    resolved,
    layout,
    alwaysVisible: {
      states,
      misses: new Set(states.flatMap((s) => Object.entries(s.items as Record<string, {ok: boolean}>).filter(([, v]) => !v.ok).map(([k]) => k))).size,
    },
    axe: {
      serious: axeSerious,
      seriousNodes: axeSerious.reduce((n, v) => n + v.nodes, 0),
      other: axeOther,
      disclosuresOpened: opened,
      incomplete: axeIncomplete,
      incompleteNodes: axeIncomplete.reduce((n, v) => n + v.nodes, 0),
    },
    keyboard: {tabsToTarget: keyboard, presses, stops, obscured},
    screenOnly,
  };
  mkdirSync(path.join(out, 'raw'), {recursive: true});
  mkdirSync(path.join(out, 'shots'), {recursive: true});
  writeFileSync(path.join(out, 'raw', `${info.project.name}.json`), JSON.stringify(result, null, 2) + '\n');

  const vw = page.viewportSize()!.width;
  const cols = vw < 800 ? 6 : 3;
  const cell = vw < 800 ? 260 : 480;
  const html = `<html><body style="margin:0;background:#888;font:14px sans-serif">
    <div style="display:grid;grid-template-columns:repeat(${cols},${cell}px);gap:8px;padding:8px">
    ${frames.map((f) => `<figure style="margin:0"><img style="width:${cell}px;display:block;border:1px solid #000" src="data:image/png;base64,${f.png.toString('base64')}"><figcaption style="color:#fff">${meta.viewport} ${meta.theme} · ${f.label}</figcaption></figure>`).join('')}
    </div></body></html>`;
  const sheet = await page.context().newPage();
  await sheet.setViewportSize({width: cols * (cell + 8) + 8, height: 600});
  await sheet.setContent(html, {waitUntil: 'load'});
  await sheet.screenshot({path: path.join(out, 'shots', `sheet-${info.project.name}.png`), fullPage: true});
  await sheet.close();

  if (gate && meta.gating) {
    expect.soft(layout.docHScrollPx, 'gate 1: horizontal page scroll').toBe(0);
    expect.soft(layout.pageOverflow.length + layout.clipped.length, 'gate 1: elements past their box').toBe(0);
    expect.soft(result.alwaysVisible.misses, 'gate 2: always-visible misses').toBe(0);
    expect.soft(result.axe.seriousNodes, 'gate 5: axe serious/critical nodes').toBe(0);
    expect.soft(Object.values(keyboard).filter((v) => v === null).length, 'gate 5: task targets not reached by keyboard').toBe(0);
    expect.soft(screenOnly.filter((s) => !s.completed).length, 'gate 4: screen-only tasks not completed').toBe(0);
  }
});
