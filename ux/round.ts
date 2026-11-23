// Round command: raw/*.json of one round -> round.json, report.md, ../trend.md; writes baseline.json when absent.
// Usage: node round.ts <round dir> --source-commit <sha> --url <page url> [--readme ../README.md]
import {existsSync, readdirSync, readFileSync, writeFileSync} from 'node:fs';
import path from 'node:path';

type Raw = any;
const args = process.argv.slice(2);
const dir = path.resolve(args[0] ?? '');
const opt = (name: string, fallback?: string) => {
  const i = args.indexOf(`--${name}`);
  return i >= 0 ? args[i + 1] : fallback;
};
const uxRoot = path.dirname(new URL(import.meta.url).pathname);
const round = path.basename(dir);
const sourceCommit = opt('source-commit', 'unknown')!;
const url = opt('url', 'unknown')!;
const readme = path.resolve(uxRoot, opt('readme', '../README.md')!);
const date = opt('date', new Date().toISOString().slice(0, 10))!;

const raws: Raw[] = readdirSync(path.join(dir, 'raw'))
  .filter((f) => f.endsWith('.json'))
  .sort()
  .map((f) => JSON.parse(readFileSync(path.join(dir, 'raw', f), 'utf8')));
const order = ['1440x900', '1280x800', '1024x768', '768x1024', '390x844'];
raws.sort((a, b) => order.indexOf(a.viewport) - order.indexOf(b.viewport) || a.theme.localeCompare(b.theme));
const tasks = JSON.parse(readFileSync(path.join(uxRoot, 'scenarios/identity-docs/tasks.json'), 'utf8')).tasks as Array<{id: string; label: string}>;

function fencesWithoutLanguage(file: string) {
  if (!existsSync(file)) return null;
  let open = false;
  let n = 0;
  for (const line of readFileSync(file, 'utf8').split('\n')) {
    const m = /^\s*(```+|~~~+)(.*)$/.exec(line);
    if (!m) continue;
    if (!open && m[2].trim() === '') n++;
    open = !open;
  }
  return n;
}
const noLang = fencesWithoutLanguage(readme);

function summary(r: Raw) {
  const L = r.layout;
  const unreached = Object.values(r.keyboard.tabsToTarget).filter((v) => v === null).length;
  return {
    project: r.project,
    viewport: r.viewport,
    theme: r.theme,
    gating: r.gating,
    gate1: {docHScrollPx: L.docHScrollPx, pastBox: L.pageOverflow.length + L.clipped.length, pass: L.docHScrollPx === 0 && L.pageOverflow.length + L.clipped.length === 0},
    gate2: {misses: missedItems(r).length, missed: missedItems(r), pass: missedItems(r).length === 0},
    gate5: {axeSeriousNodes: r.axe.seriousNodes, axeRules: r.axe.serious.map((v: any) => `${v.id}(${v.nodes})`), keyboardUnreached: unreached, pass: r.axe.seriousNodes === 0 && unreached === 0},
    gate4: {notCompleted: r.screenOnly.filter((s: any) => !s.completed).map((s: any) => s.task), pass: r.screenOnly.every((s: any) => s.completed)},
    innerHScroll: L.innerScrollers.length,
    tablesOverColumn: L.tables.filter((t: any) => t.overColumn).length,
    codeHScroll: L.codeBlocks.filter((c: any) => c.hScrollPx > 0).length,
    codeNoLanguage: L.codeBlocks.filter((c: any) => !c.lang || c.lang === 'language-text').length,
    longCells: L.tallCells === undefined ? L.longCells.filter((c: any) => c.chars > 150).length : L.longCells.length,
    tallCells: L.tallCells ?? L.longCells.filter((c: any) => c.height > 200).length,
    axeIncompleteNodes: r.axe.incompleteNodes ?? 'n/a',
    focusObscured: r.keyboard.obscured,
    screenOnly: r.screenOnly.map((s: any) => ({task: s.task, completed: s.completed, actions: s.actions, looks: s.looks, glance: s.glance})),
    keyboardTabs: r.keyboard.tabsToTarget,
  };
}
function missedItems(r: Raw) {
  const missed = new Set<string>();
  for (const s of r.alwaysVisible.states) for (const [k, v] of Object.entries<any>(s.items)) if (!v.ok) missed.add(`${k}${v.present ? (v.inside ? ' covered' : ' outside') : ' hidden'}`);
  return [...missed];
}
const rows = raws.map(summary);
const expected = 10;
if (rows.length !== expected || rows.filter((r) => r.gating).length !== 4) {
  console.error(`${round}: ${rows.length} of ${expected} projects measured (${rows.filter((r) => r.gating).length} of 4 gating); refusing to write round, report or baseline`);
  process.exit(1);
}
const gating = rows.filter((r) => r.gating);
const max = (xs: number[]) => xs.reduce((a, b) => Math.max(a, b), 0);
const UNREACHED = 9999;

const pageMetrics: Record<string, number> = {
  'layout.doc_hscroll_px': max(gating.map((r) => r.gate1.docHScrollPx)),
  'layout.past_box': max(gating.map((r) => r.gate1.pastBox)),
  'layout.inner_hscroll': max(gating.map((r) => r.innerHScroll)),
  'layout.tables_over_column': max(gating.map((r) => r.tablesOverColumn)),
  'layout.code_hscroll': max(gating.map((r) => r.codeHScroll)),
  'layout.long_cells': max(gating.map((r) => r.longCells)),
  'always_visible.misses': max(gating.map((r) => r.gate2.misses)),
  'axe.serious_nodes': max(gating.map((r) => r.gate5.axeSeriousNodes)),
  'keyboard.focus_obscured': max(gating.map((r) => r.focusObscured)),
  'source.code_fences_without_language': noLang ?? UNREACHED,
};
const taskMetrics: Record<string, Record<string, number>> = {};
for (const t of tasks) {
  const so = gating.map((r) => r.screenOnly.find((s: any) => s.task === t.id)!);
  taskMetrics[t.id] = {
    'screen_only.actions': max(so.map((s) => (s.completed ? s.actions : UNREACHED))),
    'screen_only.looks': max(so.map((s) => (s.completed ? s.looks : UNREACHED))),
    'glance_cost.max': max(so.map((s) => s.glance)),
    'keyboard.tabs': max(gating.map((r) => r.keyboardTabs[t.id] ?? UNREACHED)),
  };
}

const roundJson = {round, date, url, sourceCommit, gatingViewports: [...new Set(gating.map((r) => r.viewport))], metrics: {page: pageMetrics, tasks: taskMetrics}, projects: rows};
writeFileSync(path.join(dir, 'round.json'), JSON.stringify(roundJson, null, 2) + '\n');

const stepKeys = new Set(['screen_only.actions', 'screen_only.looks', 'keyboard.tabs']);
const baselinePath = path.join(uxRoot, 'baseline.json');
const tol = (k: string) => (stepKeys.has(k) ? 0.05 : 0);
if (!existsSync(baselinePath)) {
  const scen = (m: Record<string, number>) => Object.fromEntries(Object.entries(m).map(([k, v]) => [k, {value: v, tolerance: tol(k)}]));
  const baseline = {
    about: `Identity docs page ${url}, measured ${date} in ${round} at source ${sourceCommit}. Values are maxima over the gating viewports (${roundJson.gatingViewports.join(', ')}) x themes (light, dark); all lower is better. ${UNREACHED} = not reached.`,
    scenarios: {page: scen(pageMetrics), ...Object.fromEntries(Object.entries(taskMetrics).map(([id, m]) => [id, scen(m)]))},
    tolerances: {counts: 0, steps: 0.05},
  };
  writeFileSync(baselinePath, JSON.stringify(baseline, null, 2) + '\n');
}

const yes = (b: boolean) => (b ? 'pass' : '**FAIL**');
let md = `# ${round}: Identity docs page\n\n`;
md += `Page: ${url}, rendered from identity \`${sourceCommit.slice(0, 7)}\`. Measured ${date}. Gating viewports: ${roundJson.gatingViewports.join(', ')}; the rest are measured only.\n\n`;
md += `## Hard gates per viewport x theme\n\n`;
md += `| viewport | theme | gating | 1 page h-scroll px | 1 past box | 2 always-visible misses | 5 axe serious nodes | 5 keyboard unreached | 4 tasks not completed |\n|---|---|---|---|---|---|---|---|---|\n`;
for (const r of rows) {
  md += `| ${r.viewport} | ${r.theme} | ${r.gating ? 'yes' : ''} | ${r.gate1.docHScrollPx} | ${r.gate1.pastBox} ${yes(r.gate1.pass)} | ${r.gate2.misses} ${yes(r.gate2.pass)}${r.gate2.missed.length ? ' (' + r.gate2.missed.join(', ') + ')' : ''} | ${r.gate5.axeSeriousNodes}${r.gate5.axeRules.length ? ' ' + r.gate5.axeRules.join(', ') : ''} | ${r.gate5.keyboardUnreached} | ${r.gate4.notCompleted.length} ${yes(r.gate4.pass)} |\n`;
}
md += `\nAlways-visible misses count the elements missed in any state (top of page, the end of each of the 5 tasks). axe runs twice, as loaded and with every disclosure open; a rule counts with its larger node count. axe incomplete nodes (not decided by axe, mostly color-contrast) are reported, not gated.\n\n`;
md += `## Content measures\n\n| viewport | theme | inner h-scrollers | tables over column | code blocks with h-scroll | code blocks without language | cells over 150 chars | cells over 200 px tall | focus obscured | axe incomplete nodes |\n|---|---|---|---|---|---|---|---|---|---|\n`;
for (const r of rows) md += `| ${r.viewport} | ${r.theme} | ${r.innerHScroll} | ${r.tablesOverColumn} | ${r.codeHScroll} | ${r.codeNoLanguage} | ${r.longCells} | ${r.tallCells} | ${r.focusObscured} | ${r.axeIncompleteNodes} |\n`;
md += `\nREADME fences without a language tag: ${noLang ?? 'README not found'}.\n\n`;
md += `## Screen-only user (actions / looks / glance; keyboard Tabs to reach)\n\n| task | ${rows.map((r) => `${r.viewport} ${r.theme}`).join(' | ')} |\n|---|${rows.map(() => '---').join('|')}|\n`;
for (const t of tasks) {
  md += `| ${t.id} | ${rows.map((r) => {
    const s = r.screenOnly.find((x: any) => x.task === t.id)!;
    const k = r.keyboardTabs[t.id];
    return `${s.completed ? '' : 'NOT DONE '}${s.actions}/${s.looks}/g${s.glance}; tab ${k ?? 'never'}`;
  }).join(' | ')} |\n`;
}
md += `\n## Metrics (gating maxima)\n\n| scenario | metric | value |\n|---|---|---|\n`;
for (const [k, v] of Object.entries(pageMetrics)) md += `| page | ${k} | ${v} |\n`;
for (const [id, m] of Object.entries(taskMetrics)) for (const [k, v] of Object.entries(m)) md += `| ${id} | ${k} | ${v} |\n`;
md += `\n## Details\n`;
for (const raw of raws) {
  const L = raw.layout;
  md += `\n### ${raw.project}\n\n`;
  if (L.clipped.length) md += `- clipped: ${L.clipped.map((c: any) => `${c.element} in ${c.container} (overflow-x ${c.ox}, ${c.pastPx} px past)`).join('; ')}\n`;
  if (L.pageOverflow.length) md += `- past the viewport: ${L.pageOverflow.map((c: any) => `${c.element} (${c.pastPx} px)`).join('; ')}\n`;
  if (L.innerScrollers.length) md += `- inner scrollers: ${L.innerScrollers.map((c: any) => `${c.container} +${c.overflowPx} px`).join('; ')}\n`;
  const over = L.tables.filter((t: any) => t.overColumn);
  if (over.length) md += `- tables over the ${L.column} px column: ${over.map((t: any) => `"${t.first}" ${t.width} px`).join('; ')}\n`;
  if (L.longCells.length) md += `- long cells: ${L.longCells.map((c: any) => `${c.chars} chars / ${c.height} px "${c.text}"`).join('; ')}\n`;
  if (raw.axe.serious.length) md += `- axe serious/critical: ${raw.axe.serious.map((v: any) => `${v.id} x${v.nodes} (${v.sample})`).join('; ')}\n`;
  if (raw.axe.other.length) md += `- axe other: ${raw.axe.other.map((v: any) => `${v.id} ${v.impact} x${v.nodes}`).join('; ')}\n`;
  md += `- screen-only paths: ${raw.screenOnly.map((s: any) => `${s.task}: ${s.path.join(' > ') || 'in view'}`).join('; ')}\n`;
  md += `- contact sheet: shots/sheet-${raw.project}.png\n`;
}
writeFileSync(path.join(dir, 'report.md'), md);

const trendPath = path.join(dir, '..', 'trend.md');
const head = '# Trend: Identity docs page\n\n| round | date | source | gating gate fails | axe serious nodes | always-visible misses | past box | code h-scroll | max task actions | keyboard unreached |\n|---|---|---|---|---|---|---|---|---|---|\n';
const fails = gating.reduce((n, r) => n + [r.gate1.pass, r.gate2.pass, r.gate5.pass, r.gate4.pass].filter((p) => !p).length, 0);
const maxActions = max(Object.values(taskMetrics).map((m) => m['screen_only.actions']));
const kbUnreached = max(gating.map((r) => r.gate5.keyboardUnreached));
const line = `| ${round} | ${date} | ${sourceCommit.slice(0, 7)} | ${fails} | ${pageMetrics['axe.serious_nodes']} | ${pageMetrics['always_visible.misses']} | ${pageMetrics['layout.past_box']} | ${pageMetrics['layout.code_hscroll']} | ${maxActions} | ${kbUnreached} |\n`;
const old = existsSync(trendPath) ? readFileSync(trendPath, 'utf8').split('\n').filter((l) => l.startsWith('| R-') && !l.startsWith(`| ${round} |`)) : [];
writeFileSync(trendPath, head + [...old.map((l) => l + '\n'), line].sort().join(''));
console.log(`${round}: ${rows.length} projects, ${fails} gating gate fails, baseline ${existsSync(baselinePath) ? 'present' : 'missing'}`);
