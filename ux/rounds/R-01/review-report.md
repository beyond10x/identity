# R-01 report review

Verdict: **not fit to send as is.** Every number in `report.md`, `round.json` and `trend.md` reproduces from
`raw/*.json` (0 differences). But the keyboard pass at 390 and 768 never opens the "On this page" list,
which the README says it does (T1), so 20 keyboard cells and one baseline value are wrong. axe ran on one
closed state only and drops about 150 unchecked nodes (T2, T3).

Default action: send R-01 with the § 4 caveats. Fix T1 to T3 before R-02 and set
`source-link keyboard.tabs` in the baseline to 21. The gate verdicts do not change (4 gating gate fails).

Probes: `target/scratch/review-2/` (`recompute.mjs`, `probe-live.mjs`, `probe-toc.mjs`, `probe-tasks.mjs`,
`probe-tocbtn.mjs`, `probe-kb.mjs`). The live page is still at `e5c4e8733235` (its "Source & revision" text).

## 1. Are the numbers right and meaningful?

### Recomputed from raw/*.json

`recompute.mjs` counts each quantity from the raw records with its own code. It recounts always-visible
misses item by item and sums the axe nodes per rule. It checks:

- 10 projects: the 6 gate cells, the 6 content cells and the 5 task cells of each;
- the 30 gating maxima, in `round.json` and in `report.md`;
- the trend line: 4 gate fails, axe 141, misses 12, past box 0, code h-scroll 5, max actions 18, keyboard
  unreached 0.

**0 differences.**

### Checked against the live page

| check | report | live | diff |
|---|---|---|---|
| layout 1280x800 light, 1024x768 light, 390x844 light (inner, tables over column, code h-scroll, long cells, past box) | 4/0/4/2/0, 4/0/4/2/0, 8/3/5/12/0 | same | 0 |
| axe serious nodes 1280 light / 1024 light / 390 light, top state | 141 / 141 / 136 | 141 / 141 / 136 | 0 |
| always-visible misses at the top, 390 | 2 per state (search, toggle) | 2: both sit in the closed menu panel (toggle at x -135..-103) | 0 |
| page steps from the top at 1024x768 (run-locally/token-route/local-login/invariants), from geometry without `inpage.js` | 4/8/7/12 | 4/8/7/12 | 0 |
| invariants page steps at 1280 / 390 | 11 / 18 (1 disclosure + 17) | 11 / 17 | 0 |
| **keyboard, 390x844, with the TOC opened as the README says** (run-locally/token-route/local-login/invariants/source-link) | 18/31/28/38/10 | 10/12/11/14/21 | -8/-19/-17/-24/**+11** |
| **keyboard, 768x1024, same** | 17/30/27/34/10 | 10/12/11/14/21 | -7/-18/-16/-20/**+11** |
| **gating max `source-link keyboard.tabs`** (also in baseline.json) | 19 | 21 | **+2 (+10.5 %, over the 5 % tolerance)** |
| gating max of the other 4 `keyboard.tabs` | 26/39/36/43 | 26/39/36/43 (from 1280) | 0 |
| axe serious nodes with "Source & revision" open, 1280 light | not measured | 143 (color-contrast 142, target-size 1) | +2 over the top state |
| axe serious nodes with "Source & revision" and the TOC open, 390 light | not measured | 138 (137 + 1) | +2 |

### Do the metrics mean what their names say?

- `axe.serious_nodes`: this counts only the nodes axe could decide. In every project axe also leaves
  144 to 154 `color-contrast` nodes "incomplete" (background hidden by a pseudo element: `td` 49, `p` 27,
  `strong` 16, `li` 14 …) and 5 `link-in-text-block` nodes. That is more nodes than the 141 violations.
  "Dark: 0" means 0 among the checked nodes; about 150 text nodes are not checked in either theme.
- `axe.serious_nodes`: it is measured in one state, at the top with every disclosure closed. Opening "Source &
  revision" adds a serious `target-size` violation and one contrast node.
- `keyboard.tabs` at 390 and 768 measures a linear Tab through the article without the TOC (T1). It also
  counts Enter presses (T9).
- `screen_only.actions` for invariants (18, the trend's "max task actions") measures the keyword mismatch
  in T4 plus the page's length. The TOC names the section "The rules that shape the code", and the
  bot may not match it.
- `layout.long_cells` 12 at 390: only 2 cells are long (192 and 198 chars). The other 10 count because
  the row is over 200 px tall, for example "POST /v1/logout" (15 chars). Every 2-column row counts twice (T5).
- `always_visible.misses` 12 = 2 elements x 6 states. It grows with the number of tasks (T6).
- `screen_only.looks` = actions + 1 in all 50 records; it carries no information of its own (T10).
- A task counts as done when 24 px of the target shows. For run-locally the target is a code block of
  3.1 column widths; for local-login-refuses it is the lead-in sentence, and the refusals follow in a
  list.
- Comparability: first round, no previous round, no recordings and no questionnaire.

## 2. Findings the report misses

1. The mobile "On this page" button (390, 768) has no `aria-expanded` and no `aria-controls`
   (`<button type="button" class="clean-btn tocCollapsibleButton_TO0P">`). A screen reader does not
   announce its state. axe does not flag it.
2. The `summary` "Source & revision" is 121 x 15 px. With the disclosure open, axe reports a serious
   `target-size` violation (WCAG 2.5.8) at every viewport checked (1024, 1280, 390). The revision `code`
   inside it adds one more contrast failure.
3. axe could not check about 150 text nodes per project in either theme (incomplete, pseudo element on
   `.theme-doc-markdown`). The dark theme's contrast is therefore unproven, not passed.
4. Each code block costs 2 to 3 Tab stops (`pre` tabindex, "Toggle word wrap", "Copy code"). The 6 blocks
   are 16 of the 43 stops to the invariants at 1280. Between `#running-it-locally` and
   `#signing-in-on-a-workstation` there are 9 stops.
5. With the TOC opened by keyboard, a keyboard user at 390 or 768 reaches every section in 10 to 14
   presses. The Source link then takes 21, because the 10 TOC links come before it.
6. The contrast failures in the light theme: inline `code` #7d6bc1 on #e4e8ed, ratio 3.59, 103 nodes.
   Prism tokens #36acaa on #f6f8fa, 2.58, 27 nodes; #e3116c, 4.32, 8 nodes; #d73a49, 4.29, 3 nodes.
   UXF-004 gives the count but not the colours.
7. The theme toggle reads "currently system mode" in both theme projects: the site follows
   `prefers-color-scheme` and ignores the `theme` key that the spec seeds (T7).

## 3. Tool defects

- **T1** `tests/docs-page.spec.ts:91`, `lib/inpage.js:253`: the keyboard pass opens the mobile TOC only when
  `aria-expanded="false"`. The live button has no such attribute, so the TOC is never opened. Input: the
  live page at 390x844 and 768x1024. The report shows 390 run-locally at 18, and `probe-kb.mjs` gets 10
  once the TOC is opened.
- **T2** `tests/docs-page.spec.ts:59,65`: `layout()` and axe run once, at the top with every disclosure
  closed. Input: "Source & revision" opened at 1280 light gives `target-size` 1 and color-contrast 142,
  against 141.
- **T3** `tests/docs-page.spec.ts:66-71`: axe `incomplete` results are dropped. Input: every project, for
  example 1280 dark with 0 violations and 154 incomplete `color-contrast` nodes.
- **T4** `scenarios/identity-docs/tasks.json` (invariants): the target regex accepts `rules that shape`, but
  the keywords are only `invariants?`. The bot cannot use the TOC link "The rules that shape the code".
  Input: 390, 18 actions, path "On this page" > PageDown. If this is intended to measure UXF-002, the
  report must say so.
- **T5** `lib/inpage.js:192,202`: `longCells` counts cells by row height. Input: 390, "POST /v1/logout",
  15 chars, 218 px, counted as long.
- **T6** `tests/docs-page.spec.ts:150`: always-visible misses are summed over states. The same 2 hidden
  items count 12, and a sixth task makes 14 against a tolerance of 0.
- **T7** `tests/docs-page.spec.ts:52-54`: the `localStorage.theme` seed has no effect; the theme comes
  from `colorScheme`. Input: seed `dark` with `colorScheme: 'light'` renders `data-theme="light"`.
  Harmless now, because both are set alike.
- **T8** `round.ts:17,28`: the README fence count reads the worktree's `../README.md` (branch `ux/r01` at
  `55ab984`), not `--source-commit`. `--source-commit` is not checked against the page's
  "Source & revision". Both match today: 0 fences at either revision, and the page shows `e5c4e8733235`.
- **T9** `tests/docs-page.spec.ts:93`: an Enter press increments `presses`, so `keyboard.tabs` counts
  Enter. Input: 1280, source-link 19 = summary at stop 17 + Enter + link.
- **T10** `tests/docs-page.spec.ts:109,120,130`: `looks` is always `actions + 1`. Input: all 50
  screen-only records.
- **T11** `round.sh:9-15`: `raw/` and `shots/` are deleted, but `report.md` and `round.json` are not.
  When `round.ts` refuses (fewer than 10 projects), the previous round's report stays in the dir with no
  marker.

## 4. Caveats to send with the round

1. The numbers reproduce from `raw/*.json`. The gate verdicts stand: 4 gating gate fails (contrast in
   light, search and theme toggle hidden below 997 px).
2. The keyboard values at 390 and 768 are without the TOC (T1). The baseline holds source-link
   `keyboard.tabs` 19; with the TOC opened it is 21.
3. The axe counts cover the top state only, and only the nodes axe could decide. About 150 per project
   are unchecked, and the dark theme's "0" is not a pass of those.
4. Invariants at 18 actions reflects the absence of the word "invariant" from the page and the bot's
   keyword list (T4). It is not a navigation cost a reader who knows the section name would pay.
5. `long_cells` 12 at 390 is 2 long cells plus 10 cells in tall rows. `always_visible.misses` 12 is
   2 elements x 6 states.
6. The live page renders `e5c4e87`, two commits behind `main` (UXF-011). A README change on another
   branch is not measured here.
