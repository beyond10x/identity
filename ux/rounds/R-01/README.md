# R-01 operator notes

- Page: https://beyond10x.github.io/docs/identity/ (live). It renders identity `e5c4e87`; main is `55ab984`
  (UXF-011). README.md was not edited in this round. Another branch (`docs/readme-pass2`, `0c85741`) is rewriting it.
- No local render. The website's `preview:source` (clone of beyond10x/website at `22f9c9a` and `0dc1ba8`) exits 2:
  the live PROVENANCE.json is `b10x-website-provenance/v1`, and the preview accepts only v2/v3 (UXF-012).
- Round command, from `ux/`: `slot --timeout 15m sh round.sh R-01 e5c4e873323580945aee7dd2b8941180d644db3e`.
  It makes three Playwright runs (gating 1280x800 + 390x844; 1440x900 + 1024x768; 768x1024), each under 120 s,
  and then `node round.ts`. Tests took 17 to 24 s each; the runs took 45 s, 41 s and 27 s.
- Scenario: `ux/scenarios/identity-docs/tasks.json`, five tasks. Anchors: `run-locally`, `token-route`.
  No rotating card and no people in this round: no recordings and no questionnaire. Every state is a
  Playwright frame taken 0.75 s after it.
- Screen-only user policy (`ux/tests/docs-page.spec.ts`, `ux/lib/inpage.js`):
  1. A target already in view costs 0 actions.
  2. Otherwise the user clicks a visible same-page link whose name matches the task keywords, opening the
     "On this page" disclosure or a matching `<summary>` first if needed.
  3. Otherwise it scrolls one page step at a time (visible window under the navbar less 24 px), at most 30.

  Glance is 1 for a target in view in the article, 2 when reached through a visible control, 3 when found by
  page steps.
- Keyboard: Tab from the top of the page. A task target counts as reached when focus is inside it or on a
  same-page link to its section. The collapsed TOC or `<summary>` is expanded once with Enter.
- Harness defects found and fixed during the round, before the numbers in report.md:
  1. Links inside a closed `<details>` counted as visible.
  2. Corner hit-tests flagged round buttons as covered.
  3. The skip link counted as overflow.
  4. Keyboard PageDown (728 px at 768 px height) stepped over targets.
  5. The bot closed an open TOC again.
  6. React re-rendered code blocks after the theme switch and dropped the target mark (1024x768 dark).
- The numbers come from run 4, which both reviewers checked. After the review, the harness was fixed (T1 to T3,
  T5 to T8, T11 of review-report.md), but the run with the fixed harness was not done: it sat in the pool
  queue and was stopped at the coordinator's deadline. `round.ts` was then re-run on the run-4 raw records,
  so long cells count characters and always-visible misses count distinct elements. The keyboard numbers at
  390x844 and 768x1024 still carry T1. `round.sh` now reads README.md at the source commit (T8).
