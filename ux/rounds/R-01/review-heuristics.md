# R-01 heuristic review

Verdict: 5 pass, 9 partial, 2 fail

Evidence: the 10 contact sheets (`shots/sheet-*.png`), `raw/*.json`, `report.md`, `README.md`, and two live
probes of https://beyond10x.github.io/docs/identity/ on 2026-11-23 (shots `shots/review-*.png`; scripts in
`target/scratch/review-1/`). R-01 has no recordings and no questionnaire, so no verdict cites a recording second.

| # | heuristic | verdict | evidence |
|---|---|---|---|
| 1 | One next thing | pass | Every top frame: the first paragraph says what Identity is; the context box holds one call to action, "Choose an outcome" (`sheet-1280x800-light.png` top). |
| 2 | State in words | pass | § Status states each area in words ("implemented"). Code blocks are labelled "BASH"/"JSON". The table hint "More columns: swipe horizontally, or focus the table and use the arrow keys" is shown only for the 3 tables that overflow at 390 px (overflow 509, 167, 152 px) and hidden at 1280 px (live probe). |
| 3 | Nothing required hidden | fail | UXF-001 (run command 1444 px off to the right, `sheet-1280x800-light.png` run-locally); UXF-003 (source link in a closed disclosure); UXF-005 (search and theme toggle hidden below 997 px); UXF-007 (Routes "for" column off-screen, `sheet-390x844-light.png` token-route); new UXF-013 (copy button covers "gin" of `local-login`, `review-390x844-light-local-login-block-nohover.png`). |
| 4 | Stable layout | pass | Live CLS 0.0005 at 1280x800 and 0 at 390x844; no frame shows a jump. The code-block re-render after a theme switch (README.md harness defect 6) dropped a test mark, not visible layout. |
| 5 | Provenance of every value | partial | The context box names `identity/README.md` and `e5c4e8733235` (`sheet-1280x800-light.png` source-link), but only after opening it (UXF-003), and it does not say the page is two commits behind main (UXF-011). |
| 6 | Errors cheap | partial | At 1280 and 1440 a wrong section is fixed with one TOC click (`raw/1280x800-light.json` screenOnly, 1 action each). At 1024 there is no TOC and the fix is paging (UXF-006, 4 to 12 steps); on a phone mid-page it is 4 actions (UXF-014). |
| 7 | Words the user can say | partial | Headings are plain ("Running it locally", "Routes"). The H1 is the repository id "identity" (UXF-009); the invariants are titled "The rules that shape the code" (UXF-002). The `local-login` feature's section is "Signing in on a workstation"; the scenario card had to add "workstation" to its keywords (`scenarios/identity-docs/tasks.json`). Not filed: no cost measured. |
| 8 | The reader's time respected | partial | Page is 10,799 px tall at 1280x800 (live). Invariants take 11 page steps at 1280 and 18 at 390 (UXF-002); 1024 has no TOC (UXF-006); 12 table cells over 200 px tall on a phone (UXF-008, `review-390x844-light-mid-page-no-toc.png`). |
| 9 | Keyboard and pointer parity | pass | Keyboard reached every target in all 10 runs, 0 obscured (`report.md`, `raw/*.json` keyboard). Focus ring 2 px solid rgb(8,127,158); all 6 `pre` and the 3 overflowing table wraps at 390 px have `tabindex=0` (live probe). |
| 10 | Recognition over recall | partial | At 1280 and 1440 the TOC stays in view in every frame (`sheet-1280x800-light.png`). Below 997 px the section list is only at the top of the article (UXF-014, `review-390x844-light-mid-page-no-toc.png`); at 1024 there is none (UXF-006). |
| 11 | Calm by default | pass | No banner, toast or animation in any of the 60 frames; CLS near 0; the back-to-top button appears only on an upward scroll (live probe). |
| 12 | One state vocabulary | partial | § Status uses "implemented" for 5 of 6 rows; the sixth row, "deployment composition", holds a location ("lives in the platform's cloud umbrella chart, not in this repo") instead of a state (live probe of the table). Not filed: costs no time. |
| 13 | A wrong cue recovered in one action | partial | Desktop: one TOC click (`raw/1280x800-light.json`). Search is one click at 1280 but two below 997 px (UXF-005); mid-page on a phone, back to another section is 4 actions (UXF-014). |
| 14 | Unmistakable end state | partial | TOC-link tasks end with the heading at the top and its TOC entry highlighted (`sheet-1280x800-light.png` run-locally, token-route, local-login-refuses). The 390 token-route frame shows only route codes, with no heading and no "for" column (UXF-007, `sheet-390x844-light.png`). Paged tasks end with the target heading on the last line of the window (invariants frames at 1280 and 390): the bot's stop rule, not a page defect. |
| 15 | Readable in every theme; key data 14 px or more | fail | Light theme: 136 to 143 contrast failures per run, 0 in dark (UXF-004, `report.md` gate 5). Body text is 16 px, but TOC links are 12.8 px, "Source & revision" 10.88 px, the source link 12.48 px, code blocks 13.44 px at 390 (new UXF-015, live computed styles). |
| 16 | Focus follows the work | partial | The TOC highlight follows scrolling (live: "Read more" at the bottom, none at the top) and TOC clicks land the heading under the navbar. Below 997 px nothing shows which section the reader is in (UXF-014). The run's source-link frames at 1280 and 1440 show "Audiences" highlighted at the top of the page; this did not reproduce live (`review-1280x800-light-toc-after-return.png`, no entry highlighted): it is a harness artefact, not filed. |

## Findings filed

| id | title | severity | class | sessions (runs) | cost | owner |
|---|---|---|---|---|---|---|
| UXF-013 | On a phone the code-block buttons cover code; the local-login command reads "local-lo" | S3 | layout | 390x844 light, dark | S | website/docs-system |
| UXF-014 | Below 997 px the section list sits only at the top of the article; mid-page a reader has no way to another section in view | S2 | affordance | 390x844, 768x1024, light and dark | M | website/docs-system |
| UXF-015 | Navigation and provenance text is set below 14 px (TOC 12.8 px, "Source & revision" 10.9 px, source link 12.5 px) | S3 | affordance | all 10 (context box); 1280x800, 1440x900 (TOC); 390x844 (code) | S | website/docs-system |

Cited, not filed again: UXF-001, 002, 003, 004, 005, 006, 007, 008, 009, 011.

Measurement gap (UXF-014): the harness scrolls to the top before every task (`ux/tests/docs-page.spec.ts:103`), so
no R-01 number covers a reader who starts mid-page.
