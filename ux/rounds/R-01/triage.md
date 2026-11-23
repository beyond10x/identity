# R-01 triage

## Caveats

- The live page renders identity `e5c4e87`, not main (`55ab984`) (UXF-011). Every identity-owned finding below
  was checked against main and `docs/readme-pass2` (`0c85741`) and still applies there.
- report.md, round.json, baseline.json and trend.md are built from the run-4 raw records, which both review
  agents checked. The harness defects from review-report.md (T1 to T3, T5 to T8, T11) are fixed in the code,
  but the run with the fixed harness was not done: the pool queue did not reach it in time.
  `round.ts` already counts long cells by characters and always-visible misses by distinct elements.
  The keyboard numbers at 390x844 and 768x1024 are still the old ones: T1 meant the phone TOC was never
  opened. The review measured 10, 12, 11, 14 and 21 Tabs there.
- T4 is kept on purpose: the "invariants" task tests whether the page names the invariants (UXF-002).
- No people, no recordings and no questionnaire: frequency is runs affected ÷ 10 runs (5 viewports x 2 themes).
- Confidence is 2 when the metric and review-heuristics.md agree.

## Did the last change sets move their metrics?

First round; there is no earlier change set.

## Priorities

priority = severity weight × frequency × confidence ÷ cost (S1 = 9, S2 = 3, S3 = 1; S = 1, M = 2, L = 4)

| finding | owner | severity | frequency | confidence | cost | priority |
|---|---|---|---|---|---|---|
| UXF-001 code blocks scroll sideways | identity | S2 | 10/10 | 2 (metric + H3) | S | 6.0 |
| UXF-002 invariants not named | identity | S2 | 10/10 | 2 (metric + H7, H8) | S | 6.0 |
| UXF-008 cells over 150 chars | identity | S3 | 10/10 | 2 (metric + H8) | S | 2.0 |
| UXF-009 H1 "identity" | identity | S3 | 10/10 | 2 (H7 + manifest) | S | 2.0 |
| UXF-007 tables over the phone column | identity | S2 | 2/10 | 2 (metric + H3, H14) | M | 0.6 |
| UXF-004 light contrast | website/docs-system | S1 | 5/10 | 2 (axe + H15) | M | 13.5, known loss |
| UXF-005 search and toggle hidden | website/docs-system | S1 | 4/10 | 2 (gate 2 + H3) | M | 10.8, known loss |
| UXF-014 no section list mid-page on a phone | website/docs-system | S2 | 4/10 | 1 | M | 0.6, known loss |
| UXF-006 no TOC at 1024 | website/docs-system | S2 | 2/10 | 2 | M | 0.6, known loss |
| UXF-003, 010, 011, 012, 013, 015 | website/docs-system | S2/S3 | | | | known loss |

The two S1 findings (UXF-004, UXF-005) are rule 1 findings, but they cannot be fixed from README.md (rule 5):
they are known losses, to be filed upstream with UXF-003, 006, 010 to 015.

## Change set (5 changes, all identity-owned, built on top of `docs/readme-pass2`)

| # | finding | change in README.md | target metric | now | expected |
|---|---|---|---|---|---|
| C1 | UXF-001 | split the one-line JSON values over lines inside their quotes, or read them from a file | page/layout.code_hscroll | 5 (390), 4 (1280) | ≤ 1 (390), 0 (1280) |
| C2 | UXF-002 | a heading that names the invariants (e.g. "Invariants: the rules that shape the code") | invariants/screen_only.actions | 18 (390), 11 (1280) | 2 (390), 1 (1280) |
| C3 | UXF-008 | the two 190+ character Audiences cells become prose under the table | page/layout.long_cells | 2 | 0 |
| C4 | UXF-009 | `# Identity` | heuristic line: H1 equals the displayName | fails | passes |
| C5 | UXF-007 | Build-test-run commands into one tagged code block; one route per row | page/layout.tables_over_column | 3 (390) | 0 |

Each change gets its regression asset red first (the spec's ratchet on the target metric, or the source check
in the gate plan). C2 changes an anchor in `b10x.docs.yaml` only if the heading id changes
(`#the-rules-that-shape-the-code` is linked as "Architecture rules"); keep the old id or update the manifest in
the same change.

## Gate plan

1. Per merge, hermetic: a POSIX sh source check in `scripts/gate.sh` (not the Rust test step, no network,
   under 1 s). It enforces the rules the findings proved: no README code line over 80 chars, every fence
   tagged, no table cell over 150 chars, H1 equals `displayName`, a heading naming the invariants.
2. Per publication and per round, network: `slot sh ux/round.sh R-nn <published commit>`, or the 4 gating
   tests alone with `UX_GATING_ONLY=1` (about 45 s). It runs against the live page as a ratchet on
   `ux/baseline.json`: absolute gates for identity-owned metrics, no-worse for the known losses.
3. When the website fixes UXF-012 (`preview:source` refuses v1 provenance), point `UX_BASE_URL` at the local
   preview and run the same spec per merge in its own CI job.
