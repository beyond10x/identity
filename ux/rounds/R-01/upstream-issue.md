# Draft, not filed: issue for beyond10x/website

Title: Docs page findings from UX round R-01 (Identity docs page): contrast, mobile navbar, TOC gaps, source preview

Body:

UX round R-01 measured https://beyond10x.github.io/docs/identity/ (identity `e5c4e87`) at 5 viewports (1440x900,
1280x800, 1024x768, 768x1024, 390x844) x light and dark, with Playwright and axe-core 4.14.1 (wcag2a, wcag2aa,
wcag21a, wcag21aa, wcag22aa). These 10 findings come from the site, not the README; identity cannot fix them.
The records, contact sheets and raw measurements are in beyond10x/identity, branch `ux/r01`, under
`ux/findings/` and `ux/rounds/R-01/`.

| id | sev | finding | evidence |
|---|---|---|---|
| UXF-004 | S1 | Light theme fails WCAG AA contrast: 141 serious nodes at 1280x800, 0 in dark | inline `code` #7d6bc1 on #e4e8ed = 3.59:1 (103 nodes); Prism tokens #36acaa on #f6f8fa = 2.58:1 (27), #e3116c 4.32:1 (8), #d73a49 4.29:1 (3) |
| UXF-005 | S1 | Below 997 px, search and the theme toggle are hidden behind the menu button | navbar "Search" and "Switch between dark and light mode" not displayed at 390 and 768 px; contact sheet `sheet-390x844-light.png` |
| UXF-012 | S2 | `npm run preview:source` cannot start against the live publication | it exits 2 with "PROVENANCE.json is not b10x-website-provenance/v2 or v3"; the live PROVENANCE.json is v1 (website 0dc1ba8 and 22f9c9a) |
| UXF-006 | S2 | At 1024x768 there is no on-page table of contents: no right-hand TOC and no "On this page" button | reaching a section takes 4 to 12 page steps at 1024, against 1 TOC click at 1280; `sheet-1024x768-light.png` |
| UXF-014 | S2 | Below 997 px the section list is only at the top of the article; mid-page there is no way to another section | at 390x844 scrolled to § Routes: "On this page" is out of view, and no back-to-top button shows until the reader scrolls up 200 px; `review-390x844-light-mid-page-no-toc.png` |
| UXF-003 | S3 | The link to the page source is inside the collapsed "Source & revision" disclosure | one extra action at every size; the navbar "GitHub" link opens the organization, not the repository |
| UXF-010 | S3 | The search description is a generated filler sentence | `<span data-pagefind-meta="description">identity in the source-owned Identity documentation.</span>`; docs-system `src/source-check.ts:516` fallback; `surfaces[].summary` exists |
| UXF-011 | S3 | The published page lags the source | the live page renders identity `e5c4e87`; identity main (`0c85741`) has later README changes, among them two rewrites (`1a01792`, `5ddd008`) |
| UXF-013 | S3 | On a phone the code-block buttons cover the end of short code lines | at 390x844, `cargo run --locked --features local-login` reads "local-lo": the pre does not scroll (scrollWidth = clientWidth = 356 px) and the button group starts at 331 px |
| UXF-015 | S3 | Navigation and provenance text is below 14 px | computed at 1280x800: TOC links 12.8 px, "Source & revision" 10.88 px, source link 12.48 px, context labels 10.24 px; body text is 16 px |

Notes:

- R-01 gate results at the gating viewports (1280x800, 390x844):
  - gate 1 (no sideways page scroll) passes;
  - gate 2 (navbar, search and theme toggle always visible) fails only because of UXF-005;
  - gate 5 (axe serious = 0) fails only because of UXF-004.
- axe left about 150 color-contrast nodes per run "incomplete", in both themes, so dark's 0 is not proven.
- With "Source & revision" open, its summary also fails `target-size` (WCAG 2.5.8): 121x15 px.
- The mobile "On this page" button has no `aria-expanded` or `aria-controls`, so a screen reader does not
  hear whether the list is open.
