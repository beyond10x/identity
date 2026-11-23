# R-01: Identity docs page

Page: https://beyond10x.github.io/docs/identity/, rendered from identity `e5c4e87`. Measured 2026-11-23. Gating viewports: 1280x800, 390x844; the rest are measured only.

The harness that wrote this report (Playwright spec, in-page library, round.ts, round.sh) lives unmerged on the
branch `ux/r01-harness` of beyond10x/identity: https://github.com/beyond10x/identity/tree/ux/r01-harness/ux

## Hard gates per viewport x theme

| viewport | theme | gating | 1 page h-scroll px | 1 past box | 2 always-visible misses | 5 axe serious nodes | 5 keyboard unreached | 4 tasks not completed |
|---|---|---|---|---|---|---|---|---|
| 1440x900 | dark |  | 0 | 0 pass | 0 pass | 0 | 0 | 0 pass |
| 1440x900 | light |  | 0 | 0 pass | 0 pass | 143 color-contrast(143) | 0 | 0 pass |
| 1280x800 | dark | yes | 0 | 0 pass | 0 pass | 0 | 0 | 0 pass |
| 1280x800 | light | yes | 0 | 0 pass | 0 pass | 141 color-contrast(141) | 0 | 0 pass |
| 1024x768 | dark |  | 0 | 0 pass | 0 pass | 0 | 0 | 0 pass |
| 1024x768 | light |  | 0 | 0 pass | 0 pass | 141 color-contrast(141) | 0 | 0 pass |
| 768x1024 | dark |  | 0 | 0 pass | 2 **FAIL** (search hidden, themeToggle hidden) | 0 | 0 | 0 pass |
| 768x1024 | light |  | 0 | 0 pass | 2 **FAIL** (search hidden, themeToggle hidden) | 143 color-contrast(143) | 0 | 0 pass |
| 390x844 | dark | yes | 0 | 0 pass | 2 **FAIL** (search hidden, themeToggle hidden) | 0 | 0 | 0 pass |
| 390x844 | light | yes | 0 | 0 pass | 2 **FAIL** (search hidden, themeToggle hidden) | 136 color-contrast(136) | 0 | 0 pass |

Always-visible misses count the elements missed in any state (top of page, the end of each of the 5 tasks). axe runs twice, as loaded and with every disclosure open; a rule counts with its larger node count. axe incomplete nodes (not decided by axe, mostly color-contrast) are reported, not gated.

## Content measures

| viewport | theme | inner h-scrollers | tables over column | code blocks with h-scroll | code blocks without language | cells over 150 chars | cells over 200 px tall | focus obscured | axe incomplete nodes |
|---|---|---|---|---|---|---|---|---|---|
| 1440x900 | dark | 3 | 0 | 3 | 0 | 2 | 0 | 0 | n/a |
| 1440x900 | light | 3 | 0 | 3 | 0 | 2 | 0 | 0 | n/a |
| 1280x800 | dark | 4 | 0 | 4 | 0 | 2 | 0 | 0 | n/a |
| 1280x800 | light | 4 | 0 | 4 | 0 | 2 | 0 | 0 | n/a |
| 1024x768 | dark | 4 | 0 | 4 | 0 | 2 | 0 | 0 | n/a |
| 1024x768 | light | 4 | 0 | 4 | 0 | 2 | 0 | 0 | n/a |
| 768x1024 | dark | 4 | 0 | 4 | 0 | 2 | 0 | 0 | n/a |
| 768x1024 | light | 4 | 0 | 4 | 0 | 2 | 0 | 0 | n/a |
| 390x844 | dark | 8 | 3 | 5 | 0 | 2 | 12 | 0 | n/a |
| 390x844 | light | 8 | 3 | 5 | 0 | 2 | 12 | 0 | n/a |

README fences without a language tag: 0.

## Screen-only user (actions / looks / glance; keyboard Tabs to reach)

| task | 1440x900 dark | 1440x900 light | 1280x800 dark | 1280x800 light | 1024x768 dark | 1024x768 light | 768x1024 dark | 768x1024 light | 390x844 dark | 390x844 light |
|---|---|---|---|---|---|---|---|---|---|---|
| run-locally | 1/2/g2; tab 25 | 1/2/g2; tab 25 | 1/2/g2; tab 26 | 1/2/g2; tab 26 | 4/5/g3; tab 26 | 4/5/g3; tab 26 | 2/3/g2; tab 17 | 2/3/g2; tab 17 | 2/3/g2; tab 18 | 2/3/g2; tab 18 |
| token-route | 1/2/g2; tab 38 | 1/2/g2; tab 38 | 1/2/g2; tab 39 | 1/2/g2; tab 39 | 8/9/g3; tab 39 | 8/9/g3; tab 39 | 2/3/g2; tab 30 | 2/3/g2; tab 30 | 3/4/g3; tab 31 | 3/4/g3; tab 31 |
| local-login-refuses | 1/2/g2; tab 35 | 1/2/g2; tab 35 | 1/2/g2; tab 36 | 1/2/g2; tab 36 | 7/8/g3; tab 36 | 7/8/g3; tab 36 | 2/3/g2; tab 27 | 2/3/g2; tab 27 | 2/3/g2; tab 28 | 2/3/g2; tab 28 |
| invariants | 9/10/g3; tab 42 | 9/10/g3; tab 42 | 11/12/g3; tab 43 | 11/12/g3; tab 43 | 12/13/g3; tab 43 | 12/13/g3; tab 43 | 10/11/g3; tab 34 | 10/11/g3; tab 34 | 18/19/g3; tab 38 | 18/19/g3; tab 38 |
| source-link | 1/2/g2; tab 19 | 1/2/g2; tab 19 | 1/2/g2; tab 19 | 1/2/g2; tab 19 | 1/2/g2; tab 19 | 1/2/g2; tab 19 | 1/2/g2; tab 10 | 1/2/g2; tab 10 | 1/2/g2; tab 10 | 1/2/g2; tab 10 |

## Metrics (gating maxima)

| scenario | metric | value |
|---|---|---|
| page | layout.doc_hscroll_px | 0 |
| page | layout.past_box | 0 |
| page | layout.inner_hscroll | 8 |
| page | layout.tables_over_column | 3 |
| page | layout.code_hscroll | 5 |
| page | layout.long_cells | 2 |
| page | always_visible.misses | 2 |
| page | axe.serious_nodes | 141 |
| page | keyboard.focus_obscured | 0 |
| page | source.code_fences_without_language | 0 |
| run-locally | screen_only.actions | 2 |
| run-locally | screen_only.looks | 3 |
| run-locally | glance_cost.max | 2 |
| run-locally | keyboard.tabs | 26 |
| token-route | screen_only.actions | 3 |
| token-route | screen_only.looks | 4 |
| token-route | glance_cost.max | 3 |
| token-route | keyboard.tabs | 39 |
| local-login-refuses | screen_only.actions | 2 |
| local-login-refuses | screen_only.looks | 3 |
| local-login-refuses | glance_cost.max | 2 |
| local-login-refuses | keyboard.tabs | 36 |
| invariants | screen_only.actions | 18 |
| invariants | screen_only.looks | 19 |
| invariants | glance_cost.max | 3 |
| invariants | keyboard.tabs | 43 |
| source-link | screen_only.actions | 1 |
| source-link | screen_only.looks | 2 |
| source-link | glance_cost.max | 2 |
| source-link | keyboard.tabs | 19 |

## Details

### 1440x900-dark

- inner scrollers: pre.prism-code.language-bash.codeBlock_bY9V "IDENTITY_LISTEN=127.0.0.1:8080 \IDENTITY_PUBLIC_OR" +1324 px; pre.prism-code.language-bash.codeBlock_bY9V "IDENTITY_UPSTREAM_PROVIDERS_JSON='[{"id":"one","la" +1761 px; pre.prism-code.language-bash.codeBlock_bY9V "IDENTITY_TRUSTED_ACCESS_CALLERS_JSON='[{"id":"rely" +1341 px
- long cells: 198 chars / 108 px "an authenticated session via POST /v1/access-token, or a pub"; 192 chars / 108 px "the learning consumer's — it reaches the projection and the "
- screen-only paths: run-locally: link: a.table-of-contents__link.toc-highlight "Running it locally"; token-route: link: a.table-of-contents__link.toc-highlight "Routes"; local-login-refuses: link: a.table-of-contents__link.toc-highlight "Signing in on a workstation"; invariants: PageDown; source-link: disclosure: summary "Source & revision"
- contact sheet: shots/sheet-1440x900-dark.png

### 1440x900-light

- inner scrollers: pre.prism-code.language-bash.codeBlock_bY9V "IDENTITY_LISTEN=127.0.0.1:8080 \IDENTITY_PUBLIC_OR" +1324 px; pre.prism-code.language-bash.codeBlock_bY9V "IDENTITY_UPSTREAM_PROVIDERS_JSON='[{"id":"one","la" +1761 px; pre.prism-code.language-bash.codeBlock_bY9V "IDENTITY_TRUSTED_ACCESS_CALLERS_JSON='[{"id":"rely" +1341 px
- long cells: 198 chars / 108 px "an authenticated session via POST /v1/access-token, or a pub"; 192 chars / 108 px "the learning consumer's — it reaches the projection and the "
- axe serious/critical: color-contrast x143 (p:nth-child(5) > code)
- screen-only paths: run-locally: link: a.table-of-contents__link.toc-highlight "Running it locally"; token-route: link: a.table-of-contents__link.toc-highlight "Routes"; local-login-refuses: link: a.table-of-contents__link.toc-highlight "Signing in on a workstation"; invariants: PageDown; source-link: disclosure: summary "Source & revision"
- contact sheet: shots/sheet-1440x900-light.png

### 1280x800-dark

- inner scrollers: pre.prism-code.language-bash.codeBlock_bY9V "IDENTITY_TEST_POSTGRES_URL='postgresql://user:pass" +118 px; pre.prism-code.language-bash.codeBlock_bY9V "IDENTITY_LISTEN=127.0.0.1:8080 \IDENTITY_PUBLIC_OR" +1444 px; pre.prism-code.language-bash.codeBlock_bY9V "IDENTITY_UPSTREAM_PROVIDERS_JSON='[{"id":"one","la" +1881 px; pre.prism-code.language-bash.codeBlock_bY9V "IDENTITY_TRUSTED_ACCESS_CALLERS_JSON='[{"id":"rely" +1461 px
- long cells: 198 chars / 108 px "an authenticated session via POST /v1/access-token, or a pub"; 192 chars / 108 px "the learning consumer's — it reaches the projection and the "
- screen-only paths: run-locally: link: a.table-of-contents__link.toc-highlight "Running it locally"; token-route: link: a.table-of-contents__link.toc-highlight "Routes"; local-login-refuses: link: a.table-of-contents__link.toc-highlight "Signing in on a workstation"; invariants: PageDown; source-link: disclosure: summary "Source & revision"
- contact sheet: shots/sheet-1280x800-dark.png

### 1280x800-light

- inner scrollers: pre.prism-code.language-bash.codeBlock_bY9V "IDENTITY_TEST_POSTGRES_URL='postgresql://user:pass" +118 px; pre.prism-code.language-bash.codeBlock_bY9V "IDENTITY_LISTEN=127.0.0.1:8080 \IDENTITY_PUBLIC_OR" +1444 px; pre.prism-code.language-bash.codeBlock_bY9V "IDENTITY_UPSTREAM_PROVIDERS_JSON='[{"id":"one","la" +1881 px; pre.prism-code.language-bash.codeBlock_bY9V "IDENTITY_TRUSTED_ACCESS_CALLERS_JSON='[{"id":"rely" +1461 px
- long cells: 198 chars / 108 px "an authenticated session via POST /v1/access-token, or a pub"; 192 chars / 108 px "the learning consumer's — it reaches the projection and the "
- axe serious/critical: color-contrast x141 (p:nth-child(5) > code)
- screen-only paths: run-locally: link: a.table-of-contents__link.toc-highlight "Running it locally"; token-route: link: a.table-of-contents__link.toc-highlight "Routes"; local-login-refuses: link: a.table-of-contents__link.toc-highlight "Signing in on a workstation"; invariants: PageDown; source-link: disclosure: summary "Source & revision"
- contact sheet: shots/sheet-1280x800-light.png

### 1024x768-dark

- inner scrollers: pre.prism-code.language-bash.codeBlock_bY9V "IDENTITY_TEST_POSTGRES_URL='postgresql://user:pass" +129 px; pre.prism-code.language-bash.codeBlock_bY9V "IDENTITY_LISTEN=127.0.0.1:8080 \IDENTITY_PUBLIC_OR" +1455 px; pre.prism-code.language-bash.codeBlock_bY9V "IDENTITY_UPSTREAM_PROVIDERS_JSON='[{"id":"one","la" +1892 px; pre.prism-code.language-bash.codeBlock_bY9V "IDENTITY_TRUSTED_ACCESS_CALLERS_JSON='[{"id":"rely" +1472 px
- long cells: 198 chars / 136 px "an authenticated session via POST /v1/access-token, or a pub"; 192 chars / 108 px "the learning consumer's — it reaches the projection and the "
- screen-only paths: run-locally: PageDown; token-route: PageDown; local-login-refuses: PageDown; invariants: PageDown; source-link: disclosure: summary "Source & revision"
- contact sheet: shots/sheet-1024x768-dark.png

### 1024x768-light

- inner scrollers: pre.prism-code.language-bash.codeBlock_bY9V "IDENTITY_TEST_POSTGRES_URL='postgresql://user:pass" +129 px; pre.prism-code.language-bash.codeBlock_bY9V "IDENTITY_LISTEN=127.0.0.1:8080 \IDENTITY_PUBLIC_OR" +1455 px; pre.prism-code.language-bash.codeBlock_bY9V "IDENTITY_UPSTREAM_PROVIDERS_JSON='[{"id":"one","la" +1892 px; pre.prism-code.language-bash.codeBlock_bY9V "IDENTITY_TRUSTED_ACCESS_CALLERS_JSON='[{"id":"rely" +1472 px
- long cells: 198 chars / 136 px "an authenticated session via POST /v1/access-token, or a pub"; 192 chars / 108 px "the learning consumer's — it reaches the projection and the "
- axe serious/critical: color-contrast x141 (p:nth-child(5) > code)
- screen-only paths: run-locally: PageDown; token-route: PageDown; local-login-refuses: PageDown; invariants: PageDown; source-link: disclosure: summary "Source & revision"
- contact sheet: shots/sheet-1024x768-light.png

### 768x1024-dark

- inner scrollers: pre.prism-code.language-bash.codeBlock_bY9V "IDENTITY_TEST_POSTGRES_URL='postgresql://user:pass" +26 px; pre.prism-code.language-bash.codeBlock_bY9V "IDENTITY_LISTEN=127.0.0.1:8080 \IDENTITY_PUBLIC_OR" +1264 px; pre.prism-code.language-bash.codeBlock_bY9V "IDENTITY_UPSTREAM_PROVIDERS_JSON='[{"id":"one","la" +1671 px; pre.prism-code.language-bash.codeBlock_bY9V "IDENTITY_TRUSTED_ACCESS_CALLERS_JSON='[{"id":"rely" +1280 px
- long cells: 198 chars / 108 px "an authenticated session via POST /v1/access-token, or a pub"; 192 chars / 108 px "the learning consumer's — it reaches the projection and the "
- screen-only paths: run-locally: disclosure: button.clean-btn.tocCollapsibleButton_TO0P "On this page" > link: a.table-of-contents__link "Running it locally"; token-route: disclosure: button.clean-btn.tocCollapsibleButton_TO0P "On this page" > link: a.table-of-contents__link "Routes"; local-login-refuses: disclosure: button.clean-btn.tocCollapsibleButton_TO0P "On this page" > link: a.table-of-contents__link "Signing in on a workstation"; invariants: disclosure: button.clean-btn.tocCollapsibleButton_TO0P "On this page" > PageDown; source-link: disclosure: summary "Source & revision"
- contact sheet: shots/sheet-768x1024-dark.png

### 768x1024-light

- inner scrollers: pre.prism-code.language-bash.codeBlock_bY9V "IDENTITY_TEST_POSTGRES_URL='postgresql://user:pass" +26 px; pre.prism-code.language-bash.codeBlock_bY9V "IDENTITY_LISTEN=127.0.0.1:8080 \IDENTITY_PUBLIC_OR" +1264 px; pre.prism-code.language-bash.codeBlock_bY9V "IDENTITY_UPSTREAM_PROVIDERS_JSON='[{"id":"one","la" +1671 px; pre.prism-code.language-bash.codeBlock_bY9V "IDENTITY_TRUSTED_ACCESS_CALLERS_JSON='[{"id":"rely" +1280 px
- long cells: 198 chars / 108 px "an authenticated session via POST /v1/access-token, or a pub"; 192 chars / 108 px "the learning consumer's — it reaches the projection and the "
- axe serious/critical: color-contrast x143 (p:nth-child(5) > code)
- screen-only paths: run-locally: disclosure: button.clean-btn.tocCollapsibleButton_TO0P "On this page" > link: a.table-of-contents__link "Running it locally"; token-route: disclosure: button.clean-btn.tocCollapsibleButton_TO0P "On this page" > link: a.table-of-contents__link "Routes"; local-login-refuses: disclosure: button.clean-btn.tocCollapsibleButton_TO0P "On this page" > link: a.table-of-contents__link "Signing in on a workstation"; invariants: disclosure: button.clean-btn.tocCollapsibleButton_TO0P "On this page" > PageDown; source-link: disclosure: summary "Source & revision"
- contact sheet: shots/sheet-768x1024-light.png

### 390x844-dark

- inner scrollers: div.b10x-table-wrap "stepcommandtestscargo test --workspace --lockedtes" +509 px; pre.prism-code.language-bash.codeBlock_bY9V "IDENTITY_TEST_POSTGRES_URL='postgresql://user:pass" +404 px; pre.prism-code.language-bash.codeBlock_bY9V "IDENTITY_LISTEN=127.0.0.1:8080 \IDENTITY_PUBLIC_OR" +1642 px; pre.prism-code.language-bash.codeBlock_bY9V "IDENTITY_UPSTREAM_PROVIDERS_JSON='[{"id":"one","la" +2049 px; pre.prism-code.language-bash.codeBlock_bY9V "IDENTITY_TRUSTED_ACCESS_CALLERS_JSON='[{"id":"rely" +1658 px; div.b10x-table-wrap "routeforGET /livezprocess liveness onlyGET /readyz" +167 px; div.b10x-table-wrap "audiencereached bya registered access audiencean a" +152 px; pre.prism-code.language-json.codeBlock_bY9V "{ "version": "identity.audiences/2", "session": ["" +244 px
- tables over the 358 px column: "stepcommand" 867 px; "routefor" 525 px; "audiencereached by" 510 px
- long cells: 69 chars / 355 px "GET /oauth/authorize, GET /oauth/callback/upstream, POST /oa"; 122 chars / 355 px "the browser leg and the one-use code exchange; a registered "; 24 chars / 300 px "POST /v1/access-exchange"; 113 chars / 300 px "confidentially narrow one live human access token into an ex"; 15 chars / 218 px "POST /v1/logout"; 71 chars / 218 px "revokes the session and every outstanding access token for t"; 22 chars / 218 px "GET /v1/identity-links"; 64 chars / 218 px "lists the current person's explicitly linked upstream identi"; 28 chars / 246 px "a registered access audience"; 198 chars / 246 px "an authenticated session via POST /v1/access-token, or a pub"; 27 chars / 245 px "urn:b10x:profile-projection"; 192 chars / 245 px "the learning consumer's — it reaches the projection and the "
- screen-only paths: run-locally: disclosure: button.clean-btn.tocCollapsibleButton_TO0P "On this page" > link: a.table-of-contents__link "Running it locally"; token-route: disclosure: button.clean-btn.tocCollapsibleButton_TO0P "On this page" > link: a.table-of-contents__link "Routes" > PageDown; local-login-refuses: disclosure: button.clean-btn.tocCollapsibleButton_TO0P "On this page" > link: a.table-of-contents__link "Signing in on a workstation"; invariants: disclosure: button.clean-btn.tocCollapsibleButton_TO0P "On this page" > PageDown; source-link: disclosure: summary "Source & revision"
- contact sheet: shots/sheet-390x844-dark.png

### 390x844-light

- inner scrollers: div.b10x-table-wrap "stepcommandtestscargo test --workspace --lockedtes" +509 px; pre.prism-code.language-bash.codeBlock_bY9V "IDENTITY_TEST_POSTGRES_URL='postgresql://user:pass" +404 px; pre.prism-code.language-bash.codeBlock_bY9V "IDENTITY_LISTEN=127.0.0.1:8080 \IDENTITY_PUBLIC_OR" +1642 px; pre.prism-code.language-bash.codeBlock_bY9V "IDENTITY_UPSTREAM_PROVIDERS_JSON='[{"id":"one","la" +2049 px; pre.prism-code.language-bash.codeBlock_bY9V "IDENTITY_TRUSTED_ACCESS_CALLERS_JSON='[{"id":"rely" +1658 px; div.b10x-table-wrap "routeforGET /livezprocess liveness onlyGET /readyz" +167 px; div.b10x-table-wrap "audiencereached bya registered access audiencean a" +152 px; pre.prism-code.language-json.codeBlock_bY9V "{ "version": "identity.audiences/2", "session": ["" +244 px
- tables over the 358 px column: "stepcommand" 867 px; "routefor" 525 px; "audiencereached by" 510 px
- long cells: 69 chars / 355 px "GET /oauth/authorize, GET /oauth/callback/upstream, POST /oa"; 122 chars / 355 px "the browser leg and the one-use code exchange; a registered "; 24 chars / 300 px "POST /v1/access-exchange"; 113 chars / 300 px "confidentially narrow one live human access token into an ex"; 15 chars / 218 px "POST /v1/logout"; 71 chars / 218 px "revokes the session and every outstanding access token for t"; 22 chars / 218 px "GET /v1/identity-links"; 64 chars / 218 px "lists the current person's explicitly linked upstream identi"; 28 chars / 246 px "a registered access audience"; 198 chars / 246 px "an authenticated session via POST /v1/access-token, or a pub"; 27 chars / 245 px "urn:b10x:profile-projection"; 192 chars / 245 px "the learning consumer's — it reaches the projection and the "
- axe serious/critical: color-contrast x136 (p:nth-child(5) > code)
- screen-only paths: run-locally: disclosure: button.clean-btn.tocCollapsibleButton_TO0P "On this page" > link: a.table-of-contents__link "Running it locally"; token-route: disclosure: button.clean-btn.tocCollapsibleButton_TO0P "On this page" > link: a.table-of-contents__link "Routes" > PageDown; local-login-refuses: disclosure: button.clean-btn.tocCollapsibleButton_TO0P "On this page" > link: a.table-of-contents__link "Signing in on a workstation"; invariants: disclosure: button.clean-btn.tocCollapsibleButton_TO0P "On this page" > PageDown; source-link: disclosure: summary "Source & revision"
- contact sheet: shots/sheet-390x844-light.png
