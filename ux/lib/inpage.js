// Runs inside the page (Playwright addInitScript). Defines window.__ux; reads the DOM only.
(() => {
  const norm = (s) => (s ?? '').replace(/[​‌‍﻿]/g, '').replace(/\s+/g, ' ').trim();
  const shown = (el) => {
    if (!el) return false;
    const r = el.getBoundingClientRect();
    const cs = getComputedStyle(el);
    return r.width > 1 && r.height > 1 && cs.visibility !== 'hidden' && cs.display !== 'none' && Number(cs.opacity) > 0 && !inClosedDetails(el);
  };
  function inClosedDetails(el) {
    for (let d = el.closest('details'); d; d = d.parentElement?.closest('details')) {
      if (!d.open && !el.closest('summary')?.parentElement?.isSameNode(d)) return true;
    }
    return false;
  }
  const vp = () => ({w: document.documentElement.clientWidth, h: window.innerHeight});
  const navBottom = () => {
    const n = document.querySelector('nav.navbar');
    return n ? Math.max(0, n.getBoundingClientRect().bottom) : 0;
  };
  const article = () => document.querySelector('article') ?? document.querySelector('main');
  const markdown = () => document.querySelector('.theme-doc-markdown') ?? article();

  function headings() {
    return [...markdown().querySelectorAll('h1,h2,h3,h4,h5,h6')];
  }
  function headingByRegex(src) {
    const re = new RegExp(src, 'i');
    return headings().find((h) => re.test(norm(h.textContent))) ?? null;
  }
  function section(h) {
    if (!h) return [];
    const level = Number(h.tagName[1]);
    const out = [];
    for (let n = h.nextElementSibling; n; n = n.nextElementSibling) {
      if (/^H[1-6]$/.test(n.tagName) && Number(n.tagName[1]) <= level) break;
      out.push(n);
    }
    return out;
  }
  function smallest(nodes, selector, text) {
    for (const n of nodes) {
      const all = [n, ...n.querySelectorAll(selector)].filter((e) => e.matches(selector));
      const hit = all.filter((e) => norm(e.textContent).toLowerCase().includes(text.toLowerCase()));
      if (hit.length) return hit.sort((a, b) => a.textContent.length - b.textContent.length)[0];
    }
    return null;
  }

  const known = {};
  function resolve(task) {
    known[task.id] = task;
    const t = task.target;
    let el = null;
    let h = t.heading ? headingByRegex(t.heading) : null;
    if (t.kind === 'heading') el = h;
    if (t.kind === 'firstCodeAfter') {
      for (const n of section(h)) {
        const pre = n.matches('pre') ? n : n.querySelector('pre');
        if (pre) { el = pre.closest('.theme-code-block') ?? pre; break; }
      }
    }
    if (t.kind === 'cellContaining') el = smallest(section(h), 'td,th', t.text);
    if (t.kind === 'textContaining') el = smallest(section(h), 'p,li', t.text);
    if (t.kind === 'linkHref') {
      el = [...document.querySelectorAll('a[href]')].find((a) => a.href.startsWith(t.href) && !a.closest('nav.navbar')) ?? null;
      h = null;
    }
    if (el) el.setAttribute('data-ux-target', task.id);
    if (h) h.setAttribute('data-ux-section', task.id);
    return {found: !!el, heading: h ? h.id : null, desc: el ? describe(el) : null};
  }

  function describe(el) {
    if (!el) return null;
    const cls = typeof el.className === 'string' ? el.className.split(/\s+/).filter(Boolean).slice(0, 3).join('.') : '';
    return `${el.tagName.toLowerCase()}${el.id ? '#' + el.id : ''}${cls ? '.' + cls : ''} "${norm(el.textContent).slice(0, 50)}"`;
  }

  function inView(el) {
    if (!el || !shown(el)) return false;
    const r = el.getBoundingClientRect();
    const {h} = vp();
    const seen = Math.min(r.bottom, h) - Math.max(r.top, navBottom());
    return r.width > 0 && seen >= Math.min(24, r.height) - 1;
  }
  // One page step a reader takes: the visible window under the navbar less 24 px of overlap, so no target is skipped.
  function pageStep(el) {
    const step = Math.max(100, vp().h - navBottom() - 24);
    const up = !!el && el.getBoundingClientRect().bottom < navBottom();
    const before = window.scrollY;
    window.scrollBy({top: up ? -step : step, behavior: 'instant'});
    return {key: up ? 'PageUp' : 'PageDown', moved: window.scrollY !== before};
  }
  function glanceOf(el) {
    if (!inView(el)) return 3;
    return article()?.contains(el) ? 1 : 2;
  }
  // React may replace a marked node after hydration (Prism re-renders on a theme switch): re-resolve then.
  function target(id) {
    const el = document.querySelector(`[data-ux-target="${id}"]`);
    if (el && el.isConnected) return el;
    if (known[id]) resolve(known[id]);
    return document.querySelector(`[data-ux-target="${id}"]`);
  }

  function hitPoints(r) {
    const {w, h} = vp();
    const x0 = Math.max(r.left, 0), x1 = Math.min(r.right, w), y0 = Math.max(r.top, 0), y1 = Math.min(r.bottom, h);
    if (x1 - x0 < 2 || y1 - y0 < 2) return [];
    const cx = (x0 + x1) / 2, cy = (y0 + y1) / 2, dx = (x1 - x0) / 4, dy = (y1 - y0) / 4;
    return [[cx, cy], [cx - dx, cy], [cx + dx, cy], [cx, cy - dy], [cx, cy + dy]];
  }
  function uncovered(el) {
    const pts = hitPoints(el.getBoundingClientRect());
    if (!pts.length) return false;
    return pts.every(([x, y]) => {
      const hit = document.elementFromPoint(x, y);
      return hit && (el === hit || el.contains(hit));
    });
  }
  function fullyInside(el) {
    const r = el.getBoundingClientRect();
    const {w, h} = vp();
    return r.left >= -1 && r.top >= -1 && r.right <= w + 1 && r.bottom <= h + 1;
  }

  function alwaysVisible() {
    const {w} = vp();
    const desktop = window.innerWidth >= 997;
    const nav = document.querySelector('nav.navbar');
    const navEls = nav ? [...nav.querySelectorAll('a,button,input')] : [];
    const search = navEls.find((e) => e.matches('input[type=search]') || /search/i.test(norm(e.textContent) + ' ' + (e.getAttribute('aria-label') ?? '')));
    const toggle = navEls.find((e) => /dark and light|color mode|theme/i.test(e.getAttribute('aria-label') ?? e.getAttribute('title') ?? ''));
    const items = {navbar: nav, search, themeToggle: toggle};
    if (desktop) items.sidebar = document.querySelector('aside.theme-doc-sidebar-container nav.menu') ?? document.querySelector('aside.theme-doc-sidebar-container');
    const out = {};
    for (const [k, el] of Object.entries(items)) {
      const present = shown(el);
      out[k] = {present, inside: present && fullyInside(el), uncovered: present && uncovered(el)};
      out[k].ok = out[k].present && out[k].inside && out[k].uncovered;
    }
    return {desktop, viewportWidth: w, items: out, misses: Object.values(out).filter((v) => !v.ok).length};
  }

  function overflowAncestor(el) {
    for (let a = el.parentElement; a && a !== document.documentElement; a = a.parentElement) {
      const ox = getComputedStyle(a).overflowX;
      if (ox !== 'visible') return {a, ox};
    }
    return null;
  }
  function layout() {
    const {w} = vp();
    const de = document.documentElement;
    const docHScroll = Math.max(de.scrollWidth, document.body.scrollWidth) - de.clientWidth;
    const scrollers = new Map();
    const clipped = new Map();
    const page = [];
    for (const el of document.body.querySelectorAll('*')) {
      if (!shown(el)) continue;
      if (el.closest('.navbar-sidebar')) continue;
      const r = el.getBoundingClientRect();
      const anc = overflowAncestor(el);
      if (anc) {
        const ar = anc.a.getBoundingClientRect();
        if (r.right > ar.right + 1 || r.left < ar.left - 1) {
          if (anc.ox === 'auto' || anc.ox === 'scroll') {
            if (!scrollers.has(anc.a)) scrollers.set(anc.a, {container: describe(anc.a), overflowPx: Math.round(anc.a.scrollWidth - anc.a.clientWidth)});
          } else if (!clipped.has(anc.a)) {
            clipped.set(anc.a, {container: describe(anc.a), ox: anc.ox, element: describe(el), pastPx: Math.round(Math.max(r.right - ar.right, ar.left - r.left))});
          }
          continue;
        }
      }
      const pos = getComputedStyle(el).position;
      if ((pos === 'absolute' || pos === 'fixed') && (r.right <= 0 || r.left >= w || r.bottom <= 0)) continue;
      if (r.right > w + 1 || r.left < -1) {
        const p = el.parentElement?.getBoundingClientRect();
        if (!p || !(p.right > w + 1 || p.left < -1)) page.push({element: describe(el), pastPx: Math.round(Math.max(r.right - w, -r.left))});
      }
    }
    const column = markdown().getBoundingClientRect().width;
    const tables = [...markdown().querySelectorAll('table')].map((t) => {
      const r = t.getBoundingClientRect();
      return {first: norm(t.rows[0]?.textContent).slice(0, 40), width: Math.round(Math.max(r.width, t.scrollWidth)), column: Math.round(column), overColumn: Math.max(r.width, t.scrollWidth) > column + 1};
    });
    const codeBlocks = [...markdown().querySelectorAll('pre')].map((p) => {
      const lang = [...p.classList, ...(p.closest('.theme-code-block')?.classList ?? [])].find((c) => /^language-/.test(c)) ?? null;
      return {lang, hScrollPx: Math.max(0, p.scrollWidth - p.clientWidth), widthRatio: Number((p.scrollWidth / Math.max(1, p.clientWidth)).toFixed(2))};
    });
    const cells = [...markdown().querySelectorAll('td')].map((c) => ({chars: norm(c.textContent).length, height: Math.round(c.getBoundingClientRect().height), text: norm(c.textContent).slice(0, 60)}));
    return {
      viewportWidth: w,
      column: Math.round(column),
      docHScrollPx: Math.max(0, docHScroll),
      pageOverflow: page,
      clipped: [...clipped.values()],
      innerScrollers: [...scrollers.values()],
      tables,
      codeBlocks,
      longCells: cells.filter((c) => c.chars > 150),
      tallCells: cells.filter((c) => c.height > 200).length,
      theme: document.documentElement.dataset.theme ?? null,
    };
  }

  function sameDocLink(a) {
    try {
      const u = new URL(a.href);
      return u.hash.length > 1 && u.pathname === location.pathname;
    } catch { return false; }
  }
  function findControl(keywords) {
    const re = new RegExp(keywords, 'i');
    const links = [...document.querySelectorAll('a[href]')]
      .filter((a) => sameDocLink(a) && shown(a) && fullyInside(a) && uncovered(a))
      .filter((a) => re.test(norm(a.textContent) || a.getAttribute('aria-label') || ''))
      .filter((a) => !a.classList.contains('hash-link'));
    links.sort((a, b) => Number(!!b.closest('.table-of-contents')) - Number(!!a.closest('.table-of-contents')));
    document.querySelectorAll('[data-ux-control]').forEach((e) => e.removeAttribute('data-ux-control'));
    if (links[0]) { links[0].setAttribute('data-ux-control', 'link'); return {kind: 'link', desc: describe(links[0])}; }
    const usable = (b) => shown(b) && fullyInside(b) && uncovered(b);
    const summary = [...document.querySelectorAll('article details:not([open]) > summary')].find((b) => re.test(norm(b.textContent)) && usable(b));
    const toc = [...document.querySelectorAll('.theme-doc-toc-mobile button')]
      .find((b) => /on this page|contents/i.test(norm(b.textContent)) && b.getAttribute('aria-expanded') !== 'true' && !/Expanded/.test(b.className) && usable(b));
    const disclosure = summary ?? toc;
    if (disclosure) { disclosure.setAttribute('data-ux-control', 'disclosure'); return {kind: 'disclosure', desc: describe(disclosure)}; }
    return null;
  }

  function focusInfo(taskIds) {
    const a = document.activeElement;
    if (!a || a === document.body) return {desc: null, reached: [], obscured: false, expandable: false};
    const reached = [];
    for (const id of taskIds) {
      const t = target(id);
      const sec = document.querySelector(`[data-ux-section="${id}"]`);
      if (t && (t === a || t.contains(a))) { reached.push(id); continue; }
      if (a.tagName === 'A' && sameDocLink(a)) {
        const hash = decodeURIComponent(new URL(a.href).hash.slice(1));
        if ((sec && sec.id === hash) || (t && t.id === hash)) { reached.push(id); continue; }
      }
      if (t && t.tagName === 'A' && a.tagName === 'A' && a.href === t.href) reached.push(id);
    }
    const inNav = !!a.closest('nav.navbar');
    const r = a.getBoundingClientRect();
    let obscured = false;
    if (!inNav && r.width > 0 && r.bottom > 0 && r.top < innerHeight) {
      const x = Math.min(Math.max(r.left + r.width / 2, 0), innerWidth - 1), y = Math.min(Math.max(r.top + r.height / 2, 0), innerHeight - 1);
      const hit = document.elementFromPoint(x, y);
      obscured = !!hit && !(a === hit || a.contains(hit) || hit.contains(a));
    }
    const expandable = (a.tagName === 'BUTTON' && !!a.closest('.theme-doc-toc-mobile') && a.getAttribute('aria-expanded') !== 'true' && !/Expanded/.test(a.className))
      || (a.tagName === 'SUMMARY' && !a.parentElement.open && !!a.closest('article'));
    return {desc: describe(a), reached, obscured, expandable};
  }

  // Opens every disclosure of the page (closed <details>, the mobile "On this page" list) for a second axe pass.
  function openAll() {
    let n = 0;
    for (const d of document.querySelectorAll('details:not([open])')) { d.open = true; n++; }
    const b = document.querySelector('.theme-doc-toc-mobile button');
    if (b && shown(b) && !/Expanded/.test(b.className)) { b.click(); n++; }
    return n;
  }

  window.__ux = {openAll, resolve, glanceOf, inView, pageStep, target, alwaysVisible, layout, findControl, focusInfo, describe};
})();
