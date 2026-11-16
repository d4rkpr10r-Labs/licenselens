# DESIGN_V3 — Security License Lens (Assessment Ledger)

> Status: the binding implementation contract for the v3 GUI.
> This document **supersedes `DESIGN_V2.md` (SOC Dark) and `DESIGN.md` (v1) in full**.
> Where an old constraint conflicts with this document, this document wins.
>
> Identity: **Assessment Ledger** — a light, document-grade assessment memo for the
> MSP/IT → CFO/CISO handoff. Not a SOC dashboard. Not Tailwind cyan on near-black.
>
> Architecture (unchanged): Jinja2 + hand-written CSS + vanilla JS, offline-first,
> zero build step for fonts/CDN, zero external resources. No React/Vue/Svelte/Vite/
> Tailwind, no CDN, no external fonts, no external images, no chart libraries, no
> API calls, no data-URIs, no network requests. The report must render from a local
> file with the network unplugged.

## 0. Decision log

- **Owner pick (2026-11-16):** Direction A — Assessment Ledger (light). Direction B
  (Quiet Instrument / dark steel) is retained only as a rejected alternative in
  `audit/2026-11/design/`.
- **Critique:** `audit/2026-11/design/critique.md` — contract churn, wrong genre,
  three token systems, Tailwind defaults, serif/sans clash, false-precision %,
  duplicate Action copy, cards-in-cards, dashed disclosures.
- **Shared tokens:** `templates/design/tokens.css` is the single source of color and
  font tokens. Consumed by the single-file foundation, the report-app foundation
  include, and the local wizard CSS handler.

## 1. Identity and guardrails

**Identity: Assessment Ledger.** Cool paper canvas, white reading sheet, deep teal
identity accent, desaturated status ramp. Premium, calm, editorial — a memo you would
email or print, not a monitoring console.

**Architecture guardrails (non-negotiable):**

- Offline-first. No external JS/CSS/images/chart libraries/API calls. No data-URI
  assets in the single-file renderer. Network access is not required.
- No frontend framework. Jinja + CSS + vanilla JS only.
- Semantic HTML: exactly one `<main>`, exactly one `<h1>`, heading levels never skip.
- WCAG 2.2 AA: keyboard, visible `:focus-visible`, status never color-only,
  `prefers-reduced-motion` honored, `forced-colors` honored.
- Print stylesheet: predictable expanded content; visualizations get textual fallbacks.
- Responsive at 900px and 640px.
- Fully readable with JavaScript disabled.

**Retired (must not reappear):**

- SOC Dark (`#0B0E14` canvas, `#22D3EE` accent, Tailwind red-400/amber-500/green-500).
- Warm Charcoal / champagne-ivory (CHANGELOG 0.4.0 naming; never shipped as described).
- Ink and Verdigris.
- Serif wordmark (`Palatino` / `Georgia` stacks).
- Dashed closed `<details>` borders (placeholder craft).
- Cards-in-cards section chrome (`section` as bordered card wrapping move cards).
- Always-underlined cyan body links as the default resting state.
- Mono check IDs in the executive move list.
- Duplicate Action line when `customer_next_step` equals `title`.
- `~a few hours` effort phrasing.
- Integer `%` as the sole hero figure when the denominator is small.
- Dark-only screen UI (V2 “no light-mode screen”).

**Still forbidden:**

- Pure black `#000000` canvas or surface fill.
- Violet/purple UI chrome; neon/Tailwind-default cyan/red/amber/green as identity or status.
- Glassmorphism except the single sticky-nav blur (optional; opaque fallback required).
- External font, icon package, image asset, chart library, data-URI, or network request.
- Emoji for metadata, statuses, labels, or icons.
- Status hue on numerals or body text.
- Bundled webfonts without an explicit owner decision recorded in this file (none for V3).

## 2. Token palette

Declared once in `templates/design/tokens.css`. Every other stylesheet references tokens
by name. Literal hex outside that file is a violation except print media overrides that
map to `--print-*` names already declared there.

### 2.1 Screen tokens (light-first)

| Token | Hex | Role |
| --- | --- | --- |
| `--canvas` | `#F3F5F8` | Cool paper page stock |
| `--surface-1` | `#FFFFFF` | Primary reading sheet |
| `--surface-2` | `#EEF1F5` | Secondary wells, closed disclosures |
| `--surface-3` | `#E4E9F0` | Raised / open disclosures |
| `--surface-4` | `#D8DEE8` | Highest surface (focused panes) |
| `--border` | `#D5DCE6` | Default 1px rule |
| `--border-strong` | `#A8B4C4` | Emphasis rule |
| `--text-1` | `#15202B` | Primary ink |
| `--text-2` | `#3D4D5C` | Secondary ink (≥ 7:1 on `--canvas`) |
| `--text-3` | `#5E6E80` | Tertiary ink (≥ 4.5:1 on `--canvas`) |
| `--accent` | `#0B5F75` | Deep teal identity + interaction |
| `--accent-hover` | `#094C5E` | Accent hover |
| `--accent-focus` | `#127A94` | Focus ring |
| `--accent-print` | `#0B5F75` | Print identity / links |
| `--state-action` | `#B42318` | Gap / error (≥ 4.5:1 on white) |
| `--state-incomplete` | `#B54708` | Partial |
| `--state-ok` | `#087443` | Ok / met |
| `--state-neutral` | `#5B6B7C` | Not licensed / skipped |
| `--grad-page` | cool paper wash | Optional page atmosphere (not a hero card wash) |
| `--grad-raised` | surface-2 → surface-1 | Elevated pane only |
| `--shadow-1` / `--shadow-2` | soft cool | State elevation only |
| `--blur-nav` | `blur(8px)` | Sticky nav only, with opaque fallback |
| `--nav-surface` | white 92% | Sticky nav fill |

### 2.2 Print tokens

Print stays light. Use `--print-*` for ink/paper/border/status when a print block must
re-pin values; default screen tokens already meet paper AA.

### 2.3 Usage rules

- **Accent is identity + interaction only.** Logo mark stroke, links (underline on
  hover/focus at body sizes; resting links may use accent without a permanent underline),
  focus rings, active nav. Never the hero numerals, never status, never chart data.
- **Status color only on markers, rails, and bars.** Never on numerals, body text,
  effort labels, or titles.
- **Semantic mapping (locked):** `gap`/`error` → `--state-action`; `partial` →
  `--state-incomplete`; `ok` → `--state-ok`; `not_licensed`/`skipped` → `--state-neutral`.
- **Contrast floors (WCAG 2.2 AA):** body ≥ 4.5:1; large text / non-text status ≥ 3:1;
  focus ring ≥ 3:1 against adjacent surface. Palette edits require re-measurement.

## 3. Typography

System-only stacks (locked):

| Role | Value |
| --- | --- |
| Sans | `var(--font-sans)` — Segoe / system |
| Mono | `var(--font-mono)` — for IDs, SKUs, timestamps, evidence keys, commands only |

**No serif anywhere.** The product wordmark is sans at a distinct weight/tracking.

**Type scale (locked):**

| Role | Size / weight / line-height |
| --- | --- |
| Hero fraction | `clamp(2.75rem, 6vw, 3.5rem) / 650 / 1.0` tabular |
| Hero caption | `1rem / 400 / 1.35` `--text-2` |
| h1 | `clamp(1.75rem, 2.4vw, 2.125rem) / 650 / 1.1` |
| Tagline | `1rem / 400 / 1.4` `--text-2` |
| h2 | `1.375rem / 650 / 1.25` |
| h3 / move title | `1.0625rem / 650 / 1.3` (lead move `1.1875rem`) |
| Body | `1rem / 400 / 1.55`, prose `max-width: 62–72ch` |
| Label / meta | `0.8125rem` |
| Micro-label | `0.75rem / 700`, uppercase, kickers only |

## 4. Spacing, radius, surfaces

- Base unit 4px. Stops: 4, 8, 12, 16, 20, 24, 32, 48, 64.
- Radius: `0` (document rules, hero, tables, dist bar), `2` (inputs), `6` (controls),
  `10` (interactive elevated panes only). **No 16px. No 999px pills on text controls.**
  Proportion bars may use `0` (preferred for ledger) or `999px` only if a figure truly
  needs a capsule fill — default is `0`.
- **Not everything is a card.** Sections are open typography on the sheet with hairline
  rules. Move items are a numbered sequence separated by rules, not nested cards inside
  a section card. Cards only for interactive units that need a bound hit target.
- Elevation is state: shadows on open disclosures / selected finding only.

## 5. Information architecture

Order unchanged: A (posture) → C (priorities) → B (owned) → Findings → Evidence detail.

### A — Where you stand (fraction-first)

1. Masthead: lens mark + sans `<h1>` + tagline. No serif.
2. Dominant claim: **`fully_working / you_own`** as a fraction (`4/9`), `--text-1`.
3. Caption: “in-scope capabilities met…”; when `you_own < 20`, show percent as a
   secondary quiet qualifier, never as the only figure.
4. Distribution bar (status hues on segments only) + legend with markers.
5. Implication once (`realized_sentence`).
6. “View prioritized actions” text link.
7. Closed `<details>` “How we got here” — **solid** border at rest.

Count-up (motion) may animate the numerator; final state is always the true fraction.

### C — What matters most

- Numbered sequence; first item dominant by type size / rule weight, not a second card nest.
- Title is the action. If `customer_next_step` equals `title` (casefold/strip), **omit**
  the Action line.
- Effort as plain text meta (`Effort: Hours`) — labels from `EFFORT_PLAIN_LABELS`
  without tildes or “a few”.
- Check IDs **not** in the executive list; they live under finding technical disclosure.
- Deep link: “Open the admin page”.

### B / Findings / Evidence

Belief blocks, constellation, charts, filters, and progressive disclosure keep their
V2 information contracts, restyled to the ledger surfaces and solid disclosure chrome.

## 6. Navigation

Full-width segmented control under the masthead. Active = accent underline or inset
indicator + `aria-current`. Bundle sticky nav may use `--blur-nav` with opaque fallback.

## 7–10. Constellation, disclosure, charts, interactivity

Mechanisms from V2 remain (native `<details>`, sr-only chart tables, cross-filter
buttons as siblings, keyboard-reachable controls). Visual differences:

- Closed disclosure: `1px solid var(--border)` on `--surface-2` (never dashed).
- Open disclosure: solid `--border-strong` on `--surface-3`, `--shadow-1`.
- Links: accent color; underline on `:hover` / `:focus-visible` by default for body
  links (permanent underline allowed for critical path CTAs if needed for AA clarity).

## 11. Motion

Information-only. Opening sequence may count the numerator and fill the bar
(500–1000ms total). `prefers-reduced-motion: reduce` → instant final state, zero
information loss. JS-off: fully visible static page. No loops, ambient motion, or
layout-property animation.

## 12. Workload icons

Twelve branded Microsoft marks remain, always with a visible text label (V2 §12).

## 13–14. Accessibility and forced colors

WCAG 2.2 AA. Status never color-only (glyph + word + color). Focus ring ≥ 2px
`--accent-focus`. Target sizes 44×44 coarse / 24×24 fine. `forced-colors: active`
collapses chrome to system colors.

## 15. Print

Light paper. Expand disclosures. Show chart data tables. Suppress nav chrome and
wizard-only chrome. `print-color-adjust: exact` on status bars/rails.

## 16. Three surfaces, one token file

| Surface | Token consumption |
| --- | --- |
| Single-file report | `{% include "design/tokens.css" %}` inside `_v2_styles.css.j2` |
| Report app bundle | Same foundation include; `app.css` must not redeclare conflicting hex |
| Local wizard | `pages.py` serves `tokens.css` + wizard layout CSS from `/app.css` |

## 17. Wizard

Same identity: paper canvas, teal accent, sans wordmark, profile select, primary button
filled with `--accent` / white label. Privacy line stays first. No orphan hex palette.

## 18. Acceptance

- Offline render; no external requests.
- Fraction-first hero; small-N percent is secondary.
- No SOC Dark / Tailwind cyan signatures in shipped CSS.
- No Palatino/Georgia wordmark.
- Moves without duplicate Action / exec-path mono IDs / `~a few hours`.
- Solid disclosure borders; open sections without cards-in-cards.
- WCAG tests + Playwright report/browser suites pass.
- `prefers-reduced-motion` and JS-off verified.
