# Dashboard + clickthrough IA (owner ask, 2026-11)

**Status:** Stop line — prototypes only. Production templates untouched until owner picks A, B, or a tweak.  
**Date:** 2026-11-19  
**Identity retained:** Exposure Console (graphite + steel, `templates/design/tokens.css`). WCAG 2.2 AA, offline, status-on-markers-only, print light paper.  
**Labels:** [Documented] = current shipped report; [Inferred] = design judgment for this proposal.

---

## 1. Owner ask

> Maybe instead of a big scrolling view, we could have a really really simple dashboard, with more info as a clickthrough. It would simplify the interface and give people a more polished and approachable feel.

Goal: first screen is approachable and scannable; depth (capability, check, methodology) is opt-in via clickthrough — without becoming a dense SOC dashboard or losing the MSP → CFO/CISO forward path.

---

## 2. What ships today (scroll report) — [Documented]

Single long page, sticky section nav:

| Order | Section | Content |
| --- | --- | --- |
| A | Where you stand | Fraction-first hero, dist bar, “How we got here” |
| C | What matters most | Ranked moves (full why + effort + deep link) |
| B | What you already own | Capability constellation / ownership |
| Findings | Explore list | Progressive disclosure rows |
| Evidence | Detection / realization | Charts + detail |

Strengths: one URL, print expands naturally, JS-off still shows everything, executive can scroll past technical sections.  
Weaknesses: first viewport already competes with long page chrome; CFO/CISO who only need “4/9 + top actions” still feel the weight of the full instrument below the fold. [Inferred]

---

## 3. Proposed first screen (shared by A and B)

**One composition** (not a widget dashboard):

1. Brand / product name (hero-level, Exposure Console)
2. Fraction claim `met / owned` (+ quiet percent only as secondary)
3. One short supporting sentence
4. Distribution bar + legend (status hues on segments/rails only)
5. **Top priorities as titles** (3 rows) — click to drill
6. Three quiet entry points: Owned · Findings · How we got here

No findings list, no charts, no constellation, no nested cards on the first screen.

---

## 4. Clickthrough depth (shared content model)

| Drill target | Shows |
| --- | --- |
| Priority *n* | Full why, effort, admin deep link; optional related finding / check id under disclosure |
| Owned | Licensed / prioritized capability summary (belief blocks later if shipping) |
| Findings | Evidence-backed gaps with status marker + word; check detail in disclosure |
| How we got here | Accounting stats + methodology prose |

Back always returns to the summary first screen.

---

## 5. Direction A vs Direction B

### A — Summary + side panel / drawer

- Summary stays mounted; detail slides in from the right (or bottomsheet on narrow).
- Focus moves into the panel; Escape / Close returns.
- **Pros:** Context preserved; fast compare between priorities; feels polished/app-like. [Inferred]
- **Cons:** Panel pattern needs careful keyboard + `inert`/focus management; print must ignore the overlay and use a linear “full detail” block. [Inferred]

**Prototype:** `dashboard-a-panel.html`

### B — Summary + full-page drill routes (hash / multi-view)

- Hash routes: `#/` summary, `#/priority/1`, `#/owned`, `#/findings`, `#/method`.
- Full viewport swap; Back / “Summary” returns.
- **Pros:** Clearer mental model for “a page”; easier to deep-link a single action in chat; print can map each view or dump all views linearly. [Inferred]
- **Cons:** Loses side-by-side context; more “site” than “sheet”; hash routing needs a no-JS fallback (all views in document, CSS shows one when JS on). [Inferred]

**Prototype:** `dashboard-b-routes.html`

---

## 6. Scroll-report vs dashboard+drill — MSP → CFO/CISO

| Concern | Scroll report (today) | Dashboard + clickthrough |
| --- | --- | --- |
| 30-second board glance | Possible if they stop at hero + moves | Stronger — first screen is *only* that glance [Inferred] |
| Forward as email/PDF | Linear print already works | Must ship a **print-all / linear fallback** or PDF feels incomplete [Documented need] |
| Trust / evidence | Always visible lower down | Behind click — risk if evidence feels “hidden”; mitigate with clear entry points + print-all [Inferred] |
| Operator depth | Scroll / filters | Same content, gated by drill |
| Genre risk | Long instrument can feel heavy | Must stay Exposure Console calm — not tile/KPI SOC chrome [Inferred] |

---

## 7. Non-negotiable constraints (both directions)

| Constraint | How prototypes address it |
| --- | --- |
| Offline / no external fonts | Self-contained HTML; system stacks; Exposure Console hexes inline (prototype only — shipping would reuse `tokens.css`) |
| WCAG 2.2 AA | Focus rings, contrast, status never color-only (marker + word) |
| `prefers-reduced-motion` | Instant panel open / view swap |
| Readable without JS | A: `<details>` + `#print-all` linear block; B: all views in DOM, hash JS progressive; print shows `#print-all` |
| Status color policy | Markers / rails / bars only — never on numerals or body |
| Prefer polished/simple | No card nests on summary; no KPI strip; no neon |

---

## 8. Print / PDF / email forward

Screen: summary-first.  
Print: **always emit a linear document** (hero → priorities full → owned summary → findings → method) regardless of which panel/route was open. Overlay/route chrome suppressed. Light paper tokens.

JS-off screen: same linear block available below the summary (A) or as stacked sections with in-page anchors (B).

---

## 9. Owner decision needed (stop line)

Please pick one:

1. **Ship A** — summary + panel/drawer clickthrough  
2. **Ship B** — summary + full-page hash/multi-view drills  
3. **Tweak** — describe changes (e.g. A with bottomsheet-only mobile, B with persistent summary strip, keep scroll for print-only export, etc.)

Do **not** rewrite production Jinja/CSS until that pick is recorded.
