# Design critique — Security License Lens GUI (before V3)

**Date:** 2026-11-16  
**Scope:** single-file HTML report, report-app bundle, local wizard (`licenselens ui`)  
**Method:** read product docs + DESIGN_V2 / CHANGELOG drift; run `licenselens demo` and wizard; Playwright captures at 1440 / 1280 / 390, print media, `prefers-reduced-motion` on/off → `audit/2026-11/design/before/` (54 PNGs)  
**Labels:** [Documented] = measured in shipped artifacts; [Inferred] = design judgment

---

## 1. Verdict

The GUI feels off because the product no longer has one design identity. Contract churn (v1 → Ink and Verdigris → Warm Charcoal in CHANGELOG → SOC Dark in code) left three surfaces on three token systems, while the report itself still reads as a Tailwind-flavored SOC dashboard pasted onto an assessment document. Trust cues that an MSP/IT admin needs when handing this to a CFO/CISO are diluted by precision theater, nested chrome, and cyan link noise.

**Recommendation (see §5):** ship a **light, document-grade default** for the report artifact, with a calm instrumental dark as a secondary screen option later — not another cyan-on-near-black dashboard pass.

---

## 2. Root causes (ordered)

### 2.1 Design-contract churn is the primary root cause — [Documented]

| Source | Claims |
| --- | --- |
| `CHANGELOG.md` 0.4.0 | v2 = **"Warm Charcoal"** / champagne-ivory accent |
| `DESIGN.md` | Points at V2 as **"Warm Charcoal"** |
| `DESIGN_V2.md` + shipped CSS | Binding identity = **"SOC Dark"**, accent `#22D3EE` |
| `examples/primitive-showcase.html` | Third ramp (`#0f1114` / accent `#88b4d8`) |
| `src/licenselens/ui/pages.py` `APP_CSS` | Fourth orphan (`#0f1114` / `#88b4d8`, no shared tokens) |

Engineers and docs disagree with what ships. That produces patchwork: serif wordmark from one era, cyan Tailwind accent from another, wizard from a third. [Inferred] Until one contract owns all three surfaces, polish on any single screen will keep regressing.

### 2.2 Wrong genre for the artifact — [Inferred]

LicenseLens outputs a **shareable assessment** (email, PDF/print, board packet), not a live SOC console. SOC Dark + cyan `#22D3EE` + pill distribution bar telegraphs "monitoring dashboard." CFOs do not live in dashboards; they live in memos and ledgers. Print already inverts to light paper (`DESIGN_V2` §2.2) — the screen default fights the artifact's real life.

### 2.3 Three styling layers, zero shared token file — [Documented]

1. `templates/report.html.j2` + `templates/report/v2/_v2_styles.css.j2` (~1500 lines)  
2. `templates/report_app/v2/app.css` + `app.js` (~1500 lines; tokens re-declared)  
3. Wizard inline `APP_CSS` in `pages.py` (hardcoded hex, no status ramp, no wordmark)

There is no single source of truth for color, type, spacing, or status policy. V3 must start with one shared token file consumed by all three.

### 2.4 Density without hierarchy — [Documented] + [Inferred]

Every section except the hero is a bordered `surface-1` panel; move items are further `surface-2/3` cards inside that panel (`section` + `.move-item` rules). Result: cards-in-cards, equal visual weight, little breathing room. Accent paints indexes, links, active nav, and mono IDs — so cyan becomes "everything interactive" instead of a sparse identity signal.

---

## 3. Owner hypotheses — confirm / reject

Evidence from `docs/images/report-hero.png` (historical 38% / 8 caps) and live demo captures (44% / 9 prioritized caps, 2026-11-16).

| Hypothesis | Verdict | Evidence |
| --- | --- | --- |
| Tailwind-default palette (cyan-400, red-400 / amber-500 / green-500) → template-dashboard feel | **Confirm** | Shipped tokens: `--accent #22D3EE`, `--state-action #F87171`, `--state-incomplete #F59E0B`, `--state-ok #22C55E` — exact Tailwind cyan-400 / red-400 / amber-500 / green-500. Reads as default kit, not a product palette. |
| Serif wordmark falls back to system serif → clashes with Segoe/system sans | **Confirm** | Measured: `h1` = `Palatino, … Georgia, serif`; body/digits = Segoe/system sans. On Linux CI the serif resolves to a generic face; on Windows Palatino/Georgia appear. Either way the lockup fights the instrument UI. |
| Alignment: distribution bar inset vs "38"/"44" / body; "%" detached from number | **Confirm (partial geometry)** | Digits left ≈ 172px; bar left ≈ 212px (40px inset via section/hero padding mismatch on the bar wrapper). Unit is a separate 16px span with 10px flex gap after 54px digits — "%" reads detached from the numeral, glued to the word "realized". |
| Duplicate Action copy; "~a few hours" awkward | **Confirm** | Move title and `customer_next_step` are identical in demo data; template always prints both (`_v2_moves.html.j2`). Effort comes from `EFFORT_PLAIN_LABELS["hours"] = "~a few hours"` — tilde + vague quantity reads uncommitted next to ranked actions. |
| Cards-in-cards; underlined cyan links; mono check IDs in prose | **Confirm** | Sections bordered + move cards nested; global `a { text-decoration: underline; color: var(--accent) }`; move rows expose `Checks: id-…` in mono inside the executive path. |
| "How we got here" dashed border unfinished | **Confirm** | Contract deliberately sets closed `details.tech` to `border: 1px dashed`. In UI craft, dashed closed wells read as placeholder/drop-target, not "collapsed disclosure." |
| Hero "38%" (now "44%") overstates precision on small denom | **Confirm** | Integer percent of 8–9 capabilities implies score-like precision. 4/9 → 44% looks authoritative; it is a coarse fraction. Headline should lead with the fraction (or a band), percent as secondary. |

---

## 4. Trust cues for the MSP → CFO/CISO handoff

What this audience needs to believe in under 30 seconds:

1. **Genre:** "This is an assessment memo," not a SOC toy.  
2. **Claim hygiene:** one dominant claim, denominator visible, no false precision.  
3. **Evidence discipline:** gaps stay gaps; proxy/partial labeled; color never carries the status alone.  
4. **Action clarity:** ranked moves without duplicated sentences or engineer IDs in the first reading path.  
5. **Offline integrity:** no webfonts/CDN; print looks like a document someone would staple.  
6. **Product continuity:** wizard → report feel like one product.

Today: (1) fails (dashboard), (2) weak (big %), (3) mostly held in data model but undercut by chrome, (4) fails (dup Action + mono IDs), (5) print works but screen fights it, (6) fails (wizard is a raw form on black).

---

## 5. Dark-first vs light document-grade — recommendation

| Option | Fit | Risk |
| --- | --- | --- |
| Keep dark-first (refine SOC Dark) | Familiar to SecOps; matches current CSS investment | Keeps wrong genre; CHANGELOG/docs already confused; cyan-on-dark will keep feeling "Tailwind starter" unless palette is fully re-authored |
| **Light document-grade default** | Matches print, email, board packets; Stripe Sigma / Linear-report calm; builds CFO trust | Requires intentional dark *optional* later; must still meet WCAG on paper surfaces |

**Recommend: light document-grade as the V3 default** for all three surfaces. [Inferred]

Reasons:

- The artifact's durable form is paper/PDF/email; print tokens already assume light ink.  
- Small-N percentages and ranked prose belong in editorial layouts (rules, columns, quiet ink), not neon markers.  
- Distinguishes LicenseLens from every other "cyber" dark dashboard an MSP already shows.  
- Wizard can stop looking like an abandoned CLI stub and start looking like the cover page of the same document.

Dark may return as an explicit operator preference after the shared token system exists — not as the identity.

---

## 6. What must change in V3 (contract-level, pre-implementation)

1. **One token file** consumed by report, report-app, and wizard.  
2. **One type stack** for UI chrome (system sans). If a display face is wanted for the wordmark only, justify a *bundled* offline font explicitly — do not keep Palatino/Georgia fallback roulette. Default recommendation: **no serif**; wordmark in the same sans at a distinct weight/tracking.  
3. **Status color policy (strict):** markers, rails, bars only — never numerals, never body, never effort chips.  
4. **Hero math:** lead with `met / in-scope` (e.g. **4 / 9**); show `%` as secondary caption or omit integer % when denominator &lt; 20.  
5. **Moves:** one sentence path — title *or* action, not both when identical; effort as plain text (`Hours`), not `~a few hours` pills; check IDs only under technical disclosure.  
6. **Surfaces:** open typography + hairline rules; cards only for interactive units (findings list filters, etc.). No section-in-card-in-card.  
7. **Disclosures:** solid border at rest (or rule + background), never dashed-as-placeholder.  
8. **Links:** accent underline on hover/focus only at body sizes, or a quieter ink link style for document contexts.  
9. **Offline:** no CDN/external fonts; any bundled font needs an explicit owner decision.  
10. **Motion:** keep information-only; honor `prefers-reduced-motion`; JS-off remains fully readable.

---

## 7. Capture index

Playwright captured every section at 1440 / 1280 / 390, print media, and reduced-motion on/off (54 PNGs). The PR keeps a curated review set under `audit/2026-11/design/before/`; regenerate the full matrix with `_capture_before.py`.

Curated in-repo:

- Report viewports: `report-{1440,1280,390}-motion-{on,off}-viewport.png`
- Section crops (1440 motion-on): `hero`, `priorities`, `evidence`
- Mobile hero: `report-390-motion-on-hero.png`
- Print: `report-1280-print-firstpage.png` (full print page dumps omitted — multi‑MB)
- Wizard: `wizard-1440-{mode,scan,report-viewport}.png`, `wizard-390-mode.png`
- Helper (not product): `_capture_before.py`

---

## 8. Stop line

Two static HTML directions follow this critique (`direction-a-ledger.html`, `direction-b-instrument.html`). **No DESIGN_V3.md and no three-surface implementation until the owner picks a direction.**
