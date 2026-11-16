# Dark vuln / exposure GUI research (late 2026)

**Date retrieved:** 2026-11-16  
**Purpose:** Owner override — default screen theme must be dark, inspired by top vulnerability / exposure / ASPM / CNAPP GUIs used by security teams, without regressing to Tailwind cyan-on-black “SOC starter.”  
**Labels:** [Documented] = primary/secondary source with date; [Inferred] = design judgment for LicenseLens.

---

## 1. Products surveyed

| Product | Class | Dark-mode signal (late 2025–2026) | Sources |
| --- | --- | --- | --- |
| **Wiz** | CNAPP / cloud risk graph | Marketing and product narrative emphasize a **purposeful dark theme**, dense but uncluttered data-vis, role-scoped “Lens” views, posture → issue drill-down | [Documented] Orizon “Top 10 Cybersecurity Websites in 2026” (Wiz: “dark theme used with purpose”); Wiz blog “Introducing Wiz Lens” (2025+); Aledlie Wiz UX report (posture dashboards / heatmaps) |
| **Tenable One / VM** | Vuln / exposure | **Dark mode** called out on modern Rules Management (2025-10-22); Explore / data-dense tables; Cyber Exposure Score as shared visual language; IRIS design system history = planar density | [Documented] Tenable VM 2025 release notes (Oct 22 2025: “supports dark mode”); CLEVER°FRANKE Tenable One visual design; Wandr IRIS/Hive case study |
| **CrowdStrike Falcon** | XDR / endpoint | First-party **light + dark** theme styles (`theme-dark`); dark neutrals (≈ `#161616` canvas / `#222` card class of surfaces); brand primary is **red** `#ec0000` — console density, Shoelace/Toucan tokens | [Documented] github.com/CrowdStrike/falcon-styles; falcon-shoelace; DesignMD CrowdStrike tokens; Foundry UI skill (updated 2026-10-01) |
| **Microsoft Defender XDR** | XDR / Secure Score-adjacent | **Dark mode GA** in Defender portal; dense incident queues, severity coloring, Fluent-ish chrome; ongoing UX churn (pin/sidebar, compact queues) | [Documented] ST Digital “What’s new … Feb 2024” (Dark Mode GA); Learn Defender portal overview; Tech Community UX enhancements; community notes 2026-05 on density/clutter |
| **Rapid7 Insight / Command** | Vuln / ASM | **Dark mode** in Attack Surface Management / Surface Command (May 2025); InsightVM console refreshed to align with Command Platform (Dec 2025) — platform theme consistency | [Documented] Rapid7 Insight release notes May 2025 (dark mode); Dec 2025 (Exposure Analytics theme alignment, InsightVM console UI refresh) |
| **Qualys VMDR / TruRisk** | Vuln / risk | UI 4.0 (Jan 2025): left rail, refreshed dashboards, accessibility/color/typography; **no clear first-party dark-mode claim** in release notes surveyed | [Documented] Qualys VMDR Release 2.1.0 (2025-01-07) |
| **Orca Security** | CNAPP | Renovated Risk Dashboard (posture storytelling widgets); **users still request dark mode** as of review commentary | [Documented] Orca blog risk dashboard + news widget; SoftwareFinder Orca review 2026 (“absence of a dark mode is disappointing”) |

---

## 2. Cross-product patterns (what “feels like a vuln GUI” in 2026)

| Pattern | Evidence | LicenseLens takeaway |
| --- | --- | --- |
| **Dark as operator default** | Wiz marketing; Tenable dark mode; Falcon dual theme; Defender dark GA; Rapid7 Surface Command dark | [Inferred] Screen default for assessment tooling should be dark; print stays light paper |
| **Neutral graphite / charcoal canvas** (not pure black, not neon) | Falcon dark tokens; Wiz “confident without being loud” | [Inferred] Cool graphite ladder; forbid `#000` and neon cyan identity |
| **Identity accent ≠ severity** | Falcon brand red vs severity; Tenable Exposure Score language; Defender severity chips | [Documented]/[Inferred] Keep a **steel / muted blue** identity; status hues only on markers/rails/bars |
| **Density with scannable hierarchy** | Tenable tables/Explore; Defender queues; Wiz prioritized issues | [Inferred] Keep fraction-first hero + ranked moves; avoid card nests and dashboard chrome noise |
| **Role / audience scoping** | Wiz Lens; Tenable Exposure / Attack Path / Inventory views | [Inferred] Executive path stays prose + fraction; check IDs stay technical |
| **Theme consistency across modules** | Rapid7 Command Platform alignment; Qualys UI 4.0 standardization | [Inferred] One shared `tokens.css` across report, report-app, wizard |

**Anti-patterns to avoid (LicenseLens-specific history):** Tailwind cyan `#22D3EE` + red-400/amber-500/green-500 as the whole personality; serif/sans clash; false-precision sole `%` hero; dashed placeholder disclosures. [Documented] prior critique `audit/2026-11/design/critique.md`.

---

## 3. Proposed LicenseLens dark identity — “Exposure Console”

**Name:** Exposure Console (DESIGN_V3 dark default; Assessment Ledger layout rules retained).

| Choice | Rationale |
| --- | --- |
| Graphite canvas `#12141A` + stepped surfaces | Falcon/Wiz-class calm dark; not pure black [Inferred] |
| Steel accent `#7BA3C4` (hover `#9BB4CC`, focus `#B8C9D9`) | Quiet instrument identity; **rejects** `#22D3EE` and Falcon brand red [Inferred] |
| Desaturated status `#E07070` / `#D0A15C` / `#6FBA8A` / `#8B93A1` | Severity readable on dark; AA measured 2026-11-16 [Documented] local WCAG measure |
| Print remains light paper tokens | Shareable PDF/email still document-grade [Inferred] |
| Keep V3 information architecture | Fraction-first, open moves, solid disclosures, status-on-markers-only already fixed “feels off” content issues [Documented] |

Optional light screen theme: not required for this override; print tokens already provide the light document surface. A future `data-theme="light"` remapping can reuse the prior Ledger hexes without a second product identity.

---

## 4. Decision

Flip DESIGN_V3 screen default from light Assessment Ledger to **dark Exposure Console**, informed by Wiz/Tenable/Falcon/Defender/Rapid7 dark-operator norms, while preserving LicenseLens trust invariants (offline, AA, status-color policy, no Tailwind cyan SOC).
