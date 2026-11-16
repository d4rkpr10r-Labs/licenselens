# Architect review — LicenseLens Phase 2 (2026-11)

Role: principal Microsoft security architect review before customers.  
Branch base: Phase 1 `cursor/feat-2026-11-feature-research-4fda` (PR #2).  
Retrieval date for Learn CSV / entitlement claims: **2026-11-16**.  
Microsoft Learn MCP configured in `.cursor/mcp.json`; not available in this agent runtime — Learn HTML + official CSV fetched directly.

Labels: **[Documented]** = primary Microsoft source cited; **[Inferred]** = engineer judgment from code behavior.

---

## Method

1. Diff every catalog `service_plan_guids` / capability GUID and SKU token against the Learn licensing CSV (script committed: `scripts/diff_sku_catalog_vs_learn_csv.py`).
2. Skeptical expected-state pass over identity / MDO / Phase 1 GSA·EPM·MDCA·Security Copilot checks (false “you're fine” weighted higher than missed features).
3. API hygiene, KQL/schema, integration UX, and tool-security review of collectors, `graph_ops`, UI server, CI pinning/SBOM.
4. Fix **Critical** and **High** on this branch; leave **Medium** / **Low** as GitHub-issue-ready drafts below.

---

## Summary

| Severity | Found | Fixed on branch |
|----------|------:|----------------:|
| Critical | 1 | 1 |
| High | 9 | 9 |
| Medium | 8 | 0 (issue drafts) |
| Low | 6 | 0 (issue drafts) |

CSV GUID hard-fail result after fixes: **PASS** (0 missing GUIDs / 0 name mismatches / 0 unknown SKU String_Ids remaining).

---

## Critical (fixed)

### C1 — Modern Insider Risk plan GUID missing → false `not_licensed` on GCC / G5

- **Where:** `catalog/capabilities.yaml` (`purview_insider_risk`); was only `9d0c4ee5-…` / `INSIDER_RISK_MANAGEMENT`
- **Source:** [Documented] Learn licensing CSV 2026-08-19 — SPE_E5 ships both `INSIDER_RISK_MANAGEMENT` (`9d0c4ee5-…`, often labeled RETIRED) **and** `INSIDER_RISK` (`d587c7a3-…`). GCC High `SPE_E5_USGOV_GCCHIGH` and `M365_G5_*` ship **only** `INSIDER_RISK`.
- **Why it matters:** A GCC High / G5 customer paying for Insider Risk could be told the capability is unlicensed while the modern plan is present — the worst class of false negative for an entitlement product.
- **Fix applied:** Catalog now maps both GUIDs + `INSIDER_RISK` plan name; SKU aliases include `SPE_E5_USGOV_GCCHIGH`, `M365_G5_GOV`, `M365_G5_GCC`. Regression in `tests/test_architect_2026_11_fixes.py`.

---

## High (fixed)

### H1 — Phantom national-cloud SKU aliases

- **Where:** `catalog/capabilities.yaml` sku aliases / part numbers; `catalog/sku_service_plans.yaml` friendly names
- **Source:** [Documented] Learn CSV String_Id set — no `SPE_E5_USGOV_DOD`, no `M365_E5_GOV`, no `DEFENDER_ENDPOINT_P2(_GOV)`, no `IDENTITY_THREAT_PROTECTION_GOV` as SKU ids. Present: `SPE_E5_USGOV_GCCHIGH`, `M365_G5_GOV`, `M365_G5_GCC`, `WIN_DEF_ATP`, `DEFENDER_ENDPOINT_P1`.
- **Why it matters:** Wrong String_Ids never match Graph `skuPartNumber`, so gov/DoD tenants stay under-entitled (false `not_licensed`) or operators chase SKUs that do not exist.
- **Fix applied:** Replaced phantoms with CSV-backed ids; MDE P2 standalone → `WIN_DEF_ATP`; Power BI Premium plan name → `BI_AZURE_P3` with `PBI_PREMIUM_PER_USER*` SKUs. Diff script committed.

### H2 — `id-security-defaults-on` OK on any enabled CA

- **Where:** `src/licenselens/evaluators/identity_governance.py` (was ~L96–109)
- **Source:** [Documented] [Security defaults](https://learn.microsoft.com/entra/fundamentals/security-defaults) require MFA + legacy-auth block; [Microsoft-managed CA](https://learn.microsoft.com/entra/identity/conditional-access/managed-policies).
- **Why it matters:** Tenants that disabled Security Defaults without replacing the baseline look “fine” while MFA/legacy gaps remain — false “you're covered.”
- **Fix applied:** OK only when enforced CA replaces the SD baseline (all-user MFA **and** legacy block), else PARTIAL/GAP.

### H3 — `mdo-p2-policies-default` OK on pilot / Allow-action policies

- **Where:** `src/licenselens/evaluators/defender_mdo.py`
- **Source:** [Documented] [Preset security policies](https://learn.microsoft.com/defender-office-365/preset-security-policies)
- **Why it matters:** Pilot-scoped or `Action=Allow` Safe Attachments still reported OK — false confidence on email protection.
- **Fix applied:** Require org-wide Safe Links + blocking Safe Attachments (+ preset/default), else PARTIAL.

### H4 — GSA checks OK when profile enabled but unassigned

- **Where:** `src/licenselens/evaluators/gsa_network_access.py`; demo fixture `collectors/gsa_network_access.py`
- **Source:** [Documented] [Assign users and groups to Global Secure Access](https://learn.microsoft.com/entra/global-secure-access/how-to-manage-users-groups-assignment)
- **Why it matters:** Enabled-but-unassigned forwarding profiles do not acquire traffic; customers can believe Internet/Private Access is realized.
- **Fix applied:** Enabled without associations → PARTIAL; OK requires assignment evidence.

### H5 — `endpoint-epm-policy-present` OK on unassigned / name-only matches

- **Where:** `src/licenselens/evaluators/endpoint_intune_policy.py`
- **Source:** [Documented] [Endpoint Privilege Management overview](https://learn.microsoft.com/mem/intune/protect/epm-overview)
- **Why it matters:** Unassigned EPM config or a coincidental “privilege management” display name looked realized.
- **Fix applied:** Match template family / technologies only; require `isAssigned` / assignments for OK.

### H6 — Inventory truncation heuristics miss `@odata.nextLink`

- **Where:** `src/licenselens/collectors/entra_devices.py`; `signins.py`; runtime collectors
- **Source:** [Inferred] from Graph paging contract already implemented in `GraphClient.get_list_result`
- **Why it matters:** Silent under-sampling can inflate coverage / omit truncation demotion the product claims to enforce.
- **Fix applied:** Use `get_list_result(...).truncated` and propagate envelope truncation.

### H7 — UI copy promised a live wizard that 0.4.0 does not ship

- **Where:** `src/licenselens/ui/pages.py`
- **Source:** [Documented] in-repo UI routes (`/demo`, `/diff` only) vs `__version__` `0.4.0`
- **Why it matters:** First-run UX lied about live browser sign-in; operators waste time or mis-trust the tool.
- **Fix applied:** Copy states browser wizard is offline-demo only; live path is CLI `quickstart` / `scan --live`.

### H8 — XDR AH KQL scored dead against Sentinel LA Usage + `_CL` misclassified

- **Where:** `src/licenselens/evaluators/sentinel_parity.py`; `src/licenselens/kql/table_refs.py`
- **Source:** [Documented] Advanced Hunting tables ([AlertInfo](https://learn.microsoft.com/defender-xdr/advanced-hunting-alertinfo-table), [AADSignInEventsBeta](https://learn.microsoft.com/defender-xdr/advanced-hunting-aadsignineventsbeta-table)); LA custom tables end in `_CL`.
- **Why it matters:** False dead-rule gaps for XDR detections; custom-table rules under-evaluated (treated as parsers).
- **Fix applied:** Exclude XDR rules from LA dead-rule ratio; classify `*_CL` as tables; note AH alias in telemetry expectations.

### H9 — `graph_ops` omitted live Graph surfaces that `REQUIRED_GRAPH_APP_PERMISSIONS` still needs

- **Where:** `graph_ops_catalog_identity.py` / `graph_ops_catalog_endpoint.py` vs `auth.py` / `docs/permissions.md`
- **Source:** [Inferred] code registry drift
- **Why it matters:** Least-privilege generation / doctor / docs regeneration from ops would silently drop AccessReview, AuditLog, Organization, Secure Score, DLP, eDiscovery, Insider Risk.
- **Fix applied:** Registered those ops (IRM as beta delegated); test asserts `REQUIRED_GRAPH_APP_PERMISSIONS ⊆ all_application_permissions()`.

---

## Medium (issue drafts — not fixed)

Use templates under `.github/ISSUE_TEMPLATE/`.

### M1 — MDCA CA session control treats monitor-only as fully OK

```markdown
---
name: False positive
title: "false-positive: id-mdca-ca-session-control monitorOnly OK"
labels: ["validation", "false-positive"]
---
## Check
`id-mdca-ca-session-control`
## What the report said
Enabled CA with `sessionControls.cloudAppSecurity` (including `monitorOnly`) → OK HIGH.
## What is actually true
Monitor-only / pilot scope is not full MDCA session enforcement.
## Why you believe this is a false positive
https://learn.microsoft.com/graph/api/resources/cloudappsecuritysessioncontrol
## Proposed fix
PARTIAL for monitorOnly / narrow scope; OK for enforced block/control with meaningful scope.
```

### M2 — Security Copilot empty workspace never becomes GAP

```markdown
---
name: Evaluator methodology challenge
title: "methodology: xdr-sec-copilot-workspace-provisioned empty never GAP"
labels: ["validation", "methodology"]
---
## Check
`xdr-sec-copilot-workspace-provisioned`
## The claim being made
Empty workspace → PARTIAL/LOW always (intentional for phased inclusion).
## Why the methodology is wrong or overstated
Post-inclusion tenants with unused capacity are under-flagged vs “included but unused.”
## Proposed change
Keep PARTIAL while rollout unknown; escalate to GAP when inclusion enablement can be evidenced.
## References
https://learn.microsoft.com/copilot/security/security-copilot-inclusion
```

### M3 — Weak auth methods OK during incomplete migration

```markdown
---
name: False negative
title: "false-negative: id-auth-weak-methods-disabled during preMigration"
labels: ["validation", "false-negative"]
---
## Check
`id-auth-weak-methods-disabled` (+ `id-auth-methods-migration`)
## What the report said
Modern authenticationMethodConfigurations show weak methods disabled → OK.
## What is actually true
On preMigration / migrationInProgress, legacy MFA/SSPR can still allow SMS/voice.
## Proposed fix
If migration ≠ migrationComplete, cap weak-methods at PARTIAL.
## References
https://learn.microsoft.com/graph/api/resources/authenticationmethodspolicy
```

### M4 — Purview / audit deep links still on compliance.microsoft.com

```markdown
---
name: Check request
title: "check: update Purview deep links to purview.microsoft.com"
labels: ["documentation"]
---
## Checks
`pur-dlp-*`, `mdo-audit-retention`, `mdo-unified-audit-enabled`
## Request
Point `deep_link` at https://purview.microsoft.com/... equivalents.
## References
https://learn.microsoft.com/purview/purview-portal
```

### M5 — Intune ASR primary Graph path not documented v1.0

```markdown
---
name: API inconsistency
title: "api: intune ASR endpointSecurity path vs configurationPolicies"
labels: ["validation", "api"]
---
## Surface
`graph_ops_catalog_endpoint.py` ASR path + `collectors/intune.py`
## Issue
Primary path `/deviceManagement/endpointSecurity/attackSurfaceReductionPolicies` marked non-preview; settings-catalog `configurationPolicies` is the supported surface (fallback already exists).
## Fix
Make configurationPolicies primary; mark legacy path preview or remove.
```

### M6 — GSA / Security Copilot collectors drop pagination truncated flag

```markdown
---
name: API inconsistency
title: "api: GSA/Security Copilot collectors ignore nextLink truncation"
labels: ["validation", "api"]
---
## Surface
`collectors/gsa_network_access.py`, `collectors/security_copilot.py`
## Issue
`get_list` page caps discard next-link truncation; partial inventories can look complete.
## Fix
Use `get_list_result` and surface truncated on envelopes (keep beta warnings).
```

### M7 — Batch / MSP path lacks GDAP guidance

```markdown
---
name: New edge case
title: "edge: document GDAP + multi-tenant app for batch scans"
labels: ["documentation", "msp"]
---
## Area
`docs/msp-batch.md`, `docs/app-registration.md`, `batch.py`
## Issue
No GDAP / partner-context onboarding for multi-tenant app + per-customer tenant_id.
## Fix
Document GDAP consent model; optional doctor note when scanning foreign tenant_id.
```

### M8 — Wizard 303 redirect skips security headers

```markdown
---
name: New edge case
title: "edge: UI demo redirect omits CSP/no-store headers"
labels: ["security"]
---
## Surface
`src/licenselens/ui/pages.py` demo 303 vs `ui/server.py` `_send` SECURITY_HEADERS
## Fix
Route redirects through a helper that always applies security headers.
```

---

## Low (issue drafts — not fixed)

### L1 — `id-auth-methods-migration` empty/`unknownFutureValue` as GAP

```markdown
---
name: Evaluator methodology challenge
title: "methodology: auth methods migration unknown → PARTIAL not GAP"
labels: ["validation", "methodology"]
---
Empty / unknownFutureValue migration state should be PARTIAL, not GAP.
```

### L2 — Residual Sentinel deep links still Learn/Azure-only

```markdown
---
name: Check request
title: "check: sen-entra-diagnostics / retention deep links → Defender UX"
labels: ["documentation"]
---
Prefer security.microsoft.com Sentinel blades where Learn documents the move.
```

### L3 — UI accepts `Origin: null` on POST (intentional)

```markdown
---
name: New edge case
title: "edge: document Origin null acceptance on loopback UI POST"
labels: ["security", "documentation"]
---
Document Host+CSRF binding rationale in docs/security.md.
```

### L4 — `capabilityStatus=Warning` treated as active (confirm)

```markdown
---
name: Licensing correction
title: "licensing: document Warning SKU capabilityStatus semantics"
labels: ["entitlement", "validation"]
---
Confirm Warning seats remain usable; ensure prepaidUnits.warning is not silently ignored in assignment messaging.
```

### L5 — Trials / prepaid enabled-only counting

```markdown
---
name: Licensing correction
title: "licensing: prepaidUnits warning/suspended vs enabled display"
labels: ["entitlement"]
---
Collectors count prepaidUnits.enabled only; surface warning/suspended seats in reports without unlocking Suspended/LockedOut SKUs.
```

### L6 — Coarse admin deep links (Power Platform / Teams roots)

```markdown
---
name: Check request
title: "check: deepen Power Platform / Teams admin deep links"
labels: ["documentation"]
---
Replace portal roots with blade-deep destinations where stable.
```

---

## Entitlement notes (not findings after fix)

- **GUID map vs CSV:** PASS after Phase 2 fixes (`scripts/diff_sku_catalog_vs_learn_csv.py --csv …`).
- **Disabled plans / Suspended / LockedOut SKUs:** correctly excluded in `catalog/loader.py` (`_INACTIVE_SKU_STATUSES`, `_ACTIVE_PLAN_STATUSES`). [Documented] Graph `capabilityStatus` / `provisioningStatus`.
- **Warning SKUs:** treated as active (not in inactive set) — intentional; see L4.
- **cloud_endpoints.py:** public / us_gov / china modeled; China MDE unsupported — consistent with `docs/permissions.md`. No DoD-specific Graph root beyond us_gov today (national-cloud CLI flag still absent — known limitation).
- **User vs tenant licensing:** capability unlock remains tenant `subscribedSkus`-based; assignment coverage is separate — by design, but MSPs must not confuse seat assignment with activation.

---

## Integration / security notes (no Critical)

- CSRF + loopback bind on UI server: solid (`ui/server.py`).
- Report redaction defaults on (`config_models.py`); domains opt-in.
- CI actions SHA-pinned; publish path builds SPDX/CycloneDX SBOM + attestation.
- Throttling: `http_retry.py` honors 429 / Retry-After.
- Alerts: collectors use `/security/alerts_v2` (correct vs deprecated `/security/alerts`).
- GSA / Security Copilot remain **beta** Graph — labeled; no silent v1.0 substitute found.

---

## Phase 3 blockers (content/copy)

1. UI wizard copy was wrong on 0.4.0 — fixed on this branch; Phase 3 should not redesign around a non-existent live wizard without CLI parity messaging.
2. Several customer summaries for Security Defaults / MDO / GSA / EPM changed meaning (stricter) — Phase 3 design must not reintroduce “you're fine” tone for PARTIAL baseline gaps.
3. Purview deep-link drift (`compliance.microsoft.com`) remains Medium — fix before polish screenshots that teach the wrong portal.
4. Headline realized % must continue to exclude preview / indeterminate Security Copilot empty-workspace PARTIAL — do not let design elevate it.

---

## Gate / test results (this branch)

Recorded **2026-11-16** on `cursor/2026-11-architect-4161`:

- `python3 scripts/validate_sku_catalog.py` → OK
- `python3 scripts/diff_sku_catalog_vs_learn_csv.py --csv <Learn CSV 2026-08-19>` → **PASS** (0 missing GUIDs / 0 name mismatches / 0 unknown SKU String_Ids)
- Non-Playwright pytest (`-m "not browser"`, browser suites ignored/deselected): **1624 passed**, 1 skipped, 3 deselected; coverage **87.15%** (floor 72%)
- Pre-existing failure (not introduced by Phase 2 evaluator/catalog fixes): `tests/test_report_render.py::test_single_file_zero_network_and_zero_img` — inline SVG still contains `xmlns="http://www.w3.org/2000/svg"` while the test requires `http://` stripped
- Playwright Chromium missing in this environment (same gate gap as Phase 1): browser suites ERROR / `test_ui_flow.py::test_browser_clicks_demo_button` fails to launch Chromium
- Full `scripts/release_gate.py` not completed here (Playwright install blocked)
