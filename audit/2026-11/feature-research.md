# Feature research — LicenseLens Phase 1 (2026-11)

Retrieval window: **2026-11-16**. Primary sources preferred. Third-party indexes used as leads only.

Microsoft Learn MCP (`https://learn.microsoft.com/api/mcp`) was configured in `.cursor/mcp.json` but was **not available** in this agent runtime; Learn pages and the official licensing CSV were fetched directly.

## Baseline (Step 1)

Catalog / evaluator last touches (git log):

| Area | Last commit date | Notes |
|------|------------------|-------|
| `catalog/capabilities.yaml` | 2026-09-02 | 31 capabilities |
| `catalog/sku_service_plans.yaml` | 2026-08-23 | Friendly names + GUID table |
| `src/licenselens/evaluators/` | 2026-09-07 | Last evaluator fix |
| All `checks/<workload>/` dirs | 2026-09-06 | Pack last touched as a tree |

**Capabilities (31):** `entra_id_p2`, `conditional_access`, `workload_identities_premium`, `entitlement_management`, `identity_protection`, `defender_office_p2`, `defender_endpoint_p2`, `defender_identity`, `microsoft_sentinel`, `purview_dlp`, `exchange_online`, `exchange_online_protection`, `defender_office_p1`, `sharepoint_online`, `onedrive_for_business`, `teams`, `power_platform`, `power_bi_pro`, `power_bi_premium`, `intune`, `defender_endpoint_p1`, `defender_xdr`, `purview_audit`, `purview_sensitivity_labels`, `purview_retention`, `purview_insider_risk`, `purview_ediscovery`, `purview_communication_compliance`, `log_analytics`, `defender_for_cloud_cspm`, `defender_for_cloud_servers`.

**Checks by workload (170 enabled YAML checks on this branch tip; brief baseline “140” is the 0.4.0 marketing figure):**

| Workload dir | Count | Dir last-touch |
|--------------|------:|----------------|
| identity | 53 | 2026-09-06 |
| defender | 27 | 2026-09-06 |
| collaboration | 24 | 2026-09-06 |
| endpoint | 13 | 2026-09-06 |
| purview | 13 | 2026-09-06 |
| exchange | 12 | 2026-09-06 |
| power-bi | 10 | 2026-09-06 |
| power-platform | 8 | 2026-09-06 |
| sentinel | 8 | 2026-09-06 |
| azure | 2 | 2026-09-06 |

No capability entries today for: MDCA, Intune Suite/EPM, Entra Internet/Private Access (GSA), Security Copilot, Agent 365, Microsoft 365 E7 SKU aliases.

## Lead investigations (Step 2)

### Microsoft 365 E7 (“Frontier Suite”)

| Claim | Label | Evidence |
|-------|-------|----------|
| SKU string id `MICROSOFT_365_E7`, skuId `9a18296a-025f-4e37-9ffa-30bf8d1ce775` | [Documented] | Learn licensing reference / CSV updated **2026-08-19** ([Product names and service plan identifiers](https://learn.microsoft.com/entra/identity/users/licensing-service-plan-reference)) |
| Includes E5 security stack + Entra Suite plans + Agent 365 + M365 Copilot plans | [Documented] | Same CSV row set (111 plans); Microsoft subscription suites table ([Subscription Suites](https://www.microsoft.com/licensing/guidance/subscription-suites)) |
| Catalog gap: no E7 / Entra Suite / Agent 365 entries | [Documented] | Repo `catalog/` as of 2026-09 |

Notable E7-only (vs `SPE_E5`) security-relevant plans from CSV: `Entra_Premium_Internet_Access` (`8d23cb83-…`), `Entra_Premium_Private_Access` (`f057aab1-…`), `Entra_Identity_Governance` (`e866a266-…`), `AGENT_365` (`d0ce5ebb-…`) + agent Purview/Defender-for-AI plans.

### Security Copilot in E5/E7 (SCUs)

| Claim | Label | Evidence |
|-------|-------|----------|
| Included for eligible M365 E5/E7; 400 SCUs / month / 1,000 seats, cap 10,000 | [Documented] | [Security Copilot inclusion](https://learn.microsoft.com/copilot/security/security-copilot-inclusion) (retrieved 2026-11-16); microsoft.com Security Copilot pricing FAQ |
| Auto-provisioned when Microsoft enables the tenant | [Documented] | [Auto-provisioning](https://learn.microsoft.com/copilot/security/auto-provisioning-security-copilot) |
| MC1478465 was published to wrong audience / withdrawn | [Documented] | mc.merill.net MC1478465 update 2026-10-19 (third-party index of Message Center; confirm in tenant MC) |
| No Security Copilot service plan GUID in Aug-19 CSV | [Documented] | Official licensing CSV |
| Graph read: `GET /beta/security/securityCopilot/workspaces` needs `SecurityCopilotWorkspaces.Read.All` | [Documented] | [List workspaces](https://learn.microsoft.com/graph/api/securitycopilot-list-workspaces?view=graph-rest-beta) |
| “Entitled but unused” is a valid LicenseLens finding **only with phased-rollout uncertainty** | [Inferred] | Empty workspace list may mean Microsoft has not enabled inclusion yet → must be `partial`/`error`, never high-confidence unused-investment gap |

### July 1, 2026 packaging

| Claim | Label | Evidence |
|-------|-------|----------|
| Packaging/pricing FAQ: MDO P1 + Intune Suite components roll out CY26 Q3, complete by 2026-08-01; applies to E5 and also E7 packaging | [Documented] | [2026 M365 packaging FAQ](https://www.microsoft.com/en-us/licensing/news/2026-m365-packaging-pricing-updates-faq) |
| Suites table: MDO P1 in M365 E3/E5/E7; EPM/Cloud PKI/Enterprise App Mgmt in E5/E7; Remote Help / Advanced Analytics / Intune P2 in E3+ | [Documented] | [Subscription Suites](https://www.microsoft.com/licensing/guidance/subscription-suites) |
| CSV (2026-08-19): `SPE_E3` and `ENTERPRISEPACK` include `ATP_ENTERPRISE` (MDO P1) | [Documented] | Licensing CSV |
| CSV: `Intune-EPM` still listed under `Microsoft_Intune_Suite` only; `CLOUD_PKI` / Enterprise App Mgmt appear under `M365_E5_SUITE_COMPONENTS`, not inside `SPE_E5` plan list | [Documented] | Licensing CSV |
| Entitlement matching must follow subscribed service plans/GUIDs, not FAQ alone | [Inferred] | Avoid false “you pay for EPM” before Microsoft provisions the plan into `subscribedSkus` |

**Catalog defect found:** `defender_office_p2` currently lists `ATP_ENTERPRISE` as a unlocking plan. After July packaging, E3 tenants with only P1 would incorrectly unlock P2 checks. Fix: P2 = `THREAT_INTELLIGENCE` only; P1 = `ATP_ENTERPRISE` (+ E3/E5/E7 SKUs).

### Purview + Entra GSA network-layer DLP / Internet & Private Access

| Claim | Label | Evidence |
|-------|-------|----------|
| Entra Suite step-up SKU `Microsoft_Entra_Suite_Step_Up_for_Microsoft_Entra_ID_P2` (`2ef3064c-…`) includes Internet + Private Access + ID Governance + Verified ID request | [Documented] | Licensing CSV / Learn reference |
| Graph beta `GET /networkAccess/forwardingProfiles`, `filteringProfiles` with `NetworkAccess.Read.All` | [Documented] | [List forwardingProfiles](https://learn.microsoft.com/graph/api/networkaccess-networkaccessroot-list-forwardingprofiles?view=graph-rest-beta), [Internet Access Graph tutorial](https://learn.microsoft.com/graph/tutorial-entra-internet-access) |
| Network “Scan with Purview” GA targeted late Sep–Oct 2026 (MC1181769 / RM522096); Learn still carried preview language mid-2026 | [Documented] / [Inferred residual risk] | Message Center archives + Learn content-policy docs; treat network DLP scan action carefully — prefer GSA traffic-profile activation checks first |
| Pay-as-you-go may apply for Purview network inspection | [Documented] | MC1181769 prep text |

### Defender ↔ Entra SOC identity disable (July 2026)

| Claim | Label | Evidence |
|-------|-------|----------|
| Defender portal remediation can disable / revoke / mark compromised Entra identities | [Documented] | [Remediate compromised identities](https://learn.microsoft.com/defender-for-identity/remediation-actions) |
| Built-in role **Entra SOC Identity Responder** template id `58f930cc-fcf4-4152-852c-1d7dbf502139` | [Documented] | [Entra built-in roles](https://learn.microsoft.com/entra/identity/role-based-access-control/permissions-reference) (retrieved 2026-11-16) |
| Role is not a distinct paid service plan | [Documented] | Same permissions reference — built-in directory role |
| LicenseLens fit | [Inferred] | **Reject as primary activation check** — not SKU-gated; assigning the role is operational hygiene, not owned-entitlement realization |

### Agent governance (Agent ID / Agent 365 / DSPM for AI)

| Claim | Label | Evidence |
|-------|-------|----------|
| Standalone / E7 plan `AGENT_365` (`d0ce5ebb-9db0-491f-b780-8973a1d815fe`) plus agent Purview/Defender-for-AI plans | [Documented] | Licensing CSV |
| Existing check `id-ai-agents-risky-block` is a thin CA/identity_protection activation stub | [Documented] | Repo check YAML |
| Broad Agent 365 / Entra Agent ID / DSPM-for-AI Graph surfaces for “governance configured” | [Inferred] | Insufficient stable v1.0 read APIs verified in this pass → catalog mapping only; deeper checks deferred / post-Ignite |

### Sentinel → Defender portal

| Claim | Label | Evidence |
|-------|-------|----------|
| Sentinel GA in Defender portal; Azure portal support ends **2027-03-31** | [Documented] | [Sentinel in Defender portal](https://learn.microsoft.com/azure/sentinel/microsoft-sentinel-defender-portal) |
| Data lake onboarding is Defender-portal based; ARM analytics APIs remain for rules/settings | [Documented] | Learn data-lake onboarding + existing LicenseLens ARM collectors |
| Current check `deep_link`s point at Learn Azure Sentinel articles (still valid) | [Documented] | `checks/sentinel/*.yaml` |
| Action | [Inferred] | Keep ARM collectors; update remediation/deep links to prefer `https://security.microsoft.com` Sentinel experiences where Learn documents the move; no new SKU check required for “portal move” itself |

### Coverage gaps

| Gap | Verdict |
|-----|---------|
| MDCA capability missing despite `ADALLOM_*` friendly names | **Gap** — implement capability + CA App Control session-control check (Graph CA). Full MDCA policy API is portal-token REST, not Graph → reject deep policy checks |
| Intune Suite / EPM missing | **Gap** — capability + EPM configuration-policy family check via existing Intune collector |
| Entra ID Governance vs Suite step-up | Partially covered (`entitlement_management` already maps `Entra_Identity_Governance`); add Suite/E7 SKU aliases; Internet/Private Access are separate capabilities |

## Candidates table (Step 3)

| feature | status / date | entitling SKUs / plans (GUIDs) | read-only API | proposed check ID(s) | evidence type | expected state | priority | sources |
|---------|---------------|--------------------------------|---------------|----------------------|---------------|----------------|----------|---------|
| M365 E7 SKU + alias into existing caps | GA (CSV 2026-08-19) | `MICROSOFT_365_E7` / `9a18296a-025f-4e37-9ffa-30bf8d1ce775` | `subscribedSkus` | (catalog) | direct | E7 unlocks same security caps as included plans | **P0** | Learn licensing CSV |
| Fix MDO P1 vs P2 plan split after July packaging | GA | P1:`ATP_ENTERPRISE` `f20fedf3-…`; P2:`THREAT_INTELLIGENCE` `8e0c0a52-…`; E3/E5/E7 SKUs | `subscribedSkus` | (catalog) | direct | E3 owns P1 only | **P0** | CSV + packaging FAQ |
| Entra Internet Access | GA (product); Graph **beta** | `Entra_Premium_Internet_Access` `8d23cb83-ab07-418f-8517-d7aca77307dc`; Suite step-up; E7 | `GET /beta/networkAccess/forwardingProfiles` (`NetworkAccess.Read.All`) | `id-gsa-internet-access-enabled` | direct (beta) | Internet traffic forwarding profile enabled | **P1** | Learn Graph + CSV |
| Entra Private Access | GA; Graph **beta** | `Entra_Premium_Private_Access` `f057aab1-b184-49b2-85c0-881b02a405c5`; Suite; E7 | same forwardingProfiles API | `id-gsa-private-access-enabled` | direct (beta) | Private traffic forwarding profile enabled | **P1** | Learn Graph + CSV |
| Intune Endpoint Privilege Management | GA | `Intune-EPM` `bb73f429-78ef-4ff2-83c8-722b04c3e7d1`; `Microsoft_Intune_Suite` | `GET /deviceManagement/configurationPolicies` (`DeviceManagementConfiguration.Read.All`) filter `endpointSecurityEndpointPrivilegeManagement` | `endpoint-epm-policy-present` | direct | ≥1 EPM elevation / policy template assigned | **P1** | Learn Intune Graph + CSV |
| Defender for Cloud Apps (MDCA) | GA | `ADALLOM_S_STANDALONE` `2e2ddb96-…`, `ADALLOM_S_O365` `8c098270-…` | CA policies sessionControls.cloudAppSecurity (`Policy.Read.All`) | `id-mdca-ca-session-control` | direct (CA control surface) | Enabled CA policy uses cloud app security session control | **P1** | Learn CA session control + CSV |
| Security Copilot inclusion workspace | GA inclusion (phased) | SKU `SPE_E5` / `MICROSOFT_365_E7` (no plan GUID in CSV) | `GET /beta/security/securityCopilot/workspaces` (`SecurityCopilotWorkspaces.Read.All`) | `xdr-sec-copilot-workspace-provisioned` | direct (beta) + uncertainty | Workspace present when inclusion enabled; empty → partial w/ rollout limitation | **P1** | Learn inclusion + Graph beta |
| Entra Suite / ID Governance aliases | GA | Suite step-up SKU; E7 | `subscribedSkus` | (catalog) | direct | Governance unlocked via Suite/E7 | **P1** | CSV |
| Agent 365 catalog mapping | GA SKU | `AGENT_365` `d0ce5ebb-…` | entitlement only this pass | deferred (no check yet; capability catalog requires ≥1 check) | direct entitlement | Owned Agent 365 visible | **P2** | CSV |
| Cloud PKI / Remote Help / Advanced Analytics | GA | plan GUIDs in CSV; E5 suite-components SKU for Cloud PKI | Intune Graph (varies) | defer deeper checks | — | — | **P2** | CSV + FAQ |
| Sentinel Defender-portal deep links | Timeline to 2027-03-31 | `microsoft_sentinel` | n/a (docs) | update `deep_link` / remediation text | operator | Links land on current admin surface | **P2** | Learn Defender portal page |
| GSA + Purview network DLP “Scan with Purview” | GA window Sep–Oct 2026 (verify post-Ignite) | Entra Internet Access + Purview DLP (+ PAYG) | beta filteringPolicies contentRules | defer | preview/PAYG risk | — | **P2** | MC1181769 / Learn |

Priority heuristic: impact × confidence ÷ effort (P0 = must-fix correctness / entitlement; P1 = high-value GA read-only activation; P2 = catalog/docs or deferred).

## Rejected table

| feature | reason |
|---------|--------|
| Defender SOC identity disable / SOC Identity Responder assignment as headline check | **Not SKU-gated** (built-in Entra role); operational hygiene, not owned-SKU realization |
| Full MDCA policy inventory (session/file/anomaly policies) | **No Graph read API**; MDCA REST needs portal API token outside Graph allowlist |
| Security Copilot SCU usage / capacity metering as gap | **No stable Graph capacity read**; usage dashboard is portal/Azure; would invent false gaps during phased enablement |
| Network-layer Purview DLP as headline realized % input | **Preview/PAYG ambiguity** until Book of News + Learn GA confirmation; keep out of headline |
| Agent 365 / Entra Agent ID deep governance checks | **Insufficient verified GA read API** this pass; catalog only |
| Writing/remediating compromised accounts | **Needs write access** — invariant violation |
| Inventing E7/Entra Suite GUIDs from memory / third-party only | Forbidden — used Learn CSV only |
| Folding Intune EPM into SPE_E5 sku_part_numbers before CSV shows the plan | Would create **false entitlement** ahead of provisioning |

## Delta sweep checklist (post–Ignite Book of News)

Re-run after Ignite **2026-11-17…20** Book of News publishes:

1. Download fresh Learn licensing CSV; diff new SKUs/plans vs `catalog/sku_service_plans.yaml` + capabilities.
2. Sweep Entra / Defender XDR / MDE / MDO / MDI / MDCA / Sentinel / Purview / Intune What’s new + Graph changelog + M365 roadmap (GA ≥ 2026-06).
3. Confirm Security Copilot inclusion plan GUID (if Microsoft adds one) and whether empty workspace should remain `partial`.
4. Confirm Intune Suite plans appear under `SPE_E5` / `MICROSOFT_365_E7` subscribedSkus; only then add suite SKU aliases for EPM/Remote Help/etc.
5. Confirm GSA “Scan with Purview” GA + whether it is included vs PAYG; only then add network-DLP check (never preview → headline %).
6. Agent 365 / Entra Agent ID / DSPM for AI: look for GA Graph v1.0 reads suitable for activation checks.
7. Sentinel data lake / URBAC: any new **read-only** entitlement or configuration signal beyond current ARM workspace binding.
8. Re-verify MC / Product Terms for E7 packaging and Copilot inclusion.
9. Update this file’s retrieval dates; open a follow-up PR from a fresh branch if deltas clear the bar.

## Implementation notes (this PR)

Implemented in Phase 1 code: P0 catalog fixes; P1 capabilities + checks for GSA internet/private, Intune EPM, MDCA CA session control, Security Copilot workspace; Sentinel deep-link refresh; fixtures/tests/docs/CHANGELOG.
