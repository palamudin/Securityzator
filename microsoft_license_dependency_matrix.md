# Microsoft Control License Dependency Matrix

Purpose: simple planning view for Securityzator test spend. This file is derived from `mock_recommendations.json` and `microsoft_knowledgebase.md`; it is not a Microsoft price sheet. Use it to decide which tenant licenses, test workloads, SaaS trials, and hybrid resources are worth funding before building automation.

## How To Read This

| Field | Meaning |
|---|---|
| Control set | Secure Score service family or testing bucket. |
| Controls | Number of controls in the current 441-control export. |
| Minimum useful test dependency | The lowest practical license/capability family needed to test the controls meaningfully. |
| Resource gate | Non-license thing that must exist, such as onboarded devices, Exchange mailboxes, AD DS, or a SaaS tenant. |
| Testing value | What Securityzator can realistically prove in a lab. |

## Test Spend Buckets

| Bucket | Buy or prepare this | Unlocks | Notes |
|---|---|---|---|
| T0: Existing tenant / read-only | Existing Microsoft 365 tenant with Secure Score access and Graph read permissions | Secure Score export, recommendation inventory, score visualization, knowledgebase mapping, read-only posture discovery | Cheapest starting point. Does not prove remediation writes. |
| T1: SMB Microsoft 365 lab | Microsoft 365 Business Premium-style lab or equivalent mix of Exchange, Teams, SharePoint, Entra ID P1, Intune, and Defender for Business | Core identity, device-management, Exchange, SharePoint, Teams, and many endpoint policy workflows | Best practical retail/MSP test lane. Some E5/P2 controls will remain gated. |
| T2: Full Microsoft security lab | Microsoft 365 E5 or E5 Security/E5 Compliance equivalent trial/test tenant | Entra ID P2, Defender for Endpoint P2, Defender for Office 365 P2, Defender for Cloud Apps, Defender for Identity, advanced Purview features | Best single Microsoft bucket for proving high-end enterprise controls. |
| T3: Hybrid identity lab | AD DS, domain controllers, AD CS, Entra Connect, Windows Server VMs, and Defender for Identity sensors | Defender for Identity / Azure ATP controls, LDAP/NTLM/Kerberos/AD CS posture, hybrid remediation evidence | Compute/time heavy. License alone is not enough; topology matters. |
| T4: Cross-platform endpoint lab | Managed Windows, macOS, Linux, and WSL endpoints enrolled/onboarded to the chosen management plane | MDATP endpoint controls across OS families, Defender preferences, Intune profiles, compliance/readiness checks | Needed to prove controls beyond Windows-only demos. |
| T5: SaaS vendor lab | Vendor tenants/trials for GitHub, Zendesk, Atlassian, Salesforce, ServiceNow, Zoom, Okta, ShareFile, DocuSign, Dropbox, NetDocuments, PingOne, SailPoint, CyberArk Identity, and related SaaS products | Defender for Cloud Apps SaaS controls plus vendor-native readback/remediation paths | Likely the most annoying spend bucket because many useful controls require vendor enterprise/security tiers. |

## Microsoft Workload Matrix

| Control set | Controls | Minimum useful test dependency | Resource gate | Testing value |
|---|---:|---|---|---|
| All Secure Score metadata | 441 | Microsoft 365 tenant with Secure Score / Defender portal visibility and Graph security read permissions | Tenant connection and admin consent for read app | Export recommendations, compare tenants, build landscape, prioritize controls. |
| AzureAD / Entra | 22 | Entra ID Free for basic directory checks; Entra ID P1 for Conditional Access and stronger governance; Entra ID P2 for Identity Protection risk controls | Users, groups, admin roles, app registrations, Conditional Access test accounts | Read/write identity policy tests, admin hygiene, consent workflow, SSPR, password protection, risk policy where licensed. |
| MDATP / Defender endpoint | 170 | Defender for Endpoint / Defender Vulnerability Management visibility; Intune Plan 1 or MDE security settings management for durable policy writes | Onboarded Windows/macOS/Linux devices; MDM enrollment or MDE management channel | Endpoint recommendation evidence, ASR, Defender AV, firewall, BitLocker, SmartScreen, macOS/Linux Defender preferences, readiness/guided workflows. |
| MDO / Defender for Office 365 | 38 | Exchange Online Protection for base mail hygiene; Defender for Office 365 P1/P2 for Safe Links, Safe Attachments, anti-phishing, advanced mail policy testing | Exchange Online mailboxes, accepted domains, mail-flow test accounts | Mail protection policy read/write, forwarding controls, phishing policy, ZAP, quarantine, anti-spam, Safe Links/Attachments. |
| EXO / Exchange Online | 9 | Exchange Online license and Exchange admin role; advanced Microsoft 365 compliance license for Customer Lockbox-style controls where applicable | Exchange Online organization and mailboxes | OWA policy, role assignment policy, sharing policy, transport rule, mailbox audit, modern auth and governance checks. |
| Azure ATP / Defender for Identity | 74 | Defender for Identity or Microsoft 365 E5-style security entitlement | AD DS forest, DCs, AD CS where relevant, Entra Connect where relevant, sensors deployed | Hybrid identity posture, AD CS ESC findings, LDAP/NTLM/Kerberos hardening, risky account and Tier-0 remediation workflows. |
| MIP / Microsoft Purview | 7 | Purview Information Protection/DLP/Audit licensing; E5 Compliance/Purview advanced features for auto-labeling, advanced audit, and richer DLP | Purview portal, labels, policies, Teams/Exchange/SPO data locations | Sensitivity labels, label policies, auto-labeling, DLP, audit search/API, Data Map guidance. |
| Microsoft Teams | 6 | Teams-capable Microsoft 365 license; Teams admin role | Teams tenant, users, meetings/chats/policies | Meeting policy and Teams governance controls via Teams admin center/PowerShell. |
| SPO / SharePoint and OneDrive | 5 | SharePoint/OneDrive license; Entra ID P1 if Conditional Access/unmanaged-device enforcement is needed | SharePoint tenant, sites, OneDrive users, sharing test data | Sharing controls, unmanaged-device access, ATP-related integration checks where licensed. |
| Forms | 1 | Microsoft Forms-capable Microsoft 365 license | Forms service enabled | Basic service governance toggle testing. |
| Sway | 1 | Sway-capable Microsoft 365 license | Sway service enabled | External sharing/service governance testing. |
| Admincenter | 1 | Microsoft 365 admin center access | Tenant admin role and target users/licenses | Admin center configuration and license-assignment evidence. |
| App Governance | 2 | Defender for Cloud Apps App Governance capability, usually in higher Microsoft security plans | Microsoft 365 Defender portal and app governance onboarding | App governance predefined policy checks and evidence. |
| MCAS / Defender for Cloud Apps | 2 | Defender for Cloud Apps | Cloud app discovery/connectors/log collector where applicable | Cloud app discovery, connected app posture, policy existence, log upload flow. |

## SaaS / Vendor Matrix

| Control set | Controls | Minimum useful test dependency | Resource gate | Testing value |
|---|---:|---|---|---|
| MDA_GitHub | 9 | Defender for Cloud Apps for Microsoft-side visibility; GitHub Enterprise/Organization security settings for real remediation | GitHub org/enterprise with admin rights | Repository visibility, SAML SSO, outside collaborators, IP allow lists, dependency/security settings. |
| MDA_Zendesk | 10 | Defender for Cloud Apps visibility plus Zendesk Suite/Enterprise security admin capability | Zendesk tenant with admin rights | MFA, SSO, IP restrictions, mobile access, session/security settings. |
| MDA_Atlassian | 7 | Defender for Cloud Apps visibility plus Atlassian Guard/organization admin features | Atlassian org with admin rights | SSO, 2SV, mobile policy, auth policy, session/password settings. |
| MDA_SF / Salesforce | 29 | Defender for Cloud Apps visibility plus Salesforce org with Setup/Metadata API access; higher Salesforce editions for full metadata/policy testing | Salesforce sandbox or dev org with admin rights | Session, password, CSP, clickjack, CSRF, identity, remote-site and security settings. |
| MDA_SNOW / ServiceNow | 22 | Defender for Cloud Apps visibility plus ServiceNow instance/admin/security hardening access | ServiceNow dev/admin instance | Security properties, plugins, MFA, session, SOAP/JSONv2, CSRF, ACL/high-security settings. |
| MDA_CitrixSF / ShareFile | 9 | Defender for Cloud Apps visibility plus ShareFile/Citrix admin security settings | ShareFile tenant with admin rights | MFA, password, lockout, timeout, SAML SSO controls. |
| MDA_Zoom | 6 | Defender for Cloud Apps visibility plus Zoom account admin/security settings | Zoom account with admin rights | 2FA, domain blocking, idle timeout, E2EE, meeting/password policy. |
| MDA_Okta | 4 | Defender for Cloud Apps visibility plus Okta admin API/policy access | Okta org with admin rights | MFA, session, password complexity/age/lockout policy. |
| MDA_DocuSign | 3 | Defender for Cloud Apps visibility plus DocuSign admin/security/API access | DocuSign admin tenant | Session and password policy checks. |
| MDA_Dropbox | 1 | Defender for Cloud Apps visibility plus Dropbox Business admin | Dropbox team admin tenant | Web session control. |
| MDA_Google | 1 | Defender for Cloud Apps visibility plus Google Workspace admin | Google Workspace admin tenant | 2-step verification evidence. |
| MDA_NetDocuments | 1 | Defender for Cloud Apps visibility plus NetDocuments admin | NetDocuments tenant | SSO/security center posture. |
| MDA_Workplace | 1 | Legacy Workplace context plus Microsoft-side evidence | Workplace tenant/export or migration evidence | Likely legacy/sunset posture only. |

## Practical Testing Order

| Order | Target | Why |
|---:|---|---|
| 1 | T0 existing tenant | Proves the pipeline, recommendation export, score comparison, and visualization without extra spend. |
| 2 | T1 SMB Microsoft 365 lab | Gives the fastest useful product demo: Intune, Entra P1, Exchange, Teams, SharePoint, and many endpoint controls. |
| 3 | T2 full Microsoft security lab | Unlocks the enterprise story: Entra P2 risk, MDE P2/TVM, Defender for Identity, Defender for Cloud Apps, and Purview advanced controls. |
| 4 | T3 hybrid identity lab | Required for the big Defender for Identity/AD CS/LDAP/NTLM block; this is where Securityzator can become seriously valuable. |
| 5 | T5 SaaS vendor lab | Add only vendors we care about first. Do not buy every SaaS test surface until the Microsoft core is producing repeatable value. |

## First-Pass Spend Conclusion

| Question | Answer |
|---|---|
| Can we test 0-cost/read-only behavior? | Yes: Secure Score export, tenant comparison, knowledgebase linkage, visualization, and read-only evidence where existing tenant access permits. |
| What is the best first paid/security lab? | A Business Premium-style tenant for SMB/MSP proof, then an E5-style tenant when we need Entra P2, MDE P2, Defender for Cloud Apps, Defender for Identity, and Purview advanced gates. |
| What is the biggest hidden cost? | Hybrid AD/AD CS lab time and SaaS vendor enterprise/security tiers, not the simple Microsoft 365 base tenant. |
| What should Securityzator show users? | `Control is remediable`, `Control is licensed but needs resource onboarding`, `Control is blocked by missing license`, or `Control is guided/manual because no safe remote write exists`. |

## Next Enrichment Pass

The next useful pass is not more prose. It is adding a normalized dependency tag to every control:

| Field | Example values |
|---|---|
| `licenseBucket` | `m365-core`, `entra-p1`, `entra-p2`, `intune-p1`, `mde-p2`, `mdo-p2`, `purview-e5`, `defender-for-identity`, `defender-for-cloud-apps`, `vendor-saas`, `none-readonly` |
| `resourceBucket` | `exchange-mailbox`, `teams-users`, `windows-device`, `macos-device`, `linux-device`, `ad-ds`, `ad-cs`, `entra-connect`, `saas-tenant`, `secure-boot-hardware` |
| `testMode` | `readonly`, `automatable`, `semi-automatable`, `guided`, `blocked` |
| `fallback` | `show upsell`, `show onboarding task`, `show manual runbook`, `hide remediation button`, `collect evidence only` |
