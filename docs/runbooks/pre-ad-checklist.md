# Pre-AD Checklist

Last reviewed: `2026-04-23`

## Goal

Bring up the first AD / hybrid lane in a way that unlocks Securityzator's next control families without creating avoidable hybrid mess.

This checklist is intentionally biased toward:

- one clean forest
- one clean sync path
- password hash sync enabled
- Defender for Identity onboarded early
- cloud break-glass preserved
- minimal "clever" hybrid design

## What AD unlocks for Securityzator

The next meaningful families behind the current cloud-only lane are:

- `defender-identity-foundation` = `6`
- `defender-identity-sensor-coverage` = `2`
- `active-directory-privileged-account-hygiene` = `17`
- `active-directory-domain-security-hardening` = `17`
- `active-directory-certificate-services-hardening` = `10`

That is `52` directly mapped controls, plus the hybrid/manual items already surfaced in Entra hygiene:

- `PasswordHashSync`
- on-prem password protection
- custom banned passwords
- separate admin identities

So this is the point where the next coverage jump becomes hybrid and server-backed instead of pure tenant API work.

## Scope assumptions

This runbook assumes:

- one new AD forest or one small lab forest
- at least one writable domain controller
- Microsoft Entra tenant already exists
- a cloud-only emergency admin account is preserved
- Securityzator stays external to the domain at first

If any of these are false, pause and simplify before proceeding.

## Phase 1. Forest bring-up

### 1. Keep the first domain boring

- use a clean, supportable forest/domain name
- decide the production user UPN suffix early so synced identities do not need a painful rename later
- keep the first OU structure minimal
- do not introduce AD FS, AD CS, or multiple forests on day one unless you already need them

### 2. Build the first domain controller cleanly

- static IP
- correct DNS settings
- correct time sync
- current Windows Server patch level
- confirmed backup method
- no mystery hardening GPOs applied before baseline validation

### 3. Protect recovery before complexity

- keep at least one cloud-only Global Administrator outside the hybrid dependency chain
- record the Directory Services Restore Mode password
- document who owns:
  - domain admin
  - enterprise admin
  - schema admin
  - break-glass cloud admin

## Phase 2. Hybrid identity prerequisites

### 1. Choose the sync model deliberately

For Securityzator's immediate score and control goals, the first-class target is:

- Microsoft Entra Connect Sync
- password hash sync enabled

Why:

- Microsoft's Secure Score item is explicitly about password hash sync
- leaked credential detection depends on PHS
- the current Securityzator hybrid/readiness posture is built around validating that path, not a custom federation story

Avoid for the first run:

- federation-first design
- "we'll decide auth later"
- unsupported/manual Connect surgery

### 2. Keep sync scope tiny first

- start with a pilot OU or small synced user set
- include one normal test user
- include one admin-pattern test account if needed
- avoid syncing every object in the forest on the first pass

### 3. Align naming and account patterns

- make the primary UPN suffix routable and match the tenant sign-in pattern you actually want
- keep admin accounts separate from daily-use accounts
- do not let the first synced accounts become your only recovery path

### 4. Make password hash sync non-negotiable for the first pass

- verify PHS is enabled during Entra Connect setup
- verify a password change on-prem flows to Entra
- verify the synced object actually exists in Entra before calling the lane healthy

## Phase 3. Defender for Identity runway

### 1. Confirm licensing and RBAC first

- Defender for Identity licensing present
- Security / tenant admins know who owns the rollout
- access to Defender XDR / Identities settings is ready before sensor work starts

### 2. Install sensors on the right servers

For the first useful lane, plan for:

- all writable domain controllers
- any read-only DCs if present
- each AD FS server if AD FS exists later
- each AD CS server if AD CS exists later
- each active and staging Entra Connect server if present

Do not call Defender for Identity "deployed" if it only exists on one random server.

### 3. Treat Defender for Endpoint as a prerequisite, not an afterthought

Current Microsoft guidance for Defender for Identity sensor v3.x expects the server to have Defender for Endpoint deployed. Build that expectation into the server prep instead of discovering it mid-install.

### 4. Get time, connectivity, and exclusions right

- outbound connectivity to required Microsoft endpoints
- time sync healthy on DCs
- no proxy/path weirdness that breaks sensor cloud reachability
- antivirus / EDR exclusions reviewed only where Microsoft requires them

## Phase 4. AD CS and hybrid extras

Only open this lane if the environment actually has it.

### If AD CS exists

- inventory every CA first
- identify whether any CA is offline
- record which templates are high-risk before trying to remediate anything
- onboard Defender for Identity sensors to the online AD CS servers in scope

### If Entra Connect has staging or HA

- install Defender for Identity sensor on active and staging servers
- record which server is active before making any sync changes

## Phase 5. Securityzator readiness checks after AD exists

Do these in order:

1. Confirm Entra Connect sync is healthy.
2. Confirm password hash sync is actually working.
3. Confirm synced users appear where expected in Entra.
4. Confirm Defender for Identity licensing and portal access.
5. Install sensors on all intended DCs.
6. Wait for Defender for Identity sensor health to settle.
7. Re-run the Entra identity-hygiene assessment.
8. Re-test the AD / Defender for Identity families in Securityzator.

## Securityzator-first execution order once AD is alive

Recommended first sweep:

1. `entra-identity-hygiene-baseline`
   - use it to re-check `PasswordHashSync` and the hybrid/manual items
2. `defender-identity-foundation`
   - prove onboarding and deployment scope
3. `defender-identity-sensor-coverage`
   - prove sensors are where they should be
4. `active-directory-privileged-account-hygiene`
   - start with findings, not risky write actions
5. `active-directory-domain-security-hardening`
   - then move into delegation/protocol/domain posture
6. `active-directory-certificate-services-hardening`
   - only when AD CS inventory is real and rollback thinking exists

## Stop signs

Pause if any of these are true:

- no cloud-only break-glass admin exists
- PHS is still off or unknown
- Entra Connect sync scope is not understood
- only some DCs have sensors
- time sync or DNS is flaky
- someone wants to add AD FS just because "enterprise"
- AD CS exists but no one can explain which CAs and templates are active

## "Ready for Securityzator AD lane" definition

The environment is ready when:

- the domain is stable
- Entra Connect is installed and understood
- password hash sync is enabled and verified
- at least one test password change has proven sync
- Defender for Identity licensing is confirmed
- sensors are installed on the intended DC scope
- cloud break-glass remains independent
- admin identities are separated enough that we do not brick recovery by testing controls

## Source anchors

Official Microsoft documentation used for this checklist:

- Password hash sync with Entra Connect:
  - https://learn.microsoft.com/en-us/azure/active-directory/hybrid/how-to-connect-password-hash-synchronization
- What password hash sync is and why it matters:
  - https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/whatis-phs
- Defender for Identity sensor v3.x prerequisites:
  - https://learn.microsoft.com/en-us/defender-for-identity/deploy/prerequisites-sensor-version-3
- Defender for Identity deployment overview:
  - https://learn.microsoft.com/en-us/defender-for-identity/deploy/quick-installation-guide
- Defender for Identity sensor installation:
  - https://learn.microsoft.com/en-us/defender-for-identity/install-sensor
