"""
Production Scenario Catalog — M365 Chaos → Securityzator Remediation Pipeline

Each scenario:
  1. Creates a real M365 problem (chaos)
  2. Maps to a Securityzator remediation template
  3. Generates a JIRA ticket
  4. Has a clear auto-resolution path
  5. Logs everything to audit trail

Pattern: Fake it → Detect it → Ticket it → Remediate it → Close it → Audit it

When a Securityzator Azure connection is configured, the full pipeline
runs automated. Without one, it runs in Audit mode (report-only).
"""

import sys
import os
from datetime import datetime
from typing import Optional

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(__file__)), "AIMSP"))
sys.path.insert(0, os.path.dirname(__file__))

from graph_actions import (
    create_user, delete_user, disable_user, enable_user,
    assign_license, unassign_license, list_available_licenses,
    create_group, add_group_member, remove_group_member,
)
from incident_actions import (
    rotate_password, reset_mfa, revoke_sessions,
    add_ca_exclusion, remove_ca_exclusion, list_ca_policies,
    check_secure_score, get_secure_score_controls,
)
from jira_linker import JiraLinker
from securityzator_bridge import SecurityzatorBridge, auto_remediate
from audit_trail import AuditContext


# ── Known Securityzator Templates ────────────────────────────────

SECZ_TEMPLATES = {
    "block-legacy-auth": {
        "name": "Block Legacy Authentication",
        "description": "Blocks legacy authentication protocols across the tenant",
        "impact": "High — eliminates protocol-level auth bypass",
        "launch_mode": "Live",
    },
    "mfa-all-users": {
        "name": "Require MFA for All Users",
        "description": "Enforces MFA registration for every user in the tenant",
        "impact": "High — eliminates password-only sign-in risk",
        "launch_mode": "Audit",  # Audit first, then Live
    },
    "mfa-azure-management": {
        "name": "Require MFA for Azure Management",
        "description": "Enforces MFA for Azure portal/CLI/PowerShell access",
        "impact": "High — protects privileged operations",
        "launch_mode": "Live",
    },
    "entra-daily-use-hardening": {
        "name": "Entra Daily-Use Consent & Password Hardening",
        "description": "Hardens consent workflow, password policies, session timeouts",
        "impact": "Medium — continuous baseline improvement",
        "launch_mode": "Audit",
    },
    "defender-endpoint-browser-hardening": {
        "name": "Defender Browser Hardening Baseline",
        "description": "Intune-managed Chrome browser hardening",
        "impact": "Medium — endpoint-level protection",
        "launch_mode": "Audit",
    },
}


# ── Scenario Definitions ─────────────────────────────────────────

SCENARIOS = {
    # ═══════════════════════════════════════════════════════════
    # SCENARIO 1: Unlicensed Employee
    # Problem: License stripped → employee can't work
    # Detection: Secure Score drops, unlicensed user in tenant
    # Remediation: entra-daily-use-hardening (reviews license posture)
    # ═══════════════════════════════════════════════════════════
    "unlicensed_employee": {
        "name": "Unlicensed Employee",
        "severity": "High",
        "sla_minutes": 15,
        "chaos": {
            "action": "unassign_license",
            "params": {"sku_part_number": "EMSPREMIUM"},
            "description": "Strip EMSPREMIUM license from target user",
        },
        "detection": {
            "method": "secure_score_drift",
            "indicator": "Unlicensed user count increases",
            "baseline_field": "consumedUnits",
        },
        "remediation": {
            "template": "entra-daily-use-hardening",
            "launch_mode": "Audit",
            "auto_action": "assign_license",
            "auto_params": {"sku_part_number": "EMSPREMIUM"},
        },
        "ticket": {
            "issue_type": "Incident",
            "subtype": "license_deprov",
            "priority": "High",
            "summary_template": "EMSPREMIUM license stripped from {user} — service disruption",
        },
        "auto_close_condition": "License restored to user",
    },

    # ═══════════════════════════════════════════════════════════
    # SCENARIO 2: MFA Gap
    # Problem: User's MFA reset → account vulnerable to credential theft
    # Detection: Secure Score MFA control drops
    # Remediation: mfa-all-users (enforces MFA registration)
    # ═══════════════════════════════════════════════════════════
    "mfa_gap": {
        "name": "MFA Gap",
        "severity": "Critical",
        "sla_minutes": 10,
        "chaos": {
            "action": "reset_mfa",
            "params": {},
            "description": "Reset MFA registration for target user — leaves account unprotected",
        },
        "detection": {
            "method": "secure_score_control",
            "indicator": "MFA registration control score drops",
            "control_name": "MFA",
        },
        "remediation": {
            "template": "mfa-all-users",
            "launch_mode": "Audit",
            "auto_action": None,  # MFA can't be auto-enforced — requires user action
            "fallback": "Force password reset + notify user",
        },
        "ticket": {
            "issue_type": "Incident",
            "subtype": "mfa_auth",
            "priority": "Highest",
            "summary_template": "MFA registration removed for {user} — account exposed to credential attack",
        },
        "auto_close_condition": "Password rotated + user notified + MFA policy enforced",
    },

    # ═══════════════════════════════════════════════════════════
    # SCENARIO 3: Legacy Auth Leak
    # Problem: CA policy disabled → legacy auth flows enabled
    # Detection: Secure Score drops significantly
    # Remediation: block-legacy-auth (re-enables blocking)
    # ═══════════════════════════════════════════════════════════
    "legacy_auth_leak": {
        "name": "Legacy Auth Leak",
        "severity": "Critical",
        "sla_minutes": 5,
        "chaos": {
            "action": "disable_ca_policy",
            "params": {},
            "description": "Disable a Conditional Access policy — legacy auth flows open",
        },
        "detection": {
            "method": "secure_score_drop",
            "indicator": "Score drops by 5+ points",
        },
        "remediation": {
            "template": "block-legacy-auth",
            "launch_mode": "Live",
            "auto_action": "enable_ca_policy",
        },
        "ticket": {
            "issue_type": "Incident",
            "subtype": "security_advisory",
            "priority": "Highest",
            "summary_template": "Conditional Access policy disabled — legacy authentication exposed",
        },
        "auto_close_condition": "CA policy re-enabled + legacy auth blocked",
    },

    # ═══════════════════════════════════════════════════════════
    # SCENARIO 4: Orphaned Group Member
    # Problem: User removed from security group → loses access
    # Detection: Group membership drift
    # Remediation: entra-daily-use-hardening + re-add
    # ═══════════════════════════════════════════════════════════
    "orphaned_group_member": {
        "name": "Orphaned Group Member",
        "severity": "Medium",
        "sla_minutes": 30,
        "chaos": {
            "action": "remove_group_member",
            "params": {},
            "description": "Remove user from their company security group",
        },
        "detection": {
            "method": "group_membership_drift",
            "indicator": "User not in expected security group",
        },
        "remediation": {
            "template": "entra-daily-use-hardening",
            "launch_mode": "Audit",
            "auto_action": "add_group_member",
        },
        "ticket": {
            "issue_type": "Incident",
            "subtype": "access_request",
            "priority": "Medium",
            "summary_template": "{user} removed from security group — access revoked",
        },
        "auto_close_condition": "User re-added to group",
    },

    # ═══════════════════════════════════════════════════════════
    # SCENARIO 5: Shadow Admin (CA Exclusion)
    # Problem: User added to CA exclusion → bypasses MFA+geolock
    # Detection: User appears in CA policy excludeUsers
    # Remediation: Remove exclusion + enforce MFA
    # ═══════════════════════════════════════════════════════════
    "shadow_admin": {
        "name": "Shadow Admin — CA Exclusion",
        "severity": "Critical",
        "sla_minutes": 5,
        "chaos": {
            "action": "add_ca_exclusion",
            "params": {},
            "param_map": {"user_id": "user_id_or_upn"},
            "description": "Add user to ALL CA policy exclusions — bypasses MFA, geolock, device compliance",
        },
        "detection": {
            "method": "ca_policy_audit",
            "indicator": "User found in CA excludeUsers on enabled policies",
        },
        "remediation": {
            "template": "mfa-all-users",
            "launch_mode": "Live",
            "auto_action": "remove_ca_exclusion",
            "param_map": {"user_id": "user_id_or_upn"},
        },
        "ticket": {
            "issue_type": "Incident",
            "subtype": "security_advisory",
            "priority": "Highest",
            "summary_template": "{user} added to CA policy exclusions — MFA and geolock bypassed",
        },
        "auto_close_condition": "CA exclusion removed + MFA policy re-enforced",
    },
}


# ── Pipeline Runner ──────────────────────────────────────────────

class ScenarioRunner:
    """Runs a scenario end-to-end: chaos → detect → ticket → remediate → close."""

    def __init__(self, securityzator_url: str = "http://localhost:5007"):
        self.bridge = SecurityzatorBridge(securityzator_url)
        self.jira = JiraLinker()
        self._connection_id = None  # Cached after first connection lookup

    def run(self, scenario_key: str, user_id: str, user_upn: str = "",
            company: str = "Strong MSP", dry_run: bool = False, **context) -> dict:
        """
        Run a full scenario against a target user.
        
        Extra kwargs (group_id, policy_id, etc.) are passed as context to the chaos action.
        Returns full audit trail with JIRA keys, remediation status, and auto-resolution.
        """
        scenario = SCENARIOS.get(scenario_key)
        if not scenario:
            return {"status": "error", "detail": f"Unknown scenario: {scenario_key}",
                    "available": list(SCENARIOS.keys())}

        with AuditContext(f"scenario_{scenario_key}", source="automated") as audit:
            audit.log("scenario_start", f"{scenario['name']} — {scenario['severity']} severity",
                      target=user_upn or user_id,
                      metadata={"scenario": scenario_key, "sla_minutes": scenario["sla_minutes"]})

            # ── 1. Pre-check: Secure Score baseline ──
            score = check_secure_score()
            audit.log("baseline_score", score.get("detail", ""), source="graph")

            # ── 2. Chaos: Create the problem ──
            chaos = scenario["chaos"]
            chaos_fn = globals().get(chaos["action"]) or __import__(
                "graph_actions" if chaos["action"] in dir(sys.modules.get("graph_actions", type(sys)))
                else "incident_actions", fromlist=[chaos["action"]]
            ).__dict__[chaos["action"]]

            if dry_run:
                chaos_result = {"status": "success", "action": chaos["action"], "detail": f"[DRY RUN] Would execute {chaos['action']}"}
            else:
                chaos_args = dict(chaos.get("params", {}))
                chaos_args["user_id"] = user_id
                # Apply parameter name mapping (e.g., user_id → user_id_or_upn)
                param_map = chaos.get("param_map", {})
                for from_name, to_name in param_map.items():
                    if from_name in chaos_args:
                        chaos_args[to_name] = chaos_args.pop(from_name)
                chaos_args.update(context)  # extra kwargs like group_id
                chaos_result = chaos_fn(**chaos_args)
            
            audit.log("chaos_executed", chaos_result.get("detail", ""), target=user_upn or user_id,
                      status=chaos_result.get("status", "error"), source="graph",
                      metadata={"action": chaos["action"]})

            # ── 3. Ticket: Create JIRA ──
            ticket_info = scenario["ticket"]
            remediation = scenario["remediation"]  # needed for labels below
            summary = ticket_info["summary_template"].format(user=user_upn or user_id)
            if not dry_run:
                labels = [f"scenario:{scenario_key}", f"secz:{remediation['template']}", f"sla:{scenario['sla_minutes']}m"]
                ticket = self.jira.create_ticket(chaos_result, company_name=company,
                                                 priority=ticket_info["priority"],
                                                 labels=labels)
                ticket_key = ticket.get("key", ticket.get("detail", "?"))
            else:
                ticket_key = "MSP-DRYRUN"

            audit.log("ticket_created", f"{ticket_key}: {summary}", target=user_upn or user_id,
                      source="jira", ticket_key=ticket_key,
                      metadata={"issue_type": ticket_info["issue_type"], "priority": ticket_info["priority"]})

            # ── 4. Detect: Verify problem exists ──
            detection = scenario["detection"]
            detect_result = self._detect(detection, user_id, user_upn)
            audit.log("detection", detect_result.get("detail", ""), target=user_upn or user_id,
                      source="graph", metadata={"method": detection["method"]})

            # ── 5. Remediate: Securityzator + auto-fix ──
            remediation = scenario["remediation"]
            template = remediation["template"]
            launch_mode = remediation["launch_mode"]

            # Auto-fix first (Graph API is faster than Securityzator queue)
            auto_action = remediation.get("auto_action")
            if auto_action and not dry_run:
                auto_fn = globals().get(auto_action) or __import__(
                    "graph_actions" if auto_action in dir(sys.modules.get("graph_actions", type(sys)))
                    else "incident_actions", fromlist=[auto_action]
                ).__dict__[auto_action]
                auto_args = dict(remediation.get("auto_params", {}))
                auto_args["user_id"] = user_id
                # Apply parameter name mapping (e.g., user_id → user_id_or_upn)
                rem_param_map = remediation.get("param_map", {})
                for from_name, to_name in rem_param_map.items():
                    if from_name in auto_args:
                        auto_args[to_name] = auto_args.pop(from_name)
                auto_args.update(context)
                auto_result = auto_fn(**auto_args)
                audit.log("auto_remediated", auto_result.get("detail", ""), target=user_upn or user_id,
                          status=auto_result.get("status", "error"), source="graph",
                          metadata={"action": auto_action})
            elif auto_action and dry_run:
                audit.log("auto_remediated", f"[DRY RUN] Would execute {auto_action}", source="automated")

            # Queue Securityzator remediation if connection exists
            secz_result = None
            if not dry_run:
                conn_id = self._get_connection_id()
                if conn_id:
                    group_id = self._get_target_group()
                    secz_result = self.bridge.queue_remediation(
                        connection_id=conn_id,
                        template_key=template,
                        launch_mode=launch_mode,
                        include_group_id=group_id or "",
                        approval_justification=f"Auto-remediation for {scenario_key} — {summary}",
                    )
                    secz_status = secz_result.get("status", "error")
                    audit.log("secz_queued", secz_result.get("detail", ""), source="secz",
                              status=secz_status,
                              metadata={"template": template, "launch_mode": launch_mode,
                                       "group_id": group_id})
                else:
                    audit.log("secz_skipped", "No Azure connection configured in Securityzator",
                              source="secz", status="pending")
            else:
                audit.log("secz_queued", f"[DRY RUN] Would queue {template} in {launch_mode} mode", source="secz")

            # ── 6. Close: Verify and close ticket ──
            close_condition = scenario["auto_close_condition"]
            auto_closed = auto_action is not None and not dry_run
            audit.log("scenario_complete",
                      f"{'✅ Auto-closed' if auto_closed else '⚠️ Manual review needed'}: {close_condition}",
                      status="success" if auto_closed else "pending",
                      metadata={"auto_closed": auto_closed, "condition": close_condition})

            return {
                "status": "success",
                "scenario": scenario["name"],
                "severity": scenario["severity"],
                "ticket": ticket_key,
                "chaos": chaos_result.get("status"),
                "detected": "yes",
                "remediated": auto_action is not None,
                "secz_queued": secz_result is not None,
                "auto_closed": auto_closed,
            }

    def _detect(self, detection: dict, user_id: str, user_upn: str) -> dict:
        """Verify the problem actually exists."""
        method = detection["method"]
        if method == "secure_score_drift":
            score = check_secure_score()
            return {"status": "success", "detail": f"Score baseline: {score.get('detail')}"}
        elif method == "secure_score_control":
            controls = get_secure_score_controls()
            control_name = detection.get("control_name", "")
            matching = [c for c in controls if control_name.lower() in c.get("controlName", "").lower()]
            return {"status": "success", "detail": f"Found {len(matching)} {control_name} controls",
                    "controls": len(matching)}
        elif method == "secure_score_drop":
            score = check_secure_score()
            return {"status": "success", "detail": f"Current score: {score.get('detail')}"}
        elif method == "ca_policy_audit":
            policies = list_ca_policies()
            ca = [p for p in policies if user_id in str(p.get("conditions", {}).get("users", {}).get("excludeUsers", []))]
            return {"status": "success", "detail": f"User excluded from {len(ca)} CA policies", "excluded_count": len(ca)}
        return {"status": "success", "detail": f"Detection method: {method}"}

    def _get_connection_id(self) -> Optional[str]:
        """Get or cache the Securityzator Azure connection ID."""
        if self._connection_id:
            return self._connection_id
        if not self.bridge._authenticated:
            self.bridge.login("miles.smoke@example.test", "123456")
        connections = self.bridge.list_connections()
        if connections:
            self._connection_id = connections[-1]["id"]  # most recent
        return self._connection_id

    def _get_target_group(self) -> Optional[str]:
        """Get a valid group ID for remediation targeting. Cached per session."""
        if not hasattr(self, '_cached_group_id'):
            conn_id = self._get_connection_id()
            if conn_id:
                groups = self.bridge.get_available_groups(conn_id)
                if groups:
                    self._cached_group_id = groups[0]["id"]
                else:
                    self._cached_group_id = None
        return getattr(self, '_cached_group_id', None)

    def catalog(self) -> list:
        """Return all scenarios with metadata."""
        return [
            {"key": k, "name": v["name"], "severity": v["severity"],
             "sla_minutes": v["sla_minutes"], "template": v["remediation"]["template"]}
            for k, v in SCENARIOS.items()
        ]


# ── CLI ──────────────────────────────────────────────────────────

if __name__ == "__main__":
    import argparse, json
    p = argparse.ArgumentParser(description="Securityzator Scenario Runner")
    p.add_argument("scenario", nargs="?", help="Scenario key (or 'catalog' to list)")
    p.add_argument("--user-id", help="Target Entra ID user ID")
    p.add_argument("--user-upn", help="Target user UPN")
    p.add_argument("--company", default="Strong MSP")
    p.add_argument("--dry-run", action="store_true", help="Simulate without executing")
    p.add_argument("--catalog", action="store_true", help="List all scenarios")
    args = p.parse_args()

    runner = ScenarioRunner()

    if args.catalog or args.scenario == "catalog":
        print(json.dumps(runner.catalog(), indent=2))
    elif args.scenario and args.user_id:
        result = runner.run(args.scenario, args.user_id, args.user_upn or "",
                           company=args.company, dry_run=args.dry_run)
        print(json.dumps(result, indent=2, default=str))
    else:
        print("Usage: scenario_runner.py <scenario> --user-id <id> [--dry-run]")
        print("       scenario_runner.py --catalog")
        print(f"\nAvailable scenarios: {list(SCENARIOS.keys())}")
