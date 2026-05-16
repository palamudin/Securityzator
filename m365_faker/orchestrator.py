"""
M365 Ticket Faker Orchestrator — ties graph actions, incident actions,
JIRA linking, and Securityzator remediation into testable scenarios.

Each scenario:
1. Creates a real M365 incident
2. Creates a linked JIRA ticket
3. (Optionally) triggers Securityzator remediation
4. Returns a full audit trail

Usage:
    faker = FakerOrchestrator()
    
    # Run a scenario
    result = faker.run_scenario("password_breach", user_id="...")
    
    # Run a full test sequence
    results = faker.test_suite()
"""
import json
import sys
import os
from datetime import datetime
from typing import Optional

# Ensure we can find our sibling modules
sys.path.insert(0, os.path.dirname(__file__))

from graph_actions import (
    create_user, delete_user, disable_user, enable_user,
    create_group, add_group_member, remove_group_member,
    assign_license, unassign_license, list_available_licenses,
)
from incident_actions import (
    rotate_password, reset_mfa, revoke_sessions,
    add_ca_exclusion, remove_ca_exclusion, list_ca_policies,
    check_secure_score, get_secure_score_controls,
)
from jira_linker import JiraLinker
from securityzator_bridge import SecurityzatorBridge, auto_remediate


class FakerOrchestrator:
    """
    Main orchestrator for the M365 Ticket Faker.
    
    Runs scenarios that create real M365 problems + JIRA tickets,
    then optionally triggers Securityzator remediation.
    """

    def __init__(
        self,
        securityzator_url: str = "http://localhost:5007",
        company_name: str = "Strong MSP",
        auto_jira: bool = True,
        auto_remediate: bool = False,
    ):
        self.company_name = company_name
        self.auto_jira = auto_jira
        self.auto_remediate = auto_remediate
        self.bridge = SecurityzatorBridge(securityzator_url)
        self.jira = JiraLinker() if auto_jira else None
        self._audit_log = []
        self._connection_id = None  # Cached Securityzator connection ID

    def _log(self, event: str, detail: str, data: dict = None):
        entry = {
            "timestamp": datetime.now().isoformat(),
            "event": event,
            "detail": detail,
        }
        if data:
            entry["data"] = data
        self._audit_log.append(entry)
        print(f"  [{event.upper()}] {detail}")

    # ── Scenarios ────────────────────────────────────────────────

    def run_scenario(self, scenario: str, **kwargs) -> dict:
        """Run a named scenario. Returns the full audit trail."""
        self._audit_log = []

        scenarios = {
            "create_user_and_license": self._scenario_create_user,
            "password_breach": self._scenario_password_breach,
            "license_deprovision": self._scenario_license_deprovision,
            "group_access_revoke": self._scenario_group_access_revoke,
            "ca_user_exclusion": self._scenario_ca_user_exclusion,
            "full_breach_simulation": self._scenario_full_breach,
        }

        handler = scenarios.get(scenario)
        if not handler:
            return {"status": "error", "detail": f"Unknown scenario: {scenario}", "available": list(scenarios.keys())}

        try:
            result = handler(**kwargs)
            result["audit_log"] = self._audit_log
            return result
        except Exception as e:
            self._log("error", str(e))
            return {"status": "error", "detail": str(e), "audit_log": self._audit_log}

    def test_suite(self) -> dict:
        """Run all scenarios as a test suite (non-destructive where possible)."""
        print("=" * 60)
        print("  M365 Ticket Faker — Test Suite")
        print("=" * 60)

        results = {}

        # 1. Check connectivity
        print("\n── 1. Connectivity Check ──")
        health = self.bridge.health_check()
        score = check_secure_score()
        self._log("health", f"Securityzator: {health.get('status')}, Score: {score.get('detail')}")
        results["connectivity"] = {"health": health, "secure_score": score}

        # 2. Create a test user
        print("\n── 2. Create Test User ──")
        display_name = f"FakerTest {datetime.now().strftime('%H%M')}"
        upn = f"fakertest{datetime.now().strftime('%H%M')}@ai-msp.com"
        user_result = create_user(display_name, upn, company_name=self.company_name)
        self._log("create_user", user_result.get("detail"))
        results["create_user"] = user_result

        if user_result["status"] == "success" and self.auto_jira:
            ticket = self.jira.create_ticket(user_result, self.company_name)
            self._log("jira_ticket", ticket.get("detail"))
            results["jira_ticket"] = ticket

        # 3. Assign license to test user
        if user_result["status"] == "success":
            print("\n── 3. Assign License ──")
            user_id = user_result["user_id"]
            licenses = list_available_licenses()
            if licenses:
                first_sku = licenses[0]["sku"]
                lic_result = assign_license(user_id, first_sku)
                self._log("assign_license", lic_result.get("detail"))
                results["assign_license"] = lic_result

        # 4. Create a test group
        print("\n── 4. Create Test Group ──")
        group_result = create_group(f"FakerTest-Group-{datetime.now().strftime('%H%M')}")
        self._log("create_group", group_result.get("detail"))
        results["create_group"] = group_result

        # 5. Add user to group
        if user_result["status"] == "success" and group_result["status"] == "success":
            print("\n── 5. Add User to Group ──")
            add_result = add_group_member(group_result["group_id"], user_result["user_id"])
            self._log("add_member", add_result.get("detail"))
            results["add_to_group"] = add_result

        # 6. Check CA policies
        print("\n── 6. Conditional Access Policies ──")
        policies = list_ca_policies()
        self._log("ca_policies", f"Found {len(policies)} policies")
        results["ca_policies"] = policies

        # 7. Check Secure Score drift
        print("\n── 7. Secure Score Drift ──")
        controls = get_secure_score_controls()
        self._log("drift", f"Found {len(controls)} controls with drift")
        results["drift"] = controls

        # 8. Clean up test artifacts (optional — comment out to leave for inspection)
        print("\n── 8. Cleanup ──")
        cleanup = {}
        if group_result["status"] == "success" and user_result["status"] == "success":
            cleanup["remove_member"] = remove_group_member(group_result["group_id"], user_result["user_id"])
        # Don't delete user/group by default — leave for Securityzator to remediate

        results["cleanup"] = cleanup
        print("\n" + "=" * 60)
        print(f"  Suite complete. {len(results)} checks run.")
        print("=" * 60)

        return results

    # ── Scenario Implementations ─────────────────────────────────

    def _scenario_create_user(self, display_name: str = None, upn: str = None, **kwargs) -> dict:
        """Scenario: Provision a new user and create a JIRA ticket."""
        if not display_name:
            display_name = f"ScenarioUser {datetime.now().strftime('%H%M')}"
        if not upn:
            upn = f"scenario{datetime.now().strftime('%H%M')}@ai-msp.com"

        user_result = create_user(display_name, upn, company_name=self.company_name)
        self._log("scenario", f"Create user: {user_result.get('detail')}")

        result = {"user": user_result}

        if user_result["status"] == "success" and self.auto_jira:
            ticket = self.jira.create_ticket(user_result, self.company_name)
            self._log("jira", ticket.get("detail"))
            result["ticket"] = ticket

            if self.auto_remediate:
                remediation = auto_remediate(self.bridge, user_result, self._get_connection_id())
                result["remediation"] = remediation

        return result

    def _scenario_password_breach(self, user_id: str, **kwargs) -> dict:
        """Scenario: Simulate a password breach and trigger remediation."""
        pwd_result = rotate_password(user_id)
        self._log("breach", pwd_result.get("detail"))

        result = {"password": pwd_result}

        if pwd_result["status"] == "success" and self.auto_jira:
            ticket = self.jira.create_ticket(pwd_result, self.company_name, priority="High")
            self._log("jira", ticket.get("detail"))
            result["ticket"] = ticket

        return result

    def _scenario_license_deprovision(self, user_id: str, sku: str = None, **kwargs) -> dict:
        """Scenario: Remove a license from a user."""
        if not sku:
            licenses = list_available_licenses()
            # Pick first E5-like license
            for l in licenses:
                if "PREMIUM" in l["sku"] or "E5" in l["sku"] or "E3" in l["sku"]:
                    sku = l["sku"]
                    break
            if not sku and licenses:
                sku = licenses[0]["sku"]

        lic_result = unassign_license(user_id, sku)
        self._log("license", lic_result.get("detail"))

        result = {"license": lic_result}

        if lic_result["status"] == "success" and self.auto_jira:
            ticket = self.jira.create_ticket(lic_result, self.company_name, priority="Medium")
            self._log("jira", ticket.get("detail"))
            result["ticket"] = ticket

        return result

    def _scenario_group_access_revoke(self, group_id: str, user_id: str, **kwargs) -> dict:
        """Scenario: Remove a user from a group (access revocation)."""
        rm_result = remove_group_member(group_id, user_id)
        self._log("breach", rm_result.get("detail"))

        result = {"group": rm_result}

        if rm_result["status"] == "success" and self.auto_jira:
            ticket = self.jira.create_ticket(rm_result, self.company_name, priority="High")
            self._log("jira", ticket.get("detail"))
            result["ticket"] = ticket

        return result

    def _scenario_ca_user_exclusion(self, user_id: str, **kwargs) -> dict:
        """Scenario: Add user to CA exclusion list across all enabled policies — bypasses geolock."""
        ca_result = add_ca_exclusion(user_id)
        self._log("breach", ca_result.get("summary", ca_result.get("detail", "")))

        result = {"ca_exclusion": ca_result}

        if ca_result["status"] == "success" and self.auto_jira:
            # Strip detailed lists for the JIRA summary
            jira_result = {
                "status": "success",
                "action": "add_ca_exclusion",
                "user_id": ca_result.get("user_id"),
                "user_display": ca_result.get("user_display"),
                "detail": ca_result.get("detail"),
                "summary": ca_result.get("summary"),
                "remediation_hint": "remove_ca_exclusion",
            }
            ticket = self.jira.create_ticket(jira_result, self.company_name, priority="Highest")
            self._log("jira", ticket.get("detail"))
            result["ticket"] = ticket

        return result

    def _scenario_full_breach(self, user_id: str, group_id: str = None, **kwargs) -> dict:
        """Scenario: Full breach simulation — password, license, and group."""
        results = {}

        # 1. Rotate password
        pwd = rotate_password(user_id)
        self._log("breach", pwd.get("detail"))
        results["password"] = pwd
        if self.auto_jira:
            results["pwd_ticket"] = self.jira.create_ticket(pwd, self.company_name, priority="High")

        # 2. Remove license
        licenses = list_available_licenses()
        if licenses:
            sku = licenses[0]["sku"]
            lic = unassign_license(user_id, sku)
            self._log("breach", lic.get("detail"))
            results["license"] = lic
            if self.auto_jira:
                results["lic_ticket"] = self.jira.create_ticket(lic, self.company_name, priority="High")

        # 3. Remove from group
        if group_id:
            grp = remove_group_member(group_id, user_id)
            self._log("breach", grp.get("detail"))
            results["group"] = grp
            if self.auto_jira:
                results["grp_ticket"] = self.jira.create_ticket(grp, self.company_name, priority="High")

        # 4. Check resulting drift
        score = check_secure_score()
        self._log("drift", score.get("detail"))
        results["score"] = score

        return results

    # ── Helpers ──────────────────────────────────────────────────

    def _get_connection_id(self) -> Optional[str]:
        """Get or cache the first available Securityzator connection ID."""
        if self._connection_id:
            return self._connection_id

        connections = self.bridge.list_connections()
        if connections:
            self._connection_id = connections[0].get("id")
        return self._connection_id

    def authenticate(self, email: str, password: str) -> bool:
        """Authenticate with Securityzator for remediation operations."""
        return self.bridge.login(email, password)

    def get_audit_log(self) -> list:
        return self._audit_log


# ── CLI ─────────────────────────────────────────────────────────

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="M365 Ticket Faker")
    parser.add_argument("scenario", nargs="?", default="test_suite",
                       choices=["test_suite", "create_user", "password_breach",
                                "license_deprovision", "group_access_revoke",
                                "ca_user_exclusion", "full_breach_simulation"],
                       help="Scenario to run")
    parser.add_argument("--user-id", help="User ID or UPN for breach/exclusion scenarios")
    parser.add_argument("--group-id", help="Group ID for group scenarios")
    parser.add_argument("--policy-id", help="CA policy ID")
    parser.add_argument("--sku", help="License SKU to target")
    parser.add_argument("--display-name", help="Display name for new user")
    parser.add_argument("--upn", help="UserPrincipalName for new user")
    parser.add_argument("--company", default="Strong MSP", help="Company name for JIRA tickets")
    parser.add_argument("--no-jira", action="store_true", help="Skip JIRA ticket creation")
    parser.add_argument("--securityzator-url", default="http://localhost:5007",
                       help="Securityzator URL")

    args = parser.parse_args()

    faker = FakerOrchestrator(
        securityzator_url=args.securityzator_url,
        company_name=args.company,
        auto_jira=not args.no_jira,
    )

    kwargs = {}
    if args.user_id:
        kwargs["user_id"] = args.user_id
    if args.group_id:
        kwargs["group_id"] = args.group_id
    if args.policy_id:
        kwargs["policy_id"] = args.policy_id
    if args.sku:
        kwargs["sku"] = args.sku
    if args.display_name:
        kwargs["display_name"] = args.display_name
    if args.upn:
        kwargs["upn"] = args.upn

    if args.scenario == "test_suite":
        result = faker.test_suite()
    else:
        result = faker.run_scenario(args.scenario, **kwargs)

    print("\n" + json.dumps(result, indent=2, default=str))
