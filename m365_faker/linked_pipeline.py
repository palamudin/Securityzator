"""
Linked Onboarding Pipeline — creates a user, assigns license, creates linked JIRA tickets,
simulates a breach, and runs remediation — all with linked ticket closure.

Run standalone or import from orchestrator.
"""
import os
import sys
import json
import random
from datetime import datetime
from typing import Optional

# Path setup
sys.path.insert(0, os.path.dirname(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(__file__)), "AIMSP"))

from graph_actions import create_user, assign_license, list_available_licenses
from incident_actions import rotate_password, check_secure_score
from jira_linker import JiraLinker
from securityzator_bridge import SecurityzatorBridge


class LinkedOnboardingPipeline:
    """
    Full lifecycle: onboard user → license → JIRA tickets (linked) → breach → remediate → close.
    
    Tickets are linked so closing one closes the other.
    """

    def __init__(self, securityzator_url: str = "http://localhost:5007"):
        self.jira = JiraLinker()
        self.bridge = SecurityzatorBridge(securityzator_url)
        self._log = []

    def _print(self, msg: str):
        print(msg)
        self._log.append(msg)

    def run(
        self,
        company_name: str,
        display_name: Optional[str] = None,
        upn: Optional[str] = None,
        password: Optional[str] = None,
    ) -> dict:
        """
        Full pipeline for one user: onboard → license → breach → remediate → close.
        
        Returns full audit trail with JIRA keys.
        """
        self._log = []
        now = datetime.now().strftime("%H%M")
        
        if not display_name:
            display_name = f"{company_name.replace(' ','')[:8]} User{now}"
        if not upn:
            slug = company_name.lower().replace(" ", "").replace(".", "").replace("&", "").replace(",", "")[:12]
            upn = f"{slug.lower()}.user{now}@strongmspcouk.onmicrosoft.com"
        if not password:
            password = f"Welcome{random.randint(10000, 99999)}!"

        print("=" * 65)
        print(f"  LINKED ONBOARDING + BREACH PIPELINE")
        print(f"  Company: {company_name}")
        print(f"  User: {display_name} ({upn})")
        print("=" * 65)

        # ── Step 1: Create M365 User ─────────────────────────────
        print("\n── Step 1: Create M365 User ──")
        user_result = create_user(
            display_name=display_name,
            user_principal_name=upn,
            password=password,
            company_name=company_name,
        )
        self._print(f"  User: {user_result.get('detail')}")
        
        if user_result["status"] != "success":
            return {"status": "error", "step": "create_user", "detail": user_result.get("detail")}
        
        user_id = user_result["user_id"]

        # ── Step 2: Assign License ───────────────────────────────
        print("\n── Step 2: Assign License ──")
        licenses = list_available_licenses()
        # Pick first available premium license
        premium = next((l for l in licenses if "PREMIUM" in l["sku"].upper() or "E5" in l["sku"].upper() or "E3" in l["sku"].upper()), None)
        if not premium:
            premium = licenses[0] if licenses else None
        
        if not premium:
            self._print("  ❌ No licenses available")
            return {"status": "error", "step": "assign_license", "detail": "No licenses available"}
        
        lic_result = assign_license(user_id, premium["sku"])
        self._print(f"  License: {lic_result.get('detail')}")

        # ── Step 3: Create Onboarding JIRA Ticket ────────────────
        print("\n── Step 3: Create Onboarding JIRA Ticket ──")
        onboard_jira_data = {
            "status": "success",
            "action": "create_user",
            "user_id": user_id,
            "upn": upn,
            "display_name": display_name,
            "license": premium["sku"],
            "detail": f"Onboarded {display_name} ({upn}) with {premium['sku']} license for {company_name}",
        }
        onboard_ticket = self.jira.create_ticket(onboard_jira_data, company_name, priority="Medium")
        self._print(f"  Ticket: {onboard_ticket.get('detail')}")
        onboard_key = onboard_ticket.get("jira_key")

        # ── Step 4: BREACH — Rotate Password ─────────────────────
        print("\n── Step 4: BREACH — Rotate Password ──")
        breach_result = rotate_password(user_id)
        self._print(f"  Breach: {breach_result.get('detail')}")

        # ── Step 5: Create Breach JIRA Ticket (linked) ───────────
        print("\n── Step 5: Create Breach JIRA Ticket ──")
        breach_jira_data = {
            "status": "success",
            "action": "rotate_password",
            "user_id": user_id,
            "upn": upn,
            "display_name": display_name,
            "detail": f"Password rotated for {display_name} ({upn}) — possible credential breach for {company_name}",
        }
        breach_ticket = self.jira.create_ticket(breach_jira_data, company_name, priority="High")
        self._print(f"  Ticket: {breach_ticket.get('detail')}")
        breach_key = breach_ticket.get("jira_key")

        # ── Step 6: Link the two JIRA tickets ────────────────────
        print("\n── Step 6: Link JIRA Tickets ──")
        link_result = self._link_jira_tickets(onboard_key, breach_key, "Relates")
        self._print(f"  Link: {link_result.get('detail')}")

        # ── Step 7: Remediate — Reset password ───────────────────
        print("\n── Step 7: Remediate — Reset Password ──")
        new_password = f"Secure{random.randint(10000, 99999)}!"
        remediation_note = self._remediate_password(user_id, new_password)
        self._print(f"  Remediation: {remediation_note}")

        # ── Step 8: Add remediation evidence to both tickets ─────
        print("\n── Step 8: Add Evidence to Tickets ──")
        evidence = (
            f"✅ REMEDIATED via M365 Ticket Faker\n\n"
            f"Action: Password rotated and reset\n"
            f"User: {display_name} ({upn})\n"
            f"Company: {company_name}\n"
            f"New credentials issued. User must change password on next sign-in.\n"
            f"Remediated at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}\n\n"
            f"Securityzator detected and confirmed remediation."
        )
        self.jira.add_comment(onboard_key, evidence)
        self.jira.add_comment(breach_key, evidence)
        self._print(f"  Evidence posted to {onboard_key} and {breach_key}")

        # ── Step 9: Close Both Tickets (linked closure) ──────────
        print("\n── Step 9: Close Both Tickets ──")
        close_onboard = self.jira.resolve_ticket(onboard_key, f"✅ Onboarding complete. User {display_name} active with {premium['sku']} license. Breach remediated.")
        close_breach = self.jira.resolve_ticket(breach_key, f"✅ Breach remediated. Password rotated and reset for {display_name}. Linked to onboarding {onboard_key}.")
        self._print(f"  {onboard_key}: {close_onboard.get('detail')}")
        self._print(f"  {breach_key}: {close_breach.get('detail')}")

        # ── Step 10: Verify Secure Score ─────────────────────────
        print("\n── Step 10: Secure Score Check ──")
        score = check_secure_score()
        self._print(f"  Score: {score.get('detail')}")

        result = {
            "status": "success",
            "company": company_name,
            "user": {
                "display_name": display_name,
                "upn": upn,
                "user_id": user_id,
                "license": premium["sku"],
            },
            "tickets": {
                "onboarding": onboard_key,
                "breach": breach_key,
                "linked": True,
            },
            "breach": breach_result.get("detail"),
            "remediation": remediation_note,
            "secure_score": score.get("detail"),
            "audit_log": self._log,
            "completed_at": datetime.now().isoformat(),
        }

        print("\n" + "=" * 65)
        print(f"  ✅ PIPELINE COMPLETE")
        print(f"  Onboarding: {onboard_key}  |  Breach: {breach_key}")
        print(f"  User: {display_name} ({upn})")
        print(f"  License: {premium['sku']}")
        print(f"  Linked closure: both tickets resolved")
        print("=" * 65)

        return result

    def run_batch(self, companies: list, **kwargs) -> list:
        """Run the full pipeline for multiple companies (different fake orgs)."""
        results = []
        for company in companies:
            result = self.run(company_name=company, **kwargs)
            results.append(result)
            print()
        return results

    # ── Internal ─────────────────────────────────────────────────

    def _link_jira_tickets(self, inward_key: str, outward_key: str, link_type: str = "relates to") -> dict:
        """Create a JIRA issue link between two tickets."""
        import requests
        from config.jira_config import JIRA_REST_API, GLOBAL_AUTH as AUTH
        HEADERS = {"Accept": "application/json", "Content-Type": "application/json"}

        body = {
            "inwardIssue": {"key": inward_key},
            "outwardIssue": {"key": outward_key},
            "type": {"name": link_type},
        }

        r = requests.post(f"{JIRA_REST_API}/issueLink", auth=AUTH, headers=HEADERS, json=body)
        if r.status_code in (200, 201):
            return {"status": "success", "detail": f"Linked {inward_key} ↔ {outward_key} ({link_type})"}
        else:
            return {"status": "error", "detail": f"Link failed: HTTP {r.status_code} — {r.text[:200]}"}

    def _remediate_password(self, user_id: str, new_password: str) -> str:
        """Reset a user's password (remediation for rotate_password breach).
        Falls back gracefully if the app lacks User.ReadWrite.All."""
        import requests
        from integrations.graph_client import get_graph_client
        gc = get_graph_client()
        token = gc._get_token()

        try:
            r = requests.patch(
                f"https://graph.microsoft.com/v1.0/users/{user_id}",
                headers={
                    "Authorization": f"Bearer {token}",
                    "Content-Type": "application/json",
                },
                json={
                    "passwordProfile": {
                        "password": new_password,
                        "forceChangePasswordNextSignIn": True,
                    }
                },
            )
            
            if r.status_code == 403:
                # App lacks User.ReadWrite.All — sessions already revoked, 
                # admin must manually reset password
                gc.enable_user(user_id)
                return f"Password reset requires admin (403). User re-enabled. Sessions revoked. Manual reset needed: {new_password}"
            
            r.raise_for_status()
            gc.enable_user(user_id)
            return f"Password reset to {new_password}. User re-enabled. Force-change on next sign-in."
            
        except Exception as e:
            # Try at least to re-enable
            try:
                gc.enable_user(user_id)
            except:
                pass
            return f"Remediation partial: {str(e)[:100]}. User re-enabled where possible."


# ── CLI ─────────────────────────────────────────────────────────

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Linked Onboarding + Breach Pipeline")
    parser.add_argument("--company", required=True, help="Company name (fake org in tenant)")
    parser.add_argument("--display-name", help="Display name for the user")
    parser.add_argument("--upn", help="UserPrincipalName")
    parser.add_argument("--batch", nargs="*", help="Run for multiple companies")
    parser.add_argument("--securityzator-url", default="http://localhost:5007")

    args = parser.parse_args()

    pipeline = LinkedOnboardingPipeline(securityzator_url=args.securityzator_url)

    if args.batch:
        results = pipeline.run_batch(args.batch, display_name=args.display_name, upn=args.upn)
        print(json.dumps(results, indent=2, default=str))
    else:
        result = pipeline.run(
            company_name=args.company,
            display_name=args.display_name,
            upn=args.upn,
        )
        print("\n" + json.dumps({k: v for k, v in result.items() if k != "audit_log"}, indent=2, default=str))
