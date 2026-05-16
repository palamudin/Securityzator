"""
JIRA Ticket Linker — connects M365 faker actions to JIRA tickets.

When a real M365 incident is created, this module creates/updates a corresponding
JIRA ticket so the triage system has full context. The ticket contains:
- What M365 operation was performed
- The affected resources (user, group, license, policy)
- Remediation hints telling Securityzator what to fix
- Status tracking linking the M365 state to JIRA workflow
"""
import os
import sys
import json
import random
from datetime import datetime, timedelta
from typing import Optional

AIMSP_ROOT = os.path.join(os.path.dirname(os.path.dirname(__file__)), "AIMSP")
sys.path.insert(0, AIMSP_ROOT)

# Import the JIRA ticket spawner components
from generators.ticket_spawner import TicketSpawner
from config.jira_config import JIRA_REST_API, GLOBAL_AUTH as AUTH

HEADERS = {"Accept": "application/json", "Content-Type": "application/json"}

# Map faker actions to JIRA issue types
ACTION_ISSUE_TYPE_MAP = {
    "create_user": ("Service Request", "user_offboard", "reverse"),
    "delete_user": ("Incident", "data_loss", "direct"),
    "disable_user": ("Incident", "account_lockout", "direct"),
    "enable_user": ("Service Request", "access_request", "reverse"),
    "create_group": ("Service Request", "group_membership", "reverse"),
    "add_group_member": ("Service Request", "group_membership", "reverse"),
    "remove_group_member": ("Incident", "access_request", "direct"),
    "assign_license": ("Service Request", "license_assign", "reverse"),
    "unassign_license": ("Incident", "license_deprov", "direct"),
    "rotate_password": ("Incident", "password_reset", "direct"),
    "reset_mfa": ("Incident", "mfa_auth", "direct"),
    "revoke_sessions": ("Incident", "unusual_signin", "direct"),
    "add_ca_exclusion": ("Incident", "security_advisory", "direct"),
    "remove_ca_exclusion": ("Service Request", "security_advisory", "reverse"),
}


class JiraLinker:
    """Creates and updates JIRA tickets linked to M365 faker operations."""

    def __init__(self):
        self.spawner = TicketSpawner()
        self._ticket_cache = {}  # action_id -> jira_key

    def create_ticket(
        self,
        action_result: dict,
        company_name: str = "Strong MSP",
        priority: str = "Medium",
        labels: list = None,
    ) -> dict:
        """
        Create a JIRA ticket for an M365 action.
        
        Returns the JIRA issue key and ID for tracking.
        """
        action = action_result.get("action", "unknown")
        detail = action_result.get("detail", "")
        remediation_hint = action_result.get("remediation_hint", "")

        # Determine issue type from action
        mapping = ACTION_ISSUE_TYPE_MAP.get(action, ("Incident", "general", "direct"))
        issue_type_name, _, _ = mapping

        # Build a rich summary
        summary = self._build_summary(action_result, company_name)

        # Build a description with full M365 context
        description = self._build_description(action_result, company_name, remediation_hint)

        # Map to JIRA issue type ID
        type_id = self.spawner.type_ids.get(issue_type_name) or self.spawner.type_ids.get("Task", "10000")

        # Build the issue payload
        fields = {
            "project": {"key": self.spawner.field_map.get("project_key", "MSP")},
            "summary": summary,
            "description": {
                "type": "doc",
                "version": 1,
                "content": [
                    {"type": "paragraph", "content": [{"type": "text", "text": description}]}
                ],
            },
            "issuetype": {"id": type_id},
            "priority": {"name": priority},
        }

        # Add labels if provided
        if labels:
            fields["labels"] = labels

        # Add custom fields with M365 context
        cf = self.spawner.field_ids
        if cf.get("Company Name"):
            fields[cf["Company Name"]] = company_name
        if cf.get("Source"):
            fields[cf["Source"]] = {"value": "Auto-generated"}

        # Set subtype (skip — requires pre-configured option values in JIRA)
        subtype_name = mapping[1].replace("_", " ").title()

        # Set remediation context in SLA field
        if cf.get("SLA Tier") and remediation_hint:
            fields[cf["SLA Tier"]] = {"value": "Gold"}  # Breach = gold

        # Post to JIRA (labels must be added separately — v3 API doesn't support them on create)
        import requests
        payload = {"fields": fields}
        r = requests.post(f"{JIRA_REST_API}/issue", auth=AUTH, headers=HEADERS, json=payload)

        if r.status_code in (200, 201):
            issue = r.json()
            jira_key = issue.get("key")
            jira_id = issue.get("id")

            # Add labels via PUT (JIRA v3 doesn't accept labels on create)
            if labels:
                requests.put(f"{JIRA_REST_API}/issue/{jira_key}",
                    json={"fields": {"labels": labels}},
                    headers=HEADERS, auth=AUTH)

            # Add a comment with the M365 operation details
            self._add_m365_comment(jira_key, action_result)

            # Cache for later
            self._ticket_cache[action_result.get("user_id", action)] = jira_key

            return {
                "status": "success",
                "jira_key": jira_key,
                "jira_id": jira_id,
                "summary": summary,
                "action": action,
                "detail": f"JIRA {jira_key} created for {action}",
            }
        else:
            return {
                "status": "error",
                "action": action,
                "detail": f"JIRA create failed: HTTP {r.status_code} — {r.text[:200]}",
                "http_status": r.status_code,
            }

    def resolve_ticket(self, jira_key: str, resolution_note: str = None) -> dict:
        """Mark a JIRA ticket as resolved after Securityzator remediation."""
        if resolution_note is None:
            resolution_note = "✅ Remediated via Securityzator. M365 state restored."

        import requests
        # Add resolution comment
        comment = {
            "body": {
                "type": "doc",
                "version": 1,
                "content": [
                    {"type": "paragraph", "content": [
                        {"type": "text", "text": resolution_note}
                    ]}
                ],
            }
        }
        requests.post(f"{JIRA_REST_API}/issue/{jira_key}/comment", auth=AUTH, headers=HEADERS, json=comment)

        # Try to transition to Done/Resolved
        r = requests.get(f"{JIRA_REST_API}/issue/{jira_key}/transitions", auth=AUTH, headers=HEADERS)
        if r.status_code == 200:
            transitions = r.json().get("transitions", [])
            resolved_names = ["Resolved", "Done", "Closed", "Complete"]
            target = next((t for t in transitions if t["name"] in resolved_names), None)
            if not target and transitions:
                target = transitions[-1]
            if target:
                requests.post(
                    f"{JIRA_REST_API}/issue/{jira_key}/transitions",
                    auth=AUTH,
                    headers=HEADERS,
                    json={"transition": {"id": target["id"]}},
                )

        return {"status": "success", "jira_key": jira_key, "detail": f"Ticket {jira_key} resolved"}

    def add_comment(self, jira_key: str, comment_text: str) -> dict:
        """Add a comment to an existing JIRA ticket."""
        import requests
        comment = {
            "body": {
                "type": "doc",
                "version": 1,
                "content": [
                    {"type": "paragraph", "content": [{"type": "text", "text": comment_text}]}
                ],
            }
        }
        r = requests.post(f"{JIRA_REST_API}/issue/{jira_key}/comment", auth=AUTH, headers=HEADERS, json=comment)
        return {"status": "success" if r.status_code in (200, 201) else "error", "detail": f"Comment on {jira_key}"}

    # ── Internal Helpers ────────────────────────────────────────

    def _build_summary(self, action_result: dict, company_name: str) -> str:
        """Build a human-readable ticket summary with M365 context."""
        action = action_result.get("action", "unknown")
        upn = action_result.get("upn", action_result.get("user_id", "unknown"))

        templates = {
            "create_user": f"[M365] New user provisioned: {action_result.get('display_name', upn)} — {company_name}",
            "delete_user": f"[M365] User deleted: {upn} — {company_name}",
            "disable_user": f"[BREACH] User account disabled: {upn} — possible compromise",
            "enable_user": f"[M365] User account re-enabled: {upn} — remediation",
            "create_group": f"[M365] Security group created: {action_result.get('display_name', 'unknown')}",
            "remove_group_member": f"[BREACH] User removed from group: {upn} — potential access revocation",
            "unassign_license": f"[BREACH] License removed: {action_result.get('sku', 'unknown')} from {upn}",
            "assign_license": f"[M365] License assigned: {action_result.get('sku', 'unknown')} to {upn}",
            "rotate_password": f"[BREACH] Password rotated for {upn} — suspicious activity response",
            "reset_mfa": f"[BREACH] MFA reset for {upn} — authentication methods cleared",
            "revoke_sessions": f"[BREACH] All sessions revoked for {upn} — suspicious sign-in response",
            "disable_ca_policy": f"[BREACH] Conditional Access policy disabled — security control removed",
        }
        return templates.get(action, f"[M365] {action}: {upn}")

    def _build_description(self, action_result: dict, company_name: str, remediation_hint: str) -> str:
        """Build a detailed description with M365 and remediation context."""
        action = action_result.get("action", "unknown")
        detail = action_result.get("detail", "")
        user_id = action_result.get("user_id", "N/A")
        upn = action_result.get("upn", "N/A")

        sections = [
            f"## M365 Incident Report\n",
            f"**Action:** {action}",
            f"**Affected Tenant:** Strong MSP (ai-msp.com)",
            f"**Affected User:** {upn} (`{user_id}`)",
            f"**Company:** {company_name}",
            f"**Timestamp:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}\n",
            f"### Technical Detail",
            f"```\n{detail}\n```\n",
            f"### Remediation",
            f"**Hint:** `{remediation_hint}`",
            f"**Recommended:** Run Securityzator remediation for this control.",
            f"**Manual:** Use the Securityzator bridge to automatically queue the fix.",
        ]
        return "\n".join(sections)

    def _add_m365_comment(self, jira_key: str, action_result: dict):
        """Add M365 operation evidence as a JIRA comment."""
        action = action_result.get("action", "unknown")
        detail = action_result.get("detail", "")
        comment = f"🤖 **M365 Faker Operation**\n\nAction: `{action}`\nDetail: {detail}\n\nThis ticket was auto-generated by the M365 Ticket Faker. The underlying M365 state has been modified — remediation is required."
        self.add_comment(jira_key, comment)
