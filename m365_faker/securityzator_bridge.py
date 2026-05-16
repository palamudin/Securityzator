"""
Securityzator Bridge — links the ticket faker to Securityzator's remediation engine.

Authenticates as workspace admin and triggers remediation jobs through
Securityzator's web API. Securityzator itself is NEVER modified — this
module uses its existing endpoints exactly as a browser would.

The bridge also tracks job status so ticket resolution can be automated.
"""
import os
import json
import time
from datetime import datetime
from typing import Optional
from urllib.parse import urljoin

import requests


class SecurityzatorBridge:
    """
    Bridge to Securityzator's remediation API.
    
    Securityzator's web app must be running. Default URL: http://localhost:5007
    """

    def __init__(self, base_url: str = "http://localhost:5007"):
        self.base_url = base_url.rstrip("/")
        self.session = requests.Session()
        self._authenticated = False

    # ── Auth ────────────────────────────────────────────────────

    def login(self, email: str, password: str) -> bool:
        """
        Authenticate with Securityzator.
        Uses the same form POST as the browser login page.
        """
        # Get login page (needed for anti-forgery token)
        r = self.session.get(f"{self.base_url}/Account/Login")
        if r.status_code != 200:
            return False

        # Extract anti-forgery token
        import re
        token_match = re.search(r'name="__RequestVerificationToken" type="hidden" value="([^"]+)"', r.text)
        if not token_match:
            return False

        token = token_match.group(1)

        # Post login
        r = self.session.post(
            f"{self.base_url}/Account/Login",
            data={
                "__RequestVerificationToken": token,
                "Email": email,
                "Password": password,
                "RememberMe": "true",
            },
            allow_redirects=False,
        )

        self._authenticated = r.status_code == 302
        return self._authenticated

    def ensure_auth(self) -> bool:
        """Check if we're still authenticated."""
        if not self._authenticated:
            return False
        r = self.session.get(f"{self.base_url}/", allow_redirects=False)
        return r.status_code == 200  # 302 means redirect to login

    # ── Remediation ──────────────────────────────────────────────

    def get_remediation_page(self, connection_id: str = None) -> dict:
        """Load the remediations page to inspect available templates."""
        params = {}
        if connection_id:
            params["connectionId"] = connection_id

        r = self.session.get(f"{self.base_url}/Remediations", params=params)
        if r.status_code != 200:
            return {"status": "error", "http_status": r.status_code, "detail": "Failed to load remediations page"}

        # The page has embedded data — extraction is best-effort for now
        return {
            "status": "success",
            "detail": f"Remediations page loaded ({len(r.text)} bytes)",
        }

    def queue_remediation(
        self,
        connection_id: str,
        template_key: str,
        approval_justification: str = "M365 Faker auto-remediation",
        include_group_id: str = "",
        exclude_group_id: str = "",
        launch_mode: str = "Audit",
        confirm_report_only: bool = True,
        confirm_group_review: bool = True,
        confirm_enabled_change: bool = False,
    ) -> dict:
        """
        Queue a remediation job in Securityzator.
        
        This is equivalent to filling out the remediation form and hitting "Execute".
        
        Args:
            connection_id: The Azure connection ID in Securityzator
            template_key: The remediation template key (e.g. 'block-legacy-auth')
            approval_justification: Why this remediation is being queued (min 12 chars)
            include_group_id: Target group Object ID (REQUIRED for most templates)
            launch_mode: 'Audit' or 'Live' (ignored if template doesn't support selection)
        """
        # Get the page for anti-forgery token
        params = {"connectionId": connection_id, "templateKey": template_key}
        r = self.session.get(f"{self.base_url}/Remediations", params=params)
        if r.status_code != 200:
            return {"status": "error", "detail": f"Failed to load remediation page: HTTP {r.status_code}"}

        import re
        token_match = re.search(r'name="__RequestVerificationToken" type="hidden" value="([^"]+)"', r.text)
        if not token_match:
            return {"status": "error", "detail": "Could not extract anti-forgery token"}

        token = token_match.group(1)

        # Post the remediation
        r = self.session.post(
            f"{self.base_url}/Remediations/ExecuteQueueableTemplate",
            data={
                "__RequestVerificationToken": token,
                "ConnectionId": connection_id,
                "TemplateKey": template_key,
                "ApprovalJustification": approval_justification,
                "LaunchMode": launch_mode,
                "IncludeGroupId": include_group_id,
                "ExcludeGroupId": exclude_group_id,
                "ConfirmReportOnly": str(confirm_report_only).lower(),
                "ConfirmGroupReview": str(confirm_group_review).lower(),
                "ConfirmEnabledChange": str(confirm_enabled_change).lower(),
            },
            allow_redirects=False,
        )

        if r.status_code in (200, 302):
            return {
                "status": "success",
                "detail": f"Remediation queued: {template_key} for connection {connection_id}",
                "template_key": template_key,
                "launch_mode": launch_mode,
            }
        else:
            return {
                "status": "error",
                "http_status": r.status_code,
                "detail": f"Queue failed: HTTP {r.status_code}",
            }

    def get_jobs_status(self) -> list:
        """Get recent job statuses from the Jobs page."""
        r = self.session.get(f"{self.base_url}/Jobs")
        if r.status_code != 200:
            return [{"error": f"HTTP {r.status_code}"}]

        # The jobs page has a table — extract job data
        # This is a simplified extraction for monitoring
        jobs = []
        import re
        # Look for job rows with status badges
        for match in re.finditer(r'<span class="badge[^"]*">([^<]+)</span>', r.text):
            jobs.append({"status": match.group(1)})
        return jobs

    # ── Connections ──────────────────────────────────────────────

    def list_connections(self) -> list:
        """List saved Azure connections (must be authenticated)."""
        r = self.session.get(f"{self.base_url}/Connections")
        if r.status_code != 200:
            return []

        connections = []
        import re
        # Extract connection names and IDs from the page
        for match in re.finditer(r'href="/Connections/Edit/([a-f0-9-]+)"', r.text):
            conn_id = match.group(1)
            connections.append({"id": conn_id})
        return connections

    def create_connection(
        self,
        display_name: str,
        tenant_id: str,
        client_id: str,
        client_secret: str,
        redirect_uri: str = "http://localhost:5007/signin-oidc",
        license_capabilities: list = None,
    ) -> dict:
        """
        Create an Azure connection via form POST — no browser, no clicks.

        Uses the same anti-forgery pattern as queue_remediation.
        Returns the connection ID if successful.
        """
        import re

        # 1. GET the connections page for anti-forgery token
        r = self.session.get(f"{self.base_url}/Connections")
        if r.status_code != 200:
            return {"status": "error", "detail": f"Failed to load Connections page: HTTP {r.status_code}"}

        token_match = re.search(r'name="__RequestVerificationToken" type="hidden" value="([^"]+)"', r.text)
        if not token_match:
            return {"status": "error", "detail": "Could not extract anti-forgery token from Connections page"}

        token = token_match.group(1)

        # 2. POST the connection form
        form_data = {
            "__RequestVerificationToken": token,
            "DisplayName": display_name,
            "TenantId": tenant_id,
            "ClientId": client_id,
            "ClientSecret": client_secret,
            "RedirectUri": redirect_uri,
            "AutomationCertificateThumbprint": "",
            "AutomationCertificateStoreLocation": "LocalMachine",
            "AutomationCertificateStoreName": "My",
        }

        r = self.session.post(
            f"{self.base_url}/Connections/Save",
            data=form_data,
            allow_redirects=False,
        )

        if r.status_code not in (200, 302):
            return {
                "status": "error",
                "http_status": r.status_code,
                "detail": f"Connection save failed: HTTP {r.status_code}",
            }

        # 3. Re-list connections to get the new ID
        connections = self.list_connections()
        if connections:
            conn_id = connections[-1]["id"]
            return {
                "status": "success",
                "detail": f"Created connection '{display_name}'",
                "connection_id": conn_id,
                "display_name": display_name,
            }

        return {"status": "error", "detail": "Connection saved but could not retrieve ID"}

    def validate_connection(self, connection_id: str) -> dict:
        """Validate an Azure connection (tests Graph API connectivity)."""
        import re

        # Get the connections page for anti-forgery token
        r = self.session.get(f"{self.base_url}/Connections")
        if r.status_code != 200:
            return {"status": "error", "detail": f"Failed to load page: HTTP {r.status_code}"}

        token_match = re.search(r'name="__RequestVerificationToken" type="hidden" value="([^"]+)"', r.text)
        if not token_match:
            return {"status": "error", "detail": "Could not extract anti-forgery token"}

        token = token_match.group(1)

        r = self.session.post(
            f"{self.base_url}/Connections/Validate",
            data={
                "__RequestVerificationToken": token,
                "connectionId": connection_id,
            },
            allow_redirects=False,
        )

        return {
            "status": "success" if r.status_code in (200, 302) else "error",
            "http_status": r.status_code,
            "detail": "Validation queued — check Connections page for result",
        }

    def get_available_groups(self, connection_id: str) -> list:
        """
        List groups available for remediation targeting.
        
        Loads the remediation page with a connection to populate the group dropdown.
        Returns list of {id, name} dicts.
        """
        import re

        r = self.session.get(
            f"{self.base_url}/Remediations",
            params={"connectionId": connection_id, "templateKey": "block-legacy-auth"},
        )
        if r.status_code != 200:
            return []

        groups = []
        for match in re.finditer(r'<option value="([a-f0-9-]+)">([^<]+)</option>', r.text):
            groups.append({"id": match.group(1), "name": match.group(2).strip()})
        return groups

    # ── Health ───────────────────────────────────────────────────

    def health_check(self) -> dict:
        """Check if Securityzator is reachable."""
        try:
            r = requests.get(f"{self.base_url}/health/live", timeout=5)
            return {"status": "ok" if r.status_code == 200 else "degraded", "http_status": r.status_code}
        except Exception as e:
            return {"status": "error", "detail": str(e)}


# ── Auto-resolution helper ──────────────────────────────────────

def auto_remediate(
    bridge: SecurityzatorBridge,
    action_result: dict,
    connection_id: str,
    known_templates: dict = None,
) -> dict:
    """
    Given a faker action result, automatically queue the corresponding
    Securityzator remediation template.
    
    known_templates maps remediation_hint -> (template_key, launch_mode)
    """
    if known_templates is None:
        # Default template mappings for common actions
        known_templates = {
            "enable_user": ("entra-daily-use-hardening", "Audit"),
            "assign_license": ("entra-daily-use-hardening", "Audit"),
            "add_group_member": ("entra-daily-use-hardening", "Audit"),
            "enable_ca_policy": ("block-legacy-auth", "Live"),
            "password_reset_confirmation": ("entra-daily-use-hardening", "Audit"),
            "mfa_registration": ("block-legacy-auth", "Live"),
            "user_review": ("entra-daily-use-hardening", "Audit"),
        }

    hint = action_result.get("remediation_hint", "")
    if hint not in known_templates:
        return {"status": "skipped", "detail": f"No template mapping for hint: {hint}"}

    template_key, launch_mode = known_templates[hint]
    return bridge.queue_remediation(
        connection_id=connection_id,
        template_key=template_key,
        launch_mode=launch_mode,
        approval_justification=f"Auto-remediation for {action_result.get('action', 'unknown')}: {action_result.get('detail', '')[:100]}",
    )
