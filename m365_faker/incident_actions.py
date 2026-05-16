"""
Incident Actions — breach response and security operations for the ticket faker.

These simulate real security incidents that Securityzator can then remediate.
Every action has a `remediation_hint` that maps to a Securityzator template
or manual remediation operation.
"""
import os
import sys
import random
from datetime import datetime
from typing import Optional

AIMSP_ROOT = os.path.join(os.path.dirname(os.path.dirname(__file__)), "AIMSP")
sys.path.insert(0, AIMSP_ROOT)
from integrations.graph_client import get_graph_client

gc = get_graph_client()


# ── Password & Auth ─────────────────────────────────────────────

def rotate_password(user_id: str, new_password: Optional[str] = None) -> dict:
    """
    Force password change for a user — simulates a breach response.
    This revokes all refresh tokens AND sets a new password.
    """
    if new_password is None:
        new_password = f"BreachReset{random.randint(10000, 99999)}!"

    try:
        # First, revoke all existing sessions (this usually works)
        sessions_revoked = False
        try:
            gc.revoke_signin_sessions(user_id)
            sessions_revoked = True
        except Exception:
            pass  # Continue even if revoke fails

        # Then update password (requires User.ReadWrite.All — may get 403)
        password_set = False
        try:
            import requests
            token = gc._get_token()
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
            if r.status_code in (200, 204):
                password_set = True
            elif r.status_code == 403:
                pass  # App lacks User.ReadWrite.All
            else:
                r.raise_for_status()
                password_set = True
        except Exception:
            pass

        detail_parts = []
        if sessions_revoked:
            detail_parts.append("Sessions revoked")
        if password_set:
            detail_parts.append("password reset")
        elif sessions_revoked:
            detail_parts.append("password reset blocked (403 — app lacks User.ReadWrite.All)")
        
        detail = f"Password rotation for {user_id}: " + (", ".join(detail_parts) if detail_parts else "no actions completed")

        return {
            "status": "success" if (sessions_revoked or password_set) else "error",
            "action": "rotate_password",
            "user_id": user_id,
            "detail": detail,
            "sessions_revoked": sessions_revoked,
            "password_set": password_set,
            "remediation_hint": "password_reset_confirmation",
        }
    except Exception as e:
        return {"status": "error", "action": "rotate_password", "user_id": user_id, "detail": str(e)[:200]}


def reset_mfa(user_id: str) -> dict:
    """
    Reset MFA methods for a user — simulates MFA breach response.
    This forces the user to re-register MFA on next sign-in.
    """
    try:
        # Revoke sessions forces MFA re-registration if Conditional Access requires it
        gc.revoke_signin_sessions(user_id)

        # Also try to delete existing authentication methods (Graph beta)
        import requests
        token = gc._get_token()
        # List and delete phone methods (most common MFA method)
        r = requests.get(
            f"https://graph.microsoft.com/beta/users/{user_id}/authentication/phoneMethods",
            headers={"Authorization": f"Bearer {token}"},
        )
        if r.status_code == 200:
            methods = r.json().get("value", [])
            for method in methods:
                requests.delete(
                    f"https://graph.microsoft.com/beta/users/{user_id}/authentication/phoneMethods/{method['id']}",
                    headers={"Authorization": f"Bearer {token}"},
                )

        return {
            "status": "success",
            "action": "reset_mfa",
            "user_id": user_id,
            "detail": f"MFA reset for {user_id}. Sessions revoked, methods cleared.",
            "remediation_hint": "mfa_registration",
        }
    except Exception as e:
        return {"status": "error", "action": "reset_mfa", "user_id": user_id, "detail": str(e)[:200]}


def revoke_sessions(user_id: str) -> dict:
    """Revoke all active sessions for a user (simulates suspicious activity response)."""
    try:
        gc.revoke_signin_sessions(user_id)
        return {
            "status": "success",
            "action": "revoke_sessions",
            "user_id": user_id,
            "detail": f"All sessions revoked for {user_id}",
            "remediation_hint": "user_review",
        }
    except Exception as e:
        return {"status": "error", "action": "revoke_sessions", "detail": str(e)[:200]}


# ── Conditional Access ──────────────────────────────────────────

def add_ca_exclusion(user_id_or_upn: str) -> dict:
    """
    Add a user to the exclusion list of ALL Conditional Access policies.
    
    This simulates an unauthorized CA bypass — e.g. someone added themselves
    to bypass geolock, device compliance, or MFA requirements.
    
    The user is NOT disabled, policies are NOT disabled — the user is simply
    excluded from every enabled CA policy, making them invisible to enforcement.
    
    Returns a detailed report of which policies were modified.
    """
    try:
        import requests
        token = gc._get_token()
        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        }

        # Resolve user — accept either object ID or UPN
        user_id = user_id_or_upn
        user_display = user_id_or_upn
        if "@" in user_id_or_upn:
            # It's a UPN — resolve to object ID
            r = requests.get(
                f"https://graph.microsoft.com/v1.0/users/{user_id_or_upn}?$select=id,displayName,userPrincipalName",
                headers=headers,
            )
            r.raise_for_status()
            user_data = r.json()
            user_id = user_data["id"]
            user_display = f"{user_data.get('displayName', '?')} ({user_data.get('userPrincipalName', '?')})"

        # Get all CA policies
        r = requests.get(
            "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies?$top=999",
            headers=headers,
        )
        r.raise_for_status()
        policies = r.json().get("value", [])

        updated = []
        already_excluded = []
        skipped = []
        failed = []

        for policy in policies:
            policy_name = policy.get("displayName", "Unnamed")
            policy_state = policy.get("state", "unknown")

            # Skip disabled policies — they don't enforce anything
            if policy_state == "disabled":
                skipped.append({"policy": policy_name, "reason": "Policy is disabled"})
                continue

            conditions = policy.get("conditions", {})
            users_block = conditions.get("users", {})

            if not users_block:
                skipped.append({"policy": policy_name, "reason": "No users conditions block"})
                continue

            exclude_users = users_block.get("excludeUsers", [])
            if not isinstance(exclude_users, list):
                exclude_users = []

            # Check if user is already excluded
            if user_id in exclude_users:
                already_excluded.append({
                    "policy": policy_name,
                    "state": policy_state,
                })
                continue

            # Add user to exclusions
            exclude_users.append(user_id)
            users_block["excludeUsers"] = exclude_users
            conditions["users"] = users_block

            try:
                patch_r = requests.patch(
                    f"https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies/{policy['id']}",
                    headers=headers,
                    json={"conditions": conditions},
                )
                patch_r.raise_for_status()
                updated.append({
                    "policy": policy_name,
                    "state": policy_state,
                    "exclude_count": len(exclude_users),
                })
            except Exception as e:
                failed.append({
                    "policy": policy_name,
                    "error": str(e)[:200],
                })

        result = {
            "status": "success",
            "action": "add_ca_exclusion",
            "user_id": user_id,
            "user_display": user_display,
            "summary": f"Updated {len(updated)}, already excluded {len(already_excluded)}, skipped {len(skipped)}, failed {len(failed)}",
            "detail": f"Added {user_display} to CA exclusions across {len(updated)} enabled policies. Bypasses geolock, device compliance, and MFA enforcement.",
            "updated": updated,
            "already_excluded": already_excluded,
            "skipped": skipped,
            "failed": failed,
            "remediation_hint": "remove_ca_exclusion",
        }
        return result

    except Exception as e:
        return {"status": "error", "action": "add_ca_exclusion", "detail": str(e)[:300]}


def remove_ca_exclusion(user_id_or_upn: str) -> dict:
    """
    Remove a user from the exclusion list of ALL Conditional Access policies.
    This is the remediation for add_ca_exclusion — restores normal enforcement.
    """
    try:
        import requests
        token = gc._get_token()
        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        }

        # Resolve user
        user_id = user_id_or_upn
        user_display = user_id_or_upn
        if "@" in user_id_or_upn:
            r = requests.get(
                f"https://graph.microsoft.com/v1.0/users/{user_id_or_upn}?$select=id,displayName,userPrincipalName",
                headers=headers,
            )
            r.raise_for_status()
            user_data = r.json()
            user_id = user_data["id"]
            user_display = f"{user_data.get('displayName', '?')} ({user_data.get('userPrincipalName', '?')})"

        # Get all CA policies
        r = requests.get(
            "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies?$top=999",
            headers=headers,
        )
        r.raise_for_status()
        policies = r.json().get("value", [])

        removed = []
        not_found = []
        failed = []

        for policy in policies:
            policy_name = policy.get("displayName", "Unnamed")
            conditions = policy.get("conditions", {})
            users_block = conditions.get("users", {})

            if not users_block:
                continue

            exclude_users = users_block.get("excludeUsers", [])
            if not isinstance(exclude_users, list):
                continue

            if user_id not in exclude_users:
                continue

            # Remove user from exclusions
            exclude_users.remove(user_id)
            users_block["excludeUsers"] = exclude_users
            conditions["users"] = users_block

            try:
                patch_r = requests.patch(
                    f"https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies/{policy['id']}",
                    headers=headers,
                    json={"conditions": conditions},
                )
                patch_r.raise_for_status()
                removed.append({
                    "policy": policy_name,
                    "remaining_exclusions": len(exclude_users),
                })
            except Exception as e:
                failed.append({
                    "policy": policy_name,
                    "error": str(e)[:200],
                })

        return {
            "status": "success",
            "action": "remove_ca_exclusion",
            "user_id": user_id,
            "user_display": user_display,
            "summary": f"Removed from {len(removed)} policies, failed {len(failed)}",
            "detail": f"Removed {user_display} from CA exclusions — enforcement restored.",
            "removed": removed,
            "failed": failed,
        }
    except Exception as e:
        return {"status": "error", "action": "remove_ca_exclusion", "detail": str(e)[:300]}


def list_ca_policies() -> list:
    """List all Conditional Access policies with their current state."""
    try:
        policies = gc.get_conditional_access_policies()
        return [
            {
                "id": p.get("id"),
                "display_name": p.get("displayName"),
                "state": p.get("state"),
            }
            for p in policies
        ]
    except Exception as e:
        return [{"error": str(e)[:200]}]


def disable_ca_policy(policy_id: Optional[str] = None, user_id: Optional[str] = None) -> dict:
    """Disable a Conditional Access policy — simulates legacy auth leak. user_id ignored (tenant-wide op)."""
    try:
        if not policy_id:
            policies = list_ca_policies()
            enabled = [p for p in policies if p.get("state") == "enabled"]
            if not enabled:
                return {"status": "error", "action": "disable_ca_policy",
                        "detail": "No enabled CA policies found to disable"}
            policy_id = enabled[0]["id"]

        gc.update_ca_policy(policy_id, state="disabled")
        return {
            "status": "success",
            "action": "disable_ca_policy",
            "policy_id": policy_id,
            "detail": f"CA policy {policy_id} disabled — legacy auth flows exposed",
            "remediation_hint": "Re-enable the policy and block legacy authentication",
        }
    except Exception as e:
        return {"status": "error", "action": "disable_ca_policy", "detail": str(e)[:200]}


def enable_ca_policy(policy_id: Optional[str] = None, user_id: Optional[str] = None) -> dict:
    """Re-enable a Conditional Access policy — remediation for legacy auth leak."""
    try:
        if not policy_id:
            policies = list_ca_policies()
            disabled = [p for p in policies if p.get("state") == "disabled"]
            if not disabled:
                return {"status": "error", "action": "enable_ca_policy",
                        "detail": "No disabled CA policies found to re-enable"}
            policy_id = disabled[0]["id"]

        gc.update_ca_policy(policy_id, state="enabled")
        return {
            "status": "success",
            "action": "enable_ca_policy",
            "policy_id": policy_id,
            "detail": f"CA policy {policy_id} re-enabled",
        }
    except Exception as e:
        return {"status": "error", "action": "enable_ca_policy", "detail": str(e)[:200]}


# ── Secure Score Drift ──────────────────────────────────────────

def check_secure_score() -> dict:
    """Get current Secure Score to measure drift from chaos operations."""
    try:
        score = gc.get_secure_score()
        if score:
            return {
                "status": "success",
                "action": "check_secure_score",
                "current": score.get("currentScore"),
                "max": score.get("maxScore"),
                "created": score.get("createdDateTime"),
                "detail": f"Secure Score: {score.get('currentScore')}/{score.get('maxScore')}",
            }
        return {"status": "error", "detail": "No Secure Score data returned"}
    except Exception as e:
        return {"status": "error", "action": "check_secure_score", "detail": str(e)[:200]}


def get_secure_score_controls() -> list:
    """Get Secure Score control profiles — which controls have drift."""
    try:
        controls = gc.get_secure_score_controls(top=20)
        return [
            {
                "id": c.get("id"),
                "title": c.get("title"),
                "maxScore": c.get("maxScore"),
                "currentScore": c.get("currentScore"),
                "implementationStatus": c.get("implementationStatus"),
            }
            for c in controls
            if c.get("currentScore", 0) < c.get("maxScore", 0)
        ]
    except Exception as e:
        return [{"error": str(e)[:200]}]
