"""
M365 Graph Actions — direct M365 CRUD operations for the ticket faker.

Every action returns a structured dict with `status`, `action`, `detail`, and
the data needed for JIRA ticket creation and Securityzator remediation.
"""
import os
import sys
import random
from datetime import datetime
from typing import Optional

# Use the existing AIMSP Graph client
AIMSP_ROOT = os.path.join(os.path.dirname(os.path.dirname(__file__)), "AIMSP")
sys.path.insert(0, AIMSP_ROOT)
from integrations.graph_client import get_graph_client

gc = get_graph_client()


# ── Users ───────────────────────────────────────────────────────

def create_user(
    display_name: str,
    user_principal_name: str,
    password: Optional[str] = None,
    company_name: str = "Faker Corp",
    department: str = "Operations",
    job_title: str = "Staff",
    assign_license_sku: Optional[str] = None,
) -> dict:
    """Create a new Entra ID user and optionally assign a license."""
    if password is None:
        password = f"Faker{random.randint(10000, 99999)}!"

    try:
        created = gc.create_user(
            display_name=display_name,
            user_principal_name=user_principal_name,
            password=password,
            company_name=company_name,
            department=department,
            job_title=job_title,
        )
        user_id = created.get("id")

        license_detail = None
        if assign_license_sku and user_id:
            skus = gc.get_subscribed_skus()
            match = next((s for s in skus if s["skuPartNumber"].upper() == assign_license_sku.upper()), None)
            if match:
                gc.assign_license(user_id, match["skuId"])
                license_detail = match["skuPartNumber"]

        return {
            "status": "success",
            "action": "create_user",
            "user_id": user_id,
            "upn": user_principal_name,
            "display_name": display_name,
            "license": license_detail,
            "detail": f"Created user {display_name} ({user_principal_name})",
            "remediation_hint": "disable_user",
        }
    except Exception as e:
        return {"status": "error", "action": "create_user", "detail": str(e)[:200]}


def delete_user(user_id: str) -> dict:
    """Delete a user from Entra ID."""
    try:
        gc.delete_user(user_id)
        return {"status": "success", "action": "delete_user", "user_id": user_id, "detail": f"Deleted user {user_id}"}
    except Exception as e:
        return {"status": "error", "action": "delete_user", "detail": str(e)[:200]}


def disable_user(user_id: str) -> dict:
    """Disable a user account (simulates compromised account)."""
    try:
        gc.disable_user(user_id)
        return {"status": "success", "action": "disable_user", "user_id": user_id, "detail": f"Disabled user {user_id}", "remediation_hint": "enable_user"}
    except Exception as e:
        return {"status": "error", "action": "disable_user", "detail": str(e)[:200]}


def enable_user(user_id: str) -> dict:
    """Enable a previously disabled user account."""
    try:
        gc.enable_user(user_id)
        return {"status": "success", "action": "enable_user", "user_id": user_id, "detail": f"Enabled user {user_id}"}
    except Exception as e:
        return {"status": "error", "action": "enable_user", "detail": str(e)[:200]}


# ── Groups ──────────────────────────────────────────────────────

def create_group(
    display_name: str,
    description: str = "",
    mail_enabled: bool = False,
) -> dict:
    """Create a security group in Entra ID."""
    mail_nick = display_name.lower().replace(" ", "-").replace(".", "")[:60]
    try:
        created = gc.create_group(
            display_name=display_name,
            mail_nickname=mail_nick,
            description=description,
            security_enabled=True,
            mail_enabled=mail_enabled,
        )
        return {
            "status": "success",
            "action": "create_group",
            "group_id": created.get("id"),
            "display_name": display_name,
            "detail": f"Created group {display_name}",
        }
    except Exception as e:
        error_str = str(e)[:200]
        # Group may already exist — try to find it
        if "already" in error_str.lower():
            groups = gc.get_groups()
            match = next((g for g in groups if g.get("displayName") == display_name), None)
            if match:
                return {
                    "status": "success",
                    "action": "create_group",
                    "group_id": match["id"],
                    "display_name": display_name,
                    "detail": f"Group {display_name} already exists",
                }
        return {"status": "error", "action": "create_group", "detail": error_str}


def add_group_member(group_id: str, user_id: str) -> dict:
    """Add a user to a group."""
    try:
        gc.add_group_member(group_id, user_id)
        return {"status": "success", "action": "add_group_member", "group_id": group_id, "user_id": user_id, "detail": f"Added user {user_id} to group {group_id}"}
    except Exception as e:
        return {"status": "error", "action": "add_group_member", "detail": str(e)[:200]}


def remove_group_member(group_id: str, user_id: str) -> dict:
    """Remove a user from a group (simulates access revocation)."""
    try:
        gc.remove_group_member(group_id, user_id)
        return {"status": "success", "action": "remove_group_member", "group_id": group_id, "user_id": user_id, "detail": f"Removed user {user_id} from group {group_id}", "remediation_hint": "add_group_member"}
    except Exception as e:
        return {"status": "error", "action": "remove_group_member", "detail": str(e)[:200]}


# ── Licenses ────────────────────────────────────────────────────

def assign_license(user_id: str, sku_part_number: str) -> dict:
    """Assign a license SKU to a user."""
    try:
        skus = gc.get_subscribed_skus()
        match = next((s for s in skus if s["skuPartNumber"].upper() == sku_part_number.upper()), None)
        if not match:
            available = [s["skuPartNumber"] for s in skus]
            return {"status": "error", "action": "assign_license", "detail": f"SKU {sku_part_number} not found. Available: {available}"}

        gc.assign_license(user_id, match["skuId"])
        return {"status": "success", "action": "assign_license", "user_id": user_id, "sku": match["skuPartNumber"], "detail": f"Assigned {match['skuPartNumber']} to {user_id}", "remediation_hint": None}
    except Exception as e:
        return {"status": "error", "action": "assign_license", "detail": str(e)[:200]}


def unassign_license(user_id: str, sku_part_number: str) -> dict:
    """Remove a license from a user (simulates accidental deprovisioning)."""
    try:
        user_data = gc.get_user(user_id)
        assigned = user_data.get("assignedLicenses", [])
        skus = gc.get_subscribed_skus()
        match = next((s for s in skus if s["skuPartNumber"].upper() == sku_part_number.upper()), None)
        if not match:
            return {"status": "error", "action": "unassign_license", "detail": f"SKU {sku_part_number} not found"}

        gc.remove_license(user_id, match["skuId"])
        return {"status": "success", "action": "unassign_license", "user_id": user_id, "sku": match["skuPartNumber"], "detail": f"Removed {match['skuPartNumber']} from {user_id}", "remediation_hint": "assign_license"}
    except Exception as e:
        return {"status": "error", "action": "unassign_license", "detail": str(e)[:200]}


def list_available_licenses() -> list:
    """List all available license SKUs in the tenant."""
    skus = gc.get_subscribed_skus()
    return [{"sku": s["skuPartNumber"], "enabled": s["prepaidUnits"]["enabled"], "consumed": s["consumedUnits"]} for s in skus]
