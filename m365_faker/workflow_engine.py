"""
Workflow Engine — watches JIRA tickets and applies escalation rules.

Default rule: if a ticket is open > 20 minutes, escalate it.
Rules are configurable. Designed to run as a cron job or on-demand.

Usage:
    engine = WorkflowEngine()
    results = engine.run()  # checks all open tickets, applies rules
    
    # CLI:
    python workflow_engine.py          # run once
    python workflow_engine.py --watch  # run every 60s (daemon mode)
"""
import sys
import os
import time
import json
from datetime import datetime, timezone, timedelta
from typing import Optional

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(__file__)), "AIMSP"))
sys.path.insert(0, os.path.dirname(__file__))

import requests
from requests.auth import HTTPBasicAuth
from config.jira_config import JIRA_REST_API, GLOBAL_AUTH
from audit_trail import AuditContext, log as audit_log

HEADERS = {"Accept": "application/json", "Content-Type": "application/json"}
AUTH = HTTPBasicAuth(GLOBAL_AUTH[0], GLOBAL_AUTH[1])


class Rule:
    """A workflow rule: if condition matches → execute action."""
    
    def __init__(self, name: str, condition: dict, action: dict, priority: int = 10):
        self.name = name
        self.condition = condition  # {field, op, value}
        self.action = action        # {type, params...}
        self.priority = priority    # lower = runs first

    def matches(self, ticket: dict) -> bool:
        """Check if this rule applies to a ticket."""
        field = self.condition.get("field", "")
        op = self.condition.get("op", "gt")
        value = self.condition.get("value")
        
        actual = self._get_field(ticket, field)
        if actual is None:
            return False
        
        if op == "gt":
            return actual > value
        elif op == "lt":
            return actual < value
        elif op == "eq":
            return actual == value
        elif op == "neq":
            return actual != value
        elif op == "in":
            return actual in (value if isinstance(value, list) else [value])
        elif op == "contains":
            return value in str(actual)
        return False

    def _get_field(self, ticket: dict, field: str):
        """Extract a field value from a JIRA ticket dict."""
        fields = ticket.get("fields", {})
        
        if field == "age_minutes":
            created = fields.get("created", "")
            if created:
                created_dt = datetime.fromisoformat(created.replace("Z", "+00:00"))
                age = (datetime.now(timezone.utc) - created_dt).total_seconds() / 60
                return age
            return None
        
        if field == "status":
            return fields.get("status", {}).get("name", "")
        
        if field == "priority":
            return fields.get("priority", {}).get("name", "")
        
        if field == "issuetype":
            return fields.get("issuetype", {}).get("name", "")
        
        if field == "assignee":
            a = fields.get("assignee")
            return a.get("displayName", "") if a else "Unassigned"
        
        if field == "updated_minutes":
            updated = fields.get("updated", "")
            if updated:
                updated_dt = datetime.fromisoformat(updated.replace("Z", "+00:00"))
                age = (datetime.now(timezone.utc) - updated_dt).total_seconds() / 60
                return age
            return None
        
        # Custom fields
        if field.startswith("customfield_"):
            return fields.get(field, "")
        
        if field == "labels":
            return fields.get("labels", [])
        
        return None

    def execute(self, ticket_key: str) -> dict:
        """Execute this rule's action on a ticket."""
        action_type = self.action.get("type", "")
        params = self.action.get("params", {})
        
        if action_type == "escalate":
            return self._escalate(ticket_key, params)
        elif action_type == "comment":
            return self._comment(ticket_key, params.get("body", "Auto-escalated by workflow engine."))
        elif action_type == "transition":
            return self._transition(ticket_key, params.get("to_status", "Done"))
        elif action_type == "assign":
            return self._assign(ticket_key, params.get("assignee", ""))
        elif action_type == "set_priority":
            return self._set_priority(ticket_key, params.get("priority", "Highest"))
        else:
            return {"status": "error", "detail": f"Unknown action type: {action_type}"}

    def _escalate(self, key: str, params: dict) -> dict:
        """Full escalation: comment + bump priority + transition if configured.
        Skips if ticket is already at target priority."""
        results = []
        new_priority = params.get("priority", "Highest")
        
        # Check current priority first — skip if already escalated
        r0 = requests.get(f"{JIRA_REST_API}/issue/{key}?fields=priority", headers=HEADERS, auth=AUTH)
        current_priority = r0.json().get("fields", {}).get("priority", {}).get("name", "")
        if current_priority == new_priority:
            return {"status": "skipped", "action": "escalate", "detail": f"Already at {new_priority}"}
        
        # 1. Comment
        body = params.get("comment", f"⏰ Auto-escalated by workflow engine — ticket age exceeds threshold. Rule: {self.name}")
        r = requests.post(f"{JIRA_REST_API}/issue/{key}/comment", json={
            "body": {"type": "doc", "version": 1, "content": [
                {"type": "paragraph", "content": [{"type": "text", "text": body}]}
            ]}
        }, headers=HEADERS, auth=AUTH)
        results.append(("comment", r.status_code))
        
        # 2. Priority bump
        new_priority = params.get("priority", "Highest")
        r2 = requests.put(f"{JIRA_REST_API}/issue/{key}", json={
            "fields": {"priority": {"name": new_priority}}
        }, headers=HEADERS, auth=AUTH)
        results.append(("priority", r2.status_code))
        
        # 3. Transition if configured
        transition = params.get("transition")
        if transition:
            r3 = requests.get(f"{JIRA_REST_API}/issue/{key}/transitions", headers=HEADERS, auth=AUTH)
            transitions = r3.json().get("transitions", [])
            match = next((t for t in transitions if t["name"].lower() == transition.lower()), None)
            if match:
                r4 = requests.post(f"{JIRA_REST_API}/issue/{key}/transitions",
                    json={"transition": {"id": match["id"]}}, headers=HEADERS, auth=AUTH)
                results.append(("transition", r4.status_code))
        
        return {"status": "success", "action": "escalate", "results": results}

    def _comment(self, key: str, body: str) -> dict:
        r = requests.post(f"{JIRA_REST_API}/issue/{key}/comment", json={
            "body": {"type": "doc", "version": 1, "content": [
                {"type": "paragraph", "content": [{"type": "text", "text": body}]}
            ]}
        }, headers=HEADERS, auth=AUTH)
        return {"status": "success" if r.status_code == 201 else "error", "http": r.status_code}

    def _transition(self, key: str, to_status: str) -> dict:
        r = requests.get(f"{JIRA_REST_API}/issue/{key}/transitions", headers=HEADERS, auth=AUTH)
        transitions = r.json().get("transitions", [])
        match = next((t for t in transitions if t["name"].lower() == to_status.lower()), None)
        if not match:
            return {"status": "error", "detail": f"No transition to '{to_status}'. Available: {[t['name'] for t in transitions]}"}
        r2 = requests.post(f"{JIRA_REST_API}/issue/{key}/transitions",
            json={"transition": {"id": match["id"]}}, headers=HEADERS, auth=AUTH)
        return {"status": "success" if r2.status_code == 204 else "error", "http": r2.status_code}

    def _assign(self, key: str, assignee: str) -> dict:
        r = requests.put(f"{JIRA_REST_API}/issue/{key}/assignee", json={"accountId": assignee},
            headers=HEADERS, auth=AUTH)
        return {"status": "success" if r.status_code == 204 else "error"}

    def _set_priority(self, key: str, priority: str) -> dict:
        r = requests.put(f"{JIRA_REST_API}/issue/{key}", json={
            "fields": {"priority": {"name": priority}}
        }, headers=HEADERS, auth=AUTH)
        return {"status": "success" if r.status_code == 204 else "error"}


class ScenarioSlaRule(Rule):
    """A rule that extracts SLA from JIRA labels (sla:Xm) and escalates if breached."""

    def __init__(self, name: str = "scenario_sla_escalation", priority: int = 5):
        super().__init__(name, {}, {"type": "escalate", "params": {
            "comment": "⏰ Scenario SLA breached — auto-escalating. Remediation overdue.",
            "priority": "Highest",
        }}, priority=priority)

    def matches(self, ticket: dict) -> bool:
        """Extract SLA from labels and compare to ticket age."""
        labels = self._get_field(ticket, "labels") or []
        sla_minutes = None
        for label in labels:
            if label.startswith("sla:") and label.endswith("m"):
                try:
                    sla_minutes = int(label[4:-1])
                except ValueError:
                    continue
        
        if sla_minutes is None:
            return False  # No SLA label → skip

        age = self._get_field(ticket, "age_minutes")
        if age is None:
            return False
        
        return age > sla_minutes


# ── Default Rules ────────────────────────────────────────────────

DEFAULT_RULES = [
    ScenarioSlaRule(priority=5),  # Check scenario-specific SLAs first
    Rule(
        name="auto_escalate_20min",
        condition={"field": "age_minutes", "op": "gt", "value": 20},
        action={
            "type": "escalate",
            "params": {
                "comment": "⏰ Auto-escalated: ticket open > 20 minutes without resolution.",
                "priority": "Highest",
            }
        },
        priority=10,
    ),
    Rule(
        name="stale_ticket_warning",
        condition={"field": "updated_minutes", "op": "gt", "value": 60},
        action={
            "type": "comment",
            "params": {
                "body": "⚠️ This ticket has had no activity for over 60 minutes. Review needed."
            }
        },
        priority=20,
    ),
]


# ── Engine ───────────────────────────────────────────────────────

class WorkflowEngine:
    """Runs workflow rules against open JIRA tickets."""

    def __init__(self, project: str = "MSP", rules: list = None):
        self.project = project
        self.rules = sorted(rules or DEFAULT_RULES, key=lambda r: r.priority)

    def get_open_tickets(self, limit: int = 30) -> list:
        """Fetch open tickets from JIRA. Newest first. Excludes already-escalated (Highest priority)."""
        jql = (f"project = {self.project} AND status NOT IN (Done, Resolved, Closed, Cancelled) "
               f"AND priority != Highest ORDER BY created DESC")
        r = requests.post(f"{JIRA_REST_API}/search/jql", json={
            "jql": jql, "maxResults": limit,
            "fields": ["summary", "status", "priority", "issuetype", "assignee", "created", "updated", "labels"]
        }, headers=HEADERS, auth=AUTH)
        r.raise_for_status()
        return r.json().get("issues", [])

    def run(self) -> dict:
        """Run all rules against all open tickets. Returns summary."""
        with AuditContext("workflow_engine_run", source="automated") as audit:
            audit.log("engine_start", f"Checking {self.project} tickets with {len(self.rules)} rules")
            
            try:
                tickets = self.get_open_tickets()
            except Exception as e:
                audit.log("engine_error", f"Failed to fetch tickets: {e}", status="error")
                return {"status": "error", "detail": str(e), "tickets_checked": 0, "actions": 0}

            audit.log("tickets_fetched", f"Found {len(tickets)} open tickets")
            actions_taken = 0
            results = []

            for ticket in tickets:
                key = ticket["key"]
                summary = ticket.get("fields", {}).get("summary", "")[:60]
                
                for rule in self.rules:
                    if rule.matches(ticket):
                        result = rule.execute(key)
                        actions_taken += 1
                        audit.log(
                            "rule_triggered",
                            f"{rule.name} → {key}: {summary}",
                            target=key,
                            source="automated",
                            metadata={"rule": rule.name, "action": rule.action.get("type"), "result": result},
                        )
                        results.append({"ticket": key, "rule": rule.name, "result": result})
                        
                        # Only apply first matching rule per ticket per run
                        break
            
            audit.log("engine_complete", f"{actions_taken} actions across {len(tickets)} tickets")
            
            return {
                "status": "success",
                "tickets_checked": len(tickets),
                "actions_taken": actions_taken,
                "results": results,
            }


# ── CLI ──────────────────────────────────────────────────────────

if __name__ == "__main__":
    engine = WorkflowEngine()
    
    if "--watch" in sys.argv:
        interval = 60
        print(f"👁 Workflow engine watching every {interval}s (Ctrl+C to stop)")
        try:
            while True:
                result = engine.run()
                status = f"{result['tickets_checked']} checked, {result['actions_taken']} actions"
                print(f"  [{datetime.now().strftime('%H:%M:%S')}] {status}")
                time.sleep(interval)
        except KeyboardInterrupt:
            print("\nStopped.")
    else:
        result = engine.run()
        print(json.dumps(result, indent=2, default=str))
