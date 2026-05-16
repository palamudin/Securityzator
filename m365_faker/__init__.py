"""
M365 Ticket Faker — Standalone premium module that links AIMSP chaos to Securityzator remediation.

Creates real M365 incidents, generates corresponding JIRA tickets, and exposes
Securityzator's remediation capabilities as ticket resolution actions.

Usage:
    from m365_faker import FakerOrchestrator
    faker = FakerOrchestrator()
    result = faker.run_scenario("password_breach", company="Acme Corp")

This module is designed to work ALONGSIDE Securityzator — it links to it, but
Securityzator functions identically without this module present.
"""

__version__ = "1.0.0"
