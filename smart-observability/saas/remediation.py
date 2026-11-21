from __future__ import annotations

import uuid

from saas.database import SaaSMetadataDB, utc_now
from shared.contracts import (
    CorrelatedIncident,
    RemediationAction,
    RemediationAuditEntry,
    SeverityEnum,
)

FORBIDDEN_DESTRUCTIVE_KEYWORDS = ("drop database", "rm -rf", "wipe", "delete volume", "format")


class SafeRemediationSimulator:
    """
    Safe Autonomous Ops simulator:
    Policy Check -> Human Approval Gate -> Dry-Run Simulation -> Immutable UTC Audit Trail -> Rollback.
    NEVER executes live production commands.
    """

    def __init__(self, db: SaaSMetadataDB) -> None:
        self.db = db

    def evaluate_policy(self, incident: CorrelatedIncident) -> tuple[bool, str]:
        lowered = incident.recommended_action.lower()
        if any(word in lowered for word in FORBIDDEN_DESTRUCTIVE_KEYWORDS):
            return False, "Policy FAILED: Destructive action blocked by safety guardrail."
        if len(incident.affected_sources) > 10:
            return False, "Policy FAILED: Blast radius exceeds 10-host safe automation cap."
        return (
            True,
            (
                f"Policy PASSED: Non-destructive, reversible dry-run action scoped to "
                f"{len(incident.affected_sources)} pseudonymous source(s) in {incident.region}; "
                "human approval required before simulation."
            ),
        )

    def _build_rollback_plan(self, incident: CorrelatedIncident) -> str:
        targets = ", ".join(incident.affected_sources[:3])
        return (
            f"Revert simulated config/traffic policy on {targets} to pre-incident snapshot, "
            "restore previous routing weights, and verify health returns to GOOD/EXCELLENT."
        )

    def propose_for_incident(self, incident: CorrelatedIncident) -> RemediationAction | None:
        """Auto-proposes a policy-checked remediation for HIGH/CRITICAL incidents (idempotent per incident)."""
        if incident.severity not in (SeverityEnum.HIGH, SeverityEnum.CRITICAL):
            return None

        existing = self.db.get_remediation_by_incident(incident.incident_id, incident.tenant_id)
        if existing is not None:
            return existing

        policy_ok, policy_notes = self.evaluate_policy(incident)
        now = utc_now()

        action = RemediationAction(
            remediation_id=f"rem-{uuid.uuid4().hex[:10]}",
            incident_id=incident.incident_id,
            tenant_id=incident.tenant_id,
            proposed_action=incident.recommended_action,
            policy_check_passed=policy_ok,
            policy_notes=policy_notes,
            approval_status="PENDING",
            approved_by=None,
            rollback_plan=self._build_rollback_plan(incident),
            audit_trail=[
                RemediationAuditEntry(
                    timestamp_utc=now,
                    actor="aiops-policy-engine",
                    action="PROPOSED",
                    details=(
                        f"Proposed dry-run remediation for {incident.incident_id}. "
                        f"{policy_notes}"
                    ),
                )
            ],
        )
        self.db.save_remediation(action)
        return action

    def approve_remediation(
        self,
        remediation_id: str,
        tenant_id: str,
        approver: str,
    ) -> RemediationAction:
        action = self.db.get_remediation(remediation_id, tenant_id)
        if action is None:
            raise KeyError(f"Remediation '{remediation_id}' not found for tenant '{tenant_id}'")
        if not action.policy_check_passed:
            raise ValueError("Cannot approve remediation that failed policy check.")
        if action.approval_status == "ROLLED_BACK":
            raise ValueError("Cannot approve a remediation that has already been rolled back.")

        now = utc_now()
        updated_trail = list(action.audit_trail) + [
            RemediationAuditEntry(
                timestamp_utc=now,
                actor=approver,
                action="APPROVED",
                details=f"Human approval granted by {approver}.",
            ),
            RemediationAuditEntry(
                timestamp_utc=now,
                actor="safe-remediation-simulator",
                action="SIMULATED",
                details=(
                    f"Dry-run simulation completed (ZERO live production execution): "
                    f"{action.proposed_action}"
                ),
            ),
        ]
        updated = action.model_copy(
            update={
                "approval_status": "SIMULATED",
                "approved_by": approver,
                "audit_trail": updated_trail,
            }
        )
        self.db.save_remediation(updated)
        return updated

    def rollback_remediation(
        self,
        remediation_id: str,
        tenant_id: str,
        actor: str,
    ) -> RemediationAction:
        action = self.db.get_remediation(remediation_id, tenant_id)
        if action is None:
            raise KeyError(f"Remediation '{remediation_id}' not found for tenant '{tenant_id}'")
        if action.approval_status != "SIMULATED":
            raise ValueError(
                f"Rollback requires status 'SIMULATED' (current: '{action.approval_status}')."
            )

        now = utc_now()
        updated_trail = list(action.audit_trail) + [
            RemediationAuditEntry(
                timestamp_utc=now,
                actor=actor,
                action="ROLLED_BACK",
                details=f"Simulated rollback executed cleanly: {action.rollback_plan}",
            )
        ]
        updated = action.model_copy(
            update={
                "approval_status": "ROLLED_BACK",
                "audit_trail": updated_trail,
            }
        )
        self.db.save_remediation(updated)
        return updated