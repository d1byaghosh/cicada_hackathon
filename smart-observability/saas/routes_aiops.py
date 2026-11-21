from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel

from saas.aiops import ExplainableAIOpsEngine
from saas.database import SaaSMetadataDB
from saas.remediation import SafeRemediationSimulator
from shared.contracts import CorrelatedIncident, RemediationAction


class ApprovalRequest(BaseModel):
    approver: str = "sre-oncall"


class RollbackRequest(BaseModel):
    actor: str = "sre-oncall"


def create_aiops_router(
    db: SaaSMetadataDB,
    aiops_engine: ExplainableAIOpsEngine,
    remediation_sim: SafeRemediationSimulator,
) -> APIRouter:
    """
    Tenant-scoped AIOps & Safe Remediation router.
    Plugs into saas/main.py via a single app.include_router(...) call.
    """
    router = APIRouter(prefix="/api/v1", tags=["AIOps & Safe Remediation"])

    @router.get("/incidents", response_model=list[CorrelatedIncident])
    async def list_incidents(
        tenant_id: str = Query(..., min_length=1),
        limit: int = Query(default=50, ge=1, le=200),
    ) -> list[CorrelatedIncident]:
        return db.get_incidents(tenant_id=tenant_id, limit=limit)

    @router.get("/remediations", response_model=list[RemediationAction])
    async def list_remediations(
        tenant_id: str = Query(..., min_length=1),
        limit: int = Query(default=50, ge=1, le=200),
    ) -> list[RemediationAction]:
        return db.get_remediations(tenant_id=tenant_id, limit=limit)

    @router.post("/remediations/{remediation_id}/approve", response_model=RemediationAction)
    async def approve_remediation(
        remediation_id: str,
        tenant_id: str = Query(..., min_length=1),
        body: ApprovalRequest = ApprovalRequest(),
    ) -> RemediationAction:
        try:
            return remediation_sim.approve_remediation(
                remediation_id=remediation_id,
                tenant_id=tenant_id,
                approver=body.approver,
            )
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @router.post("/remediations/{remediation_id}/rollback", response_model=RemediationAction)
    async def rollback_remediation(
        remediation_id: str,
        tenant_id: str = Query(..., min_length=1),
        body: RollbackRequest = RollbackRequest(),
    ) -> RemediationAction:
        try:
            return remediation_sim.rollback_remediation(
                remediation_id=remediation_id,
                tenant_id=tenant_id,
                actor=body.actor,
            )
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    # Expose engine reference on router for clean inspection/testing
    router.aiops_engine = aiops_engine  # type: ignore[attr-defined]
    router.remediation_sim = remediation_sim  # type: ignore[attr-defined]
    return router