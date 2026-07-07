from __future__ import annotations

import time

from fastapi import APIRouter, Depends, Query
from starlette.responses import Response

from app.audit_export import build_audit_package
from app.auth import verify_approver
from app.config import audit_hmac_key as _audit_hmac_key
from app.config import audit_log_path as _audit_log_path
from app.config import policy_data_path as _policy_data_path
from app.policy import tenant_policy_path as _tenant_policy_path

router = APIRouter()


@router.post("/v1/audit/export", dependencies=[Depends(verify_approver)])
def audit_export(
    tenant_id: str | None = Query(default=None, description="Limit export to one tenant"),
) -> Response:
    """
    Approver-only: build a self-verifying auditor export package (.tar.gz).

    Contains the audit chain (or a per-tenant subset), a policy snapshot, a manifest with
    per-file checksums (optionally HMAC-signed), and an embedded offline verifier.
    """
    # Snapshot the tenant's policy when scoping to a tenant, else the default policy.
    policy_path = _policy_data_path()
    if tenant_id is not None:
        tenant_path = _tenant_policy_path(tenant_id)
        if tenant_path is not None and tenant_path.is_file():
            policy_path = tenant_path

    package = build_audit_package(
        audit_path=_audit_log_path(),
        policy_path=policy_path,
        tenant_id=tenant_id,
        hmac_key=_audit_hmac_key(),
    )
    stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    suffix = f"-{tenant_id}" if tenant_id else ""
    filename = f"asg-audit-export{suffix}-{stamp}.tar.gz"
    return Response(
        content=package,
        media_type="application/gzip",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
