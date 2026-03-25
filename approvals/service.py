from __future__ import annotations

from dataclasses import dataclass
from uuid import uuid4


@dataclass(slots=True)
class ApprovalRequest:
    request_id: str
    tool: str
    status: str
    approver: str | None = None


class ApprovalService:
    def __init__(self) -> None:
        self._requests: dict[str, ApprovalRequest] = {}

    def create(self, tool: str) -> ApprovalRequest:
        approval = ApprovalRequest(request_id=str(uuid4()), tool=tool, status="pending")
        self._requests[approval.request_id] = approval
        return approval

    def resolve(self, request_id: str, approver: str, approved: bool) -> ApprovalRequest:
        approval = self._requests[request_id]
        approval.status = "approved" if approved else "denied"
        approval.approver = approver
        return approval
