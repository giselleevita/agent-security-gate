from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

import pytest

from saferemediate.harness.execution import (
    ADAPTER_FAMILIES,
    EffectLedger,
    EnforcementDenied,
    EnforcementProfile,
    FaultProfile,
    InjectedFault,
    InstrumentedExecutor,
    SingleUseGrantRegistry,
    raise_decision_fault,
)


PARAMS = {"path": "/public/readme"}


def _strict(*, fault: FaultProfile = FaultProfile.NONE):
    grants = SingleUseGrantRegistry()
    ledger = EffectLedger()
    executor = InstrumentedExecutor(
        profile=EnforcementProfile.ASG_STRICT,
        grants=grants,
        ledger=ledger,
        fault=fault,
    )
    return grants, ledger, executor


def test_all_ten_adapter_families_are_instrumentable():
    assert len(ADAPTER_FAMILIES) == 10
    for family in ADAPTER_FAMILIES:
        executor = InstrumentedExecutor(
            profile=EnforcementProfile.NO_GATE, adapter_family=family
        )
        receipt = executor.execute(
            audit_id=f"evt-{family}",
            tool="tool.call",
            params={},
            tenant_id="acme",
        )
        assert receipt.adapter == family


def test_strict_rejects_missing_wrong_tenant_and_expired_grants():
    grants, ledger, executor = _strict()
    with pytest.raises(EnforcementDenied):
        executor.execute(audit_id="missing", tool="docs.read", params=PARAMS, tenant_id="acme")
    grants.issue(audit_id="wrong", tool="docs.read", params=PARAMS, tenant_id="acme")
    with pytest.raises(EnforcementDenied, match="operation mismatch"):
        executor.execute(audit_id="wrong", tool="docs.read", params=PARAMS, tenant_id="other")
    grants.issue(audit_id="expired", tool="docs.read", params=PARAMS, tenant_id="acme", ttl_s=-1)
    with pytest.raises(EnforcementDenied, match="expired"):
        executor.execute(audit_id="expired", tool="docs.read", params=PARAMS, tenant_id="acme")
    assert ledger.committed_count == 0


def test_one_of_100_concurrent_redemptions_commits():
    grants, ledger, executor = _strict()
    grants.issue(audit_id="evt-race", tool="docs.read", params=PARAMS, tenant_id="acme")

    def attempt(_index: int) -> bool:
        try:
            executor.execute(
                audit_id="evt-race",
                tool="docs.read",
                params=PARAMS,
                tenant_id="acme",
                execution_id="exec-race",
            )
            return True
        except EnforcementDenied:
            return False

    with ThreadPoolExecutor(max_workers=20) as pool:
        accepted = list(pool.map(attempt, range(100)))
    assert sum(accepted) == 1
    assert ledger.committed_count == 1


def test_duplicate_delivery_is_idempotent_in_no_gate_profile():
    ledger = EffectLedger()
    executor = InstrumentedExecutor(profile=EnforcementProfile.NO_GATE, ledger=ledger)
    first = executor.execute(
        audit_id="evt-1", tool="docs.read", params=PARAMS, tenant_id="acme", execution_id="exec-1"
    )
    second = executor.execute(
        audit_id="evt-2", tool="docs.read", params=PARAMS, tenant_id="acme", execution_id="exec-1"
    )
    assert first.execution_id == second.execution_id
    assert ledger.committed_count == 1


@pytest.mark.parametrize(
    "fault",
    [
        FaultProfile.OPA_TIMEOUT,
        FaultProfile.OPA_MALFORMED,
        FaultProfile.APPROVAL_STORE_UNAVAILABLE,
        FaultProfile.MODEL_TIMEOUT,
        FaultProfile.MODEL_RATE_LIMIT,
    ],
)
def test_decision_and_provider_faults_stop_execution(fault):
    with pytest.raises(InjectedFault):
        raise_decision_fault(fault)


@pytest.mark.parametrize(
    "fault",
    [FaultProfile.GRANT_STORE_UNAVAILABLE, FaultProfile.AUDIT_WRITE_FAILURE, FaultProfile.ADAPTER_PRECOMMIT_CRASH],
)
def test_execution_faults_commit_no_effect(fault):
    grants, ledger, executor = _strict(fault=fault)
    grants.issue(audit_id="evt-fault", tool="docs.read", params=PARAMS, tenant_id="acme")
    with pytest.raises((EnforcementDenied, InjectedFault)):
        executor.execute(audit_id="evt-fault", tool="docs.read", params=PARAMS, tenant_id="acme")
    assert ledger.committed_count == 0
