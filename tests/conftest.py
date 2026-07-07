from __future__ import annotations

import pytest

import app.main as main


@pytest.fixture(autouse=True)
def _reset_asg_clients():
    """Dispose the shared pooled clients between tests so monkeypatched backends and
    per-test environment overrides take effect and don't leak across tests."""
    main._reset_clients()
    yield
    main._reset_clients()
