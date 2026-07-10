"""Pytest configuration for SafeRemediate."""

from pathlib import Path

import pytest

_ASG_ROOT = Path(__file__).resolve().parents[2]
_SR_ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture(scope="session", autouse=True)
def _configure_asg_paths():
    import os

    os.environ.setdefault(
        "POLICY_DATA_PATH",
        str(_ASG_ROOT / "policies" / "data" / "policy_data.json"),
    )
