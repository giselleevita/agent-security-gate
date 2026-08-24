from scripts.check_version_consistency import ROOT, collect_errors


def test_public_version_surfaces_are_consistent() -> None:
    assert collect_errors(ROOT) == []


def test_release_tag_must_match_project_version() -> None:
    errors = collect_errors(ROOT, tag="v999.0.0")
    assert any(error.startswith("release tag:") for error in errors)
