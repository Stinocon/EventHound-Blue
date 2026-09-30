"""Knowledge interface tests — ATT&CK map and compliance obligations."""

from __future__ import annotations

import pytest

from core.knowledge import attack_version, obligations_for, technique


def test_attack_version_is_vendored():
    version = attack_version()
    assert version and version[0].isdigit(), "vendored ATT&CK version expected"


def test_technique_lookup():
    t = technique("T1059.001")  # Command and Scripting Interpreter: PowerShell
    assert t["id"] == "T1059.001"
    assert "name" in t and t["name"]
    assert "execution" in [tac.lower() for tac in t["tactics"]]


def test_technique_accepts_lowercase_spelling():
    """The map normalizes the case (timelines carry 'T1204.002', but any
    casing must resolve to the canonical ID)."""
    t = technique("t1059.001")
    assert t["id"] == "T1059.001"


def test_technique_rejects_non_id():
    with pytest.raises(ValueError, match="not a technique ID"):
        technique("not-a-technique")


def test_obligations_gdpr_breach():
    pytest.importorskip(
        "yaml", reason="PyYAML is a tools/compliance dependency"
    )
    out = obligations_for({"personal_data_breach": True})
    assert "gdpr-33-authority" in {o["id"] for o in out["obligations"]}
    art33 = next(
        o for o in out["obligations"] if o["id"] == "gdpr-33-authority"
    )
    assert art33["within_hours"] == 72


def test_obligations_empty_incident():
    pytest.importorskip(
        "yaml", reason="PyYAML is a tools/compliance dependency"
    )
    out = obligations_for({})
    assert out["obligations"] == []
