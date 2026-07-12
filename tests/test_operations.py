from __future__ import annotations

import pytest

from conftest import login as _login
from helpers import ALICE

_PROJECT_SLUG = "dossier-test"
_ALICE_ID = "11111111-1111-1111-1111-111111111111"


def test_read_estate_summary(gateway, make_issue):
    make_issue(title="Estate test")
    from dossier.operations import read_estate_summary

    estate = read_estate_summary(gateway, _PROJECT_SLUG)
    assert estate.project_slug == _PROJECT_SLUG
    assert len(estate.components) > 0
    assert isinstance(estate.overall_healthy, bool)
    assert isinstance(estate.findings, tuple)

    component_names = [c.name for c in estate.components]
    assert "regista-pool" in component_names
    assert "regista-maintenance" in component_names
    assert "principal-ops" in component_names


def test_read_estate_summary_reports_health(gateway, make_issue):
    make_issue(title="Health test")
    from dossier.operations import read_estate_summary

    estate = read_estate_summary(gateway, _PROJECT_SLUG)
    for comp in estate.components:
        assert comp.name
        assert isinstance(comp.healthy, bool)
        assert comp.observed_at is not None


def test_read_estate_summary_chain_component(gateway, make_issue):
    make_issue(title="Chain component test")
    from dossier.operations import read_estate_summary

    estate = read_estate_summary(gateway, _PROJECT_SLUG)
    chain = next(c for c in estate.components if c.name == "event-chain")
    assert chain.healthy is True


def test_read_operations_findings(gateway, make_issue):
    make_issue(title="Findings test")
    from dossier.operations import read_operations_findings

    findings = read_operations_findings(gateway)
    assert len(findings) > 0
    for f in findings:
        assert f.code
        assert f.label
        assert f.status


def test_read_operations_findings_in_memory_backend(gateway, make_issue):
    make_issue(title="Healthy findings test")
    from dossier.operations import read_operations_findings

    findings = read_operations_findings(gateway)
    has_principal_info = any(f.code == "principal_ops_unavailable" for f in findings)
    assert has_principal_info


def test_operations_index_requires_login(client):
    resp = client.get("/operations", follow_redirects=False)
    assert resp.status_code == 302
    assert resp.headers["location"] == "/login"


def test_operations_index_returns_200(client, make_issue):
    make_issue(title="Operations route test")
    _login(client)
    resp = client.get("/operations")
    assert resp.status_code == 200
    assert "operations" in resp.text.lower()


def test_operations_index_shows_components(client, make_issue):
    make_issue(title="Components display test")
    _login(client)
    resp = client.get("/operations")
    assert resp.status_code == 200
    assert "regista-pool" in resp.text or "pool" in resp.text.lower()
