from __future__ import annotations

import uuid

import pytest

from conftest import login as _login
from helpers import ALICE

_PROJECT_SLUG = "dossier-test"


def test_read_evidence_summary(gateway, make_issue):
    make_issue(title="Evidence test")
    from dossier.evidence import read_evidence_summary

    summary = read_evidence_summary(gateway, _PROJECT_SLUG)
    assert summary.project_slug == _PROJECT_SLUG
    assert summary.total_events > 0
    assert summary.verified_events >= 0
    assert summary.unverified_events >= 0
    assert summary.verified_events + summary.unverified_events == summary.total_events
    assert isinstance(summary.chain_intact, bool)
    assert isinstance(summary.findings, tuple)


def test_read_evidence_summary_chain_intact(gateway, make_issue):
    make_issue(title="Chain intact test")
    from dossier.evidence import read_evidence_summary

    summary = read_evidence_summary(gateway, _PROJECT_SLUG)
    assert summary.chain_intact is True


def test_read_event_verifications(gateway, make_issue):
    make_issue(title="Verification test")
    from dossier.evidence import read_event_verifications

    verifications = read_event_verifications(gateway, limit=50)
    assert len(verifications) > 0
    for v in verifications:
        assert v.event_id
        assert v.work_item_id
        assert isinstance(v.verified, bool)
        assert v.timestamp is not None


def test_read_integrity_report(gateway, make_issue):
    make_issue(title="Integrity report test")
    from dossier.evidence import read_integrity_report

    report = read_integrity_report(gateway)
    assert "replayed_ok" in report
    assert "replayed_drift" in report
    assert "halted" in report
    assert "warnings" in report
    assert "chain_intact" in report
    assert report["chain_intact"] is True
    assert report["replayed_drift"] == 0


def test_read_integrity_report_with_work_item_id(gateway, make_issue):
    wi = make_issue(title="Scoped integrity test")
    from dossier.evidence import read_integrity_report

    report = read_integrity_report(gateway, work_item_id=wi.work_item_id)
    assert report["work_item_id"] == str(wi.work_item_id)
    assert report["chain_intact"] is True


def test_evidence_index_requires_login(client):
    resp = client.get("/evidence", follow_redirects=False)
    assert resp.status_code == 302
    assert resp.headers["location"] == "/login"


def test_evidence_index_returns_200(client, make_issue):
    make_issue(title="Evidence route test")
    _login(client)
    resp = client.get("/evidence")
    assert resp.status_code == 200
    assert "evidence" in resp.text.lower()


def test_evidence_integrity_route_returns_200(client, make_issue):
    make_issue(title="Integrity route test")
    _login(client)
    resp = client.get("/evidence/integrity")
    assert resp.status_code == 200
    assert "integrity" in resp.text.lower()


def test_evidence_events_route_returns_200(client, make_issue):
    make_issue(title="Events route test")
    _login(client)
    resp = client.get("/evidence/events")
    assert resp.status_code == 200
    assert "verification" in resp.text.lower() or "event" in resp.text.lower()


def test_evidence_summary_counts_verified_and_unverified(gateway, make_issue):
    make_issue(title="Count test")
    from dossier.evidence import read_evidence_summary

    summary = read_evidence_summary(gateway, _PROJECT_SLUG)
    assert summary.total_events == summary.verified_events + summary.unverified_events
