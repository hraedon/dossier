"""Tests for Plan 011 WI-4 — cross-project reference rendering.

Covers:
- ``list_links`` gateway method (delegates to regista)
- Web helpers for link URL construction and label rendering
- Template rendering of links on the issue detail page
"""

from __future__ import annotations

import uuid
from types import SimpleNamespace

from conftest import login as _login
from dossier.web import (
    is_cross_project_link,
    link_target_label,
    link_target_url,
)


def _mock_link(
    *,
    to_id: uuid.UUID | None = None,
    link_type: str = "relates_to",
    target_project: str | None = None,
) -> SimpleNamespace:
    return SimpleNamespace(
        link_id=uuid.uuid4(),
        from_work_item_id=uuid.uuid4(),
        to_work_item_id=to_id or uuid.uuid4(),
        link_type=link_type,
        payload=None,
        target_project=target_project,
        target_entity_kind="work_item" if target_project else None,
        content_hash=None,
    )


def test_link_target_url_intra_project():
    link = _mock_link(target_project=None)
    url = link_target_url(link, "dossier-test")
    assert url == f"/p/dossier-test/issues/{link.to_work_item_id}"


def test_link_target_url_cross_project():
    link = _mock_link(target_project="agent_notes")
    url = link_target_url(link, "dossier-test")
    assert url.startswith("/p/agent-notes/issues/")


def test_link_target_url_cross_project_slug_conversion():
    link = _mock_link(target_project="cert_watch")
    url = link_target_url(link, "dossier-test")
    assert "/p/cert-watch/issues/" in url


def test_is_cross_project_link_true():
    link = _mock_link(target_project="other")
    assert is_cross_project_link(link) is True


def test_is_cross_project_link_false():
    link = _mock_link(target_project=None)
    assert is_cross_project_link(link) is False


def test_link_target_label_cross_project():
    link = _mock_link(target_project="agent_notes")
    label = link_target_label(link)
    assert "agent-notes" in label


def test_link_target_label_with_known_issue():
    to_id = uuid.uuid4()
    link = _mock_link(to_id=to_id, target_project=None)
    issue = SimpleNamespace(
        work_item_id=to_id,
        custom_fields={"title": "Bug X", "display_key": "DOSSIER-1"},
    )
    label = link_target_label(link, {to_id: issue})
    assert "DOSSIER-1" in label
    assert "Bug X" in label


def test_link_target_label_fallback_uuid():
    to_id = uuid.UUID("12345678-1234-1234-1234-123456789abc")
    link = _mock_link(to_id=to_id, target_project=None)
    label = link_target_label(link)
    assert "12345678" in label


def test_issue_detail_shows_links_section(client, gateway, make_issue, monkeypatch):
    """The issue detail page renders a 'linked items' section when links exist."""
    _login(client)
    wi = make_issue(title="Source bug")

    link = _mock_link(target_project="other_proj")
    monkeypatch.setattr(
        gateway, "list_links", lambda _wid: [link]
    )

    detail = client.get(f"/p/dossier-test/issues/{wi.work_item_id}")
    assert detail.status_code == 200
    assert "linked items" in detail.text.lower()
    assert "cross-project" in detail.text.lower()


def test_issue_detail_no_links_section_when_empty(client, make_issue):
    """No 'linked items' section when there are zero links."""
    _login(client)
    wi = make_issue(title="Lonely bug")
    detail = client.get(f"/p/dossier-test/issues/{wi.work_item_id}")
    assert detail.status_code == 200
    assert "linked items" not in detail.text.lower()


def test_list_links_gateway_returns_empty_for_no_links(gateway, make_issue):
    wi = make_issue()
    links = gateway.list_links(wi.work_item_id)
    assert links == []


def test_list_links_gateway_returns_intra_project_link(gateway, make_issue):
    """list_links returns live links created via the InMemory backend."""
    from regista._contract import Jsonb
    from regista._event_store import append_event as _store_append

    wi1 = make_issue(title="A")
    wi2 = make_issue(title="B")

    link_id = uuid.uuid4()
    payload = {
        "link_id": str(link_id),
        "from_work_item_id": str(wi1.work_item_id),
        "to_work_item_id": str(wi2.work_item_id),
        "link_type": "relates_to",
        "target_project": "other_proj",
        "target_entity_kind": "work_item",
    }
    _store_append(
        gateway._reg._store,
        work_item_id=wi1.work_item_id,
        actor_id="alice",
        actor_kind="human",
        actor_metadata=None,
        workflow_name="canonical",
        workflow_version=2,
        transition="link_created",
        payload=Jsonb(payload),
        event_id=uuid.uuid4(),
        key_set=gateway._reg._key_set,
    )

    links = gateway.list_links(wi1.work_item_id)
    assert len(links) == 1
    assert links[0].link_type == "relates_to"
    assert links[0].target_project == "other_proj"
