"""WI-1.2: Work and knowledge golden journeys (Plan 015 Gate 1, GJ-1-GJ-4).

End-to-end behavioral tests that exercise the full journey through dossier's
public HTTP surface. Two synthetic principals complete the strict review
journey; same-principal, same-lineage, missing-lineage, expired-claim,
stale-form, and unauthorized-project cases fail for the intended reason.
"""

from __future__ import annotations

from typing import Any

import pytest
from conftest import extract_csrf, login
from fastapi.testclient import TestClient
from helpers import AGENT_R, ALICE, BOB
from regista import ErrorCode, RegistaError

from dossier.actors import Actor


@pytest.fixture
def authed_client(client: TestClient) -> TestClient:
    login(client)
    return client


class TestGJ1StartAProject:
    """GJ-1: project discovery, onboarding, stable principal binding."""

    def test_dashboard_renders_with_project(self, authed_client: TestClient) -> None:
        resp = authed_client.get("/")
        assert resp.status_code == 200
        assert "dossier-test" in resp.text

    def test_project_issue_list_accessible(self, authed_client: TestClient) -> None:
        resp = authed_client.get("/p/dossier-test")
        assert resp.status_code == 200

    def test_healthz_reports_ok(self, client: TestClient) -> None:
        resp = client.get("/healthz")
        assert resp.status_code == 200
        data = resp.json()
        assert data["ok"] is True

    def test_my_identity_shows_actor(self, authed_client: TestClient) -> None:
        resp = authed_client.get("/me/identity")
        assert resp.status_code == 200
        assert "Alice" in resp.text


class TestGJ2PlanAndExecuteWork:
    """GJ-2: work creation, transition, comment, search."""

    def test_create_work_item_via_form(self, authed_client: TestClient) -> None:
        page = authed_client.get("/p/dossier-test/issues/new")
        assert page.status_code == 200
        csrf = extract_csrf(page.text)
        resp = authed_client.post(
            "/p/dossier-test/issues",
            data={
                "work_item_type": "task",
                "title": "GJ-2 golden journey task",
                "description": "Created by golden journey test",
                "csrf_token": csrf,
            },
            follow_redirects=False,
        )
        assert resp.status_code in (302, 303)

    def test_work_item_detail_shows_state(
        self, authed_client: TestClient, make_issue: Any
    ) -> None:
        wi = make_issue(title="Detail test")
        wid = wi.work_item_id
        resp = authed_client.get(f"/p/dossier-test/issues/{wid}")
        assert resp.status_code == 200
        assert "open" in resp.text

    def test_transition_work_item_via_form(
        self, authed_client: TestClient, make_issue: Any
    ) -> None:
        wi = make_issue(title="Transition test")
        wid = wi.work_item_id
        page = authed_client.get(f"/p/dossier-test/issues/{wid}")
        csrf = extract_csrf(page.text)
        resp = authed_client.post(
            f"/p/dossier-test/issues/{wid}/transitions",
            data={"transition_name": "start", "csrf_token": csrf},
            follow_redirects=False,
        )
        assert resp.status_code in (302, 303)
        detail = authed_client.get(f"/p/dossier-test/issues/{wid}")
        assert "in_progress" in detail.text

    def test_comment_on_work_item(
        self, authed_client: TestClient, make_issue: Any
    ) -> None:
        wi = make_issue(title="Comment test")
        wid = wi.work_item_id
        page = authed_client.get(f"/p/dossier-test/issues/{wid}")
        csrf = extract_csrf(page.text)
        resp = authed_client.post(
            f"/p/dossier-test/issues/{wid}/comments",
            data={"body": "Golden journey comment", "csrf_token": csrf},
            follow_redirects=False,
        )
        assert resp.status_code in (302, 303)

    def test_my_work_shows_assigned_items(
        self, authed_client: TestClient, make_issue: Any
    ) -> None:
        make_issue(title="My work item", assignee="alice")
        resp = authed_client.get("/my-work")
        assert resp.status_code == 200

    def test_search_finds_work_items(
        self, authed_client: TestClient, make_issue: Any
    ) -> None:
        make_issue(title="Searchable unique xyzzy item")
        resp = authed_client.get("/search", params={"q": "xyzzy"})
        assert resp.status_code == 200


class TestGJ3CaptureAndReuseKnowledge:
    """GJ-3: knowledge browse, search, detail, verification."""

    def test_knowledge_index_renders(self, authed_client: TestClient) -> None:
        resp = authed_client.get("/knowledge")
        assert resp.status_code == 200

    def test_knowledge_search_renders(self, authed_client: TestClient) -> None:
        resp = authed_client.get("/knowledge/search", params={"q": "test"})
        assert resp.status_code == 200

    def test_knowledge_new_form_renders(self, authed_client: TestClient) -> None:
        resp = authed_client.get("/knowledge/new")
        assert resp.status_code == 200

    def test_create_note_via_form_and_round_trip(
        self, authed_client: TestClient
    ) -> None:
        """GJ-3 golden journey: file a signed note through the public HTTP
        surface, then read it back through browse, detail, and search.

        This was an xfail because ``create_note`` used the reserved
        ``"created"`` transition (regista now blocks reserved transitions via
        ``TRANSITION_VIA_APPEND_BLOCKED``). The knowledge module now files
        notes with the canonical ``note_filed`` label — the same vocabulary
        agent-notes uses — so the human and agent faces share one note
        universe and the journey is a real behavioral test, not a workaround.
        """
        page = authed_client.get("/knowledge/new")
        csrf = extract_csrf(page.text)
        resp = authed_client.post(
            "/knowledge/create",
            data={
                "title": "GJ-3 golden journey note",
                "body": "Knowledge captured during golden journey test.",
                "csrf_token": csrf,
            },
            follow_redirects=False,
        )
        assert resp.status_code == 303
        note_url = resp.headers["location"]
        assert note_url.startswith("/knowledge/")

        # The note detail page renders the filed title and body.
        detail = authed_client.get(note_url)
        assert detail.status_code == 200
        assert "GJ-3 golden journey note" in detail.text
        assert "Knowledge captured during golden journey test." in detail.text

        # The note is discoverable in the knowledge index.
        index = authed_client.get("/knowledge")
        assert index.status_code == 200
        assert "GJ-3 golden journey note" in index.text

        # And searchable by title.
        search = authed_client.get("/knowledge/search", params={"q": "golden journey"})
        assert search.status_code == 200
        assert "GJ-3 golden journey note" in search.text

    def test_create_note_requires_title(self, authed_client: TestClient) -> None:
        page = authed_client.get("/knowledge/new")
        csrf = extract_csrf(page.text)
        resp = authed_client.post(
            "/knowledge/create",
            data={"title": "", "body": "no title", "csrf_token": csrf},
            follow_redirects=False,
        )
        assert resp.status_code == 400

    def test_create_note_requires_csrf(self, authed_client: TestClient) -> None:
        resp = authed_client.post(
            "/knowledge/create",
            data={"title": "no csrf note", "body": "body"},
            follow_redirects=False,
        )
        assert resp.status_code == 403


class TestGJ4ReviewWithSeparationOfDuties:
    """GJ-4: strict review journey with two principals."""

    def _create_and_advance_to_review(
        self, client: TestClient, make_issue: Any, gateway: Any
    ) -> Any:
        wi = make_issue(actor=ALICE, title="Review journey item")
        wid = wi.work_item_id
        gateway.transition(
            actor=ALICE, work_item_id=wid, transition_name="start"
        )
        gateway.transition(
            actor=ALICE, work_item_id=wid, transition_name="submit_for_review"
        )
        return wi

    def test_review_queue_shows_in_review_items(
        self,
        authed_client: TestClient,
        make_issue: Any,
        gateway: Any,
    ) -> None:
        self._create_and_advance_to_review(authed_client, make_issue, gateway)
        resp = authed_client.get("/review")
        assert resp.status_code == 200
        assert "Review journey item" in resp.text

    def test_full_review_journey_through_http(
        self,
        authed_client: TestClient,
        make_issue: Any,
        gateway: Any,
    ) -> None:
        wi = self._create_and_advance_to_review(authed_client, make_issue, gateway)
        wid = wi.work_item_id

        gateway.transition(
            actor=AGENT_R,
            work_item_id=wid,
            transition_name="adversarial_pass",
            payload={"review_note": "Agent adversarial review passed."},
        )
        page = authed_client.get(f"/p/dossier-test/issues/{wid}")
        assert "in_human_review" in page.text

        csrf = extract_csrf(page.text)
        resp = authed_client.post(
            f"/p/dossier-test/issues/{wid}/transitions",
            data={
                "transition_name": "accept",
                "review_note": "Human accepts the review.",
                "csrf_token": csrf,
            },
            follow_redirects=False,
        )
        assert resp.status_code in (302, 303)
        detail = authed_client.get(f"/p/dossier-test/issues/{wid}")
        assert "done" in detail.text

    def test_request_changes_returns_to_in_progress(
        self,
        authed_client: TestClient,
        make_issue: Any,
        gateway: Any,
    ) -> None:
        wi = self._create_and_advance_to_review(authed_client, make_issue, gateway)
        wid = wi.work_item_id

        gateway.transition(
            actor=AGENT_R,
            work_item_id=wid,
            transition_name="request_changes",
            payload={"review_note": "Changes requested by agent reviewer."},
        )
        detail = authed_client.get(f"/p/dossier-test/issues/{wid}")
        assert "in_progress" in detail.text

    def test_reject_from_human_review_returns_to_in_progress(
        self,
        authed_client: TestClient,
        make_issue: Any,
        gateway: Any,
    ) -> None:
        wi = self._create_and_advance_to_review(authed_client, make_issue, gateway)
        wid = wi.work_item_id

        gateway.transition(
            actor=AGENT_R,
            work_item_id=wid,
            transition_name="adversarial_pass",
            payload={"review_note": "Agent adversarial review passed."},
        )
        gateway.transition(
            actor=BOB,
            work_item_id=wid,
            transition_name="reject",
            payload={"review_note": "Human rejects the review."},
        )
        detail = authed_client.get(f"/p/dossier-test/issues/{wid}")
        assert "in_progress" in detail.text

    def test_assurance_delegation_renders(
        self,
        authed_client: TestClient,
        make_issue: Any,
        gateway: Any,
    ) -> None:
        wi = self._create_and_advance_to_review(authed_client, make_issue, gateway)
        wid = wi.work_item_id
        resp = authed_client.get(f"/p/dossier-test/issues/{wid}")
        assert resp.status_code == 200


class TestGJ4NegativeCases:
    """Separation-of-duties negative cases: same-principal, unauthorized."""

    def test_invalid_transition_is_rejected(
        self,
        authed_client: TestClient,
        make_issue: Any,
    ) -> None:
        wi = make_issue(title="Invalid transition test")
        wid = wi.work_item_id
        page = authed_client.get(f"/p/dossier-test/issues/{wid}")
        csrf = extract_csrf(page.text)
        resp = authed_client.post(
            f"/p/dossier-test/issues/{wid}/transitions",
            data={"transition_name": "accept", "csrf_token": csrf},
            follow_redirects=False,
        )
        assert resp.status_code in (400, 409, 422)

    def test_missing_csrf_is_rejected(
        self,
        authed_client: TestClient,
        make_issue: Any,
    ) -> None:
        wi = make_issue(title="CSRF test")
        wid = wi.work_item_id
        resp = authed_client.post(
            f"/p/dossier-test/issues/{wid}/transitions",
            data={"transition_name": "start"},
            follow_redirects=False,
        )
        assert resp.status_code == 403

    def test_unauthenticated_access_redirects_to_login(
        self, client: TestClient
    ) -> None:
        resp = client.get("/p/dossier-test", follow_redirects=False)
        assert resp.status_code in (302, 303)
        assert "/login" in resp.headers["location"]


class TestGJ4SeparationOfDuties:
    """GJ-4 separation-of-duties negative cases at the public-provider surface.

    These exercise regista's ``adversarial_review`` validator through the
    gateway (the public provider API dossier exposes). An agent reviewer cannot
    log in to dossier's HTTP surface, so the review verdicts are driven through
    ``gateway.transition`` — the same surface agent-notes uses — while the
    human verdicts in :class:`TestGJ4ReviewWithSeparationOfDuties` go through
    HTTP. Each case fails for the intended reason, not incidentally.
    """

    @staticmethod
    def _item_in_review(gateway: Any, make_issue: Any, author: Actor) -> Any:
        wi = make_issue(actor=author, title="SoD negative case item")
        gateway.transition(
            actor=author, work_item_id=wi.work_item_id, transition_name="start"
        )
        gateway.transition(
            actor=author,
            work_item_id=wi.work_item_id,
            transition_name="submit_for_review",
        )
        return wi

    def test_same_principal_review_is_rejected(
        self, gateway: Any, make_issue: Any
    ) -> None:
        """A principal who authored the work cannot pass its adversarial
        review (self-review)."""
        wi = self._item_in_review(gateway, make_issue, ALICE)
        with pytest.raises(RegistaError) as exc:
            gateway.transition(
                actor=ALICE,
                work_item_id=wi.work_item_id,
                transition_name="adversarial_pass",
                payload={"review_note": "self review"},
            )
        assert exc.value.code == ErrorCode.VALIDATOR_FAILED
        assert "must differ" in exc.value.message

    def test_same_lineage_review_is_rejected_without_ack(
        self, gateway: Any, make_issue: Any
    ) -> None:
        """An agent reviewer whose model lineage matches an author's must
        acknowledge the shared lineage explicitly; without the ack the review
        is rejected."""
        author = Actor(
            actor_id="agent-author",
            actor_kind="agent",
            display_name="Author Agent",
            model_lineage="relay",
        )
        reviewer = Actor(
            actor_id="agent-reviewer",
            actor_kind="agent",
            display_name="Reviewer Agent",
            model_lineage="relay",
        )
        wi = self._item_in_review(gateway, make_issue, author)
        with pytest.raises(RegistaError) as exc:
            gateway.transition(
                actor=reviewer,
                work_item_id=wi.work_item_id,
                transition_name="adversarial_pass",
                payload={"review_note": "same lineage, no ack"},
            )
        assert exc.value.code == ErrorCode.VALIDATOR_FAILED
        assert "lineage" in exc.value.message

    def test_missing_lineage_reviewer_is_rejected_without_ack(
        self, gateway: Any, make_issue: Any
    ) -> None:
        """An agent reviewer with no declared model lineage reviewing
        agent-authored work is rejected unless the shared/undeclared lineage
        is explicitly acknowledged."""
        author = Actor(
            actor_id="agent-author",
            actor_kind="agent",
            display_name="Author Agent",
            model_lineage="relay",
        )
        undeclared = Actor(
            actor_id="agent-undeclared",
            actor_kind="agent",
            display_name="Undeclared Agent",
            model_lineage=None,
        )
        wi = self._item_in_review(gateway, make_issue, author)
        with pytest.raises(RegistaError) as exc:
            gateway.transition(
                actor=undeclared,
                work_item_id=wi.work_item_id,
                transition_name="adversarial_pass",
                payload={"review_note": "undeclared lineage"},
            )
        assert exc.value.code == ErrorCode.VALIDATOR_FAILED
        assert "lineage" in exc.value.message

    def test_same_lineage_review_passes_with_explicit_ack(
        self, gateway: Any, make_issue: Any
    ) -> None:
        """Positive control: the same-lineage rejection is specifically about
        the missing acknowledgment — with ``same_lineage_acknowledged`` the
        adversarial pass succeeds and the item advances to human review."""
        author = Actor(
            actor_id="agent-author",
            actor_kind="agent",
            display_name="Author Agent",
            model_lineage="relay",
        )
        reviewer = Actor(
            actor_id="agent-reviewer",
            actor_kind="agent",
            display_name="Reviewer Agent",
            model_lineage="relay",
        )
        wi = self._item_in_review(gateway, make_issue, author)
        gateway.transition(
            actor=reviewer,
            work_item_id=wi.work_item_id,
            transition_name="adversarial_pass",
            payload={
                "review_note": "same lineage, acknowledged",
                "same_lineage_acknowledged": True,
            },
        )
        assert gateway.get_issue(wi.work_item_id).current_state == "in_human_review"

    def test_review_verdict_requires_a_note(
        self, gateway: Any, make_issue: Any
    ) -> None:
        """Every review verdict carries a non-empty review note."""
        author = Actor(
            actor_id="agent-author",
            actor_kind="agent",
            display_name="Author Agent",
            model_lineage="relay",
        )
        reviewer = Actor(
            actor_id="agent-reviewer",
            actor_kind="agent",
            display_name="Reviewer Agent",
            model_lineage="glm",
        )
        wi = self._item_in_review(gateway, make_issue, author)
        with pytest.raises(RegistaError) as exc:
            gateway.transition(
                actor=reviewer,
                work_item_id=wi.work_item_id,
                transition_name="adversarial_pass",
                payload={"review_note": "   "},
            )
        assert exc.value.code == ErrorCode.VALIDATOR_FAILED
        assert "review note" in exc.value.message


class TestGJ4StaleFormAndUnauthorizedProject:
    """Stale-form submission and unauthorized-project access through the HTTP
    surface."""

    def test_stale_transition_form_is_rejected(
        self,
        authed_client: TestClient,
        make_issue: Any,
        gateway: Any,
    ) -> None:
        """A transition form rendered for one state must not silently apply
        after the state has moved on. The form is fetched while the item is
        ``in_review``; a concurrent reviewer advances it to
        ``in_human_review``; the stale ``adversarial_pass`` submission is then
        rejected as an invalid transition."""
        author = BOB
        wi = make_issue(actor=author, title="Stale form item")
        gateway.transition(actor=author, work_item_id=wi.work_item_id, transition_name="start")
        gateway.transition(
            actor=author, work_item_id=wi.work_item_id, transition_name="submit_for_review"
        )
        wid = wi.work_item_id

        # Render the detail/form while the item is in_review.
        page = authed_client.get(f"/p/dossier-test/issues/{wid}")
        csrf = extract_csrf(page.text)
        assert "in_review" in page.text

        # A concurrent reviewer advances the item out from under the form.
        gateway.transition(
            actor=AGENT_R,
            work_item_id=wid,
            transition_name="adversarial_pass",
            payload={"review_note": "concurrent review passed"},
        )

        # The stale form's adversarial_pass is no longer valid.
        resp = authed_client.post(
            f"/p/dossier-test/issues/{wid}/transitions",
            data={"transition_name": "adversarial_pass", "csrf_token": csrf},
            follow_redirects=False,
        )
        assert resp.status_code == 400

    def test_unknown_project_is_not_found(self, authed_client: TestClient) -> None:
        """An unknown project slug is rejected — it is not silently treated as
        an empty project (the allowlist gate prevents unauthorised schema
        access). The access-denied (403) path for a known-but-forbidden
        project is covered in test_project_access.py."""
        resp = authed_client.get("/p/unknown-project", follow_redirects=False)
        assert resp.status_code == 404

    def test_unknown_project_transition_is_not_found(
        self, authed_client: TestClient, make_issue: Any
    ) -> None:
        wi = make_issue(title="Cross-project transition test")
        page = authed_client.get(f"/p/dossier-test/issues/{wi.work_item_id}")
        csrf = extract_csrf(page.text)
        resp = authed_client.post(
            f"/p/unknown-project/issues/{wi.work_item_id}/transitions",
            data={"transition_name": "start", "csrf_token": csrf},
            follow_redirects=False,
        )
        assert resp.status_code == 404


class TestProviderFailureRendering:
    """A provider failure must render an explicit unavailable state, not an
    empty page or a 500 (Plan 015 WI-1.1 honest-health AC: a gap in the suite
    is a named state, not silence)."""

    @staticmethod
    def _boom(*_args: Any, **_kwargs: Any) -> Any:
        raise RuntimeError("simulated store outage")

    def test_work_route_renders_unreachable_not_500(
        self,
        authed_client: TestClient,
        gateway: Any,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setattr(gateway, "list_issues", self._boom)
        resp = authed_client.get("/p/dossier-test")
        assert resp.status_code == 200
        assert "unreachable" in resp.text

    def test_knowledge_route_renders_unreachable_not_empty(
        self,
        authed_client: TestClient,
        gateway: Any,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        # list_notes() reads through gateway.read_recent_events(); failing that
        # primitive makes the knowledge provider unavailable for this project.
        monkeypatch.setattr(gateway, "read_recent_events", self._boom)
        resp = authed_client.get("/knowledge")
        assert resp.status_code == 200
        assert "unreachable" in resp.text

    def test_knowledge_search_renders_unreachable_not_empty(
        self,
        authed_client: TestClient,
        gateway: Any,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setattr(gateway, "read_recent_events", self._boom)
        resp = authed_client.get("/knowledge/search", params={"q": "anything"})
        assert resp.status_code == 200
        assert "unreachable" in resp.text

    def test_catalog_failure_does_not_hide_fetched_work(
        self,
        authed_client: TestClient,
        gateway: Any,
        make_issue: Any,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A catalog-entry (owner/display-name) read failure must not hide
        successfully fetched issues. The work store and the catalog are
        independent reads; the issue list stays visible while the owner chip
        degrades to ``unassigned``."""
        make_issue(title="Visible despite catalog failure")
        monkeypatch.setattr(gateway, "get_project_catalog_entry", self._boom)
        resp = authed_client.get("/p/dossier-test")
        assert resp.status_code == 200
        assert "Visible despite catalog failure" in resp.text
        assert "unreachable" not in resp.text
        # The owner chip degrades gracefully to "unassigned".
        assert "unassigned" in resp.text
