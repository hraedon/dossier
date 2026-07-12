from __future__ import annotations

from dataclasses import FrozenInstanceError

import pytest

from dossier.shell import (
    ActionRisk,
    Availability,
    ConsoleArea,
    Freshness,
    PageAction,
    Status,
    area_for_path,
    build_shell,
)
from helpers import ALICE


def test_shell_contract_enums_are_closed() -> None:
    assert set(ConsoleArea) == {
        ConsoleArea.WORK,
        ConsoleArea.KNOWLEDGE,
        ConsoleArea.ACTIVITY,
        ConsoleArea.EVIDENCE,
        ConsoleArea.OPERATIONS,
        ConsoleArea.ADMINISTRATION,
    }
    assert {item.value for item in Availability} == {
        "available",
        "degraded",
        "unavailable",
        "unsupported",
        "unreachable",
        "not_configured",
        "unknown",
    }
    assert {item.value for item in Freshness} == {"current", "stale", "partial", "unknown"}
    assert {item.value for item in Status} == {"ok", "info", "warning", "failed", "unknown"}
    assert {item.value for item in ActionRisk} == {
        "routine", "sensitive", "high", "irreversible"
    }


def test_shell_contracts_are_immutable() -> None:
    shell = build_shell("/", ALICE, is_admin=False)
    with pytest.raises(FrozenInstanceError):
        shell.area = ConsoleArea.ACTIVITY  # type: ignore[misc]


def test_area_mapping_and_active_navigation() -> None:
    assert area_for_path("/p/example/issues/123") is ConsoleArea.WORK
    assert area_for_path("/p/example/sessions/123") is ConsoleArea.ACTIVITY
    assert area_for_path("/me/identity") is ConsoleArea.ADMINISTRATION

    shell = build_shell("/sessions", ALICE, is_admin=False)
    assert [item.area for item in shell.navigation if item.active] == [ConsoleArea.ACTIVITY]
    assert shell.page.title == "Agent activity"


def test_role_aware_administration_destination() -> None:
    regular = build_shell("/", ALICE, is_admin=False)
    admin = build_shell("/", ALICE, is_admin=True)
    regular_item = next(i for i in regular.navigation if i.area is ConsoleArea.ADMINISTRATION)
    admin_item = next(i for i in admin.navigation if i.area is ConsoleArea.ADMINISTRATION)
    assert regular_item.href == "/me/identity"
    assert regular_item.availability is Availability.AVAILABLE
    assert admin_item.href == "/admin"
    assert admin_item.availability is Availability.AVAILABLE


def test_page_action_rejects_unknown_method() -> None:
    assert PageAction("Inspect", "/inspect", method="get").method == "GET"
    with pytest.raises(ValueError, match="GET or POST"):
        PageAction("Delete", "/delete", method="DELETE")


def test_rendered_shell_has_accessible_landmarks_and_current_area(client) -> None:
    from conftest import login

    login(client)
    response = client.get("/activity")
    assert response.status_code == 200
    assert 'href="#main-content"' in response.text
    assert '<main class="ds-page" id="main-content" tabindex="-1">' in response.text
    assert 'aria-label="Suite areas"' in response.text
    assert 'href="/activity" class="ds-primary-nav__item is-active"' in response.text
    assert 'aria-current="page"' in response.text
    assert 'aria-label="User menu for Alice"' in response.text


def test_all_areas_are_available_links(client) -> None:
    from conftest import login

    login(client)
    response = client.get("/")
    assert 'href="/knowledge"' in response.text
    assert 'href="/evidence"' in response.text
    assert 'href="/operations"' in response.text
    assert 'href="/activity"' in response.text
