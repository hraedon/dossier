"""Review-assurance rendering — **delegated to regista** (dossier WI-012).

dossier does not compute the assurance level. It asks regista, the suite's
single authoritative store, and renders the answer. This module is the one
seam between regista's assurance contract and dossier's display vocabulary.

Delegation (WI-012, closed)
---------------------------
The authoritative computation is :func:`regista.gate_rationale`, part of
regista's public API since 0.5.3 (regista Plan 027). One call returns both
the level *and* the evidence it rests on::

    {"assurance_level": AssuranceLevel, "reviewer_lineage": str | None,
     "author_lineages": list[str], "reason": str, "profile": str}

We pass the events dossier has already read rather than calling the
store-side ``Regista.assurance.compute_assurance(work_item_id)`` facade,
which would re-read the same event log per rendered row (an N+1 against the
store). Both paths run the identical regista function on the identical
events; ``gate_rationale`` additionally returns the lineage evidence, which
the store-side ``compute_assurance`` does not.

Honest degradation (dossier WI-014, preserved)
-----------------------------------------------
regista's ``same_lineage()`` returns ``False`` when the reviewer's lineage is
**undeclared** — so an undeclared review is reported as *independent*. That
is a fail-open for a UI whose entire point is not over-claiming. dossier does
not recompute anything to fix this: it takes regista's level plus the
evidence regista returned, and **downgrades any independence claim that has
no lineage evidence behind it**, flagging the verdict as degraded. If the
locked spine does not expose the v6 author-lineage evidence field, dossier
marks independence as unverifiable rather than reconstructing lineage from
``actor_metadata``. Rendering less than the engine claims is always safe;
rendering more never is.

Display vocabulary (unchanged, four levels):

- ``unreviewed``: no adversarial review in the log.
- ``self-reviewed``: the review shares a model lineage with the author's
  events — or independence could not be *verified* (undeclared lineage).
- ``independently-reviewed``: a cross-lineage adversarial review passed, with
  both sides' lineages declared.
- ``human-accepted``: a human accepted the reviewed work.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

from regista import Event as Event  # type: ignore[attr-defined]
from regista import gate_rationale

# The gate profile dossier renders against. It affects only the ``reason``
# field (and ``gate_permits_done``), never ``assurance_level`` — dossier is
# deployed behind the strict two-stage review gate, so it asks strictly.
_GATE_PROFILE = "strict"

# regista's AssuranceLevel values -> dossier's display vocabulary.
_REGISTA_TO_DISPLAY = {
    "none": "unreviewed",
    "self_reviewed": "self-reviewed",
    "independently_reviewed": "independently-reviewed",
    "human_accepted": "human-accepted",
    "independently_and_accepted": "human-accepted",
}

# The regista levels that assert cross-lineage independence, and what each
# degrades to when the evidence for that assertion is missing.
_INDEPENDENCE_DOWNGRADE = {
    "independently_reviewed": "self-reviewed",
    "independently_and_accepted": "human-accepted",
}

_UNKNOWN_LEVEL = "unreviewed"

@dataclass(frozen=True, slots=True)
class AssuranceVerdict:
    """What dossier renders, plus the provenance of the answer.

    ``level`` is what the UI shows. ``regista_level`` is what the engine
    said. When they differ, ``degraded`` is True and ``degradation_reason``
    says exactly why dossier claims less than regista did.
    """

    level: str
    regista_level: str
    source: str
    reviewer_lineage: str | None
    author_lineages: tuple[str, ...]
    degraded: bool
    degradation_reason: str | None
    undeclared_agent_author: bool = False
    author_lineage_evidence_available: bool = True

    @property
    def independence_verifiable(self) -> bool:
        """True when the evidence for an independence claim holds up."""
        return (
            self.author_lineage_evidence_available
            and bool(self.reviewer_lineage)
            and not self.undeclared_agent_author
        )


def compute_assurance_verdict(events: Sequence[Event]) -> AssuranceVerdict:
    """Ask regista for the assurance level; render it honestly.

    Named ``compute_*`` for continuity with the call sites, but the level is
    not computed here — it comes from :func:`regista.gate_rationale`. The only
    local decision is whether regista's answer over-claims independence
    relative to the evidence (see module docstring); that check inspects the
    event log for *evidence*, it never derives a level of its own.
    """
    event_list = list(events)
    rationale = gate_rationale(event_list, _GATE_PROFILE)
    declared_by_engine = rationale.get("agent_author_undeclared")
    author_lineage_evidence_available = isinstance(declared_by_engine, bool)
    undeclared_agent_author = (
        bool(declared_by_engine) if author_lineage_evidence_available else False
    )
    return _verdict_from_rationale(
        rationale,
        undeclared_agent_author=undeclared_agent_author,
        author_lineage_evidence_available=author_lineage_evidence_available,
    )


def _verdict_from_rationale(
    rationale: dict[str, Any],
    *,
    undeclared_agent_author: bool = False,
    author_lineage_evidence_available: bool = True,
) -> AssuranceVerdict:
    raw_level = rationale.get("assurance_level")
    # AssuranceLevel is a StrEnum; str() gives the wire value either way.
    regista_level = str(raw_level) if raw_level is not None else "none"

    reviewer_lineage_raw = rationale.get("reviewer_lineage")
    reviewer_lineage = str(reviewer_lineage_raw) if reviewer_lineage_raw else None
    author_lineages_raw = rationale.get("author_lineages") or []
    author_lineages = tuple(str(x) for x in author_lineages_raw if x)

    display = _REGISTA_TO_DISPLAY.get(regista_level)
    if display is None:
        # An assurance level this dossier does not know about. Do not guess a
        # generous reading — render the floor and say so.
        return AssuranceVerdict(
            level=_UNKNOWN_LEVEL,
            regista_level=regista_level,
            source="regista",
            reviewer_lineage=reviewer_lineage,
            author_lineages=author_lineages,
            degraded=True,
            degradation_reason=(
                f"regista reported assurance level {regista_level!r}, which this "
                "dossier build does not know how to render; showing the floor"
            ),
            undeclared_agent_author=undeclared_agent_author,
            author_lineage_evidence_available=author_lineage_evidence_available,
        )

    downgrade = _INDEPENDENCE_DOWNGRADE.get(regista_level)
    if downgrade is not None:
        missing = _missing_independence_evidence(
            reviewer_lineage,
            undeclared_agent_author,
            author_lineage_evidence_available,
        )
        if missing is not None:
            return AssuranceVerdict(
                level=downgrade,
                regista_level=regista_level,
                source="regista",
                reviewer_lineage=reviewer_lineage,
                author_lineages=author_lineages,
                degraded=True,
                degradation_reason=missing,
                undeclared_agent_author=undeclared_agent_author,
                author_lineage_evidence_available=author_lineage_evidence_available,
            )

    return AssuranceVerdict(
        level=display,
        regista_level=regista_level,
        source="regista",
        reviewer_lineage=reviewer_lineage,
        author_lineages=author_lineages,
        degraded=False,
        degradation_reason=None,
        undeclared_agent_author=undeclared_agent_author,
        author_lineage_evidence_available=author_lineage_evidence_available,
    )


def _missing_independence_evidence(
    reviewer_lineage: str | None,
    undeclared_agent_author: bool,
    author_lineage_evidence_available: bool,
) -> str | None:
    """Why an independence claim cannot be verified, or ``None`` if it can."""
    if not author_lineage_evidence_available:
        return (
            "independence not verifiable: regista did not provide the v6 author-"
            "lineage evidence needed to evaluate the independence claim"
        )
    if not reviewer_lineage:
        return (
            "independence not verifiable: the reviewer declared no model "
            "lineage, so it cannot be shown to differ from the author's"
        )
    if undeclared_agent_author:
        return (
            "independence not verifiable: an agent authored this item without "
            "declaring a model lineage"
        )
    return None


def compute_assurance_level(events: Sequence[Event]) -> str:
    """The display assurance level for an item's event history.

    Thin accessor over :func:`compute_assurance_verdict` for the call sites
    that only need the badge text.
    """
    return compute_assurance_verdict(events).level


def assurance_label(level: str) -> str:
    """Human-readable label for an assurance level."""
    return {
        "human-accepted": "human-accepted",
        "independently-reviewed": "independently reviewed",
        "self-reviewed": "self-reviewed (same lineage)",
        "unreviewed": "unreviewed",
    }.get(level, level)


def assurance_class(level: str) -> str:
    """CSS class suffix for the assurance badge."""
    return {
        "human-accepted": "ok",
        "independently-reviewed": "ok",
        "self-reviewed": "warn",
        "unreviewed": "muted",
    }.get(level, "muted")
