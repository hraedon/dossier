from __future__ import annotations

from .actors import Actor


def can_read_project(actor: Actor, project: str) -> bool:
    """The single authorization seam for project read access (Plan 014 WI-1.1).

    In v1 this returns ``True`` for any authenticated actor — the plan
    ships flat-open *knowingly*, with the enforcement path already designed.
    The v1.1 milestone will consult a project↔team/role mapping (defaulting
    open); v1.5 will flip enforcement on.

    Every project-listing and project-entering path MUST route through this
    function. A test (``test_authz_seam``) verifies no code bypasses it by
    reaching a project's gateway without calling this check.

    To enable per-project permissions in v1.1/v1.5, replace the body with a
    lookup against the project catalog's team/role mapping — the call sites
    are already in place.
    """
    return True
