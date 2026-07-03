"""Auth & identity for dossier.

This package is the root of provenance guarantee G1
(``docs/provenance-model.md``): it resolves an authenticated principal into the
:class:`~dossier.actors.Actor` that the regista gateway injects into every
signed event. There is no path here that constructs an Actor from client input
— the actor is built only from verified credentials
(``CredentialBackend.authenticate``) and the signed session.
"""

from __future__ import annotations
