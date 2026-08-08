"""Per-actor signing for human actions (WI-035).

The defect these tests pin down came out of the Plan 020 Lane C Linux
qualification: an agent authored a work item, a cross-lineage agent reviewed it,
a human accepted it through dossier's web face, and the chain verified like this::

    seq | actor_id                             | kind  | key_id              | scheme
      1 | qual-author                          | agent | pk_27d291ec18b8490f | ed25519
      2 | qual-author                          | agent | pk_27d291ec18b8490f | ed25519
      3 | qual-author                          | agent | pk_27d291ec18b8490f | ed25519
      4 | qual-reviewer                        | agent | pk_1ca753730f2b4470 | ed25519
      5 | 4814fec5-7b84-4f61-ae43-99a91dc76a63 | human | qual-linux-2026-07  | hmac-sha256

    Bundle verified - 5 event(s), 4 signature(s) verified, 1 unverifiable
    (symmetric scheme)

Three agent legs signed with their own Ed25519 keys. The human's ``accept`` — the
one signature the review gate exists to record — was signed with
``qual-linux-2026-07``, the shared store-level HMAC key. Anyone holding that key
could produce it. The human's ``actor_id`` was the ``users.json`` stable_id uuid;
the provisioned principal was ``qual-human`` with key ``pk_c7507e4caba447aa``, a
different identifier, so regista's ``resolve_signing_key`` found nothing bound to
the acting id and fell back to ``active_key()``. Silently.

``InMemoryRegista`` reproduces this exactly: it resolves signing keys through the
same ``KeySet.resolve_signing_key`` the Postgres backend uses, so a key-set
manifest carrying a per-principal Ed25519 entry produces real Ed25519 signatures
that ``verify_event_signature`` and the offline bundle verifier accept.
"""

from __future__ import annotations

import base64
import json
import logging
from pathlib import Path

import pytest
from regista.testing import InMemoryRegista
from test_ldap import _MockEntry

from dossier.actors import Actor
from dossier.auth.backends import LdapBackend, LocalBackend, Principal
from dossier.auth.resolver import principal_to_actor
from dossier.authz import AccessGrant
from dossier.gateway import RegistaGateway
from dossier.keys import generate_keyset
from dossier.signing import HumanSigningRefusedError, parse_policy

# The qualification's actual identifiers, so the reproduction is not merely
# shaped like the defect but is the defect.
QUAL_STABLE_ID = "4814fec5-7b84-4f61-ae43-99a91dc76a63"
QUAL_PRINCIPAL = "qual-human"

# The human gate requires a non-empty review note on every verdict.
ACCEPT_PAYLOAD = {"review_note": "accepted after review"}


# ── fixtures ──────────────────────────────────────────────────────────────


def _add_ed25519_principal(
    key_path: Path, key_dir: Path, principal_id: str
) -> tuple[str, bytes]:
    """Register a per-principal Ed25519 key in the key-set manifest.

    Mirrors what ``agent-suite bootstrap --user <principal_id>`` /
    ``regista provision-principal`` leave behind: a 0600 private key file plus a
    manifest entry binding ``key_id`` → ``principal_id`` with the public half
    inline for verification. Returns ``(key_id, public_key)``.
    """
    import nacl.signing

    signing_key = nacl.signing.SigningKey.generate()
    key_dir.mkdir(parents=True, exist_ok=True)
    private_path = key_dir / f"{principal_id}_ed25519.key"
    private_path.write_bytes(bytes(signing_key))
    private_path.chmod(0o600)

    public_key = bytes(signing_key.verify_key)
    key_id = f"pk_{principal_id.replace('-', '_')}"
    manifest = json.loads(key_path.read_text())
    manifest["keys"].append(
        {
            "key_id": key_id,
            "scheme": "ed25519",
            "principal_id": principal_id,
            "secret_ref": f"file:{private_path}",
            "public_key": base64.b64encode(public_key).decode("ascii"),
            "role": "actor",
            "status": "active",
        }
    )
    key_path.write_text(json.dumps(manifest, indent=2))
    return key_id, public_key


@pytest.fixture
def suite(tmp_path):
    """A store HMAC key plus per-principal Ed25519 keys for the qual cast.

    Deliberately includes both: the store key is what the defect falls back to,
    so a fixture without it could not reproduce the downgrade.
    """
    key_path = tmp_path / "keys.json"
    store = generate_keyset(key_path)
    store_key_id = store["keys"][0]["key_id"]
    key_dir = tmp_path / "principals"

    keys: dict[str, bytes] = {}
    ids: dict[str, str] = {}
    for principal in (QUAL_PRINCIPAL, "qual-author", "qual-reviewer", "ldap-human"):
        key_id, public_key = _add_ed25519_principal(key_path, key_dir, principal)
        keys[principal] = public_key
        ids[principal] = key_id

    return {
        "key_path": key_path,
        "key_dir": key_dir,
        "store_key_id": store_key_id,
        "public_keys": keys,
        "key_ids": ids,
    }


def _gateway(suite, *, policy="warn", project="wi035"):
    reg = InMemoryRegista(project=project, hmac_key_path=str(suite["key_path"]))
    gw = RegistaGateway(reg, project_name=project, human_signing=policy)
    gw.register_workflow()
    InMemoryRegista._catalog.clear()
    return gw


@pytest.fixture
def gw_warn(suite):
    gw = _gateway(suite, policy="warn")
    yield gw
    InMemoryRegista._catalog.clear()
    gw.close()


@pytest.fixture
def gw_require(suite):
    gw = _gateway(suite, policy="require", project="wi035_req")
    yield gw
    InMemoryRegista._catalog.clear()
    gw.close()


def _local_users_file(tmp_path: Path, *, principal_id: str | None) -> Path:
    from dossier.auth.passwords import hash_password

    entry = {
        "stable_id": QUAL_STABLE_ID,
        "username": QUAL_PRINCIPAL,
        "display_name": "Qual Human",
        "password": hash_password("s3cret"),
        "groups": [],
    }
    if principal_id is not None:
        entry["principal_id"] = principal_id
    path = tmp_path / "users.json"
    path.write_text(json.dumps([entry]))
    return path


def _agent(actor_id="qual-author"):
    return Actor(
        actor_id=actor_id,
        actor_kind="agent",
        display_name="Qual Author",
        model_lineage="glm",
    )


def _drive_to_review(gw, author, *, reviewer=None):
    """Author + cross-lineage agent review, leaving the item in ``in_human_review``.

    The same shape as the qualification run: three agent legs then a human
    acceptance. Stops one step short so the caller owns the human transition.
    """
    wi, _ = gw.create_issue(
        actor=author,
        work_item_type="bug",
        custom_fields={"title": "WI-035 reproduction", "assignee": author.actor_id},
    )
    wid = wi.work_item_id
    gw.transition(actor=author, work_item_id=wid, transition_name="start")
    gw.transition(actor=author, work_item_id=wid, transition_name="submit_for_review")
    gw.transition(
        actor=reviewer or _reviewer(),
        work_item_id=wid,
        transition_name="adversarial_pass",
        payload={"review_note": "cross-lineage review complete"},
    )
    return wid


def _reviewer():
    """The cross-lineage reviewer agent, with its own provisioned key.

    A distinct principal from the author: regista's ``adversarial_review``
    validator rejects a self-review, and the qualification's chain had a separate
    ``qual-reviewer`` leg for exactly that reason.
    """
    return Actor(
        actor_id="qual-reviewer",
        actor_kind="agent",
        display_name="Qual Reviewer",
        model_lineage="kimi",
    )


# ── (a) identity binding ──────────────────────────────────────────────────


def test_local_identity_binds_to_recorded_principal_id(tmp_path):
    """A ``principal_id`` on the user record becomes the signing actor_id.

    The binding must land on ``actor_id`` and nowhere else: regista's offline
    bundle verifier rejects any event whose ``actor_id`` differs from its key's
    ``principal_id``, so a "principal_id kept alongside a uuid actor_id" design
    cannot produce a verifiable human signature at all.
    """
    backend = LocalBackend(_local_users_file(tmp_path, principal_id=QUAL_PRINCIPAL))
    principal = backend.authenticate(QUAL_PRINCIPAL, "s3cret")
    assert principal is not None
    assert principal.principal_id == QUAL_PRINCIPAL

    actor = principal_to_actor(principal, backend.fetch_groups(principal))
    assert actor.actor_id == QUAL_PRINCIPAL
    assert actor.principal_id == QUAL_PRINCIPAL
    # the stable_id survives as an authorization alias, never for signing
    assert actor.alias_actor_ids == (QUAL_STABLE_ID,)


def test_local_identity_without_principal_id_is_unbound(tmp_path):
    """No derivation. An unrecorded binding is reported as absent, not guessed.

    Deriving a principal_id from the username or the stable_id would claim a
    signing identity the suite may never have provisioned a key for — which is
    how the defect reads to an operator today ("DOSSIER_PRINCIPAL_KEY_DIR was set
    correctly, so surely it's bound").
    """
    backend = LocalBackend(_local_users_file(tmp_path, principal_id=None))
    principal = backend.authenticate(QUAL_PRINCIPAL, "s3cret")
    assert principal is not None
    assert principal.principal_id is None

    actor = principal_to_actor(principal)
    assert actor.actor_id == QUAL_STABLE_ID
    assert actor.principal_id is None
    assert actor.alias_actor_ids == ()


def test_local_users_file_rejects_a_malformed_principal_id(tmp_path):
    """A typo fails at load, not on somebody's acceptance."""
    path = tmp_path / "users.json"
    path.write_text(
        json.dumps(
            [
                {
                    "stable_id": QUAL_STABLE_ID,
                    "username": "u",
                    "display_name": "U",
                    "password": "x",
                    "principal_id": "not a valid id!",
                }
            ]
        )
    )
    with pytest.raises(ValueError, match="alphanumeric"):
        LocalBackend(path)


def test_ldap_identity_binds_via_the_configured_attribute():
    """The LDAP backend reads the binding from a directory attribute.

    This estate runs LDAP in production (``DOSSIER_AUTH_BACKEND=ldap``), where
    there is no users file to annotate. The binding therefore has to come from the
    directory, and from an attribute the operator names — never a hardcoded one.
    """
    backend = LdapBackend(
        server_urls=["ldaps://dc.example.test"],
        base_dn="dc=example,dc=test",
        bind_dn="cn=svc,dc=example,dc=test",
        bind_password="pw",
        domain="example.test",
        ca_cert_file="/dev/null",
        principal_id_attr="employeeNumber",
    )

    entry = _MockEntry(
        "cn=Ldap Human,dc=example,dc=test",
        {"objectGUID": b"\x00" * 16, "employeeNumber": "ldap-human"},
    )
    assert backend._read_principal_id(entry, "lhuman") == "ldap-human"


def test_ldap_identity_is_unbound_when_no_attribute_is_configured():
    """Unset attribute means unbound — an upgrade cannot silently re-key users.

    If the default were ``sAMAccountName``, upgrading dossier would change the
    ``actor_id`` of every LDAP human at once, orphaning their history and their
    ACL entries. Opt-in is the only safe default.
    """
    backend = LdapBackend(
        server_urls=["ldaps://dc.example.test"],
        base_dn="dc=example,dc=test",
        bind_dn="cn=svc,dc=example,dc=test",
        bind_password="pw",
        domain="example.test",
        ca_cert_file="/dev/null",
    )

    entry = _MockEntry(
        "cn=Ldap Human,dc=example,dc=test",
        {"objectGUID": b"\x00" * 16, "sAMAccountName": "lhuman"},
    )
    assert backend._read_principal_id(entry, "lhuman") is None


def test_binding_keeps_acl_entries_written_against_the_stable_id(tmp_path):
    """Provisioning signing must not lock the operator out.

    An existing deployment's ACL and ``DOSSIER_BOOTSTRAP_ADMINS`` name the
    pre-binding id (the qual host lists both, precisely because of this split).
    Binding changes ``actor_id``, so authorization matches on the alias union.
    """
    backend = LocalBackend(_local_users_file(tmp_path, principal_id=QUAL_PRINCIPAL))
    principal = backend.authenticate(QUAL_PRINCIPAL, "s3cret")
    assert principal is not None
    actor = principal_to_actor(principal)

    legacy = AccessGrant(frozenset({QUAL_STABLE_ID}), frozenset())
    assert legacy.matches(actor), "an ACL naming the old stable_id must still match"

    modern = AccessGrant(frozenset({QUAL_PRINCIPAL}), frozenset())
    assert modern.matches(actor)

    stranger = AccessGrant(frozenset({"someone-else"}), frozenset())
    assert not stranger.matches(actor)


# ── the defect: reproduction and fix ──────────────────────────────────────


def test_unbound_human_acceptance_falls_back_to_the_store_hmac_key(gw_warn, suite):
    """The defect itself, reproduced: seq 5 of the qualification chain.

    Kept as a passing test on purpose. It is the *precondition* of the fix, and it
    documents that the fallback still exists in regista — dossier's job is to
    ensure a human write never reaches it silently, not to remove it.
    """
    author = _agent()
    wid = _drive_to_review(gw_warn, author)
    unbound = Actor(
        actor_id=QUAL_STABLE_ID, actor_kind="human", display_name="Qual Human"
    )

    event = gw_warn.transition(
        actor=unbound, work_item_id=wid, transition_name="accept", payload=ACCEPT_PAYLOAD
    )

    assert event.scheme_id == "hmac-sha256"
    assert event.key_id == suite["store_key_id"]


def test_bound_human_acceptance_is_signed_with_that_humans_own_key(gw_warn, suite):
    """The fix: the human leg carries an Ed25519 signature under their own key.

    This is the acceptance criterion from agent-suite ``docs/bootstrap-contract.md``
    §5 — the mixed human+agent chain verifying "with per-actor signatures".
    """
    author = _agent()
    wid = _drive_to_review(gw_warn, author)
    bound = principal_to_actor(
        Principal(
            stable_id=QUAL_STABLE_ID,
            display_name="Qual Human",
            source="local",
            principal_id=QUAL_PRINCIPAL,
        )
    )

    event = gw_warn.transition(
        actor=bound, work_item_id=wid, transition_name="accept", payload=ACCEPT_PAYLOAD
    )

    assert event.scheme_id == "ed25519"
    assert event.key_id == suite["key_ids"][QUAL_PRINCIPAL]
    assert event.key_id != suite["store_key_id"]
    assert event.actor_id == QUAL_PRINCIPAL


def test_bound_human_signature_verifies_against_the_registered_public_key(
    gw_warn, suite
):
    """Independent verification with only the public half — non-repudiation.

    Verifies twice: through regista's registry-driven check, and against the raw
    Ed25519 public key on its own, which is what an offline auditor holds.
    """
    author = _agent()
    wid = _drive_to_review(gw_warn, author)
    bound = principal_to_actor(
        Principal(
            stable_id=QUAL_STABLE_ID,
            display_name="Qual Human",
            source="local",
            principal_id=QUAL_PRINCIPAL,
        )
    )
    event = gw_warn.transition(
        actor=bound, work_item_id=wid, transition_name="accept", payload=ACCEPT_PAYLOAD
    )

    info = gw_warn.verify_event(event)
    assert info["verified"] is True
    assert info["signature_valid"] is True
    assert info["signer_registered"] is True
    assert info["scheme"] == "ed25519"
    assert info["principal_id"] == QUAL_PRINCIPAL

    public_key = suite["public_keys"][QUAL_PRINCIPAL]
    assert gw_warn._reg.verify_event_signature(event, public_key=public_key) is True

    # ...and it must NOT verify under another principal's public key
    other = suite["public_keys"]["qual-author"]
    assert gw_warn._reg.verify_event_signature(event, public_key=other) is False


def test_whole_mixed_chain_verifies_per_actor(gw_warn, suite):
    """Every leg of the human+agent chain attributable to its own principal.

    The qualification's verdict was "4 signatures verified, 1 unverifiable
    (symmetric scheme)". Here every event — including the human's — carries an
    asymmetric signature bound to the acting principal.
    """
    author = _agent()
    wid = _drive_to_review(gw_warn, author)
    bound = principal_to_actor(
        Principal(
            stable_id=QUAL_STABLE_ID,
            display_name="Qual Human",
            source="local",
            principal_id=QUAL_PRINCIPAL,
        )
    )
    gw_warn.transition(
        actor=bound, work_item_id=wid, transition_name="accept", payload=ACCEPT_PAYLOAD
    )

    events = gw_warn.history(wid)
    assert [e.scheme_id for e in events] == ["ed25519"] * len(events)
    assert all(gw_warn.verify_event(e)["verified"] for e in events)

    human_events = [e for e in events if e.actor_kind == "human"]
    assert len(human_events) == 1
    assert human_events[0].transition == "accept"
    assert human_events[0].key_id == suite["key_ids"][QUAL_PRINCIPAL]


def test_bound_human_comment_and_create_are_also_per_actor(gw_warn, suite):
    """Not just transitions: every human write carries their own signature.

    Special-casing ``accept`` would leave a comment — which can carry the
    substance of a decision — signed by the store.
    """
    bound = principal_to_actor(
        Principal(
            stable_id=QUAL_STABLE_ID,
            display_name="Qual Human",
            source="local",
            principal_id=QUAL_PRINCIPAL,
        )
    )
    wi, create_event = gw_warn.create_issue(
        actor=bound, work_item_type="bug", custom_fields={"title": "human-authored"}
    )
    assert create_event.scheme_id == "ed25519"
    assert create_event.key_id == suite["key_ids"][QUAL_PRINCIPAL]

    comment = gw_warn.comment(
        actor=bound, work_item_id=wi.work_item_id, body="my judgement"
    )
    assert comment.scheme_id == "ed25519"
    assert comment.key_id == suite["key_ids"][QUAL_PRINCIPAL]


def test_agent_and_system_writes_are_untouched(gw_warn, suite):
    """The policy governs human actors only.

    Agents already resolve their own key (their ``actor_id`` *is* their
    ``principal_id``), and the system actor legitimately signs with the store key —
    it is the store. Refusing those would brick project registration.
    """
    from dossier.actors import SYSTEM_ACTOR

    author = _agent()
    wid = _drive_to_review(gw_warn, author)
    events = gw_warn.history(wid)
    assert all(e.scheme_id == "ed25519" for e in events)

    identity = gw_warn.human_signing_identity(SYSTEM_ACTOR, "probe")
    assert identity.per_actor is False
    assert identity.reason == "not a human actor"


# ── (b) refusal and loudness ──────────────────────────────────────────────


def test_require_policy_refuses_an_unbound_human_transition(gw_require):
    """Refuse, do not downgrade. And write nothing.

    The refusal has to happen before the append: a half-recorded acceptance would
    be worse than either outcome.
    """
    author = _agent()
    wid = _drive_to_review(gw_require, author)
    unbound = Actor(
        actor_id=QUAL_STABLE_ID, actor_kind="human", display_name="Qual Human"
    )
    before = len(gw_require.history(wid))

    with pytest.raises(HumanSigningRefusedError) as excinfo:
        gw_require.transition(
            actor=unbound,
            work_item_id=wid,
            transition_name="accept",
            payload=ACCEPT_PAYLOAD,
        )

    assert len(gw_require.history(wid)) == before, "nothing may be appended"
    assert gw_require.get_issue(wid).current_state == "in_human_review"

    message = str(excinfo.value)
    assert "no regista principal_id recorded" in message
    assert "agent-suite bootstrap --user" in message
    assert "shared store key" in message
    assert excinfo.value.detail["error"] == "human_signing_required"
    assert excinfo.value.detail["actor_id"] == QUAL_STABLE_ID


def test_require_policy_names_the_missing_key_when_the_binding_exists(gw_require):
    """Bound but unprovisioned is a different fix, so it gets a different message."""
    author = _agent()
    wid = _drive_to_review(gw_require, author)
    bound_but_keyless = principal_to_actor(
        Principal(
            stable_id=QUAL_STABLE_ID,
            display_name="Nobody",
            source="local",
            principal_id="never-provisioned",
        )
    )

    with pytest.raises(HumanSigningRefusedError) as excinfo:
        gw_require.transition(
            actor=bound_but_keyless,
            work_item_id=wid,
            transition_name="accept",
            payload=ACCEPT_PAYLOAD,
        )

    message = str(excinfo.value)
    assert "never-provisioned" in message
    assert "no active per-actor asymmetric signing key" in message


def test_require_policy_permits_a_bound_human(gw_require, suite):
    """Fail-closed must still let a correctly provisioned human work."""
    author = _agent()
    wid = _drive_to_review(gw_require, author)
    bound = principal_to_actor(
        Principal(
            stable_id=QUAL_STABLE_ID,
            display_name="Qual Human",
            source="local",
            principal_id=QUAL_PRINCIPAL,
        )
    )
    event = gw_require.transition(
        actor=bound, work_item_id=wid, transition_name="accept", payload=ACCEPT_PAYLOAD
    )
    assert event.scheme_id == "ed25519"
    assert event.key_id == suite["key_ids"][QUAL_PRINCIPAL]


def test_warn_policy_logs_the_downgrade_loudly(gw_warn, caplog):
    """``warn`` is the escape hatch, and it is not allowed to be quiet.

    The qualification's complaint was that "nothing in the UI, the response, or
    the doctor says the acceptance was signed with a shared symmetric key". This
    covers the log; the route test covers the response and the UI; the health test
    covers the doctor.
    """
    author = _agent()
    wid = _drive_to_review(gw_warn, author)
    unbound = Actor(
        actor_id=QUAL_STABLE_ID, actor_kind="human", display_name="Qual Human"
    )

    with caplog.at_level(logging.WARNING, logger="dossier.signing"):
        gw_warn.transition(
            actor=unbound,
            work_item_id=wid,
            transition_name="accept",
            payload=ACCEPT_PAYLOAD,
        )

    downgrades = [
        r for r in caplog.records if r.message == "provenance.human_signature_downgraded"
    ]
    assert len(downgrades) == 1
    record = downgrades[0]
    assert record.levelno == logging.WARNING
    assert record.actor_id == QUAL_STABLE_ID
    assert record.operation == "transition:accept"
    assert "cannot attribute" in record.consequence
    assert "agent-suite bootstrap --user" in record.remediation


def test_signing_identity_is_a_read_only_probe(gw_warn, suite):
    """The UI and doctor need to ask without risking a refusal or a write."""
    bound = principal_to_actor(
        Principal(
            stable_id=QUAL_STABLE_ID,
            display_name="Qual Human",
            source="local",
            principal_id=QUAL_PRINCIPAL,
        )
    )
    identity = gw_warn.signing_identity(bound)
    assert identity.per_actor is True
    assert identity.key_id == suite["key_ids"][QUAL_PRINCIPAL]
    assert identity.scheme == "ed25519"
    assert identity.fingerprint

    unbound = Actor(actor_id=QUAL_STABLE_ID, actor_kind="human", display_name="Q")
    gap = gw_warn.signing_identity(unbound)
    assert gap.per_actor is False
    assert gap.reason == "no regista principal_id is recorded for this identity"


def test_revoked_key_does_not_silently_become_a_store_signature(tmp_path):
    """A revoked key must refuse, not fall back — the leaver case.

    ``agent-suite offboard`` revokes a leaver's key. If revocation quietly
    re-enabled store-key signing, offboarding would *weaken* the record instead of
    closing it.
    """
    key_path = tmp_path / "keys.json"
    generate_keyset(key_path)
    key_dir = tmp_path / "principals"
    _add_ed25519_principal(key_path, key_dir, "leaver")
    _add_ed25519_principal(key_path, key_dir, "qual-author")
    _add_ed25519_principal(key_path, key_dir, "qual-reviewer")
    manifest = json.loads(key_path.read_text())
    for entry in manifest["keys"]:
        if entry.get("principal_id") == "leaver":
            entry["status"] = "revoked"
    key_path.write_text(json.dumps(manifest))

    reg = InMemoryRegista(project="wi035_rev", hmac_key_path=str(key_path))
    gw = RegistaGateway(reg, project_name="wi035_rev", human_signing="require")
    gw.register_workflow()
    InMemoryRegista._catalog.clear()
    try:
        leaver = principal_to_actor(
            Principal(
                stable_id=QUAL_STABLE_ID,
                display_name="Leaver",
                source="local",
                principal_id="leaver",
            )
        )
        wid = _drive_to_review(gw, _agent())
        with pytest.raises(HumanSigningRefusedError):
            gw.transition(
                actor=leaver,
                work_item_id=wid,
                transition_name="accept",
                payload=ACCEPT_PAYLOAD,
            )
    finally:
        InMemoryRegista._catalog.clear()
        gw.close()


# ── policy resolution ─────────────────────────────────────────────────────


def test_policy_defaults_to_require_in_prod_and_warn_in_dev():
    """A production deployment fails closed by default; a dev box stays usable."""
    assert parse_policy("", prod=True) == "require"
    assert parse_policy("", prod=False) == "warn"


def test_policy_can_be_overridden_explicitly():
    """The documented escape hatch out of a fail-closed upgrade."""
    assert parse_policy("warn", prod=True) == "warn"
    assert parse_policy("REQUIRE", prod=False) == "require"


def test_policy_rejects_an_unknown_value():
    with pytest.raises(ValueError, match="DOSSIER_HUMAN_SIGNING"):
        parse_policy("maybe", prod=False)


def test_settings_resolve_the_policy_from_the_environment(monkeypatch, tmp_path):
    from dossier.config import load_settings

    monkeypatch.setenv("DOSSIER_ENV", "prod")
    monkeypatch.setenv("DOSSIER_SESSION_SECRET", "x" * 40)
    monkeypatch.setenv("REGISTA_KEY_PATH", str(tmp_path / "keys.json"))
    monkeypatch.setenv("REGISTA_DSN", "postgresql://localhost/x")
    monkeypatch.delenv("DOSSIER_HUMAN_SIGNING", raising=False)
    assert load_settings(strict=False).human_signing == "require"

    monkeypatch.setenv("DOSSIER_HUMAN_SIGNING", "warn")
    assert load_settings(strict=False).human_signing == "warn"

    monkeypatch.setenv("DOSSIER_LDAP_PRINCIPAL_ID_ATTR", "employeeNumber")
    assert load_settings(strict=False).ldap_principal_id_attr == "employeeNumber"


# ── doctor ────────────────────────────────────────────────────────────────


def _health(settings, gw):
    from dossier.health import build_health
    from dossier.multi import GatewayRegistry

    registry = GatewayRegistry(known_projects=["wi035"])
    registry.add("wi035", gw)
    return build_health(settings, registry)


def _settings(tmp_path, **overrides):
    from dossier.config import Settings

    base = dict(
        database_url="postgresql://localhost/x",
        project="wi035",
        hmac_key_path=str(tmp_path / "keys.json"),
        session_secret="x" * 40,
        session_max_age_seconds=3600,
        secure_cookies=False,
        require_ssl=False,
        users_path="",
        auth_backend="local",
        principal_key_dir=str(tmp_path / "principals"),
        # open access so an unrelated authz check cannot be what fails these
        # assertions — human_signing is the subject here
        project_access_mode="open",
    )
    base.update(overrides)
    return Settings(**base)


def _check(health, name):
    return next(c for c in health["checks"] if c["name"] == name)


def test_doctor_reports_an_unbound_local_identity(gw_warn, suite, tmp_path):
    """The doctor is where an operator finds this before a qualification does."""
    users = _local_users_file(tmp_path, principal_id=None)
    health = _health(
        _settings(tmp_path, users_path=str(users), human_signing="warn"), gw_warn
    )
    check = _check(health, "human_signing")
    assert check["status"] == "warn"
    assert QUAL_PRINCIPAL in check["detail"]
    assert "no principal_id recorded" in check["detail"]
    assert "shared store key" in check["detail"]
    assert health["degraded"] is True


def test_doctor_fails_under_require_when_an_identity_is_unbound(gw_warn, tmp_path):
    """Under ``require`` the gap stops human decisions, so it is a failure."""
    users = _local_users_file(tmp_path, principal_id=None)
    health = _health(
        _settings(tmp_path, users_path=str(users), human_signing="require"), gw_warn
    )
    check = _check(health, "human_signing")
    assert check["status"] == "fail"
    assert "will be refused" in check["detail"]
    assert "agent-suite bootstrap --user" in check["detail"]
    assert health["ok"] is False


def test_doctor_flags_a_binding_with_no_provisioned_key(gw_warn, tmp_path):
    """"Recorded a principal_id" and "provisioned its key" are separate steps."""
    users = _local_users_file(tmp_path, principal_id="never-provisioned")
    health = _health(
        _settings(tmp_path, users_path=str(users), human_signing="require"), gw_warn
    )
    check = _check(health, "human_signing")
    assert check["status"] == "fail"
    assert "no active per-actor key" in check["detail"]
    assert "never-provisioned" in check["detail"]


def test_doctor_is_ok_when_every_identity_is_bound_and_keyed(gw_warn, tmp_path):
    users = _local_users_file(tmp_path, principal_id=QUAL_PRINCIPAL)
    health = _health(
        _settings(tmp_path, users_path=str(users), human_signing="require"), gw_warn
    )
    check = _check(health, "human_signing")
    assert check["status"] == "ok"
    assert "active per-actor key" in check["detail"]


def test_doctor_flags_an_ldap_deployment_with_no_binding_attribute(gw_warn, tmp_path):
    """LDAP cannot be enumerated from health, but the missing wiring can be."""
    health = _health(
        _settings(
            tmp_path,
            auth_backend="ldap",
            human_signing="require",
            ldap_principal_id_attr="",
        ),
        gw_warn,
    )
    check = _check(health, "human_signing")
    assert check["status"] == "fail"
    assert "DOSSIER_LDAP_PRINCIPAL_ID_ATTR" in check["detail"]


def test_doctor_is_ok_for_a_wired_ldap_deployment(gw_warn, tmp_path):
    health = _health(
        _settings(
            tmp_path,
            auth_backend="ldap",
            human_signing="require",
            ldap_principal_id_attr="employeeNumber",
        ),
        gw_warn,
    )
    check = _check(health, "human_signing")
    assert check["status"] == "ok"
    assert "employeeNumber" in check["detail"]


def test_doctor_never_prints_key_material(gw_warn, suite, tmp_path):
    """A diagnostic that leaks a private key is not a diagnostic."""
    users = _local_users_file(tmp_path, principal_id=QUAL_PRINCIPAL)
    health = _health(
        _settings(tmp_path, users_path=str(users), human_signing="require"), gw_warn
    )
    blob = json.dumps(health)
    for public_key in suite["public_keys"].values():
        assert base64.b64encode(public_key).decode("ascii") not in blob
    assert "BEGIN" not in blob
    assert "_ed25519.key" not in blob


# ── HTTP surface: response and UI ─────────────────────────────────────────


def _web(suite, tmp_path, *, policy, principal_id):
    """A TestClient over the real app with one local human identity."""
    from fastapi.testclient import TestClient

    from dossier.app import create_app
    from dossier.multi import GatewayRegistry

    users = _local_users_file(tmp_path, principal_id=principal_id)
    gw = _gateway(suite, policy=policy, project="wi035_web")
    registry = GatewayRegistry(known_projects=["wi035_web"])
    registry.add("wi035_web", gw)
    settings = _settings(
        tmp_path,
        project="wi035_web",
        users_path=str(users),
        human_signing=policy,
    )
    app = create_app(settings, registry, LocalBackend(users))
    return gw, TestClient(app)


def _login_and_reach_review(gw, client):
    """Log the human in and leave a work item in ``in_human_review``."""
    from conftest import extract_csrf

    page = client.get("/login")
    resp = client.post(
        "/login",
        data={
            "username": QUAL_PRINCIPAL,
            "password": "s3cret",
            "csrf_token": extract_csrf(page.text),
        },
        follow_redirects=False,
    )
    assert resp.status_code == 302, resp.text
    # login clears the session, so the CSRF token rotates — read the new one
    csrf = client.get("/csrf").json()["csrf_token"]
    wid = _drive_to_review(gw, _agent())
    return csrf, wid


def test_route_refuses_the_acceptance_with_an_actionable_409(suite, tmp_path):
    """The refusal reaches the human in the page, and the response says so.

    409 rather than 500: nothing is broken. The body is the remediation.
    """
    gw, client = _web(suite, tmp_path, policy="require", principal_id=None)
    try:
        csrf, wid = _login_and_reach_review(gw, client)
        resp = client.post(
            f"/p/wi035-web/issues/{wid}/transitions",
            data={
                "transition_name": "accept",
                "review_note": "accepted after review",
                "csrf_token": csrf,
            },
            follow_redirects=False,
        )
        assert resp.status_code == 409
        assert resp.headers["X-Dossier-Human-Signing"] == "refused"
        assert "agent-suite bootstrap --user" in resp.text
        assert "shared store key" in resp.text
        # nothing recorded
        assert gw.get_issue(wid).current_state == "in_human_review"
    finally:
        InMemoryRegista._catalog.clear()
        gw.close()


def test_route_marks_the_downgrade_on_the_response_and_the_page(suite, tmp_path):
    """``warn`` records the action but never lets it pass unremarked."""
    gw, client = _web(suite, tmp_path, policy="warn", principal_id=None)
    try:
        csrf, wid = _login_and_reach_review(gw, client)
        resp = client.post(
            f"/p/wi035-web/issues/{wid}/transitions",
            data={
                "transition_name": "accept",
                "review_note": "accepted after review",
                "csrf_token": csrf,
            },
            follow_redirects=False,
        )
        assert resp.status_code == 303
        assert resp.headers["X-Dossier-Human-Signing"] == "downgraded"
        assert "signing=downgraded" in resp.headers["location"]

        page = client.get(resp.headers["location"])
        assert page.status_code == 200
        assert 'data-testid="signing-downgraded"' in page.text
        assert "Recorded without your signature" in page.text
        # loud by design (WI-035): the callout renders full-width BEFORE the
        # record grid, never in the rail where narrow viewports would push it
        # below the chain (Plan 026 last-pass finding, 2026-08-07)
        assert page.text.index('data-testid="signing-downgraded"') < page.text.index(
            'class="ds-record-grid"'
        )
        # and the history row is honest about which key sealed it
        assert 'data-testid="shared-key-signature"' in page.text
    finally:
        InMemoryRegista._catalog.clear()
        gw.close()


def test_route_is_quiet_when_the_human_signed_for_themselves(suite, tmp_path):
    """No banner, no header, no downgrade marker on the correct path."""
    gw, client = _web(suite, tmp_path, policy="require", principal_id=QUAL_PRINCIPAL)
    try:
        csrf, wid = _login_and_reach_review(gw, client)
        resp = client.post(
            f"/p/wi035-web/issues/{wid}/transitions",
            data={
                "transition_name": "accept",
                "review_note": "accepted after review",
                "csrf_token": csrf,
            },
            follow_redirects=False,
        )
        assert resp.status_code == 303
        assert "X-Dossier-Human-Signing" not in resp.headers
        assert "signing=downgraded" not in resp.headers["location"]

        page = client.get(resp.headers["location"])
        assert 'data-testid="signing-downgraded"' not in page.text
        assert 'data-testid="shared-key-signature"' not in page.text

        accept = next(e for e in gw.history(wid) if e.transition == "accept")
        assert accept.scheme_id == "ed25519"
        assert accept.actor_id == QUAL_PRINCIPAL
    finally:
        InMemoryRegista._catalog.clear()
        gw.close()


def test_healthz_surfaces_the_posture_over_http(suite, tmp_path):
    """The doctor's umbrella reads /healthz, so the gap has to be visible there."""
    gw, client = _web(suite, tmp_path, policy="require", principal_id=None)
    try:
        body = client.get("/healthz").json()
        check = next(c for c in body["checks"] if c["name"] == "human_signing")
        assert check["status"] == "fail"
        assert body["ok"] is False
    finally:
        InMemoryRegista._catalog.clear()
        gw.close()
