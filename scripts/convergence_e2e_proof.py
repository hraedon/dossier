"""Plan 010 §6 — live end-to-end proof of the convergence north star.

One shared regista project on a real Postgres. The agent-notes face (RegistaFace)
and the dossier face (RegistaGateway) — each its own connection — drive ONE
work-item through the canonical workflow: an agent files+works it, a cross-lineage
agent reviewer passes the adversarial gate, a HUMAN accepts it to `done`. Then we
read the single mixed agent+human chain back through dossier's read path and
verify the regista hash chain.

MANUAL proof, NOT a CI test: it needs a live Postgres and BOTH faces importable
in one interpreter (dossier does not depend on agent-notes). To run:

    docker run -d --name dossier-e2e -e POSTGRES_USER=reg -e POSTGRES_PASSWORD=reg \\
        -e POSTGRES_DB=convergence -p 55432:5432 postgres:15
    PYTHONPATH=/projects/dossier/src /projects/agent-notes/.venv/bin/python \\
        /projects/dossier/scripts/convergence_e2e_proof.py
    docker rm -f dossier-e2e

Last run 2026-06-29: 4/4 checks PASS (final state done; mixed agent+human chain;
one canonical workflow; hash chain verifies drift=0 halted=0). Backs Plan 010 §6.
"""

from __future__ import annotations

import sys
import uuid

import regista
from regista.testing import drop_project_schema

from agent_notes.core.actor import Actor as AgentActor
from agent_notes.core.regista_face import RegistaFace

from dossier.actors import Actor as HumanActor
from dossier.gateway import RegistaGateway

DSN = "postgresql://reg:reg@localhost:55432/convergence"
KEY_PATH = "/projects/regista/tests/test_keys.json"
PROJECT = f"converge_{uuid.uuid4().hex[:8]}"


def banner(msg: str) -> None:
    print(f"\n=== {msg} ===")


def main() -> int:
    banner(f"bootstrap project {PROJECT!r} + register canonical workflow")
    boot = regista.Regista.create_project(DSN, PROJECT, KEY_PATH)
    boot.register_workflow(regista.canonical_workflow_yaml())
    wf_name = "canonical"
    print(f"registered workflow: {wf_name} (from regista.canonical_workflow_yaml)")
    boot.close()

    # Two independent faces, two independent connections, ONE project.
    agent_face = RegistaFace(regista.Regista(DSN, PROJECT, KEY_PATH))
    human_face = RegistaGateway(regista.Regista(DSN, PROJECT, KEY_PATH))

    # Actors: two agents of different model lineage + one human.
    glm = AgentActor(actor_id="glm-agent", actor_kind="agent",
                     display_name="GLM worker", role="agent", model_lineage="glm")
    kimi = AgentActor(actor_id="kimi-agent", actor_kind="agent",
                      display_name="Kimi reviewer", role="agent", model_lineage="kimi")
    paul = HumanActor(actor_id="paul", actor_kind="human", display_name="Paul")

    try:
        banner("AGENT FACE (agent-notes): file + work the item")
        wid, state = agent_face.create_breadcrumb(
            actor=glm, title="prove the convergence end-to-end",
            description="one item, both faces", kind="task",
        )
        print(f"created breadcrumb {wid} -> {state}")
        state = agent_face.transition_breadcrumb(glm, wid, "start")
        print(f"glm start -> {state}")
        state = agent_face.transition_breadcrumb(glm, wid, "submit_for_review")
        print(f"glm submit_for_review -> {state}")

        banner("AGENT FACE: cross-lineage adversarial review (kimi != glm)")
        state = agent_face.transition_breadcrumb(
            kimi, wid, "adversarial_pass",
            payload={"review_note": "independent cross-lineage review: sound"},
        )
        print(f"kimi adversarial_pass -> {state}")

        banner("HUMAN FACE (dossier): accept to done")
        human_face.transition(
            actor=paul, work_item_id=wid, transition_name="accept",
            payload={"review_note": "human sign-off"},
        )
        item = human_face.get_issue(wid)
        print(f"paul accept -> {item.current_state}")

        banner("READ BACK via dossier's read path (the verified-history data)")
        events = human_face.history(wid)
        for e in events:
            role = (e.actor_metadata or {}).get("role", "-")
            lin = (e.actor_metadata or {}).get("model_lineage", "-")
            print(f"  seq {e.event_seq:>2}  {e.transition:<18} "
                  f"{e.actor_kind:<7} {e.actor_id:<12} role={role:<7} lineage={lin}")

        banner("VERIFY")
        report = human_face.integrity()
        kinds = {e.actor_kind for e in events}
        wf_versions = {getattr(e, "workflow_version", None) for e in events}
        integrity_ok = report.replayed_drift == 0 and report.halted == 0 and report.replayed_ok > 0
        ok = True
        checks = [
            ("final state is done", item.current_state == "done"),
            ("chain is mixed (agent + human)", {"agent", "human"} <= kinds),
            ("one workflow governs the item (canonical)", item.workflow_name == wf_name),
            (f"hash chain verifies (ok={report.replayed_ok} drift={report.replayed_drift} "
             f"halted={report.halted})", integrity_ok),
        ]
        for label, passed in checks:
            print(f"  [{'PASS' if passed else 'FAIL'}] {label}")
            ok = ok and passed
        print(f"  (workflow_name={item.workflow_name!r}, actor_kinds={sorted(kinds)}, "
              f"event workflow_versions={wf_versions})")
        return 0 if ok else 1
    finally:
        agent_face.close()
        human_face.close()
        drop_project_schema(DSN, PROJECT)
        print(f"\ncleaned up project schema {PROJECT!r}")


if __name__ == "__main__":
    sys.exit(main())
