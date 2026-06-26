from __future__ import annotations

from dossier.actors import Actor

ALICE = Actor(actor_id="alice", actor_kind="human", display_name="Alice")
BOB = Actor(actor_id="bob", actor_kind="human", display_name="Bob")
CAROL = Actor(actor_id="carol", actor_kind="human", display_name="Carol")
DAVE = Actor(actor_id="dave", actor_kind="human", display_name="Dave")
AGENT_R = Actor(
    actor_id="agent-relay", actor_kind="agent", display_name="Agent Relay", model_lineage="relay"
)
AGENT_GLM = Actor(
    actor_id="agent-glm", actor_kind="agent", display_name="GLM Agent", model_lineage="glm"
)
AGENT_KIMI = Actor(
    actor_id="agent-kimi", actor_kind="agent", display_name="Kimi Agent", model_lineage="kimi"
)
