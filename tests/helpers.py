from __future__ import annotations

from dossier.actors import Actor

ALICE = Actor(
    actor_id="human:alice", actor_kind="human", display_name="Alice", principal_id="human:alice"
)
BOB = Actor(
    actor_id="human:bob", actor_kind="human", display_name="Bob", principal_id="human:bob"
)
CAROL = Actor(
    actor_id="human:carol", actor_kind="human", display_name="Carol", principal_id="human:carol"
)
DAVE = Actor(
    actor_id="human:dave", actor_kind="human", display_name="Dave", principal_id="human:dave"
)
AGENT_R = Actor(
    actor_id="agent:relay", actor_kind="agent", display_name="Agent Relay", model_lineage="relay"
)
AGENT_GLM = Actor(
    actor_id="agent:glm", actor_kind="agent", display_name="GLM Agent", model_lineage="glm"
)
AGENT_KIMI = Actor(
    actor_id="agent:kimi", actor_kind="agent", display_name="Kimi Agent", model_lineage="kimi"
)
