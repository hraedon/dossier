# Plan 023 — Central service deployment: dossier as the team URL

**Status:** Proposed 2026-07-11 (structure ratified by the operator in the
2026-07-11 suite-benchmark conversation).
**Author:** Claude (Fable 5)
**Strategic role:** dossier's product vision is a stripped-down Jira for a mixed
human/agent team — which makes it a **shared service with one URL**, not a
per-box component. Nearly every prerequisite already shipped: Plan 011 gave it
multi-project fronting (WI-1..6), Plan 013 gave it the suite config contract, a
pinned container image, `/healthz`, and secrets-through-backend, and Plan 002
gave it server-derived actor auth. What has never happened is the deployment
itself — Plan 011's WI-7 ("stand up the web service — its own infra step") has
been the open tail for ten days. This plan executes it as a Kubernetes
deployment on the existing homelab cluster, moves the signing key into Vault
(closing a standing single-copy custody risk), and proves the result from a
second machine. It supersedes Plan 011 WI-7 and composes with agent-suite
Plan 004 WI-1.6 (shared-service locality in the doctor umbrella).

## Decisions ratified 2026-07-11

1. **Central service, not per-box.** A human face installed per-box inverts the
   vision; one URL, backed by the one store on the production Postgres host.
2. **Kubernetes namespace over a dedicated VM.** dossier is the ideal k8s
   workload — stateless FastAPI, all state in external Postgres — and the
   operator already runs the cluster (Vault lives on it), so ingress, TLS,
   restarts, and isolation are already paid for. A dedicated VM is another OS
   to patch for one Python process. **Boundary:** k8s is this deployment's
   choice, never a suite requirement — agent-suite's no-k8s-dependency non-goal
   stands, and `deploy/systemd` + `winsw` remain the documented non-k8s
   profiles for other shops.
3. **Auth posture now = Plan 002, TLS at ingress.** The implemented auth
   foundation (server-derived actors, signed sessions) is the launch posture
   for LAN humans. Entra/OIDC federation and step-up remain Plan 020 — an
   upgrade, not a blocker.
4. **Manifests live here** (`deploy/k8s/`), not in agent-suite: the component
   owns its packaging; the suite orchestrates and health-checks it.

## Ground truth at time of writing

- Container image + pinned-regista build exist (Plan 013 WI-2.1); `/healthz`
  and `doctor --json` in the common shape (WI-3.1); suite config contract
  adopted with legacy aliases (WI-1.1); secrets-through-backend (WI-4.1).
- The prod HMAC signing key exists **only** at
  `~/.config/regista/keys.json` on the operator box (key_id
  `regista-prod-001`). Both faces must share it. It is not in Vault and has no
  second copy — loss means the chain can't be verified. This plan fixes that
  independently of the deployment (WI-1 stands alone).
- The store: `regista` DB on the production Postgres host, 23 per-project
  schemas at migration v42, per-project service roles provisioned 2026-07-11.
- agent-suite doctor currently reports dossier `absent (tier: face)` on the
  operator box — the locality misconception this plan + Plan 004 WI-1.6 fix.

## Non-goals

- No HA / multi-replica (a one-or-two-human team; the k8s restart loop is the
  availability story). No public/internet exposure. No new auth system (that
  is Plan 020). No suite-level k8s requirement.

---

## WI-1 — Signing-key custody: the key leaves the laptop

Move the prod HMAC key into Vault (KV v2, e.g. `kv/homelab/suite/regista-hmac`,
aligned with regista's backend-aware custody — see regista Plan 029 / dossier
Plan 015 usage) so it is (a) injectable into the dossier pod and (b) durably
backed up. Keep the operator-box file as documented break-glass copy. Record
the custody change + recovery procedure in agent-suite `docs/key-operations.md`.

- **AC:** both faces resolve the key through their existing resolution path
  with the Vault-sourced value; a chain `verify` passes before and after the
  switch on at least two project schemas; the recovery procedure is written
  and names both copies; the laptop file is no longer the only copy.

## WI-2 — Kubernetes manifests

`deploy/k8s/`: Namespace, Deployment (image pinned to the SUITE.lock pair, not
`:latest`), Service, Ingress with TLS via the cluster's existing cert story,
liveness/readiness probes on `/healthz`, resource requests/limits, and secrets
delivered via the cluster's established Vault integration — **verify which
pattern the cluster already uses** (agent injector / CSI / ExternalSecrets)
and follow it rather than introducing a second mechanism. Private-image pull
needs an imagePullSecret for ghcr.

- **AC:** `kubectl apply` from a clean checkout converges; pod healthy;
  `/healthz` returns ok from a machine that is not the operator box; no
  secret material appears in any committed manifest (grep-able AC); the
  identifier gate stays green (manifests use lab hostnames only).

## WI-3 — Multi-project configuration against the production store

Configure via the suite contract (`REGISTA_DSN`, `REGISTA_KEY_PATH` resolved
from the Vault-injected environment) with `DOSSIER_PROJECTS` fronting the full
schema set. This is Plan 011 WI-7's substance, done through Plan 013's config
surface.

- **AC:** `/p/<project>/` routes serve every live schema; the cross-project
  landing aggregates them; per-project isolation spot-checked (no cross-schema
  leakage, Plan 011 WI-6 tests re-run against prod config in a staging
  namespace or with a read-only smoke pass).

## WI-4 — Launch auth posture

Enable the Plan 002 auth backend for LAN humans; session secret from Vault;
confirm actor identity is server-derived end-to-end (the audit trail shows the
logged-in human, never a request-supplied string). Document in README that
ingress TLS + Plan 002 is the launch posture and Plan 020 (OIDC/step-up) is
the upgrade path.

- **AC:** an unauthenticated request cannot transition a work item; a
  transition performed through the UI lands in regista attributed to the
  authenticated human actor; session secret absent from manifests and image.

## WI-5 — Live proof from a second system

From a machine that is not the operator box: a human loads the team URL, views
the cross-project landing, and drives one real work item through a transition;
the agent face (agent-notes CLI on the operator box) observes the same state;
regista chain verify passes afterward. Append the run to agent-suite's
deployment record (`docs/deployments/`, the Plan 004 WI-1.5 template).

- **AC:** both observations recorded with identifiers and timestamps; chain
  verification output attached; every deviation found becomes a WI or doc fix.

## WI-6 — Suite doctor sees the service

Add the dossier endpoint to the suite config; agent-suite's umbrella checks it
as a **shared service** (reachability + `/healthz` + lock-compatibility) rather
than a local install. Depends on agent-suite Plan 004 WI-1.6 (the locality
concept); this WI is dossier's half: expose whatever version/lock metadata the
remote check needs on `/healthz` (or a sibling endpoint) if not already there.

- **AC:** `agent-suite doctor` on the operator box reports dossier
  `remote: ok @ <version>`; stopping the pod flips it to a legible failure
  naming the endpoint.

## Sequencing

WI-1 first and independently (it is a custody fix, valuable even if deployment
slips). WI-2 → WI-3 → WI-4 in order; WI-5 proves the stack; WI-6 lands
whenever agent-suite WI-1.6 exists (either order relative to WI-5).

## Risks

- **Key custody transition** is the one step touching the suite's trust root:
  mitigation is WI-1's verify-before/verify-after AC and the break-glass copy.
- **Cluster as a dependency for the human face only.** Agents are unaffected
  (CLI path never touches dossier); if the cluster is down, work continues and
  only the human window is dark. Accepted for a homelab.
- **Config drift between staging smoke and prod namespace** — mitigate by
  applying the same manifests with a kustomize overlay (or plain env diff)
  rather than hand-edited copies.
