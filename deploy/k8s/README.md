# Kubernetes deployment profile

This is an optional component-owned profile for operators who already run
Kubernetes. It does not make Kubernetes a requirement for dossier or
agent-suite.

The committed manifests are a reusable, secret-free base. Before applying
them:

1. Set `AGENT_SUITE_CONFIG` to the intended `suite.env` (or use the default
   `~/.config/agent-suite/suite.env`). It must define `REGISTA_DSN`,
   `REGISTA_KEY_PATH`, `DOSSIER_SESSION_SECRET`, `DOSSIER_PROJECTS`,
   `DOSSIER_ADMIN_PRINCIPALS`, and the `DOSSIER_LDAP_*` launch settings.
   The LDAP CA path must exist locally; generation fails closed if it does not.
2. Run `python scripts/gen-k8s-secret.py`. It writes two Secret manifests and
   two ConfigMaps under this directory atomically with mode `0600` on POSIX or
   a current-user-only ACL on Windows. Every output is gitignored. The generated
   ACL is fail-closed: projects are private and the declared administrators can
   configure access deliberately.
3. Replace `dossier.work-domain.example` in `ingress.yaml`. Add the local
   ingress class, certificate issuer, and image-pull secret in a private
   kustomize overlay; cluster-specific identifiers do not belong in this base.
4. Confirm that the image pair in `deployment.yaml` matches `SUITE.lock`, then
   run `kubectl apply -k deploy/k8s/`.

Readiness uses `/healthz`, so a pod does not receive traffic until its store,
authentication, TLS-proxy declaration, and production posture are healthy.
Liveness uses `/livez`, which checks only the process and therefore does not
restart-loop the service during a dependency outage.

Never add the generated files with `git add -f`. The repository's identifier
gate and `.gitignore` are defense in depth, not permission to commit secret
material.
