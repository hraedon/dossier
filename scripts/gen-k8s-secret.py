"""Generate the dossier k8s Secret and CA ConfigMap from the operator's suite.env.

Reads the per-user suite.env (or the path in AGENT_SUITE_CONFIG) and emits
Secret/ConfigMap manifests under deploy/k8s/. The output files are gitignored
and never committed.

The generated Secret sets DOSSIER_ALLOWED_HOSTS from the operator's env. If
the operator does not set it, the placeholder ``dossier.work-domain.example``
is used, and ``127.0.0.1`` is always appended so in-pod liveness/readiness
probes (which connect to 127.0.0.1) are not rejected by TrustedHostMiddleware.

The operator must still replace the placeholder hostname in ingress.yaml
before applying (e.g. with envsubst or a kustomize overlay). No real hostname
is committed to this repo.
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

OUTPUT_DIR = Path(__file__).parent.parent / "deploy" / "k8s"


DEFAULT_HOSTS = "dossier.work-domain.example"
DEFAULT_PROJECTS = sorted(
    [
        "acme_adcs_ra",
        "ad_steward",
        "adcs_lens",
        "agent_capability_broker",
        "agent_notes",
        "agent_provenance",
        "agent_suite",
        "agent_wake",
        "agentic_onboarding",
        "cert_watch",
        "dossier",
        "frontier_lag",
        "gpo_lens",
        "gpo_studio",
        "openbia",
        "patina",
        "sf2",
        "sluice",
        "substrate",
        "switchboard",
        "sysadmin_competence_evaluation",
        "usage_dashboard",
        "vitrine",
        "windows_evidence_lab",
    ]
)


def _suite_env_path() -> Path:
    override = os.environ.get("AGENT_SUITE_CONFIG")
    if override:
        return Path(override).expanduser()
    return Path.home() / ".config" / "agent-suite" / "suite.env"


def _load_env(path: Path) -> dict[str, str]:
    env: dict[str, str] = {}
    if not path.is_file():
        return env
    for line in path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        key, _, value = stripped.partition("=")
        key = key.strip()
        if key.startswith("export "):
            key = key[7:].strip()
        value = value.strip()
        if len(value) >= 2 and value[0] in "\"'" and value[-1] == value[0]:
            value = value[1:-1]
        env[key] = value
    return env


def _allowed_hosts(suite_env: dict[str, str]) -> str:
    raw = suite_env.get("DOSSIER_ALLOWED_HOSTS", DEFAULT_HOSTS)
    hosts = [h.strip() for h in raw.split(",") if h.strip()]
    if "127.0.0.1" not in hosts:
        hosts.append("127.0.0.1")
    return ",".join(hosts)


def _require(env: dict[str, str], key: str) -> str:
    value = env.get(key, "").strip()
    if not value:
        raise SystemExit(f"{key} is required in suite.env")
    return value


def main() -> int:
    suite_env = _load_env(_suite_env_path())
    ca_cert_path = Path.home() / ".config" / "agent-suite" / "secrets" / "ad-root-ca.pem"
    ca_pem = ca_cert_path.read_text(encoding="utf-8") if ca_cert_path.is_file() else ""

    secret = {
        "apiVersion": "v1",
        "kind": "Secret",
        "metadata": {
            "name": "dossier-suite-env",
            "namespace": "dossier",
            "labels": {
                "app.kubernetes.io/name": "dossier",
                "app.kubernetes.io/part-of": "agent-suite",
            },
        },
        "type": "Opaque",
        "stringData": {
            "REGISTA_DSN": _require(suite_env, "REGISTA_DSN"),
            "REGISTA_KEY_PATH": "/etc/regista/keys.json",
            "DOSSIER_ENV": "prod",
            "DOSSIER_SESSION_SECRET": _require(suite_env, "DOSSIER_SESSION_SECRET"),
            "DOSSIER_PROJECTS": suite_env.get("DOSSIER_PROJECTS", ",".join(DEFAULT_PROJECTS)),
            "DOSSIER_PROJECT_ACL_PATH": "/etc/dossier/acl/acl.json",
            "DOSSIER_ALLOWED_HOSTS": _allowed_hosts(suite_env),
            "DOSSIER_REQUIRE_SSL": "true",
            "DOSSIER_BEHIND_TLS_PROXY": "true",
            "DOSSIER_AUTH_BACKEND": "ldap",
            "DOSSIER_LDAP_SERVER": _require(suite_env, "DOSSIER_LDAP_SERVER"),
            "DOSSIER_LDAP_BASE_DN": _require(suite_env, "DOSSIER_LDAP_BASE_DN"),
            "DOSSIER_LDAP_BIND_DN": _require(suite_env, "DOSSIER_LDAP_BIND_DN"),
            "DOSSIER_LDAP_BIND_PASSWORD": _require(suite_env, "DOSSIER_LDAP_BIND_PASSWORD"),
            "DOSSIER_LDAP_DOMAIN": _require(suite_env, "DOSSIER_LDAP_DOMAIN"),
            "DOSSIER_LDAP_USER_FILTER": suite_env.get(
                "DOSSIER_LDAP_USER_FILTER",
                "(&(objectClass=user)(sAMAccountName={login}))",
            ),
            "DOSSIER_LDAP_GROUP_STRATEGY": suite_env.get(
                "DOSSIER_LDAP_GROUP_STRATEGY", "direct"
            ),
            "DOSSIER_LDAP_CA_CERT_FILE": "/etc/dossier/secrets/ad-root-ca.pem",
        },
    }

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    secret_path = OUTPUT_DIR / "secret-suite-env.yaml"
    secret_path.write_text(json.dumps(secret, indent=2) + "\n", encoding="utf-8")

    if not ca_pem:
        print(f"wrote {secret_path}")
        print(f"skipped CA ConfigMap: {ca_cert_path} not found")
        return 0

    ca_cm = {
        "apiVersion": "v1",
        "kind": "ConfigMap",
        "metadata": {
            "name": "dossier-ad-root-ca",
            "namespace": "dossier",
            "labels": {
                "app.kubernetes.io/name": "dossier",
                "app.kubernetes.io/part-of": "agent-suite",
            },
        },
        "data": {"ad-root-ca.pem": ca_pem},
    }
    cm_path = OUTPUT_DIR / "configmap-ad-root-ca.yaml"
    cm_path.write_text(json.dumps(ca_cm, indent=2) + "\n", encoding="utf-8")
    print(f"wrote {secret_path}")
    print(f"wrote {cm_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
