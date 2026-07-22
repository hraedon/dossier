"""Generate dossier's private Kubernetes inputs from the operator's suite.env.

Reads the per-user suite.env (or the path in AGENT_SUITE_CONFIG) and emits
Secret/ConfigMap manifests under deploy/k8s/. The output files are gitignored,
written atomically with mode 0600, and never committed.

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
import tempfile
from pathlib import Path
from typing import Any

OUTPUT_DIR = Path(__file__).parent.parent / "deploy" / "k8s"


DEFAULT_HOSTS = "dossier.work-domain.example"


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


def _require_literal(env: dict[str, str], key: str) -> str:
    value = _require(env, key)
    lower = value.lower()
    if lower.startswith("env:"):
        variable = value.split(":", 1)[1]
        resolved = os.environ.get(variable, "").strip()
        if not resolved:
            raise SystemExit(f"{key} references unset environment variable {variable}")
        return resolved
    if lower.startswith("file:"):
        path = Path(value.split(":", 1)[1]).expanduser()
        if not path.is_file():
            raise SystemExit(f"{key} references a missing file: {path}")
        resolved = path.read_text(encoding="utf-8").strip()
        if not resolved:
            raise SystemExit(f"{key} references an empty file: {path}")
        return resolved
    if lower.startswith(("vault:", "azure:", "akv:", "wincred:", "literal:")):
        raise SystemExit(
            f"{key} must be resolved in the process environment before generating "
            "a Kubernetes Secret"
        )
    return value


def _csv(env: dict[str, str], key: str, *, required: bool = False) -> list[str]:
    raw = _require(env, key) if required else env.get(key, "")
    return [value.strip() for value in raw.split(",") if value.strip()]


def _write_private_json(path: Path, document: dict[str, Any]) -> None:
    """Atomically replace *path* without ever creating a world-readable file."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary_path = Path(temporary)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(document, handle, indent=2)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary_path, 0o600)
        os.replace(temporary_path, path)
    finally:
        temporary_path.unlink(missing_ok=True)


def _key_file(env: dict[str, str]) -> Path:
    reference = _require(env, "REGISTA_KEY_PATH")
    if reference.startswith("file:"):
        reference = reference[5:]
    elif reference.split(":", 1)[0].lower() in {
        "env",
        "vault",
        "azure",
        "akv",
        "wincred",
        "literal",
    }:
        raise SystemExit(
            "REGISTA_KEY_PATH must be a local path or file: reference when generating "
            "a Kubernetes Secret"
        )
    path = Path(reference).expanduser()
    if not path.is_file():
        raise SystemExit(f"REGISTA_KEY_PATH does not exist: {path}")
    return path


def _ca_file(env: dict[str, str]) -> Path:
    configured = env.get("DOSSIER_LDAP_CA_CERT_FILE", "").strip()
    path = (
        Path(configured).expanduser()
        if configured
        else Path.home() / ".config" / "agent-suite" / "secrets" / "ad-root-ca.pem"
    )
    if not path.is_file():
        raise SystemExit(f"DOSSIER_LDAP_CA_CERT_FILE does not exist: {path}")
    return path


def main() -> int:
    suite_env = _load_env(_suite_env_path())
    # Match the suite config contract: process environment wins over suite.env.
    suite_env.update(os.environ)
    projects = _csv(suite_env, "DOSSIER_PROJECTS", required=True)
    administrators = _csv(suite_env, "DOSSIER_ADMIN_PRINCIPALS", required=True)
    administrator_groups = _csv(suite_env, "DOSSIER_ADMIN_GROUPS")
    ca_cert_path = _ca_file(suite_env)
    ca_pem = ca_cert_path.read_text(encoding="utf-8")
    key_text = _key_file(suite_env).read_text(encoding="utf-8")
    try:
        key_document = json.loads(key_text)
    except json.JSONDecodeError as error:
        raise SystemExit(f"REGISTA_KEY_PATH is not valid JSON: {error.msg}") from error
    if not isinstance(key_document, dict):
        raise SystemExit("REGISTA_KEY_PATH must contain a JSON object")

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
            "REGISTA_DSN": _require_literal(suite_env, "REGISTA_DSN"),
            "REGISTA_KEY_PATH": "/etc/regista/keys.json",
            "DOSSIER_ENV": "prod",
            "DOSSIER_SESSION_SECRET": _require_literal(suite_env, "DOSSIER_SESSION_SECRET"),
            "DOSSIER_PROJECTS": ",".join(projects),
            "DOSSIER_PROJECT_ACL_PATH": "/etc/dossier/acl/acl.json",
            "DOSSIER_ALLOWED_HOSTS": _allowed_hosts(suite_env),
            "DOSSIER_REQUIRE_SSL": "true",
            "DOSSIER_BEHIND_TLS_PROXY": "true",
            "DOSSIER_AUTH_BACKEND": "ldap",
            "DOSSIER_LDAP_SERVER": _require(suite_env, "DOSSIER_LDAP_SERVER"),
            "DOSSIER_LDAP_BASE_DN": _require(suite_env, "DOSSIER_LDAP_BASE_DN"),
            "DOSSIER_LDAP_BIND_DN": _require(suite_env, "DOSSIER_LDAP_BIND_DN"),
            "DOSSIER_LDAP_BIND_PASSWORD": _require_literal(suite_env, "DOSSIER_LDAP_BIND_PASSWORD"),
            "DOSSIER_LDAP_DOMAIN": _require(suite_env, "DOSSIER_LDAP_DOMAIN"),
            "DOSSIER_LDAP_USER_FILTER": suite_env.get(
                "DOSSIER_LDAP_USER_FILTER",
                "(&(objectClass=user)(sAMAccountName={login}))",
            ),
            "DOSSIER_LDAP_GROUP_STRATEGY": suite_env.get("DOSSIER_LDAP_GROUP_STRATEGY", "direct"),
            "DOSSIER_LDAP_CA_CERT_FILE": "/etc/dossier/secrets/ad-root-ca.pem",
        },
    }

    project_acl = {
        "apiVersion": "v1",
        "kind": "ConfigMap",
        "metadata": {
            "name": "dossier-project-acl",
            "namespace": "dossier",
            "labels": {
                "app.kubernetes.io/name": "dossier",
                "app.kubernetes.io/part-of": "agent-suite",
            },
        },
        "data": {
            "acl.json": json.dumps(
                {
                    "version": 1,
                    "administrators": {
                        "principals": administrators,
                        "groups": administrator_groups,
                    },
                    # Fail closed: each project is private unless the operator
                    # deliberately changes its ACL after reviewing the list.
                    "projects": {project: {"public": False} for project in projects},
                },
                indent=2,
            )
            + "\n"
        },
    }
    signing_keys = {
        "apiVersion": "v1",
        "kind": "Secret",
        "metadata": {
            "name": "regista-signing-keys",
            "namespace": "dossier",
            "labels": {
                "app.kubernetes.io/name": "dossier",
                "app.kubernetes.io/part-of": "agent-suite",
            },
        },
        "type": "Opaque",
        "stringData": {"keys.json": key_text},
    }

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    secret_path = OUTPUT_DIR / "secret-suite-env.yaml"
    keys_path = OUTPUT_DIR / "secret-regista-keys.yaml"
    acl_path = OUTPUT_DIR / "configmap-project-acl.yaml"
    _write_private_json(secret_path, secret)
    _write_private_json(keys_path, signing_keys)
    _write_private_json(acl_path, project_acl)

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
    _write_private_json(cm_path, ca_cm)
    print(f"wrote {secret_path}")
    print(f"wrote {keys_path}")
    print(f"wrote {acl_path}")
    print(f"wrote {cm_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
