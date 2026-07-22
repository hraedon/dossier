"""Behavioral tests for the central-service Kubernetes packaging (Plan 023)."""

from __future__ import annotations

import importlib.util
import json
import stat
import tomllib
from pathlib import Path
from types import ModuleType

import pytest


_ROOT = Path(__file__).resolve().parents[1]
_GENERATOR = _ROOT / "scripts" / "gen-k8s-secret.py"
_PROCESS_OVERRIDES = (
    "REGISTA_DSN",
    "REGISTA_KEY_PATH",
    "DOSSIER_SESSION_SECRET",
    "DOSSIER_PROJECTS",
    "DOSSIER_ADMIN_PRINCIPALS",
    "DOSSIER_ADMIN_GROUPS",
    "DOSSIER_LDAP_SERVER",
    "DOSSIER_LDAP_BASE_DN",
    "DOSSIER_LDAP_BIND_DN",
    "DOSSIER_LDAP_BIND_PASSWORD",
    "DOSSIER_LDAP_DOMAIN",
    "DOSSIER_LDAP_CA_CERT_FILE",
)


def _load_generator() -> ModuleType:
    spec = importlib.util.spec_from_file_location("dossier_gen_k8s_secret", _GENERATOR)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _clear_process_config(monkeypatch: pytest.MonkeyPatch) -> None:
    for key in _PROCESS_OVERRIDES:
        monkeypatch.delenv(key, raising=False)


def _suite_env(path: Path, key_path: Path, ca_path: Path, *, include_projects: bool = True) -> None:
    values = {
        "REGISTA_DSN": "postgresql://example.invalid/dossier",
        "REGISTA_KEY_PATH": str(key_path),
        "DOSSIER_SESSION_SECRET": "synthetic-session-secret-for-tests",
        "DOSSIER_ADMIN_PRINCIPALS": "operator-example",
        "DOSSIER_LDAP_SERVER": "ldaps://directory.example",
        "DOSSIER_LDAP_BASE_DN": "DC=example,DC=invalid",
        "DOSSIER_LDAP_BIND_DN": "CN=svc-example,DC=example,DC=invalid",
        "DOSSIER_LDAP_BIND_PASSWORD": "synthetic-password",
        "DOSSIER_LDAP_DOMAIN": "EXAMPLE",
        "DOSSIER_LDAP_CA_CERT_FILE": str(ca_path),
    }
    if include_projects:
        values["DOSSIER_PROJECTS"] = "project_one,project_two"
    path.write_text("".join(f"{key}={value}\n" for key, value in values.items()))


def test_generator_writes_private_fail_closed_manifests(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _load_generator()
    suite_env = tmp_path / "suite.env"
    output = tmp_path / "out"
    key_path = tmp_path / "keys.json"
    key_path.write_text('{"active_key_id":"example","keys":{}}\n')
    ca_path = tmp_path / "directory-ca.pem"
    ca_path.write_text("synthetic CA certificate\n")
    _suite_env(suite_env, key_path, ca_path)
    _clear_process_config(monkeypatch)
    monkeypatch.setenv("AGENT_SUITE_CONFIG", str(suite_env))
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setattr(module, "OUTPUT_DIR", output)

    assert module.main() == 0

    secret_path = output / "secret-suite-env.yaml"
    keys_path = output / "secret-regista-keys.yaml"
    acl_path = output / "configmap-project-acl.yaml"
    ca_path = output / "configmap-ad-root-ca.yaml"
    assert stat.S_IMODE(secret_path.stat().st_mode) == 0o600
    assert stat.S_IMODE(keys_path.stat().st_mode) == 0o600
    assert stat.S_IMODE(acl_path.stat().st_mode) == 0o600
    assert stat.S_IMODE(ca_path.stat().st_mode) == 0o600

    secret = json.loads(secret_path.read_text())
    assert secret["stringData"]["DOSSIER_PROJECTS"] == "project_one,project_two"
    assert secret["stringData"]["DOSSIER_ALLOWED_HOSTS"].endswith(",127.0.0.1")

    acl_manifest = json.loads(acl_path.read_text())
    acl = json.loads(acl_manifest["data"]["acl.json"])
    assert acl["administrators"]["principals"] == ["operator-example"]
    assert acl["projects"] == {
        "project_one": {"public": False},
        "project_two": {"public": False},
    }


def test_generator_refuses_implicit_estate_inventory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _load_generator()
    suite_env = tmp_path / "suite.env"
    key_path = tmp_path / "keys.json"
    key_path.write_text("{}\n")
    ca_path = tmp_path / "directory-ca.pem"
    ca_path.write_text("synthetic CA certificate\n")
    _suite_env(suite_env, key_path, ca_path, include_projects=False)
    _clear_process_config(monkeypatch)
    monkeypatch.setenv("AGENT_SUITE_CONFIG", str(suite_env))
    monkeypatch.setattr(module, "OUTPUT_DIR", tmp_path / "out")

    with pytest.raises(SystemExit, match="DOSSIER_PROJECTS is required"):
        module.main()


def test_generator_refuses_unresolved_secret_reference(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _load_generator()
    suite_env = tmp_path / "suite.env"
    key_path = tmp_path / "keys.json"
    key_path.write_text("{}\n")
    ca_path = tmp_path / "directory-ca.pem"
    ca_path.write_text("synthetic CA certificate\n")
    _suite_env(suite_env, key_path, ca_path)
    with suite_env.open("a") as handle:
        handle.write("DOSSIER_LDAP_BIND_PASSWORD=env:UNRESOLVED_EXAMPLE\n")
    _clear_process_config(monkeypatch)
    monkeypatch.setenv("AGENT_SUITE_CONFIG", str(suite_env))
    monkeypatch.setattr(module, "OUTPUT_DIR", tmp_path / "out")

    with pytest.raises(SystemExit, match="references unset environment variable"):
        module.main()


def test_k8s_base_uses_locked_image_and_split_probes() -> None:
    lock = tomllib.loads((_ROOT / "SUITE.lock").read_text())
    deployment = (_ROOT / "deploy" / "k8s" / "deployment.yaml").read_text()
    expected = f"{lock['container']['registry']}/{lock['container']['image']}:"
    expected += f"{lock['component']['version']}-{lock['spine']['version']}"

    assert f"image: {expected}" in deployment
    assert "readinessProbe:\n            httpGet:\n" in deployment
    assert "path: /healthz" in deployment
    assert "livenessProbe:\n            httpGet:\n" in deployment
    assert "path: /livez" in deployment
    assert "automountServiceAccountToken: false" in deployment
    assert "readOnlyRootFilesystem: true" in deployment


def test_generated_inputs_are_gitignored() -> None:
    patterns = (_ROOT / ".gitignore").read_text().splitlines()
    for name in (
        "secret-suite-env.yaml",
        "secret-regista-keys.yaml",
        "configmap-ad-root-ca.yaml",
        "configmap-project-acl.yaml",
    ):
        assert f"deploy/k8s/{name}" in patterns
