from __future__ import annotations

import ast
from pathlib import Path

import pytest

_FORBIDDEN_MODULES = {
    "regista._custody",
    "regista._provision",
    "regista._secrets",
    "regista._errors",
    "regista._contract",
    "regista._connection",
    "regista._keys",
    "regista._events_api",
    "regista._event_store",
    "regista._principal_keys",
}

_SRC_DIR = Path(__file__).parent.parent / "src" / "dossier"


def _collect_imports(module_name: str, filepath: Path) -> list[tuple[str, str]]:
    tree = ast.parse(filepath.read_text(), filename=str(filepath))
    imports: list[tuple[str, str]] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            if node.module and any(
                node.module == forbidden or node.module.startswith(forbidden + ".")
                for forbidden in _FORBIDDEN_MODULES
            ):
                for alias in node.names:
                    imports.append((module_name, f"from {node.module} import {alias.name}"))
        elif isinstance(node, ast.Import):
            for alias in node.names:
                if any(
                    alias.name == forbidden or alias.name.startswith(forbidden + ".")
                    for forbidden in _FORBIDDEN_MODULES
                ):
                    imports.append((module_name, f"import {alias.name}"))
    return imports


def _all_source_files() -> list[tuple[str, Path]]:
    files: list[tuple[str, Path]] = []
    for py in sorted(_SRC_DIR.rglob("*.py")):
        rel = py.relative_to(_SRC_DIR)
        module_name = "dossier." + ".".join(rel.with_suffix("").parts)
        if module_name.endswith(".__init__"):
            module_name = module_name[:-9]
        files.append((module_name, py))
    return files


class TestNoPrivateRegistaImports:
    def test_no_production_imports_from_regista_private_modules(self) -> None:
        violations: list[str] = []
        for module_name, filepath in _all_source_files():
            violations.extend(_collect_imports(module_name, filepath))
        if violations:
            formatted = "\n".join(f"  {mod}: {imp}" for mod, imp in violations)
            pytest.fail(
                f"Found {len(violations)} import(s) from regista private modules:\n{formatted}"
            )

    def test_gateway_does_not_import_custody_or_provision(self) -> None:
        import dossier.gateway as gw_mod

        source = Path(gw_mod.__file__).read_text()
        assert "regista._custody" not in source
        assert "regista._provision" not in source
        assert "regista._secrets" not in source

    def test_app_does_not_import_regista_private_errors(self) -> None:
        import dossier.app as app_mod

        source = Path(app_mod.__file__).read_text()
        assert "from regista._errors" not in source
