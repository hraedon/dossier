from __future__ import annotations

import pytest
from regista.testing import InMemoryRegista

from dossier.gateway import RegistaGateway
from dossier.keys import generate_keyset

from helpers import ALICE


@pytest.fixture
def gateway(tmp_path):
    key_path = tmp_path / "keys.json"
    generate_keyset(key_path)
    reg = InMemoryRegista(project="dossier_test", hmac_key_path=str(key_path))
    gw = RegistaGateway(reg)
    gw.register_workflow()
    yield gw
    gw.close()


@pytest.fixture
def make_issue(gateway):
    def _make(*, actor=ALICE, work_item_type="bug", **fields):
        wi, _ = gateway.create_issue(
            actor=actor,
            work_item_type=work_item_type,
            custom_fields=fields or None,
        )
        return wi

    return _make
