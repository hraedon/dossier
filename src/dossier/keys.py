from __future__ import annotations

import base64
import json
import os
import secrets
from pathlib import Path


def generate_keyset(path: Path, *, key_id: str | None = None) -> dict:
    if key_id is None:
        key_id = f"dossier-{secrets.token_hex(4)}"

    secret = secrets.token_bytes(32)
    keyset = {
        "keys": [
            {
                "key_id": key_id,
                "secret": base64.b64encode(secret).decode("ascii"),
                "status": "active",
                "scheme": "hmac-sha256",
            }
        ]
    }

    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    data = json.dumps(keyset, indent=2).encode("utf-8")

    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
    except Exception:
        try:
            os.close(fd)
        except OSError:
            pass
        raise
    os.chmod(path, 0o600)

    return keyset
