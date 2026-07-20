# dossier — suite container image (Plan 013 WI-2.1)
#
# Substrate-agnostic: runs under compose or k8s. Reads all config from
# environment (suite.env mounted at runtime); no baked secrets.
#
# regista-hraedon is the published PyPI distribution (the import name stays
# 'regista'). Pin both the dossier version and the regista-hraedon version
# together when advancing the candidate.

ARG PYTHON_VERSION=3.13
ARG REGISTA_VERSION=0.5.1

# ── Stage 1: builder ─────────────────────────────────────────────────────────
FROM python:${PYTHON_VERSION}-slim AS builder

ARG REGISTA_VERSION
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
        libpq-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Build into a virtualenv that we copy wholesale into the runtime image.
RUN python -m venv /venv
ENV PATH="/venv/bin:$PATH"

# Install regista-hraedon from PyPI, then dossier.
# Temporary: patch the version lookup until regista-hraedon 0.5.2 is published
# (https://github.com/hraedon/regista/pull/6). The PyPI rename from 'regista' to
# 'regista-hraedon' broke importlib.metadata.version("regista") in _integrity.py.
RUN pip install "regista-hraedon==${REGISTA_VERSION}" \
    && python3 -c "\
import pathlib, importlib.util; \
p = pathlib.Path(importlib.util.find_spec('regista._integrity').origin); \
t = p.read_text(); \
old = 'REGISTA_VERSION = importlib.metadata.version(\"regista\")'; \
new = 'REGISTA_VERSION = importlib.metadata.version(\"regista-hraedon\")'; \
if old in t: \
    p.write_text(t.replace(old, new, 1)); \
    print(f'patched {p}'); \
else: \
    print('patch not needed (regista >= 0.5.2?)')"

COPY pyproject.toml .
COPY src/ src/
RUN pip install ".[auth-ldap]"

# ── Stage 2: runtime ─────────────────────────────────────────────────────────
FROM python:${PYTHON_VERSION}-slim AS runtime

ARG REGISTA_VERSION
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    REGISTA_VERSION=${REGISTA_VERSION} \
    PATH="/venv/bin:$PATH"

# Only the shared libpq library is needed at runtime — no git, no compilers.
RUN apt-get update && apt-get install -y --no-install-recommends \
        libpq5 \
    && rm -rf /var/lib/apt/lists/* \
    && useradd -r -u 65532 -s /usr/sbin/nologin dossier

COPY --from=builder /venv /venv

# Smoke test: verify imports resolve in the runtime image before entrypoint.
RUN python -c "import dossier, regista, uvicorn, itsdangerous" && dossier --version

WORKDIR /app

USER dossier

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request, json; r=urllib.request.urlopen('http://127.0.0.1:8000/healthz', timeout=4); d=json.load(r); exit(1 if any(c['status']=='fail' for c in d.get('checks',[])) else 0)" || exit 1

ENTRYPOINT ["dossier", "serve", "--host", "0.0.0.0", "--port", "8000"]
