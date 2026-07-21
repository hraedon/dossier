# dossier — suite container image (Plan 013 WI-2.1)
#
# Substrate-agnostic: runs under compose or k8s. Reads all config from
# environment (suite.env mounted at runtime); no baked secrets.
#
# The regista pin is explicit and matches SUITE.lock [spine].version. CI passes
# --build-arg REGISTA_VERSION from the lock; update both together.

ARG PYTHON_VERSION=3.13
ARG REGISTA_VERSION=0.5.3

# ── Stage 1: builder ─────────────────────────────────────────────────────────
# regista-hraedon installs from PyPI (a wheel), so no git is needed here — the
# builder only compiles the libpq-backed deps.
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

# Install the regista spine from PyPI at the locked version, then dossier.
# (regista-hraedon >= 0.5.2 fixes importlib.metadata.version() post-rename, so
# no version-lookup patch is needed — the lock pins 0.5.3.)
RUN pip install "regista-hraedon==${REGISTA_VERSION}"

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
    && useradd -r -s /usr/sbin/nologin dossier

COPY --from=builder /venv /venv

# Smoke test: verify imports resolve in the runtime image before entrypoint.
RUN python -c "import dossier, regista, uvicorn, itsdangerous" && dossier --version

WORKDIR /app

USER dossier

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request, json; r=urllib.request.urlopen('http://127.0.0.1:8000/healthz', timeout=4); d=json.load(r); exit(1 if any(c['status']=='fail' for c in d.get('checks',[])) else 0)" || exit 1

ENTRYPOINT ["dossier", "serve", "--host", "0.0.0.0", "--port", "8000"]
