# dossier — suite container image (Plan 013 WI-2.1)
#
# Substrate-agnostic: runs under compose or k8s. Reads all config from
# environment (suite.env mounted at runtime); no baked secrets.
#
# The regista pin is explicit and matches SUITE.lock. Update both together.

ARG PYTHON_VERSION=3.13
ARG REGISTA_REF=dd22197eaafe11afabdae488b6908a5729b3b343

# ── Stage 1: builder ─────────────────────────────────────────────────────────
# git is needed here to pip-install regista from a pinned SHA but does NOT
# carry into the runtime image (WI-013).
FROM python:${PYTHON_VERSION}-slim AS builder

ARG REGISTA_REF
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

RUN apt-get update && apt-get install -y --no-install-recommends \
        git \
        build-essential \
        libpq-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Build into a virtualenv that we copy wholesale into the runtime image.
RUN python -m venv /venv
ENV PATH="/venv/bin:$PATH"

# Install regista from the pinned SHA, then dossier.
RUN pip install "regista @ git+https://github.com/hraedon/regista.git@${REGISTA_REF}"

COPY pyproject.toml .
COPY src/ src/
RUN pip install ".[auth-ldap]"

# ── Stage 2: runtime ─────────────────────────────────────────────────────────
FROM python:${PYTHON_VERSION}-slim AS runtime

ARG REGISTA_REF
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    REGISTA_REF=${REGISTA_REF} \
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
