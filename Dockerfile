# dossier — suite container image (Plan 013 WI-2.1)
#
# Substrate-agnostic: runs under compose or k8s. Reads all config from
# environment (suite.env mounted at runtime); no baked secrets.
#
# The regista pin is explicit and matches SUITE.lock. Update both together.

ARG PYTHON_VERSION=3.13
FROM python:${PYTHON_VERSION}-slim AS base

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# regista pin — must match SUITE.lock
ARG REGISTA_REF=3613d95432548e81596183659c08d80d354843d1
ENV REGISTA_REF=${REGISTA_REF}

WORKDIR /app

# Install regista from the pinned SHA, then dossier
RUN pip install "regista @ git+https://github.com/hraedon/regista.git@${REGISTA_REF}"

COPY pyproject.toml .
COPY src/ src/
RUN pip install -e ".[auth-ldap]"

# Non-root user for the runtime
RUN useradd -r -s /usr/sbin/nologin dossier
USER dossier

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/healthz')" || exit 1

ENTRYPOINT ["dossier", "serve", "--host", "0.0.0.0", "--port", "8000"]
