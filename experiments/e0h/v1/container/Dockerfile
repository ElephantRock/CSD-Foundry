FROM python:3.11.13-slim-bookworm@sha256:86adf8dbadc3d6e82ee5dd2c74bec2e1c2467cdad47886280501df722372d2e1

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    TOKENIZERS_PARALLELISM=false

WORKDIR /opt/csd-foundry

COPY experiments/e0h/v1/requirements-cu128.lock /tmp/requirements-cu128.lock
RUN python -m pip install --require-hashes -r /tmp/requirements-cu128.lock

COPY pyproject.toml README.md ./
COPY src ./src
RUN python -m pip install --no-deps --no-build-isolation .

COPY data ./data
COPY experiments/e0h/v1 ./experiments/e0h/v1

ENTRYPOINT ["python", "-m", "csd_foundry.empirical.e0h.harness.preflight"]
CMD ["--run-root", "experiments/e0h/v1", "--mode", "gpu", "--require-snapshot"]
