FROM pytorch/pytorch@sha256:0a3b9fedefe1f61ac4d5a9de9015c0863db27ca0fde2d4e37e6268147980b726

WORKDIR /workspace

COPY experiments/e0h/v1/container/requirements.lock /tmp/e0h-requirements.lock
RUN python -m pip install --no-cache-dir --no-deps -r /tmp/e0h-requirements.lock \
    && (python -m pip check > /tmp/e0h-pip-check.txt 2>&1 || true) \
    && cat /tmp/e0h-pip-check.txt \
    && sed '/^ninja 1\.11\.1\.1 is not supported on this platform$/d' \
        /tmp/e0h-pip-check.txt > /tmp/e0h-unexpected-pip-check.txt \
    && test ! -s /tmp/e0h-unexpected-pip-check.txt

ENV HF_HUB_DISABLE_TELEMETRY=1 \
    PYTHONHASHSEED=1729 \
    TOKENIZERS_PARALLELISM=false \
    TRANSFORMERS_NO_ADVISORY_WARNINGS=1

COPY . /workspace
