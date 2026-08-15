ARG ARVANCLD_GIT_REF=19f8b49b993bbec935f7cd61bbb65ff9bcb1982f

FROM python:3.13-slim AS wheel-builder

ARG ARVANCLD_GIT_REF

ENV PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /build

RUN apt-get update \
    && apt-get install --no-install-recommends --yes ca-certificates git \
    && rm -rf /var/lib/apt/lists/*

RUN git init /build/arvancld \
    && git -C /build/arvancld remote add origin https://github.com/faridrasidov/arvancld.git \
    && git -C /build/arvancld fetch --depth=1 origin "${ARVANCLD_GIT_REF}" \
    && git -C /build/arvancld checkout --detach FETCH_HEAD \
    && test "$(git -C /build/arvancld rev-parse HEAD)" = "${ARVANCLD_GIT_REF}"

COPY pyproject.toml README.md /build/bot/
COPY src /build/bot/src

RUN python -m pip wheel --wheel-dir /wheels /build/arvancld \
    && python -m pip wheel --wheel-dir /wheels \
        "pyTelegramBotAPI==4.34.0" "python-dotenv>=1.0,<2" \
    && python -m pip wheel --no-deps --wheel-dir /wheels /build/bot \
    && python -m pip install --no-cache-dir --no-index --find-links=/wheels arvancld \
    && python -c "from arvancld.auth import AsyncAuthService; assert hasattr(AsyncAuthService, 'submit_totp')"

FROM python:3.13-slim

ARG ARVANCLD_GIT_REF

LABEL io.github.faridrasidov.arvancld.revision="${ARVANCLD_GIT_REF}"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    ARVANCLD_SDK_REF="${ARVANCLD_GIT_REF}"

WORKDIR /app

COPY --from=wheel-builder /wheels /wheels

RUN python -m pip install --no-cache-dir --no-index --find-links=/wheels \
        "arvancld==0.1.0" "pyTelegramBotAPI==4.34.0" "python-dotenv>=1.0,<2" \
    && python -m pip install --no-cache-dir --no-index --no-deps \
        /wheels/arvancld_telegram-*.whl \
    && python -c "from arvancld.auth import AsyncAuthService; assert hasattr(AsyncAuthService, 'submit_totp')" \
    && rm -rf /wheels \
    && groupadd --gid 10001 bot \
    && useradd --uid 10001 --gid bot --create-home --shell /usr/sbin/nologin bot \
    && mkdir -p /app/data \
    && chown -R bot:bot /app

USER bot

CMD ["python", "-m", "arvancld_telegram"]

