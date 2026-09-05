FROM python:3.11-slim-bookworm AS development

WORKDIR /workspace

ENV VIRTUAL_ENV=/opt/venv
ENV PATH="${VIRTUAL_ENV}/bin:${PATH}"

RUN apt-get update \
    && apt-get upgrade -y \
    && apt-get install -y --no-install-recommends build-essential protobuf-compiler \
    && rm -rf /var/lib/apt/lists/* \
    && python -m venv "${VIRTUAL_ENV}" \
    && pip install --no-cache-dir --upgrade pip setuptools wheel

COPY shared /workspace/shared
COPY extension/client-runtime /workspace/extension/client-runtime

WORKDIR /workspace/extension/client-runtime

ENV PRIVOKE_GRPC_HOST=0.0.0.0

ARG PRIVOKE_INSTALL_GPU=false

RUN pip install --no-cache-dir -r requirements.txt /workspace/shared/python \
    && if [ "${PRIVOKE_INSTALL_GPU}" = "true" ]; then \
      pip install --no-cache-dir -r requirements-gpu.txt; \
    fi \
    && mkdir -p generated \
    && python -m grpc_tools.protoc \
      -I /workspace/shared/proto \
      --python_out=/workspace/extension/client-runtime/generated \
      --grpc_python_out=/workspace/extension/client-runtime/generated \
      /workspace/shared/proto/privoke/v1/parameters.proto \
      /workspace/shared/proto/privoke/v1/runtime.proto \
      /workspace/shared/proto/privoke/v1/telemetry.proto

EXPOSE 50054

CMD ["python", "src/grpc_main.py"]

FROM python:3.11-slim-bookworm AS runtime

ENV VIRTUAL_ENV=/opt/venv
ENV PATH="${VIRTUAL_ENV}/bin:${PATH}"
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV HOME=/tmp
ENV PRIVOKE_GRPC_HOST=0.0.0.0

RUN apt-get update \
    && apt-get upgrade -y \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --system --gid 10001 privoke \
    && useradd --system --uid 10001 --gid privoke --no-create-home privoke

COPY --from=development /opt/venv /opt/venv
COPY --from=development /workspace /workspace
# Runtime unit tests exercise the checked-in model artifacts in the release image.
COPY models /workspace/models

RUN pip uninstall -y grpcio-tools wheel \
    && /usr/local/bin/python -m pip uninstall -y pip setuptools wheel

WORKDIR /workspace/extension/client-runtime

EXPOSE 50054

USER privoke:privoke

CMD ["python", "src/grpc_main.py"]
