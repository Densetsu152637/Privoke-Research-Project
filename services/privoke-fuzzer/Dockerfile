FROM python:3.11-slim-bookworm AS development

WORKDIR /workspace

ENV VIRTUAL_ENV=/opt/venv
ENV PATH="${VIRTUAL_ENV}/bin:${PATH}"

RUN apt-get update \
    && apt-get upgrade -y \
    && rm -rf /var/lib/apt/lists/* \
    && python -m venv "${VIRTUAL_ENV}" \
    && pip install --no-cache-dir --upgrade pip setuptools wheel

COPY shared /workspace/shared
COPY services/privoke-fuzzer /workspace/services/privoke-fuzzer

WORKDIR /workspace/services/privoke-fuzzer

ENV PRIVOKE_FUZZER_DUMP_DIR=/workspace/dumps/privoke-fuzzer

RUN pip install --no-cache-dir -r requirements.txt /workspace/shared/python \
    && mkdir -p /workspace/dumps/privoke-fuzzer \
    && mkdir -p generated \
    && python -m grpc_tools.protoc \
      -I /workspace/shared/proto \
      --python_out=/workspace/services/privoke-fuzzer/generated \
      --grpc_python_out=/workspace/services/privoke-fuzzer/generated \
      /workspace/shared/proto/privoke/v1/parameters.proto \
      /workspace/shared/proto/privoke/v1/runtime.proto

EXPOSE 50053

CMD ["python", "src/main.py"]

FROM python:3.11-slim-bookworm AS runtime

ENV VIRTUAL_ENV=/opt/venv
ENV PATH="${VIRTUAL_ENV}/bin:${PATH}"
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV HOME=/tmp
ENV PRIVOKE_FUZZER_DUMP_DIR=/workspace/dumps/privoke-fuzzer

RUN apt-get update \
    && apt-get upgrade -y \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --system --gid 10001 privoke \
    && useradd --system --uid 10001 --gid privoke --no-create-home privoke

COPY --from=development /opt/venv /opt/venv
COPY --from=development /workspace /workspace

RUN pip uninstall -y grpcio-tools wheel \
    && /usr/local/bin/python -m pip uninstall -y pip setuptools wheel \
    && chown -R privoke:privoke /workspace/dumps/privoke-fuzzer

WORKDIR /workspace/services/privoke-fuzzer

EXPOSE 50053

USER privoke:privoke

CMD ["python", "src/main.py"]
