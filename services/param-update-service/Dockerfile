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
COPY services/param-update-service /workspace/services/param-update-service

WORKDIR /workspace/services/param-update-service

RUN pip install --no-cache-dir -r requirements.txt \
    && mkdir -p generated \
    && python -m grpc_tools.protoc \
      -I /workspace/shared/proto \
      --python_out=/workspace/services/param-update-service/generated \
      --grpc_python_out=/workspace/services/param-update-service/generated \
      /workspace/shared/proto/privoke/v1/parameters.proto

EXPOSE 50052

CMD ["python", "app/server.py"]

FROM python:3.11-slim-bookworm AS runtime

ENV VIRTUAL_ENV=/opt/venv
ENV PATH="${VIRTUAL_ENV}/bin:${PATH}"
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV HOME=/tmp

RUN apt-get update \
    && apt-get upgrade -y \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --system --gid 10001 privoke \
    && useradd --system --uid 10001 --gid privoke --no-create-home privoke \
    && mkdir -p /data \
    && chown privoke:privoke /data

COPY --from=development /opt/venv /opt/venv
COPY --from=development /workspace /workspace

RUN pip uninstall -y grpcio-tools wheel \
    && /usr/local/bin/python -m pip uninstall -y pip setuptools wheel

WORKDIR /workspace/services/param-update-service

EXPOSE 50052

USER privoke:privoke

CMD ["python", "app/server.py"]
