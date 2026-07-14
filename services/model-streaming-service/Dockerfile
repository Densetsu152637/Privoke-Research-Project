FROM golang:1.25.12-bookworm AS development

WORKDIR /workspace

ENV PATH="/go/bin:${PATH}"

RUN apt-get update \
    && apt-get upgrade -y \
    && apt-get install -y --no-install-recommends netcat-openbsd protobuf-compiler \
    && rm -rf /var/lib/apt/lists/*

RUN go install google.golang.org/protobuf/cmd/protoc-gen-go@v1.36.11 \
    && go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@v1.6.2

COPY shared/proto /workspace/shared/proto
COPY services/model-streaming-service /workspace/services/model-streaming-service

WORKDIR /workspace/services/model-streaming-service

RUN mkdir -p gen \
    && protoc \
      --proto_path=/workspace/shared/proto \
      --go_out=paths=source_relative:/workspace/services/model-streaming-service/gen \
      --go-grpc_out=paths=source_relative:/workspace/services/model-streaming-service/gen \
      /workspace/shared/proto/privoke/v1/parameters.proto

RUN go mod download

EXPOSE 50051

CMD ["go", "run", "./cmd/server"]

FROM development AS builder

RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" \
    -o /out/model-streaming-service ./cmd/server

FROM gcr.io/distroless/static-debian12:nonroot AS runtime

COPY --from=builder /out/model-streaming-service /model-streaming-service

EXPOSE 50051

USER nonroot:nonroot

ENTRYPOINT ["/model-streaming-service"]
