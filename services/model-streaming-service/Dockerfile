FROM golang:1.22-bookworm

WORKDIR /workspace

RUN apt-get update \
    && apt-get install -y --no-install-recommends protobuf-compiler \
    && rm -rf /var/lib/apt/lists/*

RUN go install google.golang.org/protobuf/cmd/protoc-gen-go@v1.34.1 \
    && go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@v1.4.0 \
    && go install github.com/cosmtrek/air@v1.52.3

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
