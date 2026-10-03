#!/bin/sh
set -eu
script_root=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$script_root/../services/model-streaming-service"
go test -race ./...
