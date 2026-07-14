import assert from "node:assert/strict";
import test from "node:test";
import { frameGrpcWebMessage, parseGrpcWebResponse } from "../src/grpc-web.js";

test("frames a protobuf payload for gRPC-Web", () => {
  assert.deepEqual(
    [...frameGrpcWebMessage(Uint8Array.from([1, 2, 3]))],
    [0, 0, 0, 0, 3, 1, 2, 3],
  );
});

test("parses data and trailer frames", () => {
  const data = frameGrpcWebMessage(Uint8Array.from([8, 1]));
  const trailerText = new TextEncoder().encode("grpc-status: 0\r\ngrpc-message: OK\r\n");
  const trailer = frameGrpcWebMessage(trailerText);
  trailer[0] = 0x80;
  const response = new Uint8Array(data.length + trailer.length);
  response.set(data);
  response.set(trailer, data.length);

  const parsed = parseGrpcWebResponse(response);
  assert.deepEqual([...parsed.messages[0]], [8, 1]);
  assert.deepEqual(parsed.trailers, { "grpc-status": "0", "grpc-message": "OK" });
});
