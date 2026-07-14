import protobuf from "protobufjs";
import runtimeProto from "../../shared/proto/privoke/v1/runtime.proto";
import { frameGrpcWebMessage, parseGrpcWebResponse } from "./grpc-web.js";

const RPC_PATH = "/privoke.v1.PrivokeRuntimeService/AnalyzePrompt";
const root = protobuf.parse(runtimeProto).root;
const Request = root.lookupType("privoke.v1.AnalyzePromptRequest");
const Response = root.lookupType("privoke.v1.AnalyzePromptResponse");

export class RuntimeClient {
  constructor(baseUrl = "http://127.0.0.1:8080") {
    this.baseUrl = baseUrl.replace(/\/$/, "");
  }

  async analyzePrompt(values, { signal } = {}) {
    const request = Request.fromObject(values);
    const body = frameGrpcWebMessage(Request.encode(request).finish());
    const response = await fetch(`${this.baseUrl}${RPC_PATH}`, {
      method: "POST",
      headers: {
        "Content-Type": "application/grpc-web+proto",
        "X-Grpc-Web": "1",
        "X-User-Agent": "privoke-extension/0.1",
      },
      body,
      signal,
    });

    if (!response.ok) {
      throw new Error(`Runtime bridge returned HTTP ${response.status}.`);
    }

    const { messages, trailers } = parseGrpcWebResponse(await response.arrayBuffer());
    const grpcStatus = trailers["grpc-status"] ?? response.headers.get("grpc-status") ?? "0";
    if (grpcStatus !== "0") {
      const grpcMessage = trailers["grpc-message"] ?? response.headers.get("grpc-message");
      throw new Error(grpcMessage ? decodeURIComponent(grpcMessage) : `gRPC status ${grpcStatus}.`);
    }
    if (messages.length !== 1) {
      throw new Error(`Expected one runtime response, received ${messages.length}.`);
    }

    return Response.toObject(Response.decode(messages[0]), {
      defaults: true,
      enums: String,
      arrays: true,
      objects: true,
    });
  }
}
