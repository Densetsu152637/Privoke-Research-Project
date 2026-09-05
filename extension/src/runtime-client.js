import { privoke } from "./generated/runtime.js";
import { requireExplicitLayers } from "./analysis-request.js";
import { frameGrpcWebMessage, parseGrpcWebResponse } from "./grpc-web.js";

const RPC_PATH = "/privoke.v1.PrivokeRuntimeService/AnalyzePrompt";
const STREAMING_HEALTH_PATH = "/privoke.v1.PrivokeRuntimeControlService/ModelStreamingHealth";
const RUNTIME_CONTROL_PATH = "/privoke.v1.PrivokeRuntimeControlService/SetRuntimeEnabled";
const RUNTIME_STATUS_PATH = "/privoke.v1.PrivokeRuntimeControlService/Status";
const {
  AnalyzePromptRequest: Request,
  AnalyzePromptResponse: Response,
  RuntimeHealthRequest,
  RuntimeHealthResponse,
  SetRuntimeEnabledRequest,
  RuntimeControlStatus,
} = privoke.v1;

export class RuntimeClient {
  constructor(baseUrl = "http://127.0.0.1:8080") {
    this.baseUrl = baseUrl.replace(/\/$/, "");
  }

  async analyzePrompt(values, { signal } = {}) {
    requireExplicitLayers(values);
    return this.#unary(RPC_PATH, Request, Response, values, { signal });
  }

  async streamingHealth({ signal } = {}) {
    return this.#unary(
      STREAMING_HEALTH_PATH,
      RuntimeHealthRequest,
      RuntimeHealthResponse,
      {},
      { signal },
    );
  }

  async setRuntimeEnabled(enabled, { signal, useLocalStack } = {}) {
    return this.#unary(
      RUNTIME_CONTROL_PATH,
      SetRuntimeEnabledRequest,
      RuntimeControlStatus,
      { enabled, ...(typeof useLocalStack === "boolean" ? { useLocalStack } : {}) },
      { signal },
    );
  }

  async runtimeStatus({ signal } = {}) {
    return this.#unary(
      RUNTIME_STATUS_PATH,
      RuntimeHealthRequest,
      RuntimeControlStatus,
      {},
      { signal },
    );
  }

  async #unary(path, requestType, responseType, values, { signal } = {}) {
    const request = requestType.fromObject(values);
    const body = frameGrpcWebMessage(requestType.encode(request).finish());
    const response = await fetch(`${this.baseUrl}${path}`, {
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

    return responseType.toObject(responseType.decode(messages[0]), {
      defaults: true,
      enums: String,
      arrays: true,
      objects: true,
    });
  }
}
