import { privoke } from "./generated/runtime.js";
import { requireExplicitLayers } from "./analysis-request.js";
import { NativePortTransport } from "./native-port-transport.js";

const {
  AnalyzePromptRequest: Request,
  AnalyzePromptResponse: Response,
  RuntimeHealthRequest,
  RuntimeHealthResponse,
  SetRuntimeEnabledRequest,
  RuntimeControlStatus,
} = privoke.v1;

// The runtime client keeps the request and response messages of the gRPC-Web client it replaced
// (PrivokeRuntimeService.AnalyzePrompt and PrivokeRuntimeControlService); only the carrier changed, from
// loopback HTTP to a native-messaging port to the controller. The transport rejects on any failure,
// so a caller never sees a response that did not come from the runtime.
export class RuntimeClient {
  constructor(transport = new NativePortTransport()) {
    this.transport = transport;
  }

  async analyzePrompt(values, { signal } = {}) {
    requireExplicitLayers(values);
    return this.#unary("AnalyzePrompt", Request, Response, values, { signal });
  }

  async streamingHealth({ signal } = {}) {
    return this.#unary("ModelStreamingHealth", RuntimeHealthRequest, RuntimeHealthResponse, {}, { signal });
  }

  async setRuntimeEnabled(enabled, { signal, useLocalStack } = {}) {
    return this.#unary(
      "SetRuntimeEnabled",
      SetRuntimeEnabledRequest,
      RuntimeControlStatus,
      { enabled, ...(typeof useLocalStack === "boolean" ? { useLocalStack } : {}) },
      { signal },
    );
  }

  async runtimeStatus({ signal } = {}) {
    return this.#unary("Status", RuntimeHealthRequest, RuntimeControlStatus, {}, { signal });
  }

  async #unary(method, requestType, responseType, values, { signal } = {}) {
    const request = requestType.fromObject(values);
    const reply = await this.transport.request(method, requestType.encode(request).finish(), { signal });
    return responseType.toObject(responseType.decode(reply), {
      defaults: true,
      enums: String,
      arrays: true,
      objects: true,
    });
  }
}
