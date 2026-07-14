const DATA_FRAME = 0x00;
const TRAILER_FRAME = 0x80;

export function frameGrpcWebMessage(message) {
  const payload = message instanceof Uint8Array ? message : new Uint8Array(message);
  const framed = new Uint8Array(payload.length + 5);
  const view = new DataView(framed.buffer);
  framed[0] = DATA_FRAME;
  view.setUint32(1, payload.length, false);
  framed.set(payload, 5);
  return framed;
}

export function parseGrpcWebResponse(buffer) {
  const bytes = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
  const messages = [];
  let trailers = {};
  let offset = 0;

  while (offset < bytes.length) {
    if (offset + 5 > bytes.length) {
      throw new Error("The gRPC-Web response ended inside a frame header.");
    }

    const flags = bytes[offset];
    const length = new DataView(bytes.buffer, bytes.byteOffset + offset + 1, 4)
      .getUint32(0, false);
    const end = offset + 5 + length;
    if (end > bytes.length) {
      throw new Error("The gRPC-Web response ended inside a frame body.");
    }

    const payload = bytes.subarray(offset + 5, end);
    if ((flags & TRAILER_FRAME) === TRAILER_FRAME) {
      trailers = parseTrailers(new TextDecoder().decode(payload));
    } else if (flags === DATA_FRAME) {
      messages.push(payload);
    } else {
      throw new Error(`Unsupported compressed gRPC-Web frame: ${flags}.`);
    }
    offset = end;
  }

  return { messages, trailers };
}

function parseTrailers(value) {
  const trailers = {};
  for (const line of value.split(/\r?\n/)) {
    const separator = line.indexOf(":");
    if (separator > 0) {
      trailers[line.slice(0, separator).trim().toLowerCase()] =
        line.slice(separator + 1).trim();
    }
  }
  return trailers;
}
