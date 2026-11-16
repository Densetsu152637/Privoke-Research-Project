"""Test-only mutual-TLS front for a plaintext gRPC server that cannot terminate TLS itself.

``tls_front.py LISTEN_PORT BACKEND_HOST:PORT CERT KEY CLIENT_CA``

The Python param-update server still binds plaintext (its mutual-TLS listener arrives with the stage 5 Rust service),
while the fuzzer's publisher client uses one process-wide channel policy for every target: mutual TLS as soon as it
holds a service certificate (stage 6 ``service_channel``) for the receipt lookup, and a plaintext channel for the update
itself (``training/parameter_updates.py`` keeps ``grpc.insecure_channel``). This front accepts both on one port: a TLS
ClientHello (first byte 0x16) is terminated here, with the client certificate required to chain to the client CA, and
anything else is passed through untouched. It forwards bytes to the backend and holds no model, no key of the
fuzzer's, and no state. It is not part of any deployment.
"""
import socket
import ssl
import sys
import threading


def pump(source, destination):
    try:
        while True:
            data = source.recv(65536)
            if not data:
                break
            destination.sendall(data)
    except (OSError, ssl.SSLError):
        pass
    finally:
        for stream in (source, destination):
            try:
                stream.shutdown(socket.SHUT_RDWR)
            except (OSError, ssl.SSLError):
                pass


def handle(client, context, backend):
    try:
        client.settimeout(10)
        first = client.recv(1, socket.MSG_PEEK)
        if not first:
            client.close()
            return
        if first == b"\x16":
            client = context.wrap_socket(client, server_side=True)
        client.settimeout(None)
        upstream = socket.create_connection(backend, timeout=10)
        upstream.settimeout(None)
    except (OSError, ssl.SSLError):
        client.close()
        return
    threading.Thread(target=pump, args=(client, upstream), daemon=True).start()
    threading.Thread(target=pump, args=(upstream, client), daemon=True).start()


def main():
    port, backend, cert, key, client_ca = sys.argv[1:6]
    host, _, backend_port = backend.rpartition(":")
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(cert, key)
    context.load_verify_locations(client_ca)
    context.verify_mode = ssl.CERT_REQUIRED
    context.set_alpn_protocols(["h2"])
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("0.0.0.0", int(port)))
    listener.listen(64)
    while True:
        client, _ = listener.accept()
        threading.Thread(target=handle, args=(client, context, (host, int(backend_port))), daemon=True).start()


if __name__ == "__main__":
    main()
