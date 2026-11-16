"""Test-only TCP forwarder: publishes a loopback port that reaches a service on an internal Compose network.

``tcp_gateway.py LISTEN_PORT=HOST:PORT [LISTEN_PORT=HOST:PORT ...]``

Bytes are copied unchanged, so TLS stays end to end between the host test client and the service; the gateway holds no
credential. It exists only in ``docker-compose.analysis-test.yml``, because a host cannot reach a container whose only
networks are ``internal: true``.
"""
import socket
import sys
import threading


def pump(source, destination):
    try:
        while True:
            data = source.recv(65536)
            if not data:
                break
            destination.sendall(data)
    except OSError:
        pass
    finally:
        for stream in (source, destination):
            try:
                stream.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass


def serve(port, host, target):
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("0.0.0.0", port))
    listener.listen(64)
    while True:
        client, _ = listener.accept()
        try:
            upstream = socket.create_connection((host, target), timeout=10)
        except OSError:
            client.close()
            continue
        upstream.settimeout(None)
        threading.Thread(target=pump, args=(client, upstream), daemon=True).start()
        threading.Thread(target=pump, args=(upstream, client), daemon=True).start()


def main():
    threads = []
    for mapping in sys.argv[1:]:
        listen, _, target = mapping.partition("=")
        host, _, port = target.rpartition(":")
        thread = threading.Thread(target=serve, args=(int(listen), host, int(port)), daemon=True)
        thread.start()
        threads.append(thread)
    for thread in threads:
        thread.join()


if __name__ == "__main__":
    main()
