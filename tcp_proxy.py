import socket
import select
from typing import Optional, Tuple

LISTEN_HOST = "127.0.0.1"
LISTEN_PORT = 8888

# Fixed upstream for now (we will add filtering soon)
UPSTREAM_HOST = "example.org"
UPSTREAM_PORT = 80

BUFFER_SIZE = 65536
INITIAL_READ_MAX = 65536
INITIAL_READ_TIMEOUT = 2  # seconds

def recv_until_double_crlf(sock: socket.socket, timeout: float, max_bytes: int) -> bytes:
    """Receive until we see \\r\\n\\r\\n or timeout/max reach."""
    sock.setblocking(False)
    data = bytearray()
    while len(data) < max_bytes:
        r, _, _ = select.select([sock], [], [], timeout)
        if not r:
            break
        chunk = sock.recv(BUFFER_SIZE)
        if not chunk:
            break
        data += chunk
        if b"\r\n\r\n" in data:
            break
    return bytes(data)

def parse_http_request_line_and_host(raw: bytes) -> Tuple[Optional[str], Optional[str]]:
    """
    Return (request_line, host_header) if looks like HTTP, else (None, None).
    We decode as ISO-8859-1 to be permissive per HTTP spec.
    """
    try:
        text = raw.decode("iso-8859-1", errors="replace")
    except Exception:
        return (None, None)

    # Split headers
    parts = text.split("\r\n\r\n", 1)
    head = parts[0] if parts else text
    lines = head.split("\r\n")
    if not lines:
        return (None, None)

    request_line = lines[0].strip() if lines[0] else None
    host_header = None
    for line in lines[1:]:
        if line.lower().startswith("host:"):
            host_header = line.split(":", 1)[1].strip()
            break
    return (request_line, host_header)

def forward(src: socket.socket, dst: socket.socket) -> bool:
    """Read from src and write to dst. Return False if src closed or error."""
    try:
        data = src.recv(BUFFER_SIZE)
        if not data:
            return False
        dst.sendall(data)
        return True
    except Exception:
        return False

def main():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((LISTEN_HOST, LISTEN_PORT))
        listener.listen(1)
        print(f"Proxy listening on {LISTEN_HOST}:{LISTEN_PORT} → {UPSTREAM_HOST}:{UPSTREAM_PORT}")

        client_sock, client_addr = listener.accept()
        print(f"Accepted client {client_addr}")

        with client_sock:
            # Read initial request bytes (non-blocking, short timeout)
            initial = recv_until_double_crlf(client_sock, INITIAL_READ_TIMEOUT, INITIAL_READ_MAX)
            if not initial:
                print("No initial data from client. Closing.")
                return

            req_line, host_hdr = parse_http_request_line_and_host(initial)
            if req_line:
                print(f"[HTTP] Request-Line: {req_line}")
            if host_hdr:
                print(f"[HTTP] Host: {host_hdr}")

            # Connect upstream
            upstream_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                upstream_sock.connect((UPSTREAM_HOST, UPSTREAM_PORT))
                print(f"Connected to upstream {UPSTREAM_HOST}:{UPSTREAM_PORT}")
            except Exception as e:
                print(f"Failed to connect upstream: {e}")
                return

            with upstream_sock:
                # Send the initial bytes we already consumed
                try:
                    upstream_sock.sendall(initial)
                except Exception as e:
                    print(f"Failed to send initial request upstream: {e}")
                    return

                # Bidirectional pump
                client_sock.setblocking(False)
                upstream_sock.setblocking(False)

                sockets = [client_sock, upstream_sock]
                while True:
                    readable, _, errored = select.select(sockets, [], sockets, 60)
                    if errored:
                        print("Socket error, closing.")
                        break
                    if not readable:
                        print("Timeout, closing.")
                        break

                    for s in readable:
                        if s is client_sock:
                            if not forward(client_sock, upstream_sock):
                                print("Client closed.")
                                return
                        else:
                            if not forward(upstream_sock, client_sock):
                                print("Upstream closed.")
                                return

if __name__ == "__main__":
    main()
