import socket
import select
import json
from pathlib import Path
from typing import Optional, Tuple, Dict, Any, Set, List

CONFIG_PATH = Path(__file__).with_name("config.json")

BUFFER_SIZE = 65536
INITIAL_READ_MAX = 65536
INITIAL_READ_TIMEOUT = 2.0  # seconds


def load_config() -> Dict[str, Any]:
    defaults = {
        "listen_host": "127.0.0.1",
        "listen_port": 8888,
        "allow_hosts": [],
        "block_hosts": [],
        "block_url_keywords": ["secret", "blocked", "forbidden"],
        "default_policy": "allow"  # used only if allow_hosts is empty; values: "allow" or "block"
    }
    try:
        with open(CONFIG_PATH, "r", encoding="utf-8") as f:
            cfg = json.load(f)
        defaults.update(cfg or {})
    except FileNotFoundError:
        print(f"[CONFIG] {CONFIG_PATH} not found; using defaults.")
    except Exception as e:
        print(f"[CONFIG] Failed to load {CONFIG_PATH}: {e}. Using defaults.")
    return defaults


def recv_until_double_crlf(sock: socket.socket, timeout: float, max_bytes: int) -> bytes:
    """Receive until we see \\r\\n\\r\\n or timeout/max reached."""
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
    Decode as ISO-8859-1 per HTTP/1.1 rules for header octets.
    """
    try:
        text = raw.decode("iso-8859-1", errors="replace")
    except Exception:
        return (None, None)

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


def parse_host_and_port(host_header: Optional[str], default_port: int = 80) -> Tuple[Optional[str], int]:
    if not host_header:
        return (None, default_port)
    if ":" in host_header:
        host, port_str = host_header.rsplit(":", 1)
        try:
            return (host.strip(), int(port_str))
        except ValueError:
            return (host.strip(), default_port)
    return (host_header.strip(), default_port)


def extract_path_from_request_line(request_line: Optional[str]) -> str:
    """
    From 'GET /path?x=1 HTTP/1.1' -> '/path?x=1'
    If absolute-form ('GET http://host/path HTTP/1.1'), strip scheme/host.
    """
    if not request_line:
        return "/"
    parts = request_line.split()
    if len(parts) < 2:
        return "/"
    target = parts[1]
    if target.startswith("http://") or target.startswith("https://"):
        try:
            after_scheme = target.split("://", 1)[1]
            first_slash = after_scheme.find("/")
            return after_scheme[first_slash:] if first_slash >= 0 else "/"
        except Exception:
            return "/"
    return target


def hostname_matches(rule_host: str, req_host: str) -> bool:
    """
    Exact match or leading-dot suffix rule:
    - 'example.org' matches only 'example.org'
    - '.example.org' matches 'sub.example.org' (not the bare apex)
    """
    rule = rule_host.lower().strip()
    host = (req_host or "").lower().strip()
    if not rule or not host:
        return False
    if rule.startswith("."):
        return host.endswith(rule) and host != rule.lstrip(".")
    return host == rule


def is_blocked_by_config(host: Optional[str], path: str,
                         allow_hosts: List[str], block_hosts: List[str],
                         block_keywords: List[str], default_policy: str) -> Tuple[bool, str]:
    h = (host or "").lower()
    p = (path or "/").lower()

    # 1) URL keyword block (highest precedence to keep it simple)
    for kw in block_keywords:
        if kw.lower() in p:
            return True, f"Blocked by keyword '{kw}' in URL: {path}"

    # 2) Allowlist mode (if present)
    if allow_hosts:
        allowed = any(hostname_matches(rule, h) for rule in allow_hosts)
        if not allowed:
            return True, f"Host not in allowlist: {host}"
        # If allowed, still check explicit block_hosts (to override allow)
        if any(hostname_matches(rule, h) for rule in block_hosts):
            return True, f"Blocked by host rule: {host}"
        return False, ""

    # 3) Blocklist mode
    if any(hostname_matches(rule, h) for rule in block_hosts):
        return True, f"Blocked by host rule: {host}"

    # 4) Default policy (when allowlist is empty)
    if default_policy.lower() == "block":
        return True, "Blocked by default policy"

    return False, ""


def make_block_response(reason: str) -> bytes:
    body = f"""<!doctype html>
<html><head><meta charset="utf-8"><title>Blocked</title></head>
<body style="font-family: sans-serif;">
<h1>403 Forbidden</h1>
<p>Request was blocked by local policy.</p>
<pre>{reason}</pre>
</body></html>"""
    body_bytes = body.encode("utf-8")
    headers = (
        "HTTP/1.1 403 Forbidden\r\n"
        "Content-Type: text/html; charset=utf-8\r\n"
        f"Content-Length: {len(body_bytes)}\r\n"
        "Connection: close\r\n"
        "\r\n"
    ).encode("iso-8859-1")
    return headers + body_bytes


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


def run_once(config: Dict[str, Any]) -> None:
    listen_host = config["listen_host"]
    listen_port = int(config["listen_port"])

    allow_hosts = list(config.get("allow_hosts", []))
    block_hosts = list(config.get("block_hosts", []))
    block_keywords = list(config.get("block_url_keywords", []))
    default_policy = str(config.get("default_policy", "allow")).lower()

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((listen_host, listen_port))
        listener.listen(1)
        print(f"Web filter listening on {listen_host}:{listen_port}")
        if allow_hosts:
            print(f"[MODE] Allowlist enabled: {allow_hosts}")
        else:
            print(f"[MODE] Blocklist mode, default_policy={default_policy}")

        client_sock, client_addr = listener.accept()
        print(f"Accepted client {client_addr}")

        with client_sock:
            initial = recv_until_double_crlf(client_sock, INITIAL_READ_TIMEOUT, INITIAL_READ_MAX)
            if not initial:
                print("No initial data from client. Closing.")
                return

            req_line, host_hdr = parse_http_request_line_and_host(initial)
            path = extract_path_from_request_line(req_line)
            upstream_host, upstream_port = parse_host_and_port(host_hdr, 80)

            print(f"[HTTP] Request-Line: {req_line}")
            print(f"[HTTP] Host: {host_hdr} (parsed → {upstream_host}:{upstream_port})")
            print(f"[HTTP] Path: {path}")

            blocked, reason = is_blocked_by_config(
                upstream_host, path, allow_hosts, block_hosts, block_keywords, default_policy
            )
            if blocked:
                print(f"[FILTER] {reason}")
                try:
                    client_sock.sendall(make_block_response(reason))
                except Exception:
                    pass
                return

            if not upstream_host:
                reason = "Missing Host header"
                print(f"[FILTER] {reason}")
                try:
                    client_sock.sendall(make_block_response(reason))
                except Exception:
                    pass
                return

            # Connect upstream (allowed)
            upstream_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                upstream_sock.connect((upstream_host, upstream_port))
                print(f"Connected to upstream {upstream_host}:{upstream_port}")
            except Exception as e:
                print(f"Failed to connect upstream: {e}")
                try:
                    client_sock.sendall(make_block_response(f"Upstream connect failed: {e}"))
                except Exception:
                    pass
                return

            with upstream_sock:
                try:
                    upstream_sock.sendall(initial)
                except Exception as e:
                    print(f"Failed to send initial request upstream: {e}")
                    return

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


def main():
    config = load_config()
    run_once(config)


if __name__ == "__main__":
    main()
