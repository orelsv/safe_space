import socket
import select
import json
import threading
from pathlib import Path
from typing import Optional, Tuple, Dict, Any, List
from datetime import datetime, timezone

CONFIG_PATH = Path(__file__).with_name("config.json")
DECISIONS_LOG_PATH = Path(__file__).with_name("decisions.log")

BUFFER_SIZE = 65536
INITIAL_READ_MAX = 65536
INITIAL_READ_TIMEOUT = 2.0  # seconds


def load_config() -> Dict[str, Any]:
    defaults = {
        "listen_host": "127.0.0.1",
        "listen_port": 8888,
        "allow_hosts": ["httpbin.org"],
        "block_hosts": ["example.org"],
        "block_url_keywords": ["secret", "blocked", "forbidden"],
        "default_policy": "allow"  # used only if allow_hosts is empty; "allow" or "block"
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


def log_decision(entry: Dict[str, Any]) -> None:
    try:
        entry = dict(entry)
        entry["ts"] = datetime.now(timezone.utc).isoformat()
        with open(DECISIONS_LOG_PATH, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")
    except Exception:
        # Logging must never crash the proxy
        pass


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
    """Return (request_line, host_header) if looks like HTTP, else (None, None)."""
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
                         block_keywords: List[str], default_policy: str,
                         is_connect: bool = False) -> Tuple[bool, str]:
    h = (host or "").lower()
    p = (path or "/").lower()

    # For CONNECT, we can't inspect path keywords (TLS). Apply only host rules/defaults.
    if not is_connect:
        for kw in block_keywords:
            if kw.lower() in p:
                return True, f"Blocked by keyword '{kw}' in URL: {path}"

    # Allowlist mode
    if allow_hosts:
        allowed = any(hostname_matches(rule, h) for rule in allow_hosts)
        if not allowed:
            return True, f"Host not in allowlist: {host}"
        if any(hostname_matches(rule, h) for rule in block_hosts):
            return True, f"Blocked by host rule: {host}"
        return False, ""

    # Blocklist mode
    if any(hostname_matches(rule, h) for rule in block_hosts):
        return True, f"Blocked by host rule: {host}"

    # Default policy
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


def handle_tunnel(client_sock: socket.socket, upstream_sock: socket.socket) -> None:
    """Bidirectional relay without inspecting (used after CONNECT 200)."""
    client_sock.setblocking(False)
    upstream_sock.setblocking(False)
    sockets = [client_sock, upstream_sock]
    while True:
        readable, _, errored = select.select(sockets, [], sockets, 60)
        if errored:
            break
        if not readable:
            break
        for s in readable:
            if s is client_sock:
                if not forward(client_sock, upstream_sock):
                    return
            else:
                if not forward(upstream_sock, client_sock):
                    return


def parse_connect_authority(request_line: str) -> Tuple[Optional[str], int]:
    """From 'CONNECT host:443 HTTP/1.1' -> ('host', 443)."""
    try:
        parts = request_line.split()
        if len(parts) < 2:
            return (None, 443)
        authority = parts[1]
        if ":" in authority:
            host, port_str = authority.rsplit(":", 1)
            return (host.strip(), int(port_str))
        return (authority.strip(), 443)
    except Exception:
        return (None, 443)


def handle_client(client_sock: socket.socket, client_addr, config: Dict[str, Any]) -> None:
    try:
        allow_hosts = list(config.get("allow_hosts", []))
        block_hosts = list(config.get("block_hosts", []))
        block_keywords = list(config.get("block_url_keywords", []))
        default_policy = str(config.get("default_policy", "allow")).lower()

        print(f"[THREAD {threading.current_thread().name}] Accepted client {client_addr}")

        initial = recv_until_double_crlf(client_sock, INITIAL_READ_TIMEOUT, INITIAL_READ_MAX)
        if not initial:
             print(f"[THREAD {threading.current_thread().name}] No initial data from client. Closing.")
             return

        req_line, host_hdr = parse_http_request_line_and_host(initial)
        if not req_line:
            try:
                client_sock.sendall(make_block_response("Malformed request"))
            except Exception:
                pass
            log_decision({
                "client": f"{client_addr[0]}:{client_addr[1]}",
                "proto": "HTTP",
                "action": "BLOCK",
                "reason": "Malformed request"
            })
            return

        # HTTPS CONNECT branch
        if req_line.upper().startswith("CONNECT "):
            target_host, target_port = parse_connect_authority(req_line)
            print(f"[HTTPS-CONNECT] {req_line}  → parsed {target_host}:{target_port}")

            blocked, reason = is_blocked_by_config(
                target_host, "/", allow_hosts, block_hosts, block_keywords, default_policy, is_connect=True
            )
            if blocked or not target_host:
                reason = reason or "Missing CONNECT host"
                print(f"[FILTER] {reason}")
                try:
                    client_sock.sendall(make_block_response(reason))
                except Exception:
                    pass
                log_decision({
                    "client": f"{client_addr[0]}:{client_addr[1]}",
                    "proto": "CONNECT",
                    "action": "BLOCK",
                    "reason": reason,
                    "host": target_host,
                    "port": target_port
                })
                return

            upstream_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                upstream_sock.connect((target_host, target_port))
                print(f"Connected to upstream (CONNECT) {target_host}:{target_port}")
            except Exception as e:
                msg = f"Upstream connect failed: {e}"
                print(f"Failed to connect upstream (CONNECT): {e}")
                try:
                    client_sock.sendall(make_block_response(msg))
                except Exception:
                    pass
                log_decision({
                    "client": f"{client_addr[0]}:{client_addr[1]}",
                    "proto": "CONNECT",
                    "action": "BLOCK",
                    "reason": msg,
                    "host": target_host,
                    "port": target_port
                })
                return

            with upstream_sock:
                try:
                    client_sock.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                except Exception:
                    return
                log_decision({
                    "client": f"{client_addr[0]}:{client_addr[1]}",
                    "proto": "CONNECT",
                    "action": "ALLOW",
                    "host": target_host,
                    "port": target_port
                })
                handle_tunnel(client_sock, upstream_sock)
            return

        # Regular HTTP
        path = extract_path_from_request_line(req_line)
        upstream_host, upstream_port = parse_host_and_port(host_hdr, 80)

        print(f"[HTTP] Request-Line: {req_line}")
        print(f"[HTTP] Host: {host_hdr} (parsed \u2192 {upstream_host}:{upstream_port})")
        print(f"[HTTP] Path: {path}")

        blocked, reason = is_blocked_by_config(
            upstream_host, path, allow_hosts, block_hosts, block_keywords, default_policy, is_connect=False
        )
        if blocked or not upstream_host:
            reason = reason or "Missing Host header"
            print(f"[FILTER] {reason}")
            try:
                client_sock.sendall(make_block_response(reason))
            except Exception:
                pass
            log_decision({
                "client": f"{client_addr[0]}:{client_addr[1]}",
                "proto": "HTTP",
                "action": "BLOCK",
                "reason": reason,
                "host": upstream_host,
                "port": upstream_port,
                "path": path,
                "request": req_line
            })
            return

        upstream_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            upstream_sock.connect((upstream_host, upstream_port))
            print(f"Connected to upstream {upstream_host}:{upstream_port}")
        except Exception as e:
            msg = f"Upstream connect failed: {e}"
            print(f"Failed to connect upstream: {e}")
            try:
                client_sock.sendall(make_block_response(msg))
            except Exception:
                pass
            log_decision({
                "client": f"{client_addr[0]}:{client_addr[1]}",
                "proto": "HTTP",
                "action": "BLOCK",
                "reason": msg,
                "host": upstream_host,
                "port": upstream_port,
                "path": path,
                "request": req_line
            })
            return

        with upstream_sock:
            try:
                upstream_sock.sendall(initial)
            except Exception as e:
                print(f"Failed to send initial request upstream: {e}")
                return

            # Log allow decision once upstream connected and initial sent
            log_decision({
                "client": f"{client_addr[0]}:{client_addr[1]}",
                "proto": "HTTP",
                "action": "ALLOW",
                "host": upstream_host,
                "port": upstream_port,
                "path": path,
                "request": req_line
            })

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
    finally:
        try:
            client_sock.close()
        except Exception:
            pass


def serve_forever(config: Dict[str, Any]) -> None:
    listen_host = config["listen_host"]
    listen_port = int(config["listen_port"])

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((listen_host, listen_port))
        listener.listen(128)
        mode = "Allowlist enabled" if config.get("allow_hosts") else f"Blocklist mode, default_policy={config.get('default_policy','allow')}"
        print(f"Web filter listening on {listen_host}:{listen_port}")
        print(f"[MODE] {mode}")

        while True:
            client_sock, client_addr = listener.accept()
            t = threading.Thread(target=handle_client, args=(client_sock, client_addr, config), daemon=True)
            t.start()


def main():
    config = load_config()
    serve_forever(config)


if __name__ == "__main__":
    main()
