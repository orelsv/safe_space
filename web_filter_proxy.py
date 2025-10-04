#!/usr/bin/env python3
import socket
import select
import json
import threading
import os
import ssl
import certifi

from OpenSSL import crypto
from pathlib import Path
from typing import Optional, Tuple, Dict, Any, List
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from collections import Counter

CONFIG_PATH = Path(__file__).with_name("config.json")
DECISIONS_LOG_PATH = Path(__file__).with_name("decisions.log")

BUFFER_SIZE = 65536
INITIAL_READ_MAX = 65536
INITIAL_READ_TIMEOUT = 2.0  # seconds

# -------- In-memory metrics (thread-safe) --------
METRICS_LOCK = threading.Lock()
METRICS = {
    "start_ts": datetime.now(timezone.utc),
    "connections_total": 0,
    "decisions_total": 0,
    "allow_total": 0,
    "block_total": 0,
    "by_proto": Counter(),
    "allowed_hosts": Counter(),
    "blocked_hosts": Counter(),
    "block_reasons": Counter(),
}

def _now_iso():
    return datetime.now(timezone.utc).isoformat()

def load_config() -> Dict[str, Any]:
    defaults = {
        "listen_host": "127.0.0.1",
        "listen_port": 8888,
        "allow_hosts": [],
        "block_hosts": ["example.org"],
        "block_url_keywords": ["secret", "blocked", "forbidden"],
        "default_policy": "allow",  # used only if allow_hosts is empty; "allow" or "block"
        "admin_host": "127.0.0.1",
        "admin_port": 8890,
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

# ---- CA / certs for MITM ----
CA_KEY_PATH = Path(__file__).with_name("ca.key.pem")
CA_CERT_PATH = Path(__file__).with_name("ca.cert.pem")
CERTS_DIR = Path(__file__).with_name("certs")

def ensure_certs_dir():
    CERTS_DIR.mkdir(parents=True, exist_ok=True)

def gen_cert_for_host(hostname: str) -> Tuple[str, str]:
    """
    Return (cert_path, key_path) for hostname.
    If already exists on disk, reuse it.
    """
    ensure_certs_dir()
    base = hostname.replace(":", "_")
    cert_path = CERTS_DIR / f"{base}.crt.pem"
    key_path = CERTS_DIR / f"{base}.key.pem"

    if cert_path.exists() and key_path.exists():
        return str(cert_path), str(key_path)

    with open(CA_KEY_PATH, "rb") as f:
        ca_key = crypto.load_privatekey(crypto.FILETYPE_PEM, f.read())
    with open(CA_CERT_PATH, "rb") as f:
        ca_cert = crypto.load_certificate(crypto.FILETYPE_PEM, f.read())

    key = crypto.PKey()
    key.generate_key(crypto.TYPE_RSA, 2048)

    req = crypto.X509Req()
    subj = req.get_subject()
    subj.CN = hostname
    req.set_pubkey(key)
    req.sign(key, "sha256")

    cert = crypto.X509()
    cert.set_serial_number(int.from_bytes(os.urandom(16), "big") >> 1)
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(365 * 5 * 24 * 3600)  # 5 years
    cert.set_issuer(ca_cert.get_subject())
    cert.set_subject(req.get_subject())
    cert.set_pubkey(req.get_pubkey())

    san = f"DNS:{hostname}"
    cert.add_extensions([
        crypto.X509Extension(b"subjectAltName", False, san.encode("utf-8")),
        crypto.X509Extension(b"basicConstraints", False, b"CA:FALSE"),
        crypto.X509Extension(b"keyUsage", False, b"digitalSignature, keyEncipherment"),
        crypto.X509Extension(b"extendedKeyUsage", False, b"serverAuth"),
    ])
    cert.sign(ca_key, "sha256")

    with open(cert_path, "wb") as f:
        f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))
    with open(key_path, "wb") as f:
        f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, key))

    print(f"[MITM] Generated cert for {hostname}: {cert_path.name}")
    return str(cert_path), str(key_path)

# ---- logging / metrics ----
def note_decision(entry: Dict[str, Any]) -> None:
    action = (entry.get("action") or "").upper()
    proto = (entry.get("proto") or "HTTP").upper()
    host = (entry.get("host") or "").lower()
    reason = (entry.get("reason") or "").strip()

    with METRICS_LOCK:
        METRICS["decisions_total"] += 1
        METRICS["by_proto"][proto] += 1
        if action == "ALLOW":
            METRICS["allow_total"] += 1
            if host:
                METRICS["allowed_hosts"][host] += 1
        elif action == "BLOCK":
            METRICS["block_total"] += 1
            if host:
                METRICS["blocked_hosts"][host] += 1
            if reason:
                METRICS["block_reasons"][reason] += 1

def log_decision(entry: Dict[str, Any]) -> None:
    try:
        entry = dict(entry)
        entry["ts"] = _now_iso()
        note_decision(entry)
        with open(DECISIONS_LOG_PATH, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")
    except Exception:
        pass

# ---- HTTP parsing helpers ----
def recv_until_double_crlf(sock: socket.socket, timeout: float, max_bytes: int) -> bytes:
    """Receive until we see \r\n\r\n or timeout/max reached (RESTORES original blocking mode)."""
    prev_blocking = sock.getblocking()
    try:
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
    finally:
        # дуже важливо: повернути початковий режим
        try:
            sock.setblocking(prev_blocking)
        except Exception:
            pass


def recv_http_over_ssl(ssl_sock: ssl.SSLSocket, max_bytes: int) -> Optional[bytes]:
    """
    Read an HTTP request from an SSL socket until \r\n\r\n or max_bytes or EOF.
    Uses blocking reads with timeout set on the socket.
    """
    buf = bytearray()
    while len(buf) < max_bytes:
        try:
            chunk = ssl_sock.recv(4096)
        except socket.timeout:
            # no full headers yet; give up to let caller decide
            return None if not buf else bytes(buf)
        except Exception:
            return None
        if not chunk:
            break
        buf += chunk
        if b"\r\n\r\n" in buf:
            break
    return bytes(buf) if buf else None

def parse_http_request_line_and_host(raw: bytes) -> Tuple[Optional[str], Optional[str]]:
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

    if default_policy.lower() == "block":
        return True, "Blocked by default policy"

    return False, ""

def make_block_response(reason: str) -> bytes:
    body = """<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>Blocked</title>
  <style>
    body {
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
      display: flex; align-items: center; justify-content: center;
      height: 100vh; margin: 0; background: #f8f9fb; color: #222;
    }
    .card {
      text-align: center; padding: 30px; border-radius: 12px;
      box-shadow: 0 6px 24px rgba(20,20,30,0.08);
      background: white; max-width: 720px;
    }
    h1 { margin: 0 0 10px 0; font-size: 36px; }
    p.lead { margin: 0 0 18px 0; font-size: 18px; color: #555; }
    pre {
      text-align: left; background: #f4f6f8; padding: 10px;
      border-radius: 6px; overflow: auto; font-family: monospace; font-size: 13px;
    }
    .big { font-size: 48px; font-weight: 600; color: #b22222; margin: 14px 0; }
  </style>
</head>
<body>
  <div class="card">
    <h1>403 — Forbidden</h1>
    <p class="lead">Request blocked by local policy.</p>
    <p class="big">Go do some work, you lazybones!</p>
    <pre>%s</pre>
  </div>
</body>
</html>""" % (reason or "")
    body_bytes = body.encode("utf-8")
    headers = (
        "HTTP/1.1 403 Forbidden\r\n"
        "Content-Type: text/html; charset=utf-8\r\n"
        f"Content-Length: {len(body_bytes)}\r\n"
        "Connection: close\r\n"
        "\r\n"
    ).encode("iso-8859-1")
    return headers + body_bytes

# ---- generic forwarding for plain sockets ----
def forward(src: socket.socket, dst: socket.socket) -> bool:
    try:
        data = src.recv(BUFFER_SIZE)
        if not data:
            return False
        dst.sendall(data)
        return True
    except Exception:
        return False

def handle_tunnel(client_sock: socket.socket, upstream_sock: socket.socket) -> None:
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

# ------------- Admin HTTP (status) -------------
class AdminHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path in ("/", "/status"):
            with METRICS_LOCK:
                uptime_sec = (datetime.now(timezone.utc) - METRICS["start_ts"]).total_seconds()
                payload = {
                    "now": _now_iso(),
                    "uptime_seconds": int(uptime_sec),
                    "connections_total": METRICS["connections_total"],
                    "decisions_total": METRICS["decisions_total"],
                    "allow_total": METRICS["allow_total"],
                    "block_total": METRICS["block_total"],
                    "by_proto": dict(METRICS["by_proto"]),
                    "allowed_hosts": dict(METRICS["allowed_hosts"]),
                    "blocked_hosts": dict(METRICS["blocked_hosts"]),
                    "block_reasons": dict(METRICS["block_reasons"]),
                }
            body = json.dumps(payload, ensure_ascii=False, indent=2).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            self.send_error(404, "Not Found")

    def log_message(self, format: str, *args) -> None:
        return

def start_admin_server(host: str, port: int):
    httpd = HTTPServer((host, port), AdminHandler)
    t = threading.Thread(target=httpd.serve_forever, name="AdminHTTP", daemon=True)
    t.start()
    print(f"[ADMIN] Status available at http://{host}:{port}/status")

# ------------- Proxy core -------------
def handle_client(client_sock: socket.socket, client_addr, config: Dict[str, Any]) -> None:
    try:
        allow_hosts = list(config.get("allow_hosts", []))
        block_hosts = list(config.get("block_hosts", []))
        block_keywords = list(config.get("block_url_keywords", []))
        default_policy = str(config.get("default_policy", "allow")).lower()

        with METRICS_LOCK:
            METRICS["connections_total"] += 1

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

        # -------- HTTPS CONNECT --------
        if req_line.upper().startswith("CONNECT "):
            # Parse target_host and target_port from CONNECT request line
            target_host, target_port = parse_connect_authority(req_line)
            blocked, reason = is_blocked_by_config(
                target_host, "/", allow_hosts, block_hosts, block_keywords, default_policy, is_connect=True
            )

            # MITM block page if blocked
            if blocked or not target_host:
                try:
                    client_sock.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                except Exception:
                    return
                try:
                    certfile, keyfile = gen_cert_for_host(target_host or "blocked.host")
                    server_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                    try:
                        server_ctx.minimum_version = ssl.TLSVersion.TLSv1_2
                    except Exception:
                        pass
                    server_ctx.load_cert_chain(certfile, keyfile)
                    try:
                        server_ctx.set_alpn_protocols(["http/1.1"])
                    except Exception:
                        pass

                    client_sock.setblocking(True)
                    client_sock.settimeout(5.0)
                    client_ssl = server_ctx.wrap_socket(client_sock, server_side=True)
                    client_ssl.settimeout(5.0)

                    try:
                        client_ssl.sendall(make_block_response(reason or "Blocked host"))
                        try:
                            client_ssl.shutdown(socket.SHUT_WR)
                        except Exception:
                            pass
                    except Exception:
                        pass
                    try:
                        client_ssl.close()
                    except Exception:
                        pass
                except Exception as e:
                    print("MITM/block path error:", e)
                    try:
                        client_sock.close()
                    except Exception:
                        pass
                log_decision({
                    "client": f"{client_addr[0]}:{client_addr[1]}",
                    "proto": "CONNECT",
                    "action": "BLOCK",
                    "reason": reason or "Blocked host",
                    "host": target_host,
                    "port": target_port
                })
                return

            # Allowed host: plain tunnel
            upstream_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                upstream_sock.connect((target_host, target_port))
            except Exception as e:
                msg = f"Upstream connect failed: {e}"
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

            try:
                client_sock.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            except Exception:
                upstream_sock.close()
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

        # -------- Regular HTTP --------
        path = extract_path_from_request_line(req_line)
        upstream_host, upstream_port = parse_host_and_port(host_hdr, 80)

        print(f"[HTTP] Request-Line: {req_line}")
        print(f"[HTTP] Host: {host_hdr} (parsed → {upstream_host}:{upstream_port})")
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
            print(msg)
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
    admin_host = config.get("admin_host", "127.0.0.1")
    admin_port = int(config.get("admin_port", 8890))

    start_admin_server(admin_host, admin_port)

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
    print("[CONFIG] Effective:", json.dumps({
        "listen_host": config.get("listen_host"),
        "listen_port": config.get("listen_port"),
        "allow_hosts_len": len(config.get("allow_hosts", [])),
        "block_hosts_len": len(config.get("block_hosts", [])),
        "default_policy": config.get("default_policy"),
    }, ensure_ascii=False))
    serve_forever(config)

if __name__ == "__main__":
    main()
