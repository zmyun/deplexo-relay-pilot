#!/usr/bin/env python3
"""Minimal relay pilot for Deplexo free tier.

- GET /health            -> 200 ok (platform health check)
- /ws-echo              -> WebSocket echo (tests WS upgrade through Deplexo edge)
- HTTP proxy (GET http://...) and CONNECT tunnelling, both gated by a
  bearer token in the Proxy-Authorization header.

Stdlib only. Listens on $PORT (default 3000), 0.0.0.0.
Env: PROXY_TOKEN (required for proxy use; empty = deny all proxied traffic).
"""
import base64
import hashlib
import os
import socket
import threading

PORT = int(os.environ.get("PORT", "3000"))
TOKEN = os.environ.get("PROXY_TOKEN", "")
BUF = 65536


def recv_headers(conn):
    data = b""
    while b"\r\n\r\n" not in data:
        chunk = conn.recv(4096)
        if not chunk:
            break
        data += chunk
        if len(data) > 65536:
            break
    head, _, rest = data.partition(b"\r\n\r\n")
    lines = head.decode("latin1").split("\r\n")
    request_line = lines[0] if lines else ""
    headers = {}
    for ln in lines[1:]:
        if ":" in ln:
            k, v = ln.split(":", 1)
            headers[k.strip().lower()] = v.strip()
    return request_line, headers, rest


def authorized(headers):
    if not TOKEN:
        return False
    return headers.get("proxy-authorization", "") == "Bearer " + TOKEN


def shuttle(a, b):
    def pipe(src, dst):
        try:
            while True:
                chunk = src.recv(BUF)
                if not chunk:
                    break
                dst.sendall(chunk)
        except OSError:
            pass
        finally:
            for s in (src, dst):
                try:
                    s.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
    t1 = threading.Thread(target=pipe, args=(a, b), daemon=True)
    t2 = threading.Thread(target=pipe, args=(b, a), daemon=True)
    t1.start()
    t2.start()
    t1.join()
    t2.join()


def handle_connect(conn, target):
    host, _, port_s = target.partition(":")
    port = int(port_s or 443)
    try:
        upstream = socket.create_connection((host, port), timeout=15)
    except OSError:
        conn.sendall(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
        return
    conn.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
    shuttle(conn, upstream)


def handle_http(conn, request_line, headers, rest):
    # request_line: GET http://host:port/path HTTP/1.1
    parts = request_line.split()
    if len(parts) < 2:
        conn.sendall(b"HTTP/1.1 400 Bad Request\r\n\r\n")
        return
    url = parts[1]
    if not url.startswith("http://"):
        conn.sendall(b"HTTP/1.1 400 Bad Request\r\n\r\n")
        return
    no_scheme = url[7:]
    hostport, _, path = no_scheme.partition("/")
    host, _, port_s = hostport.partition(":")
    port = int(port_s or 80)
    try:
        upstream = socket.create_connection((host, port), timeout=15)
    except OSError:
        conn.sendall(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
        return
    # Rewrite to origin-form before forwarding.
    fwd = f"{parts[0]} /{path} {parts[2]}\r\n".encode("latin1")
    for k, v in headers.items():
        if k in ("proxy-authorization", "proxy-connection"):
            continue
        fwd += f"{k}: {v}\r\n".encode("latin1")
    fwd += b"\r\n"
    try:
        upstream.sendall(fwd + rest)
    except OSError:
        conn.close()
        return
    shuttle(conn, upstream)


def ws_accept(key):
    magic = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
    return base64.b64encode(hashlib.sha1((key + magic).encode()).digest()).decode()


def ws_serve(conn, headers, rest):
    key = headers.get("sec-websocket-key", "")
    if not key:
        conn.sendall(b"HTTP/1.1 400 Bad Request\r\n\r\n")
        return
    resp = (
        "HTTP/1.1 101 Switching Protocols\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        f"Sec-WebSocket-Accept: {ws_accept(key)}\r\n\r\n"
    )
    conn.sendall(resp.encode("latin1"))
    buf = bytearray(rest)
    conn.settimeout(300)
    try:
        while True:
            while len(buf) < 2:
                chunk = conn.recv(4096)
                if not chunk:
                    return
                buf += chunk
            b1, b2 = buf[0], buf[1]
            opcode = b1 & 0x0F
            masked = b2 & 0x80
            length = b2 & 0x7F
            idx = 2
            if length == 126:
                while len(buf) < idx + 2:
                    buf += conn.recv(4096)
                length = int.from_bytes(buf[idx:idx + 2], "big")
                idx += 2
            elif length == 127:
                while len(buf) < idx + 8:
                    buf += conn.recv(4096)
                length = int.from_bytes(buf[idx:idx + 8], "big")
                idx += 8
            if masked:
                while len(buf) < idx + 4:
                    buf += conn.recv(4096)
                mask = buf[idx:idx + 4]
                idx += 4
            while len(buf) < idx + length:
                chunk = conn.recv(4096)
                if not chunk:
                    return
                buf += chunk
            payload = bytes(buf[idx:idx + length])
            del buf[:idx + length]
            if masked:
                payload = bytes(p ^ mask[i % 4] for i, p in enumerate(payload))
            if opcode == 0x8:  # close
                conn.sendall(b"\x88\x00")
                return
            if opcode == 0x9:  # ping -> pong
                conn.sendall(b"\x8a" + bytes([len(payload)]) + payload)
                continue
            if opcode not in (0x1, 0x2):
                continue
            # echo back
            out = bytes([0x80 | opcode])
            if len(payload) < 126:
                out += bytes([len(payload)])
            elif len(payload) < 65536:
                out += b"\x7e" + len(payload).to_bytes(2, "big")
            else:
                out += b"\x7f" + len(payload).to_bytes(8, "big")
            conn.sendall(out + payload)
    except (OSError, TimeoutError):
        pass
    finally:
        conn.close()


def handle(conn, addr):
    try:
        request_line, headers, rest = recv_headers(conn)
        parts = request_line.split()
        method = parts[0].upper() if parts else ""
        target = parts[1] if len(parts) > 1 else ""
        path = target.split("?", 1)[0]

        if method == "GET" and path == "/health":
            body = b"ok"
            conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n" + body)
            return
        if path == "/ws-echo":
            ws_serve(conn, headers, rest)
            return
        if not authorized(headers):
            conn.sendall(
                b"HTTP/1.1 407 Proxy Authentication Required\r\n"
                b"Proxy-Authenticate: Bearer\r\nContent-Length: 0\r\n\r\n"
            )
            return
        if method == "CONNECT":
            handle_connect(conn, target)
        elif target.startswith("http://"):
            handle_http(conn, request_line, headers, rest)
        else:
            conn.sendall(b"HTTP/1.1 400 Bad Request\r\n\r\n")
    except Exception:
        pass
    finally:
        try:
            conn.close()
        except OSError:
            pass


def main():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", PORT))
    srv.listen(128)
    print(f"relay pilot listening on 0.0.0.0:{PORT}", flush=True)
    while True:
        conn, addr = srv.accept()
        threading.Thread(target=handle, args=(conn, addr), daemon=True).start()


if __name__ == "__main__":
    main()
