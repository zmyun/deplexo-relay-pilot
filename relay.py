#!/usr/bin/env python3
"""WebSocket relay server (Deplexo side).

Endpoints:
  GET /health   -> "ok"
  WS  /ws-echo  -> echo (edge/diagnostic check)
  WS  /egress   -> the exit node (VM) connects here (Bearer token)
  WS  /ingress  -> clients connect here (Bearer token)

Multiplexing protocol:
  text frames   = JSON control messages
  binary frames = stream_id (4 bytes big-endian) + payload

Client -> relay: {"open": sid, "host": "...", "port": 443}
Relay  -> VM:    {"open": sid, "host": "...", "port": 443}
VM     -> relay: {"opened": sid} | {"open_failed": sid} | {"closed": sid}
Relay  -> client: same, routed by sid
Either side:     {"close": sid}  -> forwarded, stream torn down.

Stdlib only. Listens on $PORT (default 3000), 0.0.0.0.
Env: PROXY_TOKEN (Bearer token required on /egress and /ingress).
"""
import base64
import hashlib
import json
import os
import socket
import struct
import threading

PORT = int(os.environ.get("PORT", "3000"))
TOKEN = os.environ.get("PROXY_TOKEN", "")


def ws_accept(key):
    magic = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
    return base64.b64encode(hashlib.sha1((key + magic).encode()).digest()).decode()


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


class WSConn:
    """Server-side WebSocket connection (peer frames are masked)."""

    def __init__(self, conn):
        self.conn = conn
        self.buf = bytearray()
        self.wlock = threading.Lock()
        self.closed = False

    def _fill(self, n):
        while len(self.buf) < n:
            chunk = self.conn.recv(65536)
            if not chunk:
                raise ConnectionError("eof")
            self.buf += chunk

    def read_frame(self):
        """Returns (opcode, payload) or (None, None) on close/error."""
        try:
            self._fill(2)
            b1, b2 = self.buf[0], self.buf[1]
            opcode = b1 & 0x0F
            masked = b2 & 0x80
            length = b2 & 0x7F
            idx = 2
            if length == 126:
                self._fill(idx + 2)
                length = struct.unpack(">H", self.buf[idx:idx + 2])[0]
                idx += 2
            elif length == 127:
                self._fill(idx + 8)
                length = struct.unpack(">Q", self.buf[idx:idx + 8])[0]
                idx += 8
            if masked:
                self._fill(idx + 4)
                mask = bytes(self.buf[idx:idx + 4])
                idx += 4
            else:
                mask = None
            self._fill(idx + length)
            payload = bytes(self.buf[idx:idx + length])
            del self.buf[:idx + length]
            if mask:
                payload = bytes(p ^ mask[i % 4] for i, p in enumerate(payload))
            return opcode, payload
        except (ConnectionError, OSError):
            return None, None

    def _send(self, opcode, payload):
        out = bytes([0x80 | opcode])
        n = len(payload)
        if n < 126:
            out += bytes([n])
        elif n < 65536:
            out += b"\x7e" + struct.pack(">H", n)
        else:
            out += b"\x7f" + struct.pack(">Q", n)
        with self.wlock:
            try:
                self.conn.sendall(out + payload)
            except OSError:
                self.closed = True

    def send_text(self, s):
        self._send(0x1, s.encode("utf-8"))

    def send_binary(self, b):
        self._send(0x2, b)

    def send_close(self):
        try:
            self._send(0x8, b"")
        finally:
            self.close()

    def close(self):
        self.closed = True
        try:
            self.conn.close()
        except OSError:
            pass


def ws_handshake(conn, headers):
    key = headers.get("sec-websocket-key", "")
    if not key:
        return False
    resp = (
        "HTTP/1.1 101 Switching Protocols\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        f"Sec-WebSocket-Accept: {ws_accept(key)}\r\n\r\n"
    )
    conn.sendall(resp.encode("latin1"))
    return True


def authorized(headers):
    if not TOKEN:
        return False
    auth = headers.get("authorization", "")
    if auth == "Bearer " + TOKEN:
        return True
    # also accept ?token= query for convenience
    return False


# ---------------- relay state ----------------
state_lock = threading.Lock()
vm_conn = None            # WSConn of the exit node, or None
streams = {}              # sid -> {"client": WSConn}


def vm_send_text(msg):
    with state_lock:
        vm = vm_conn
    if vm and not vm.closed:
        vm.send_text(msg)


def client_of(sid):
    with state_lock:
        e = streams.get(sid)
    return e["client"] if e else None


def drop_stream(sid):
    with state_lock:
        streams.pop(sid, None)


def handle_egress(ws):
    global vm_conn
    with state_lock:
        old = vm_conn
        vm_conn = ws
    if old and old is not ws:
        old.send_close()
    print("egress node connected", flush=True)
    try:
        while True:
            op, payload = ws.read_frame()
            if op is None:
                break
            if op == 0x8:
                break
            if op == 0x9:  # ping
                ws._send(0xA, payload)
                continue
            if op == 0x1:  # control
                try:
                    msg = json.loads(payload.decode("utf-8"))
                except ValueError:
                    continue
                sid = msg.get("opened", msg.get("open_failed", msg.get("closed")))
                client = client_of(sid) if sid is not None else None
                if client and not client.closed:
                    client.send_text(payload.decode("utf-8"))
                if "closed" in msg or "open_failed" in msg:
                    drop_stream(msg.get("closed", msg.get("open_failed")))
            elif op == 0x2:  # data
                if len(payload) >= 4:
                    sid = struct.unpack(">I", payload[:4])[0]
                    client = client_of(sid)
                    if client and not client.closed:
                        client.send_binary(payload)
    finally:
        with state_lock:
            if vm_conn is ws:
                vm_conn = None
            dead = list(streams.keys())
            streams.clear()
        for sid in dead:
            pass
        print("egress node disconnected", flush=True)
        ws.close()


def handle_ingress(ws):
    owned = set()
    try:
        while True:
            op, payload = ws.read_frame()
            if op is None:
                break
            if op == 0x8:
                break
            if op == 0x9:
                ws._send(0xA, payload)
                continue
            if op == 0x1:
                try:
                    msg = json.loads(payload.decode("utf-8"))
                except ValueError:
                    continue
                if "open" in msg:
                    sid = msg["open"]
                    with state_lock:
                        vm = vm_conn
                    if vm is None or vm.closed:
                        ws.send_text(json.dumps({"open_failed": sid, "error": "no egress node"}))
                        continue
                    with state_lock:
                        streams[sid] = {"client": ws}
                    owned.add(sid)
                    vm.send_text(json.dumps({"open": sid, "host": msg.get("host"), "port": msg.get("port")}))
                elif "close" in msg:
                    sid = msg["close"]
                    owned.discard(sid)
                    drop_stream(sid)
                    vm_send_text(json.dumps({"close": sid}))
            elif op == 0x2:
                if len(payload) >= 4:
                    sid = struct.unpack(">I", payload[:4])[0]
                    if sid in owned:
                        vm_send_text_raw(payload)
    finally:
        for sid in list(owned):
            drop_stream(sid)
            vm_send_text(json.dumps({"close": sid}))
        ws.close()


def vm_send_text_raw(payload):
    with state_lock:
        vm = vm_conn
    if vm and not vm.closed:
        vm.send_binary(payload)


def handle_echo(ws):
    try:
        while True:
            op, payload = ws.read_frame()
            if op is None or op == 0x8:
                break
            if op == 0x9:
                ws._send(0xA, payload)
            elif op in (0x1, 0x2):
                ws._send(op, payload)
    finally:
        ws.close()


def handle(conn, addr):
    try:
        request_line, headers, rest = recv_headers(conn)
        parts = request_line.split()
        method = parts[0].upper() if parts else ""
        target = parts[1] if len(parts) > 1 else ""
        path = target.split("?", 1)[0]

        if method == "GET" and path == "/health":
            conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
            return
        if path in ("/egress", "/ingress", "/ws-echo"):
            if path != "/ws-echo" and not authorized(headers):
                conn.sendall(b"HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                return
            conn.settimeout(300)
            if not ws_handshake(conn, headers):
                conn.sendall(b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n")
                return
            ws = WSConn(conn)
            # any bytes after headers belong to the WS stream
            ws.buf += rest
            if path == "/egress":
                handle_egress(ws)
            elif path == "/ingress":
                handle_ingress(ws)
            else:
                handle_echo(ws)
            return
        conn.sendall(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
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
    print(f"ws relay listening on 0.0.0.0:{PORT}", flush=True)
    while True:
        conn, addr = srv.accept()
        threading.Thread(target=handle, args=(conn, addr), daemon=True).start()


if __name__ == "__main__":
    main()
