#!/usr/bin/env python3
"""VLESS bridge (Deplexo side).

Standard VLESS clients (v2rayNG / Shadowrocket / Clash-Meta / Nekoray)
connect via wss://<host>/vless. The bridge validates the VLESS UUID,
parses the target, and relays the TCP stream through the VM egress node
(ws /egress, multiplexed), so traffic exits via the VM.

VLESS request:  ver(1) uuid(16) addon_len(1) [addon] cmd(1) port(2) atype(1) addr
VLESS response: ver(1) addon_len(1)  (0x00 0x00), then raw stream.
Only TCP (cmd=1) is supported.

Also keeps: /health, /ws-echo, /egress (VM uplink), /ingress (JSON test proto).

Stdlib only. Env: PORT (default 3000), PROXY_TOKEN (Bearer for /egress,
/ingress), VLESS_UUID (client credential for /vless).
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
VLESS_UUID = os.environ.get("VLESS_UUID", "").lower().replace("-", "")


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
    return headers.get("authorization", "") == "Bearer " + TOKEN


# ---------------- relay state ----------------
state_lock = threading.Lock()
vm_conn = None
streams = {}          # sid -> {"client": WSConn, "kind": "vless"|"json",
                      #          "ready": threading.Event, "ok": bool}
_sid_counter = [0]


def next_sid():
    with state_lock:
        _sid_counter[0] += 1
        return _sid_counter[0]


def vm_send_text(msg):
    with state_lock:
        vm = vm_conn
    if vm and not vm.closed:
        vm.send_text(msg)


def vm_send_binary(payload):
    with state_lock:
        vm = vm_conn
    if vm and not vm.closed:
        vm.send_binary(payload)


def get_stream(sid):
    with state_lock:
        return streams.get(sid)


def drop_stream(sid):
    with state_lock:
        streams.pop(sid, None)


# ---------------- VLESS ----------------
def parse_vless(buf):
    """Parse VLESS handshake. Returns (uuid_hex, cmd, port, host, hdr_len)
    or None if more bytes are needed. Raises ValueError on malformed."""
    if len(buf) < 18:
        return None
    ver = buf[0]
    if ver != 0:
        raise ValueError("bad version")
    uuid_hex = bytes(buf[1:17]).hex()
    addon_len = buf[17]
    idx = 18 + addon_len
    if len(buf) < idx + 4:
        return None
    cmd = buf[idx]
    port = struct.unpack(">H", buf[idx + 1:idx + 3])[0]
    atype = buf[idx + 3]
    idx += 4
    if atype == 1:  # IPv4
        if len(buf) < idx + 4:
            return None
        host = socket.inet_ntoa(bytes(buf[idx:idx + 4]))
        idx += 4
    elif atype == 2:  # domain
        if len(buf) < idx + 1:
            return None
        alen = buf[idx]
        idx += 1
        if len(buf) < idx + alen:
            return None
        host = bytes(buf[idx:idx + alen]).decode("ascii")
        idx += alen
    elif atype == 3:  # IPv6
        if len(buf) < idx + 16:
            return None
        host = socket.inet_ntop(socket.AF_INET6, bytes(buf[idx:idx + 16]))
        idx += 16
    else:
        raise ValueError("bad atype")
    return uuid_hex, cmd, port, host, idx


def handle_vless(ws):
    pre = bytearray()
    sid = None
    try:
        # 1. accumulate until the VLESS handshake parses
        while True:
            op, payload = ws.read_frame()
            if op is None or op == 0x8:
                return
            if op == 0x9:
                ws._send(0xA, payload)
                continue
            if op != 0x2:
                continue
            pre += payload
            try:
                parsed = parse_vless(pre)
            except ValueError:
                return  # malformed -> drop
            if parsed is None:
                continue
            break
        uuid_hex, cmd, port, host, hdr_len = parsed
        if not VLESS_UUID or uuid_hex != VLESS_UUID:
            return  # bad uuid -> drop silently
        if cmd != 1:  # only TCP
            return
        # 2. open stream via the VM egress node
        sid = next_sid()
        ready = threading.Event()
        with state_lock:
            streams[sid] = {"client": ws, "kind": "vless", "ready": ready, "ok": False}
        with state_lock:
            vm = vm_conn
        if vm is None or vm.closed:
            drop_stream(sid)
            return
        vm.send_text(json.dumps({"open": sid, "host": host, "port": port}))
        if not ready.wait(25):
            drop_stream(sid)
            vm_send_text(json.dumps({"close": sid}))
            return
        entry = get_stream(sid)
        if entry is None or not entry["ok"]:
            return
        # 3. VLESS response header, then shuttle
        ws.send_binary(b"\x00\x00")
        leftover = bytes(pre[hdr_len:])
        if leftover:
            vm_send_binary(struct.pack(">I", sid) + leftover)
        while True:
            op, payload = ws.read_frame()
            if op is None or op == 0x8:
                break
            if op == 0x9:
                ws._send(0xA, payload)
                continue
            if op == 0x2 and payload:
                vm_send_binary(struct.pack(">I", sid) + payload)
    finally:
        if sid is not None:
            drop_stream(sid)
            vm_send_text(json.dumps({"close": sid}))
        ws.close()


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
            if op == 0x9:
                ws._send(0xA, payload)
                continue
            if op == 0x1:
                try:
                    msg = json.loads(payload.decode("utf-8"))
                except ValueError:
                    continue
                sid = msg.get("opened", msg.get("open_failed", msg.get("closed")))
                entry = get_stream(sid) if sid is not None else None
                if entry is None:
                    continue
                client = entry["client"]
                if "opened" in msg:
                    entry["ok"] = True
                    entry["ready"].set()
                    if entry["kind"] == "json" and not client.closed:
                        client.send_text(payload.decode("utf-8"))
                else:  # open_failed / closed
                    entry["ready"].set()
                    drop_stream(sid)
                    if entry["kind"] == "json" and not client.closed:
                        client.send_text(payload.decode("utf-8"))
                    elif entry["kind"] == "vless":
                        try:
                            client.close()
                        except OSError:
                            pass
            elif op == 0x2:
                if len(payload) >= 4:
                    sid = struct.unpack(">I", payload[:4])[0]
                    entry = get_stream(sid)
                    if entry and not entry["client"].closed:
                        # strip the 4-byte sid for vless clients (raw stream)
                        out = payload[4:] if entry["kind"] == "vless" else payload
                        entry["client"].send_binary(out)
    finally:
        with state_lock:
            if vm_conn is ws:
                vm_conn = None
            dead = list(streams.items())
            streams.clear()
        for sid, entry in dead:
            try:
                entry["client"].close()
            except OSError:
                pass
        print("egress node disconnected", flush=True)
        ws.close()


def handle_ingress(ws):
    # JSON test protocol (diagnostics)
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
                    ready = threading.Event()
                    with state_lock:
                        streams[sid] = {"client": ws, "kind": "json", "ready": ready, "ok": False}
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
                        vm_send_binary(payload)
    finally:
        for sid in list(owned):
            drop_stream(sid)
            vm_send_text(json.dumps({"close": sid}))
        ws.close()


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
        if path in ("/egress", "/ingress", "/ws-echo", "/vless"):
            if path in ("/egress", "/ingress") and not authorized(headers):
                conn.sendall(b"HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                return
            conn.settimeout(300)
            if not ws_handshake(conn, headers):
                conn.sendall(b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n")
                return
            ws = WSConn(conn)
            ws.buf += rest
            if path == "/egress":
                handle_egress(ws)
            elif path == "/ingress":
                handle_ingress(ws)
            elif path == "/vless":
                handle_vless(ws)
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
    print(f"vless bridge listening on 0.0.0.0:{PORT}", flush=True)
    while True:
        conn, addr = srv.accept()
        threading.Thread(target=handle, args=(conn, addr), daemon=True).start()


if __name__ == "__main__":
    main()
