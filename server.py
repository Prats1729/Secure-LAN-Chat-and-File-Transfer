#!/usr/bin/env python3
"""
Secure LAN Chat & File Transfer - SERVER (v3: encrypted + UDP discovery)
Run: python3 server.py [tcp_port] [udp_discovery_port]
     defaults: tcp_port=5050, udp_discovery_port=5051

WHAT'S NEW IN THIS VERSION
---------------------------------------------------------------------
1. AES-256-GCM ENCRYPTION - every byte exchanged with a client (chat
   text AND file contents) is encrypted using a key derived from a
   shared passphrase (see SHARED_PASSPHRASE below). Anyone sniffing
   the LAN with Wireshark sees only ciphertext, not the actual chat
   or file content. This is what makes the project's "Secure" name
   actually true, not just a title.

   IMPORTANT: SHARED_PASSPHRASE below must be IDENTICAL in server.py
   and client.py, or clients simply won't be able to talk to the
   server (decryption will fail and the connection will be dropped).

2. UDP AUTO-DISCOVERY - the server also listens on a UDP port and
   answers "where are you?" broadcasts from clients on the LAN, so
   the client doesn't need to be told the server's IP address
   manually. This also gives you a second protocol (UDP, connection-
   less) to show in Wireshark next to the TCP chat traffic.

3. CHAT HISTORY - the last 20 broadcast messages are kept in memory
   and replayed (still encrypted) to any client that joins, so late
   joiners aren't starting from a blank screen.

4. CHUNKED FILE TRANSFER - files are now sent in fixed-size chunks
   instead of one big blob, which is what lets both sides show a
   live progress bar (see client.py).

PROTOCOL (all payloads below are ENCRYPTED FRAMES - see send_frame /
recv_frame - the text shown here is the plaintext *inside* the frame
after decryption):

  First frame from client after connecting: <username>  (plain text)

  Client -> Server:
    MSG:<text>
    PMSG:<target_user>:<text>
    LIST:
    FILE_START:<filename>:<filesize>:<sha256hex>:<numchunks>
        (followed by <numchunks> raw-bytes frames = broadcast file)
    PFILE_START:<target_user>:<filename>:<filesize>:<sha256hex>:<numchunks>
        (followed by <numchunks> raw-bytes frames = private file)

  Server -> Client:
    SYS:<message>
    CHAT:<sender>:<text>
    PCHAT:<sender>:<text>
    HIST:<timestamp>:<sender>:<text>          (chat history replay)
    FILE_START:<sender>:<filename>:<filesize>:<sha256hex>:<numchunks>
    PFILE_START:<sender>:<filename>:<filesize>:<sha256hex>:<numchunks>
    USERLIST:<comma-separated usernames>
    ERR:<message>
"""

import socket
import threading
import sys
import datetime
import os
from collections import deque

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

# ============================================================
# SHARED SECRET - must match client.py exactly. Change this to
# your own passphrase before a real demo (anyone who knows this
# string can decrypt the traffic - that's the whole point of it
# being a *shared secret*, like a Wi-Fi password).
# ============================================================
SHARED_PASSPHRASE = "SecureLANChat2026"
_SALT = b"lan-chat-fixed-salt-v1"  # fixed so both sides derive the same key

def _derive_key(passphrase: str) -> bytes:
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=_SALT, iterations=200_000)
    return kdf.derive(passphrase.encode())

AES_KEY = _derive_key(SHARED_PASSPHRASE)
aesgcm = AESGCM(AES_KEY)

CHUNK_SIZE = 64 * 1024  # 64 KB per file chunk
UDP_DISCOVER_MSG = b"LANCHAT_DISCOVER"


# ---------------- encrypted framing over TCP ----------------
def recv_exact(conn, n):
    data = bytearray()
    while len(data) < n:
        chunk = conn.recv(min(4096, n - len(data)))
        if not chunk:
            return None
        data.extend(chunk)
    return bytes(data)


def send_frame(conn, plaintext: bytes):
    nonce = os.urandom(12)
    ct = aesgcm.encrypt(nonce, plaintext, None)
    payload = nonce + ct
    conn.sendall(len(payload).to_bytes(4, "big") + payload)


def send_text(conn, text: str):
    send_frame(conn, text.encode())


def recv_frame(conn):
    """Returns decrypted plaintext bytes, or None on disconnect/decrypt failure."""
    hdr = recv_exact(conn, 4)
    if hdr is None:
        return None
    length = int.from_bytes(hdr, "big")
    payload = recv_exact(conn, length)
    if payload is None:
        return None
    nonce, ct = payload[:12], payload[12:]
    try:
        return aesgcm.decrypt(nonce, ct, None)
    except Exception:
        return None  # wrong key / tampered data


def recv_text(conn):
    data = recv_frame(conn)
    if data is None:
        return None
    return data.decode(errors="replace")


# ---------------- shared state ----------------
clients = []          # list of dicts: {"conn": socket, "username": str}
clients_lock = threading.Lock()

history = deque(maxlen=20)   # tuples: (timestamp, sender, text)
history_lock = threading.Lock()

LOG_FILE = "chat_log.txt"
log_lock = threading.Lock()


def log(line):
    ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with log_lock:
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(f"[{ts}] {line}\n")
    print(f"[{ts}] {line}")


def find_conn(username):
    with clients_lock:
        for c in clients:
            if c["username"] == username:
                return c["conn"]
    return None


def broadcast_text(text, exclude_conn=None):
    with clients_lock:
        targets = [c["conn"] for c in clients if c["conn"] is not exclude_conn]
    for conn in targets:
        try:
            send_text(conn, text)
        except OSError:
            pass


def remove_client(conn):
    with clients_lock:
        clients[:] = [c for c in clients if c["conn"] is not conn]


def current_usernames():
    with clients_lock:
        return [c["username"] for c in clients]


def relay_chunks(conn, src_conn, target_conns, num_chunks):
    """Read num_chunks raw frames from src_conn and forward each to every
    connection in target_conns, as they arrive (streaming, not buffered
    all at once) - this is what lets the receiver show live progress."""
    for _ in range(num_chunks):
        chunk = recv_frame(src_conn)
        if chunk is None:
            return False
        for t in target_conns:
            try:
                send_frame(t, chunk)
            except OSError:
                pass
    return True


def handle_client(conn, addr):
    username = recv_text(conn)
    if not username:
        conn.close()
        return

    with clients_lock:
        if any(c["username"] == username for c in clients):
            try:
                send_text(conn, "ERR:That username is already taken on this server.")
            except OSError:
                pass
            conn.close()
            return
        clients.append({"conn": conn, "username": username})

    log(f"+ {username} connected from {addr[0]}:{addr[1]}")

    # Replay recent chat history to the new joiner only
    with history_lock:
        hist_snapshot = list(history)
    for ts, sender, text in hist_snapshot:
        try:
            send_text(conn, f"HIST:{ts}:{sender}:{text}")
        except OSError:
            break

    broadcast_text(f"SYS:{username} has joined the chat", exclude_conn=conn)

    try:
        while True:
            line = recv_text(conn)
            if line is None:
                break

            if line.startswith("MSG:"):
                text = line[4:]
                ts = datetime.datetime.now().strftime("%H:%M:%S")
                with history_lock:
                    history.append((ts, username, text))
                log(f"[broadcast] {username}: {text}")
                broadcast_text(f"CHAT:{username}:{text}", exclude_conn=conn)

            elif line.startswith("PMSG:"):
                rest = line[5:]
                target, text = rest.split(":", 1)
                target_conn = find_conn(target)
                if target_conn is None:
                    send_text(conn, f"ERR:User '{target}' is not online.")
                    continue
                log(f"[private] {username} -> {target}: {text}")
                try:
                    send_text(target_conn, f"PCHAT:{username}:{text}")
                except OSError:
                    send_text(conn, f"ERR:Could not deliver message to '{target}'.")

            elif line.startswith("LIST:"):
                names = current_usernames()
                send_text(conn, "USERLIST:" + ",".join(names))

            elif line.startswith("FILE_START:"):
                rest = line[len("FILE_START:"):]
                filename, filesize_str, filehash, numchunks_str = rest.split(":", 3)
                filesize = int(filesize_str)
                numchunks = int(numchunks_str)

                log(f"[broadcast file] {username} -> everyone: {filename} "
                    f"({filesize} bytes, {numchunks} chunks, sha256={filehash})")

                with clients_lock:
                    targets = [c["conn"] for c in clients if c["conn"] is not conn]
                header = f"FILE_START:{username}:{filename}:{filesize}:{filehash}:{numchunks}"
                for t in targets:
                    try:
                        send_text(t, header)
                    except OSError:
                        pass

                if not relay_chunks(conn, conn, targets, numchunks):
                    break

            elif line.startswith("PFILE_START:"):
                rest = line[len("PFILE_START:"):]
                target, filename, filesize_str, filehash, numchunks_str = rest.split(":", 4)
                filesize = int(filesize_str)
                numchunks = int(numchunks_str)

                target_conn = find_conn(target)
                if target_conn is None:
                    # Still need to drain the chunks off the wire so the
                    # protocol stays in sync, even though we discard them.
                    for _ in range(numchunks):
                        if recv_frame(conn) is None:
                            break
                    send_text(conn, f"ERR:User '{target}' is not online. File not sent.")
                    continue

                log(f"[private file] {username} -> {target}: {filename} "
                    f"({filesize} bytes, {numchunks} chunks, sha256={filehash})")
                try:
                    send_text(target_conn, f"PFILE_START:{username}:{filename}:{filesize}:{filehash}:{numchunks}")
                except OSError:
                    pass

                if not relay_chunks(conn, conn, [target_conn], numchunks):
                    break
    finally:
        log(f"- {username} disconnected")
        remove_client(conn)
        broadcast_text(f"SYS:{username} has left the chat", exclude_conn=conn)
        conn.close()


def udp_discovery_server(udp_port, tcp_port):
    udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    udp_sock.bind(("0.0.0.0", udp_port))
    print(f"UDP discovery listening on port {udp_port} (clients can auto-find this server)")

    while True:
        try:
            data, addr = udp_sock.recvfrom(1024)
        except OSError:
            break
        if data == UDP_DISCOVER_MSG:
            reply = f"LANCHAT_SERVER:{tcp_port}".encode()
            try:
                udp_sock.sendto(reply, addr)
                print(f"[UDP] discovery request from {addr[0]}:{addr[1]} -> replied with TCP port {tcp_port}")
            except OSError:
                pass


def main():
    tcp_port = int(sys.argv[1]) if len(sys.argv) > 1 else 5050
    udp_port = int(sys.argv[2]) if len(sys.argv) > 2 else 5051

    threading.Thread(target=udp_discovery_server, args=(udp_port, tcp_port), daemon=True).start()

    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_sock.bind(("0.0.0.0", tcp_port))
    server_sock.listen(20)

    print("=== Secure LAN Chat Server (Python, Encrypted) ===")
    print(f"TCP chat/file port: {tcp_port}")
    print(f"UDP discovery port: {udp_port}")
    print(f"Chat log: {LOG_FILE}")
    print("Encryption: AES-256-GCM, key derived from the shared passphrase in this file.")
    print("(Ctrl+C to stop)")

    try:
        while True:
            conn, addr = server_sock.accept()
            print(f"New connection from {addr[0]}:{addr[1]}")
            t = threading.Thread(target=handle_client, args=(conn, addr), daemon=True)
            t.start()
    except KeyboardInterrupt:
        print("\nShutting down.")
    finally:
        server_sock.close()


if __name__ == "__main__":
    main()
