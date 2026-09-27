#!/usr/bin/env python3
"""
Secure LAN Chat & File Transfer - CLIENT (v3: encrypted + UDP discovery)

Run with auto-discovery (finds the server on the LAN automatically):
    python3 client.py

Run with a manual server address (skips discovery):
    python3 client.py <server_ip> <tcp_port>

Commands once connected:
  <text>                    -> broadcast chat message to everyone
  /msg <user> <text>        -> private message to one user
  /file <path>              -> send a file to everyone
  /fileto <user> <path>     -> send a file to one user only
  /list                     -> show who's online
  /help                     -> show this command list
  /quit                     -> exit
"""

import socket
import threading
import sys
import os
import hashlib
import datetime

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

# ============================================================
# Must match SHARED_PASSPHRASE in server.py EXACTLY, or this
# client will not be able to decrypt anything the server sends.
# ============================================================
SHARED_PASSPHRASE = "SecureLANChat2026"
_SALT = b"lan-chat-fixed-salt-v1"

def _derive_key(passphrase: str) -> bytes:
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=_SALT, iterations=200_000)
    return kdf.derive(passphrase.encode())

AES_KEY = _derive_key(SHARED_PASSPHRASE)
aesgcm = AESGCM(AES_KEY)

CHUNK_SIZE = 64 * 1024
UDP_DISCOVER_MSG = b"LANCHAT_DISCOVER"
DEFAULT_UDP_PORT = 5051

sock = None

# ---- simple ANSI colors (safe no-op if the terminal doesn't render them) ----
RESET = "\033[0m"
BOLD = "\033[1m"
CYAN = "\033[36m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
MAGENTA = "\033[35m"
RED = "\033[31m"
GRAY = "\033[90m"


def ts():
    return datetime.datetime.now().strftime("%H:%M:%S")


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
        return None


def recv_text(conn):
    data = recv_frame(conn)
    if data is None:
        return None
    return data.decode(errors="replace")


def sha256_of_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def prompt():
    print("> ", end="", flush=True)


def progress_bar(prefix, done, total, width=30):
    frac = done / total if total else 1
    filled = int(width * frac)
    bar = "#" * filled + "-" * (width - filled)
    pct = int(frac * 100)
    sys.stdout.write(f"\r{prefix} [{bar}] {pct}% ({done}/{total} bytes)")
    sys.stdout.flush()


# ---------------- UDP discovery ----------------
def discover_server(udp_port=DEFAULT_UDP_PORT, timeout=3):
    udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    udp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    udp_sock.settimeout(timeout)
    try:
        udp_sock.sendto(UDP_DISCOVER_MSG, ("255.255.255.255", udp_port))
        data, addr = udp_sock.recvfrom(1024)
        text = data.decode(errors="replace")
        if text.startswith("LANCHAT_SERVER:"):
            tcp_port = int(text.split(":", 1)[1])
            return addr[0], tcp_port
    except (socket.timeout, OSError):
        return None
    finally:
        udp_sock.close()
    return None


# ---------------- file receive with progress ----------------
def receive_file(sender, filename, filesize, expected_hash, numchunks, tag):
    received = bytearray()
    label = f"{MAGENTA}[{tag} file]{RESET} receiving '{filename}' from {BOLD}{sender}{RESET}"
    print(f"\n{GRAY}[{ts()}]{RESET} {label}")

    for _ in range(numchunks):
        chunk = recv_frame(sock)
        if chunk is None:
            print(f"\n{RED}[error receiving file - connection lost mid-transfer]{RESET}")
            prompt()
            return
        received.extend(chunk)
        progress_bar("  progress", len(received), filesize)

    print()  # newline after progress bar finishes

    outname = "received_" + filename
    with open(outname, "wb") as f:
        f.write(bytes(received))

    actual_hash = sha256_of_bytes(bytes(received))
    ok = (actual_hash == expected_hash)

    print(f"  saved as: {outname}")
    if ok:
        print(f"  integrity check: {GREEN}OK (hash matches){RESET}")
    else:
        print(f"  integrity check: {RED}FAILED (hash mismatch!){RESET}")
    prompt()


def receiver_loop():
    global sock
    while True:
        line = recv_text(sock)
        if line is None:
            print(f"\n{RED}[disconnected from server - check the passphrase matches, "
                  f"or the server may have closed]{RESET}")
            os._exit(0)

        if line.startswith("CHAT:"):
            rest = line[5:]
            sender, text = rest.split(":", 1)
            print(f"\n{GRAY}[{ts()}]{RESET} {CYAN}[{sender}]{RESET} {text}")
            prompt()

        elif line.startswith("PCHAT:"):
            rest = line[6:]
            sender, text = rest.split(":", 1)
            print(f"\n{GRAY}[{ts()}]{RESET} {YELLOW}[PM from {sender}]{RESET} {text}")
            prompt()

        elif line.startswith("HIST:"):
            rest = line[5:]
            # Timestamp is a fixed "HH:MM:SS" (8 chars, 2 colons), so slice it
            # off explicitly instead of splitting on ":" - otherwise the
            # colons inside the timestamp itself break a plain split.
            htime, remainder = rest[:8], rest[9:]
            sender, text = remainder.split(":", 1)
            print(f"{GRAY}[history {htime}] {sender}: {text}{RESET}")

        elif line.startswith("SYS:"):
            print(f"\n{GRAY}[{ts()}]{RESET} {GREEN}*** {line[4:]} ***{RESET}")
            prompt()

        elif line.startswith("ERR:"):
            print(f"\n{RED}[error] {line[4:]}{RESET}")
            prompt()

        elif line.startswith("USERLIST:"):
            names = line[9:]
            names_list = [n for n in names.split(",") if n]
            print(f"\n{BOLD}Online users ({len(names_list)}):{RESET} "
                  f"{', '.join(names_list) if names_list else '(none)'}")
            prompt()

        elif line.startswith("PFILE_START:"):
            rest = line[len("PFILE_START:"):]
            sender, filename, filesize_str, expected_hash, numchunks_str = rest.split(":", 4)
            receive_file(sender, filename, int(filesize_str), expected_hash, int(numchunks_str), "private")

        elif line.startswith("FILE_START:"):
            rest = line[len("FILE_START:"):]
            sender, filename, filesize_str, expected_hash, numchunks_str = rest.split(":", 4)
            receive_file(sender, filename, int(filesize_str), expected_hash, int(numchunks_str), "broadcast")


def print_help():
    print(f"""{BOLD}Commands:{RESET}
  <text>                    send a broadcast chat message to everyone
  /msg <user> <text>        send a private message to one user
  /file <path>              send a file to everyone
  /fileto <user> <path>     send a file to one user only
  /list                     show who's currently online
  /help                     show this list again
  /quit                     disconnect and exit""")


def send_file(path, target=None):
    if not os.path.isfile(path):
        print(f"{RED}Could not open file: {path}{RESET}")
        prompt()
        return

    with open(path, "rb") as f:
        data = f.read()
    filesize = len(data)
    filehash = sha256_of_bytes(data)
    filename = os.path.basename(path)
    numchunks = (filesize + CHUNK_SIZE - 1) // CHUNK_SIZE if filesize > 0 else 0

    if target:
        send_text(sock, f"PFILE_START:{target}:{filename}:{filesize}:{filehash}:{numchunks}")
    else:
        send_text(sock, f"FILE_START:{filename}:{filesize}:{filehash}:{numchunks}")

    sent = 0
    for i in range(numchunks):
        chunk = data[i * CHUNK_SIZE:(i + 1) * CHUNK_SIZE]
        send_frame(sock, chunk)
        sent += len(chunk)
        progress_bar(f"Sending '{filename}'", sent, filesize)
    print()

    dest = f"privately to {BOLD}{target}{RESET}" if target else "to everyone"
    print(f"{GREEN}Sent{RESET} '{filename}' ({filesize} bytes) {dest}")
    prompt()


def main():
    global sock

    if len(sys.argv) >= 3:
        server_ip = sys.argv[1]
        port = int(sys.argv[2])
    else:
        print("No server address given - trying UDP auto-discovery on the LAN...")
        result = discover_server()
        if result is None:
            print(f"{RED}No server found automatically.{RESET}")
            print("Make sure the server is running and you're on the same LAN, "
                  "or connect manually with: python client.py <server_ip> <port>")
            sys.exit(1)
        server_ip, port = result
        print(f"{GREEN}Found server{RESET} at {server_ip}:{port} via UDP discovery")

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.connect((server_ip, port))
    except OSError as e:
        print(f"connect() failed: {e}")
        sys.exit(1)

    print(f"Connected to server {server_ip}:{port} (AES-256-GCM encrypted)")
    username = input("Enter your username: ").strip()
    send_text(sock, username)

    t = threading.Thread(target=receiver_loop, daemon=True)
    t.start()

    print_help()
    prompt()

    for line in sys.stdin:
        text = line.rstrip("\n")
        if text == "/quit":
            break

        elif text == "/help":
            print_help()
            prompt()

        elif text == "/list":
            send_text(sock, "LIST:")

        elif text.startswith("/fileto "):
            try:
                _, target, path = text.split(" ", 2)
            except ValueError:
                print(f"{RED}Usage: /fileto <username> <path>{RESET}")
                prompt()
                continue
            send_file(path, target=target)

        elif text.startswith("/file "):
            path = text[6:]
            send_file(path)

        elif text.startswith("/msg "):
            try:
                _, target, msg = text.split(" ", 2)
            except ValueError:
                print(f"{RED}Usage: /msg <username> <message>{RESET}")
                prompt()
                continue
            send_text(sock, f"PMSG:{target}:{msg}")
            prompt()

        else:
            send_text(sock, f"MSG:{text}")
            prompt()

    sock.close()


if __name__ == "__main__":
    main()
