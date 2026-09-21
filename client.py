#!/usr/bin/env python3
"""
Secure LAN Chat & File Transfer - CLIENT
Run: python3 client.py <server_ip> <port>

Commands once connected:
  just type text  -> send a chat message
  /file <path>    -> send a file to everyone
  /quit           -> exit
"""

import socket
import threading
import sys
import os
import hashlib

sock = None


def recv_line(conn):
    chars = []
    while True:
        b = conn.recv(1)
        if not b:
            return None
        if b == b"\n":
            return b"".join(chars).decode(errors="replace")
        chars.append(b)


def recv_all(conn, n):
    data = bytearray()
    while len(data) < n:
        chunk = conn.recv(min(4096, n - len(data)))
        if not chunk:
            return None
        data.extend(chunk)
    return bytes(data)


def send_line(conn, text):
    conn.sendall((text + "\n").encode())


def sha256_of_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def receiver_loop():
    global sock
    while True:
        line = recv_line(sock)
        if line is None:
            print("\n[disconnected from server]")
            os._exit(0)

        if line.startswith("CHAT:"):
            rest = line[5:]
            sender, text = rest.split(":", 1)
            print(f"\n[{sender}] {text}\n> ", end="", flush=True)

        elif line.startswith("SYS:"):
            print(f"\n*** {line[4:]} ***\n> ", end="", flush=True)

        elif line.startswith("FILE:"):
            # FILE:<sender>:<filename>:<filesize>:<sha256hex>
            rest = line[5:]
            sender, filename, filesize_str, expected_hash = rest.split(":", 3)
            filesize = int(filesize_str)

            filedata = recv_all(sock, filesize)
            if filedata is None:
                print("\n[error receiving file]\n> ", end="", flush=True)
                continue

            outname = "received_" + filename
            with open(outname, "wb") as f:
                f.write(filedata)

            actual_hash = hashlib.sha256(filedata).hexdigest()
            ok = (actual_hash == expected_hash)

            print(f"\n[file received] '{filename}' from {sender} ({filesize} bytes)")
            print(f"  saved as: {outname}")
            print(f"  integrity check: {'OK (hash matches)' if ok else 'FAILED (hash mismatch!)'}")
            print("> ", end="", flush=True)


def main():
    global sock
    if len(sys.argv) < 3:
        print("Usage: python3 client.py <server_ip> <port>")
        sys.exit(1)

    server_ip = sys.argv[1]
    port = int(sys.argv[2])

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.connect((server_ip, port))
    except OSError as e:
        print(f"connect() failed: {e}")
        sys.exit(1)

    print(f"Connected to server {server_ip}:{port}")
    username = input("Enter your username: ")
    send_line(sock, username)

    t = threading.Thread(target=receiver_loop, daemon=True)
    t.start()

    print("Commands:")
    print("  just type text  -> send a chat message")
    print("  /file <path>    -> send a file to everyone")
    print("  /quit           -> exit")
    print("> ", end="", flush=True)

    for line in sys.stdin:
        text = line.rstrip("\n")
        if text == "/quit":
            break

        if text.startswith("/file "):
            path = text[6:]
            if not os.path.isfile(path):
                print(f"Could not open file: {path}\n> ", end="", flush=True)
                continue

            filesize = os.path.getsize(path)
            filehash = sha256_of_file(path)
            filename = os.path.basename(path)

            send_line(sock, f"FILE:{filename}:{filesize}:{filehash}")
            with open(path, "rb") as f:
                sock.sendall(f.read())

            print(f"Sent '{filename}' ({filesize} bytes, sha256={filehash})\n> ", end="", flush=True)
        else:
            send_line(sock, f"MSG:{text}")
            print("> ", end="", flush=True)

    sock.close()


if __name__ == "__main__":
    main()