#!/usr/bin/env python3
"""
Secure LAN Chat & File Transfer - SERVER
Run: python3 server.py [port]   (default port 5050)

Same protocol/logic as the C++ version:
  Client sends its username as the first line.
  MSG:<text>                              -> broadcast as CHAT:<user>:<text>
  FILE:<filename>:<filesize>:<sha256hex>  -> followed by <filesize> raw bytes,
                                              relayed to every other client as
                                              FILE:<sender>:<filename>:<filesize>:<sha256hex>
                                              followed by the same raw bytes.
"""

import socket
import threading
import sys

HOST = "0.0.0.0"

clients = []          # list of (conn, username)
clients_lock = threading.Lock()


def recv_line(conn):
    """Read one line terminated by '\\n' from the socket (blocking, byte by byte)."""
    chars = []
    while True:
        b = conn.recv(1)
        if not b:
            return None  # disconnected
        if b == b"\n":
            return b"".join(chars).decode(errors="replace")
        chars.append(b)


def recv_all(conn, n):
    """Read exactly n bytes from the socket."""
    data = bytearray()
    while len(data) < n:
        chunk = conn.recv(min(4096, n - len(data)))
        if not chunk:
            return None  # disconnected
        data.extend(chunk)
    return bytes(data)


def send_line(conn, text):
    conn.sendall((text + "\n").encode())


def broadcast_line(text, exclude_conn=None):
    with clients_lock:
        for conn, _ in clients:
            if conn is not exclude_conn:
                try:
                    send_line(conn, text)
                except OSError:
                    pass


def remove_client(conn):
    with clients_lock:
        clients[:] = [(c, u) for c, u in clients if c is not conn]


def handle_client(conn, addr):
    username = recv_line(conn)
    if not username:
        conn.close()
        return

    with clients_lock:
        clients.append((conn, username))
    print(f"[+] {username} connected from {addr[0]}:{addr[1]}")
    broadcast_line(f"SYS:{username} has joined the chat", exclude_conn=conn)

    try:
        while True:
            line = recv_line(conn)
            if line is None:
                break

            if line.startswith("MSG:"):
                text = line[4:]
                print(f"{username}: {text}")
                broadcast_line(f"CHAT:{username}:{text}", exclude_conn=conn)

            elif line.startswith("FILE:"):
                # FILE:<filename>:<filesize>:<sha256hex>
                rest = line[5:]
                filename, filesize_str, filehash = rest.split(":", 2)
                filesize = int(filesize_str)

                print(f"[file] {username} -> {filename} ({filesize} bytes, sha256={filehash})")

                filedata = recv_all(conn, filesize)
                if filedata is None:
                    break

                header = f"FILE:{username}:{filename}:{filesize}:{filehash}"
                with clients_lock:
                    for c, _ in clients:
                        if c is not conn:
                            try:
                                send_line(c, header)
                                c.sendall(filedata)
                            except OSError:
                                pass
    finally:
        print(f"[-] {username} disconnected")
        remove_client(conn)
        broadcast_line(f"SYS:{username} has left the chat", exclude_conn=conn)
        conn.close()


def main():
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 5050

    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_sock.bind((HOST, port))
    server_sock.listen(10)

    print("=== Secure LAN Chat Server (Python) ===")
    print(f"Listening on port {port} ... (Ctrl+C to stop)")
    print("Find this machine's LAN IP with 'ipconfig' (Windows) or 'ip addr' (Linux).")

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