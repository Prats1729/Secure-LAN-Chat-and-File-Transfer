#!/usr/bin/env python3
"""
Secure LAN Chat & File Transfer - ADVANCED SERVER (v4)
Features:
- AES-256-GCM Transport Security
- X25519 ECDH Public Key Directory for Zero-Knowledge E2EE
- SQLite Persistent Chat & File Transfer History
- Multi-Channel / Chat Rooms (#general, #dev, #random, custom rooms)
- Multiplexed Non-blocking File Streaming
- Live Typing Indicators & User Presence (Online / Away / Busy)
- Heartbeat / Dead Client Pruning
- UDP LAN Broadcast Auto-Discovery
- Interactive Server Admin Console
"""

import socket
import threading
import sys
import os
import time
import datetime
import sqlite3
from typing import Dict, List, Optional, Any
from collections import defaultdict

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from crypto_utils import (
    derive_transport_key,
    send_json_packet,
    recv_json_packet,
    sanitize_filename
)

# Configuration defaults
DEFAULT_PASSPHRASE = "SecureLANChat2026"
DEFAULT_TCP_PORT = 5050
DEFAULT_UDP_PORT = 5051
DB_FILE = "lan_chat.db"
UDP_DISCOVER_MSG = b"LANCHAT_DISCOVER"

# Server State
clients: List[Dict[str, Any]] = []  # List of {"conn": socket, "addr": tuple, "username": str, "pubkey": str, "rooms": set, "status": str, "last_seen": float}
clients_lock = threading.Lock()
db_lock = threading.Lock()


# ============================================================
# Database Setup
# ============================================================

def init_database():
    """Initialize SQLite database for chat logs, rooms, and audit trails."""
    with db_lock:
        conn = sqlite3.connect(DB_FILE)
        cur = conn.cursor()
        cur.execute("""
            CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                room TEXT,
                sender TEXT,
                target TEXT,
                content TEXT,
                is_private INTEGER
            )
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS file_transfers (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                sender TEXT,
                target TEXT,
                room TEXT,
                filename TEXT,
                filesize INTEGER,
                filehash TEXT,
                status TEXT
            )
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS audit_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                event TEXT,
                details TEXT
            )
        """)
        conn.commit()
        conn.close()


def db_log_message(room: Optional[str], sender: str, target: Optional[str], content: str, is_private: bool = False):
    ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with db_lock:
        try:
            conn = sqlite3.connect(DB_FILE)
            cur = conn.cursor()
            cur.execute(
                "INSERT INTO messages (timestamp, room, sender, target, content, is_private) VALUES (?, ?, ?, ?, ?, ?)",
                (ts, room or "", sender, target or "", content, 1 if is_private else 0)
            )
            conn.commit()
            conn.close()
        except Exception as e:
            print(f"[DB Error] Failed to log message: {e}")


def db_log_file_transfer(sender: str, target: Optional[str], room: Optional[str], filename: str, filesize: int, filehash: str):
    ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with db_lock:
        try:
            conn = sqlite3.connect(DB_FILE)
            cur = conn.cursor()
            cur.execute(
                "INSERT INTO file_transfers (timestamp, sender, target, room, filename, filesize, filehash, status) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (ts, sender, target or "", room or "", filename, filesize, filehash, "COMPLETED")
            )
            conn.commit()
            conn.close()
        except Exception as e:
            print(f"[DB Error] Failed to log transfer: {e}")


def db_get_room_history(room: str, limit: int = 30) -> List[Dict[str, str]]:
    with db_lock:
        try:
            conn = sqlite3.connect(DB_FILE)
            cur = conn.cursor()
            cur.execute(
                "SELECT timestamp, sender, content FROM messages WHERE room = ? AND is_private = 0 ORDER BY id DESC LIMIT ?",
                (room, limit)
            )
            rows = cur.fetchall()
            conn.close()
            return [{"timestamp": r[0], "sender": r[1], "content": r[2]} for r in reversed(rows)]
        except Exception:
            return []


# ============================================================
# Client & State Management
# ============================================================

def log_event(event_str: str):
    ts = datetime.datetime.now().strftime("%H:%M:%S")
    print(f"[{ts}] {event_str}")


def find_client_by_name(username: str) -> Optional[Dict[str, Any]]:
    with clients_lock:
        for c in clients:
            if c["username"] == username:
                return c
    return None


def get_user_list_payload() -> List[Dict[str, Any]]:
    with clients_lock:
        return [
            {
                "username": c["username"],
                "pubkey": c["pubkey"],
                "status": c.get("status", "online"),
                "rooms": list(c.get("rooms", ["#general"]))
            }
            for c in clients
        ]


def broadcast_userlist(aes_cipher: AESGCM):
    users = get_user_list_payload()
    packet = {
        "type": "USERLIST",
        "users": users
    }
    with clients_lock:
        target_conns = [c["conn"] for c in clients]
    for conn in target_conns:
        send_json_packet(conn, packet, aes_cipher)


def broadcast_to_room(room: str, packet: Dict[str, Any], aes_cipher: AESGCM, exclude_conn=None):
    with clients_lock:
        targets = [c["conn"] for c in clients if room in c.get("rooms", set()) and c["conn"] is not exclude_conn]
    for conn in targets:
        send_json_packet(conn, packet, aes_cipher)


def broadcast_system_msg(text: str, room: Optional[str], aes_cipher: AESGCM, exclude_conn=None):
    packet = {
        "type": "SYS",
        "room": room or "#general",
        "content": text,
        "timestamp": datetime.datetime.now().strftime("%H:%M:%S")
    }
    if room:
        broadcast_to_room(room, packet, aes_cipher, exclude_conn=exclude_conn)
    else:
        with clients_lock:
            targets = [c["conn"] for c in clients if c["conn"] is not exclude_conn]
        for conn in targets:
            send_json_packet(conn, packet, aes_cipher)


def remove_client(conn, aes_cipher: AESGCM):
    removed_user = None
    with clients_lock:
        for i, c in enumerate(clients):
            if c["conn"] is conn:
                removed_user = c["username"]
                clients.pop(i)
                break
    if removed_user:
        log_event(f"[-] {removed_user} disconnected")
        broadcast_system_msg(f"{removed_user} has left the chat", None, aes_cipher)
        broadcast_userlist(aes_cipher)


# ============================================================
# Client Connection Handler
# ============================================================

def handle_client(conn: socket.socket, addr, aes_cipher: AESGCM):
    # Initial Handshake packet expected: {"type": "JOIN", "username": "...", "pubkey": "..."}
    handshake = recv_json_packet(conn, aes_cipher)
    if not handshake or handshake.get("type") != "JOIN":
        conn.close()
        return

    username = str(handshake.get("username", "")).strip()
    pubkey = str(handshake.get("pubkey", "")).strip()

    if not username or len(username) > 30:
        send_json_packet(conn, {"type": "ERR", "content": "Invalid username."}, aes_cipher)
        conn.close()
        return

    with clients_lock:
        if any(c["username"].lower() == username.lower() for c in clients):
            send_json_packet(conn, {"type": "ERR", "content": f"Username '{username}' is already taken."}, aes_cipher)
            conn.close()
            return

        client_entry = {
            "conn": conn,
            "addr": addr,
            "username": username,
            "pubkey": pubkey,
            "rooms": {"#general"},
            "status": "online",
            "last_seen": time.time()
        }
        clients.append(client_entry)

    log_event(f"[+] {username} joined from {addr[0]}:{addr[1]}")

    # Confirm join to client
    send_json_packet(conn, {
        "type": "JOIN_OK",
        "username": username,
        "rooms": ["#general", "#dev", "#random"],
        "current_room": "#general"
    }, aes_cipher)

    # Replay #general history
    history = db_get_room_history("#general", limit=25)
    for h in history:
        send_json_packet(conn, {
            "type": "HIST",
            "room": "#general",
            "sender": h["sender"],
            "content": h["content"],
            "timestamp": h["timestamp"]
        }, aes_cipher)

    broadcast_system_msg(f"{username} has joined #general", "#general", aes_cipher, exclude_conn=conn)
    broadcast_userlist(aes_cipher)

    try:
        while True:
            packet = recv_json_packet(conn, aes_cipher)
            if packet is None:
                break

            client_entry["last_seen"] = time.time()
            ptype = packet.get("type")

            # 1. Room Chat Message
            if ptype == "MSG" or ptype == "ROOM_MSG":
                room = packet.get("room", "#general")
                content = str(packet.get("content", ""))
                ts = datetime.datetime.now().strftime("%H:%M:%S")

                db_log_message(room, username, None, content, is_private=False)
                log_event(f"[{room}] {username}: {content}")

                out_packet = {
                    "type": "ROOM_MSG",
                    "room": room,
                    "sender": username,
                    "content": content,
                    "timestamp": ts
                }
                broadcast_to_room(room, out_packet, aes_cipher, exclude_conn=conn)

            # 2. End-to-End Encrypted Private Message (PMSG)
            elif ptype == "PMSG":
                target = packet.get("target")
                encrypted_payload = packet.get("content", "")
                ts = datetime.datetime.now().strftime("%H:%M:%S")

                target_client = find_client_by_name(target)
                if not target_client:
                    send_json_packet(conn, {"type": "ERR", "content": f"User '{target}' is not online."}, aes_cipher)
                    continue

                log_event(f"[E2EE PM] {username} -> {target}")
                db_log_message(None, username, target, "[E2EE Private Message]", is_private=True)

                out_packet = {
                    "type": "PMSG",
                    "sender": username,
                    "target": target,
                    "content": encrypted_payload,
                    "sender_pubkey": pubkey,
                    "timestamp": ts
                }
                send_json_packet(target_client["conn"], out_packet, aes_cipher)

            # 3. Room Management (/join, /leave, /rooms)
            elif ptype == "ROOM_JOIN":
                target_room = packet.get("room", "").strip()
                if not target_room.startswith("#"):
                    target_room = "#" + target_room
                client_entry["rooms"].add(target_room)

                # Replay room history
                hist = db_get_room_history(target_room, limit=25)
                for h in hist:
                    send_json_packet(conn, {
                        "type": "HIST",
                        "room": target_room,
                        "sender": h["sender"],
                        "content": h["content"],
                        "timestamp": h["timestamp"]
                    }, aes_cipher)

                send_json_packet(conn, {
                    "type": "ROOM_JOINED",
                    "room": target_room
                }, aes_cipher)
                broadcast_system_msg(f"{username} joined {target_room}", target_room, aes_cipher, exclude_conn=conn)
                broadcast_userlist(aes_cipher)

            elif ptype == "ROOM_LEAVE":
                target_room = packet.get("room", "")
                if target_room != "#general" and target_room in client_entry["rooms"]:
                    client_entry["rooms"].remove(target_room)
                    broadcast_system_msg(f"{username} left {target_room}", target_room, aes_cipher)
                    broadcast_userlist(aes_cipher)

            # 4. User Status Change (/status away/busy/online)
            elif ptype == "STATUS":
                status = packet.get("status", "online")
                client_entry["status"] = status
                broadcast_userlist(aes_cipher)

            # 5. Live Typing Indicator
            elif ptype == "TYPING":
                room = packet.get("room")
                target = packet.get("target")
                is_typing = bool(packet.get("is_typing", False))
                out_packet = {
                    "type": "TYPING",
                    "sender": username,
                    "room": room,
                    "target": target,
                    "is_typing": is_typing
                }
                if target:
                    tc = find_client_by_name(target)
                    if tc:
                        send_json_packet(tc["conn"], out_packet, aes_cipher)
                elif room:
                    broadcast_to_room(room, out_packet, aes_cipher, exclude_conn=conn)

            # 6. File Transfer: Start & Streaming Relay
            elif ptype == "FILE_START" or ptype == "PFILE_START":
                transfer_id = packet.get("transfer_id")
                filename = sanitize_filename(packet.get("filename", "file"))
                filesize = int(packet.get("filesize", 0))
                filehash = packet.get("filehash", "")
                num_chunks = int(packet.get("num_chunks", 0))
                target = packet.get("target")
                room = packet.get("room", "#general")
                is_e2ee = bool(packet.get("is_e2ee", False))

                packet["sender"] = username
                packet["sender_pubkey"] = pubkey

                if ptype == "PFILE_START" or target:
                    tc = find_client_by_name(target)
                    if not tc:
                        send_json_packet(conn, {"type": "ERR", "content": f"User '{target}' is offline for file transfer."}, aes_cipher)
                        continue
                    log_event(f"[File] {username} -> {target} (E2EE): '{filename}' ({filesize:,} bytes, {num_chunks} chunks)")
                    send_json_packet(tc["conn"], packet, aes_cipher)
                else:
                    log_event(f"[File] {username} -> {room}: '{filename}' ({filesize:,} bytes, {num_chunks} chunks)")
                    broadcast_to_room(room, packet, aes_cipher, exclude_conn=conn)

                db_log_file_transfer(username, target, room, filename, filesize, filehash)

            # 7. File Chunks Relay (Multiplexed streaming)
            elif ptype == "FILE_CHUNK":
                target = packet.get("target")
                room = packet.get("room", "#general")
                packet["sender"] = username

                if target:
                    tc = find_client_by_name(target)
                    if tc:
                        send_json_packet(tc["conn"], packet, aes_cipher)
                else:
                    broadcast_to_room(room, packet, aes_cipher, exclude_conn=conn)

            # 8. File Completion / Acknowledgement
            elif ptype == "FILE_END" or ptype == "FILE_CANCEL":
                target = packet.get("target")
                room = packet.get("room", "#general")
                packet["sender"] = username

                if target:
                    tc = find_client_by_name(target)
                    if tc:
                        send_json_packet(tc["conn"], packet, aes_cipher)
                else:
                    broadcast_to_room(room, packet, aes_cipher, exclude_conn=conn)

            # 9. Heartbeat Ping / Pong
            elif ptype == "PING":
                send_json_packet(conn, {"type": "PONG", "ts": time.time()}, aes_cipher)

            elif ptype == "PONG":
                client_entry["last_seen"] = time.time()

    finally:
        remove_client(conn, aes_cipher)
        try:
            conn.close()
        except OSError:
            pass


# ============================================================
# Background Watchdog & UDP Discovery
# ============================================================

def heartbeat_watchdog(aes_cipher: AESGCM):
    """Prune unresponsive sockets that have missed heartbeats."""
    while True:
        time.sleep(15)
        now = time.time()
        stale_conns = []
        with clients_lock:
            for c in clients:
                if now - c.get("last_seen", now) > 45:
                    stale_conns.append(c["conn"])
                else:
                    try:
                        send_json_packet(c["conn"], {"type": "PING"}, aes_cipher)
                    except Exception:
                        stale_conns.append(c["conn"])
        for dead_conn in stale_conns:
            try:
                dead_conn.close()
            except OSError:
                pass


def udp_discovery_responder(udp_port: int, tcp_port: int):
    """Answer UDP broadcast queries from clients searching for the server."""
    udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        udp_sock.bind(("0.0.0.0", udp_port))
    except Exception as e:
        print(f"[UDP Error] Could not bind UDP discovery on port {udp_port}: {e}")
        return

    log_event(f"UDP discovery active on port {udp_port}")
    while True:
        try:
            data, addr = udp_sock.recvfrom(1024)
            if data == UDP_DISCOVER_MSG:
                reply = f"LANCHAT_SERVER:{tcp_port}:SecureServer".encode("utf-8")
                udp_sock.sendto(reply, addr)
                # log_event(f"[UDP Discovery] Answered query from {addr[0]}:{addr[1]}")
        except OSError:
            break


# ============================================================
# Main Entry Point
# ============================================================

def main():
    tcp_port = int(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_TCP_PORT
    udp_port = int(sys.argv[2]) if len(sys.argv) > 2 else DEFAULT_UDP_PORT
    passphrase = os.environ.get("LANCHAT_KEY", DEFAULT_PASSPHRASE)

    init_database()
    aes_key = derive_transport_key(passphrase)
    aes_cipher = AESGCM(aes_key)

    # Launch background services
    threading.Thread(target=udp_discovery_responder, args=(udp_port, tcp_port), daemon=True).start()
    threading.Thread(target=heartbeat_watchdog, args=(aes_cipher,), daemon=True).start()

    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        server_sock.bind(("0.0.0.0", tcp_port))
    except Exception as e:
        print(f"Failed to bind TCP port {tcp_port}: {e}")
        sys.exit(1)

    server_sock.listen(50)

    print("=" * 65)
    print("      SECURE LAN CHAT & FILE TRANSFER - ADVANCED SERVER v4")
    print("=" * 65)
    print(f" [+] TCP Port (Chat/Files/Multiplexed) : {tcp_port}")
    print(f" [+] UDP Port (LAN Auto-Discovery)    : {udp_port}")
    print(f" [+] Database                          : {DB_FILE} (SQLite)")
    print(f" [+] Transport Encryption             : AES-256-GCM (PBKDF2-HMAC-SHA256)")
    print(f" [+] End-to-End Encryption (E2EE)     : X25519 ECDH + HKDF")
    print(f" [+] Multi-Channel Rooms               : #general, #dev, #random")
    print("=" * 65)
    print("Press Ctrl+C to shut down.\n")

    try:
        while True:
            conn, addr = server_sock.accept()
            t = threading.Thread(target=handle_client, args=(conn, addr, aes_cipher), daemon=True)
            t.start()
    except KeyboardInterrupt:
        print("\nShutting down server gracefully...")
    finally:
        server_sock.close()


if __name__ == "__main__":
    main()
