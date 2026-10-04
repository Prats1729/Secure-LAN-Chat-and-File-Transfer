#!/usr/bin/env python3
"""
Secure LAN Chat & File Transfer - ADVANCED CLI CLIENT (v4)
Features:
- AES-256-GCM Transport Encryption
- True End-to-End Encryption (E2EE) with X25519 ECDH + HKDF for Private Messages & Files
- Multi-Channel Chat Rooms (#general, #dev, #random, /join #custom)
- Streaming Disk-to-Disk File Transfer with live MB/s, ETA, and progress bar
- Non-blocking Asynchronous Terminal UI with un-clobbered prompt
- Real-time User Presence (Online / Away / Busy) and Typing Alerts
- UDP LAN Server Auto-Discovery
"""

import socket
import threading
import sys
import os
import time
import base64
import uuid
import datetime
from typing import Dict, Optional, Tuple, Any

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from crypto_utils import (
    derive_transport_key,
    generate_ecdh_keypair,
    derive_e2ee_shared_key,
    e2ee_encrypt_payload,
    e2ee_decrypt_payload,
    e2ee_encrypt_bytes,
    e2ee_decrypt_bytes,
    send_json_packet,
    recv_json_packet,
    sanitize_filename,
    get_unique_filepath,
    compute_file_sha256,
    CHUNK_SIZE
)

# Configuration defaults
DEFAULT_PASSPHRASE = "SecureLANChat2026"
DEFAULT_UDP_PORT = 5051
DOWNLOADS_DIR = "downloads"
UDP_DISCOVER_MSG = b"LANCHAT_DISCOVER"

# ANSI Colors
RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"
CYAN = "\033[36m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
MAGENTA = "\033[35m"
RED = "\033[31m"
BLUE = "\033[34m"
GRAY = "\033[90m"
WHITE_BG = "\033[47m\033[30m"

# Client Global State
sock: Optional[socket.socket] = None
aes_cipher: Optional[AESGCM] = None
my_priv_key, my_pubkey_hex = generate_ecdh_keypair()
my_username = ""
current_room = "#general"
my_rooms = {"#general"}
online_users: Dict[str, Dict[str, Any]] = {}  # username -> {pubkey, status, rooms}
e2ee_keys_cache: Dict[str, bytes] = {}  # username -> shared_key_bytes

# Active incoming file transfers: transfer_id -> {file_obj, filename, filesize, received_bytes, hasher, start_time, sender, is_e2ee, shared_key}
active_downloads: Dict[str, Dict[str, Any]] = {}
active_downloads_lock = threading.Lock()

input_buffer = ""
prompt_lock = threading.Lock()


def ts() -> str:
    return datetime.datetime.now().strftime("%H:%M:%S")


def clear_prompt():
    """Erase the current input line to avoid text collision."""
    sys.stdout.write("\r\033[K")
    sys.stdout.flush()


def render_prompt():
    """Redraw the input prompt cleanly."""
    sys.stdout.write(f"\r\033[K{CYAN}[{current_room}]{RESET} > {input_buffer}")
    sys.stdout.flush()


def print_message(formatted_str: str):
    """Safely print a message without disrupting the user's active typing."""
    with prompt_lock:
        clear_prompt()
        print(formatted_str)
        render_prompt()


def get_e2ee_shared_key(target_user: str) -> Optional[bytes]:
    """Retrieve or compute the cached ECDH shared key for a peer."""
    if target_user in e2ee_keys_cache:
        return e2ee_keys_cache[target_user]
    user_info = online_users.get(target_user)
    if not user_info or not user_info.get("pubkey"):
        return None
    try:
        shared = derive_e2ee_shared_key(my_priv_key, user_info["pubkey"])
        e2ee_keys_cache[target_user] = shared
        return shared
    except Exception:
        return None


# ============================================================
# UDP Server Auto-Discovery
# ============================================================

def discover_server(udp_port=DEFAULT_UDP_PORT, timeout=3) -> Optional[Tuple[str, int]]:
    udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    udp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    udp_sock.settimeout(timeout)
    try:
        udp_sock.sendto(UDP_DISCOVER_MSG, ("255.255.255.255", udp_port))
        data, addr = udp_sock.recvfrom(1024)
        text = data.decode("utf-8", errors="replace")
        if text.startswith("LANCHAT_SERVER:"):
            parts = text.split(":")
            tcp_port = int(parts[1])
            return addr[0], tcp_port
    except (socket.timeout, OSError):
        return None
    finally:
        udp_sock.close()
    return None


# ============================================================
# File Transfer Engine (Disk-to-Disk Streaming)
# ============================================================

def format_size(bytes_num: int) -> str:
    for unit in ['B', 'KB', 'MB', 'GB']:
        if bytes_num < 1024.0:
            return f"{bytes_num:.1f} {unit}"
        bytes_num /= 1024.0
    return f"{bytes_num:.1f} TB"


def send_file_stream(filepath: str, target_user: Optional[str] = None):
    if not os.path.isfile(filepath):
        print_message(f"{RED}[Error] File not found: {filepath}{RESET}")
        return

    filename = os.path.basename(filepath)
    print_message(f"{GRAY}[{ts()}]{RESET} {YELLOW}Hashing & preparing '{filename}'...{RESET}")
    
    filehash, filesize = compute_file_sha256(filepath)
    num_chunks = (filesize + CHUNK_SIZE - 1) // CHUNK_SIZE if filesize > 0 else 1
    transfer_id = str(uuid.uuid4())[:8]

    shared_key = None
    is_e2ee = False
    if target_user:
        shared_key = get_e2ee_shared_key(target_user)
        if not shared_key:
            print_message(f"{RED}[Error] Cannot establish E2EE session with '{target_user}'.{RESET}")
            return
        is_e2ee = True

    # 1. Send FILE_START packet
    start_packet = {
        "type": "PFILE_START" if is_e2ee else "FILE_START",
        "transfer_id": transfer_id,
        "filename": filename,
        "filesize": filesize,
        "filehash": filehash,
        "num_chunks": num_chunks,
        "target": target_user,
        "room": current_room,
        "is_e2ee": is_e2ee
    }
    send_json_packet(sock, start_packet, aes_cipher)

    dest_str = f"{MAGENTA}[E2EE Direct to @{target_user}]{RESET}" if is_e2ee else f"{CYAN}[Room {current_room}]{RESET}"
    print_message(f"{GRAY}[{ts()}]{RESET} {GREEN}Uploading '{filename}' ({format_size(filesize)}) {dest_str}...{RESET}")

    # 2. Stream Chunks directly from disk
    sent_bytes = 0
    start_time = time.time()
    with open(filepath, "rb") as f:
        for idx in range(num_chunks):
            chunk = f.read(CHUNK_SIZE)
            if not chunk:
                break
            
            # Encrypt chunk if E2EE
            if is_e2ee and shared_key:
                chunk_payload = e2ee_encrypt_bytes(shared_key, chunk)
            else:
                chunk_payload = chunk

            chunk_b64 = base64.b64encode(chunk_payload).decode("ascii")
            chunk_packet = {
                "type": "FILE_CHUNK",
                "transfer_id": transfer_id,
                "chunk_idx": idx,
                "total_chunks": num_chunks,
                "data": chunk_b64,
                "target": target_user,
                "room": current_room
            }
            send_json_packet(sock, chunk_packet, aes_cipher)
            sent_bytes += len(chunk)

            # Live speed calculation
            elapsed = max(0.001, time.time() - start_time)
            speed = sent_bytes / elapsed
            pct = int((sent_bytes / max(1, filesize)) * 100)
            
            with prompt_lock:
                clear_prompt()
                bar_len = 20
                filled = int(bar_len * (sent_bytes / max(1, filesize)))
                bar = "#" * filled + "-" * (bar_len - filled)
                sys.stdout.write(f"\r  Sending [{bar}] {pct}% | {format_size(int(speed))}/s | {sent_bytes}/{filesize} bytes")
                sys.stdout.flush()

    # 3. Send FILE_END packet
    end_packet = {
        "type": "FILE_END",
        "transfer_id": transfer_id,
        "target": target_user,
        "room": current_room
    }
    send_json_packet(sock, end_packet, aes_cipher)
    
    with prompt_lock:
        print()
        print_message(f"{GRAY}[{ts()}]{RESET} {GREEN}[OK] Upload complete:{RESET} '{filename}' ({format_size(filesize)}) in {elapsed:.2f}s")


# ============================================================
# Background Receiver Thread
# ============================================================

def handle_incoming_file_start(packet: Dict[str, Any]):
    transfer_id = packet.get("transfer_id")
    filename = sanitize_filename(packet.get("filename", "file"))
    filesize = int(packet.get("filesize", 0))
    filehash = packet.get("filehash", "")
    sender = packet.get("sender", "Unknown")
    is_e2ee = bool(packet.get("is_e2ee", False))
    sender_pubkey = packet.get("sender_pubkey")

    shared_key = None
    if is_e2ee:
        if sender_pubkey:
            try:
                shared_key = derive_e2ee_shared_key(my_priv_key, sender_pubkey)
            except Exception:
                pass
        if not shared_key:
            shared_key = get_e2ee_shared_key(sender)

    os.makedirs(DOWNLOADS_DIR, exist_ok=True)
    out_filepath = get_unique_filepath(DOWNLOADS_DIR, filename)

    try:
        f_obj = open(out_filepath, "wb")
    except Exception as e:
        print_message(f"{RED}[Error] Failed to open download file '{out_filepath}': {e}{RESET}")
        return

    import hashlib
    hasher = hashlib.sha256()

    with active_downloads_lock:
        active_downloads[transfer_id] = {
            "file_obj": f_obj,
            "filepath": out_filepath,
            "filename": filename,
            "filesize": filesize,
            "expected_hash": filehash,
            "received_bytes": 0,
            "hasher": hasher,
            "start_time": time.time(),
            "sender": sender,
            "is_e2ee": is_e2ee,
            "shared_key": shared_key
        }

    tag = f"{MAGENTA}[E2EE Private File]{RESET}" if is_e2ee else f"{CYAN}[Room File]{RESET}"
    print_message(f"{GRAY}[{ts()}]{RESET} {tag} Receiving '{filename}' ({format_size(filesize)}) from {BOLD}{sender}{RESET}...")


def handle_incoming_file_chunk(packet: Dict[str, Any]):
    transfer_id = packet.get("transfer_id")
    chunk_b64 = packet.get("data", "")
    
    with active_downloads_lock:
        transfer = active_downloads.get(transfer_id)
        if not transfer:
            return

        raw_payload = base64.b64decode(chunk_b64.encode("ascii"))
        if transfer["is_e2ee"] and transfer["shared_key"]:
            chunk = e2ee_decrypt_bytes(transfer["shared_key"], raw_payload)
            if chunk is None:
                print_message(f"{RED}[Error] E2EE Chunk Decryption failed!{RESET}")
                return
        else:
            chunk = raw_payload

        transfer["file_obj"].write(chunk)
        transfer["hasher"].update(chunk)
        transfer["received_bytes"] += len(chunk)

        # Progress update
        rec = transfer["received_bytes"]
        tot = max(1, transfer["filesize"])
        elapsed = max(0.001, time.time() - transfer["start_time"])
        speed = rec / elapsed
        pct = int((rec / tot) * 100)

        with prompt_lock:
            clear_prompt()
            bar_len = 20
            filled = int(bar_len * (rec / tot))
            bar = "#" * filled + "-" * (bar_len - filled)
            sys.stdout.write(f"\r  Downloading '{transfer['filename']}' [{bar}] {pct}% | {format_size(int(speed))}/s")
            sys.stdout.flush()


def handle_incoming_file_end(packet: Dict[str, Any]):
    transfer_id = packet.get("transfer_id")
    with active_downloads_lock:
        transfer = active_downloads.pop(transfer_id, None)
        if not transfer:
            return

        transfer["file_obj"].close()
        actual_hash = transfer["hasher"].hexdigest()
        ok = (actual_hash == transfer["expected_hash"])

        with prompt_lock:
            print()
            if ok:
                print_message(f"{GRAY}[{ts()}]{RESET} {GREEN}[OK] Download complete:{RESET} '{transfer['filepath']}' {GREEN}[SHA-256 Verified]{RESET}")
            else:
                print_message(f"{GRAY}[{ts()}]{RESET} {RED}[FAIL] Download corrupted:{RESET} '{transfer['filepath']}' {RED}[Hash Mismatch]{RESET}")


def receiver_loop():
    global current_room, my_rooms, online_users
    while True:
        packet = recv_json_packet(sock, aes_cipher)
        if packet is None:
            print_message(f"\n{RED}[Disconnected from server - connection lost or key mismatch]{RESET}")
            os._exit(0)

        ptype = packet.get("type")

        if ptype == "ROOM_MSG":
            room = packet.get("room", "#general")
            sender = packet.get("sender")
            content = packet.get("content")
            ptime = packet.get("timestamp", ts())
            print_message(f"{GRAY}[{ptime}]{RESET} {CYAN}[{room}]{RESET} {BOLD}{sender}{RESET}: {content}")

        elif ptype == "PMSG":
            sender = packet.get("sender")
            encrypted_payload = packet.get("content")
            sender_pubkey = packet.get("sender_pubkey")
            ptime = packet.get("timestamp", ts())

            shared_key = None
            if sender_pubkey:
                try:
                    shared_key = derive_e2ee_shared_key(my_priv_key, sender_pubkey)
                except Exception:
                    pass
            if not shared_key:
                shared_key = get_e2ee_shared_key(sender)

            if shared_key:
                plaintext = e2ee_decrypt_payload(shared_key, encrypted_payload)
                if plaintext is not None:
                    print_message(f"{GRAY}[{ptime}]{RESET} {MAGENTA}[E2EE Direct from @{sender}]{RESET} {plaintext}")
                else:
                    print_message(f"{GRAY}[{ptime}]{RESET} {RED}[E2EE Decryption Failed from @{sender}]{RESET}")
            else:
                print_message(f"{GRAY}[{ptime}]{RESET} {YELLOW}[Encrypted PM from @{sender} - Missing Key]{RESET}")

        elif ptype == "HIST":
            room = packet.get("room", "#general")
            sender = packet.get("sender")
            content = packet.get("content")
            ptime = packet.get("timestamp", "")
            print_message(f"{GRAY}[History {ptime}] [{room}] {sender}: {content}{RESET}")

        elif ptype == "SYS":
            content = packet.get("content", "")
            print_message(f"{GRAY}[{ts()}]{RESET} {GREEN}*** {content} ***{RESET}")

        elif ptype == "ERR":
            content = packet.get("content", "")
            print_message(f"{RED}[Error] {content}{RESET}")

        elif ptype == "USERLIST":
            raw_users = packet.get("users", [])
            online_users = {u["username"]: u for u in raw_users}
            # Auto-compute shared keys for peers
            for u in raw_users:
                if u["username"] != my_username and u.get("pubkey"):
                    try:
                        e2ee_keys_cache[u["username"]] = derive_e2ee_shared_key(my_priv_key, u["pubkey"])
                    except Exception:
                        pass

        elif ptype == "TYPING":
            sender = packet.get("sender")
            room = packet.get("room")
            is_typing = packet.get("is_typing", False)
            if is_typing:
                print_message(f"{DIM}{GRAY}* {sender} is typing...{RESET}")

        elif ptype == "ROOM_JOINED":
            joined_room = packet.get("room")
            current_room = joined_room
            my_rooms.add(joined_room)
            print_message(f"{GREEN}Switched to room {BOLD}{current_room}{RESET}")

        elif ptype == "FILE_START" or ptype == "PFILE_START":
            handle_incoming_file_start(packet)

        elif ptype == "FILE_CHUNK":
            handle_incoming_file_chunk(packet)

        elif ptype == "FILE_END":
            handle_incoming_file_end(packet)

        elif ptype == "PING":
            send_json_packet(sock, {"type": "PONG"}, aes_cipher)


# ============================================================
# Help & Interactive Commands
# ============================================================

def print_help():
    help_text = f"""
{BOLD}{CYAN}=== COMMAND REFERENCE ==={RESET}
  {BOLD}<text>{RESET}                     Send message to active room ({CYAN}{current_room}{RESET})
  {BOLD}/msg <user> <text>{RESET}         Send Zero-Knowledge E2EE private message to @user
  {BOLD}/file <path>{RESET}               Stream file upload to current room
  {BOLD}/fileto <user> <path>{RESET}      Send Zero-Knowledge E2EE private file to @user
  {BOLD}/join <#room>{RESET}             Join or switch to a chat room (#general, #dev, #random, etc.)
  {BOLD}/leave <#room>{RESET}            Leave a chat room
  {BOLD}/rooms{RESET}                    List active joined rooms
  {BOLD}/status <online|away|busy>{RESET} Change your presence status
  {BOLD}/list or /users{RESET}           View online users, statuses, and E2EE lock status
  {BOLD}/whoami{RESET}                   Show your username, public key fingerprint & active room
  {BOLD}/clear{RESET}                    Clear terminal screen
  {BOLD}/help{RESET}                     Show this command list
  {BOLD}/quit{RESET}                     Disconnect and exit
"""
    print_message(help_text)


def print_users():
    lines = [f"\n{BOLD}Online Users ({len(online_users)}):{RESET}"]
    for name, data in online_users.items():
        st = data.get("status", "online")
        st_color = GREEN if st == "online" else (YELLOW if st == "away" else RED)
        e2ee_badge = f"{GREEN}[E2EE Ready]{RESET}" if name in e2ee_keys_cache or name == my_username else f"{GRAY}[Standard]{RESET}"
        you_badge = f" {CYAN}(You){RESET}" if name == my_username else ""
        rooms_str = ", ".join(data.get("rooms", []))
        lines.append(f"  * {st_color}[{st[0].upper()}]{RESET} {BOLD}{name}{RESET}{you_badge} - {st_color}{st}{RESET} {e2ee_badge} (in {rooms_str})")
    print_message("\n".join(lines) + "\n")


# ============================================================
# Main Entry Point
# ============================================================

def main():
    global sock, aes_cipher, my_username, current_room, input_buffer

    passphrase = os.environ.get("LANCHAT_KEY", DEFAULT_PASSPHRASE)
    aes_key = derive_transport_key(passphrase)
    aes_cipher = AESGCM(aes_key)

    print("=" * 65)
    print("      SECURE LAN CHAT & FILE TRANSFER - CLIENT v4")
    print("=" * 65)

    if len(sys.argv) >= 3:
        server_ip = sys.argv[1]
        server_port = int(sys.argv[2])
    else:
        print("[*] Searching for server via UDP LAN discovery...")
        result = discover_server()
        if result is None:
            print(f"{YELLOW}[!] No server detected via auto-discovery.{RESET}")
            server_ip = input("Enter server IP (default 127.0.0.1): ").strip() or "127.0.0.1"
            server_port = int(input("Enter server TCP port (default 5050): ").strip() or "5050")
        else:
            server_ip, server_port = result
            print(f"{GREEN}[OK] Discovered server at {server_ip}:{server_port}{RESET}")

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.connect((server_ip, server_port))
    except Exception as e:
        print(f"{RED}[Error] Could not connect to {server_ip}:{server_port} - {e}{RESET}")
        sys.exit(1)

    while not my_username:
        my_username = input("Choose a username: ").strip()

    # Handshake with X25519 ECDH public key
    join_packet = {
        "type": "JOIN",
        "username": my_username,
        "pubkey": my_pubkey_hex
    }
    send_json_packet(sock, join_packet, aes_cipher)

    # Start background receiver
    threading.Thread(target=receiver_loop, daemon=True).start()

    time.sleep(0.3)
    print_help()
    render_prompt()

    try:
        while True:
            line = sys.stdin.readline()
            if not line:
                break
            text = line.rstrip("\r\n").strip()
            input_buffer = ""

            if not text:
                render_prompt()
                continue

            if text == "/quit":
                break

            elif text == "/help":
                print_help()

            elif text == "/clear":
                os.system("cls" if os.name == "nt" else "clear")
                render_prompt()

            elif text in ("/list", "/users"):
                print_users()

            elif text == "/rooms":
                print_message(f"Active rooms: {', '.join(sorted(my_rooms))} (Current: {BOLD}{current_room}{RESET})")

            elif text == "/whoami":
                fp = my_pubkey_hex[:16] + "..."
                print_message(f"User: {BOLD}{my_username}{RESET} | Current Room: {CYAN}{current_room}{RESET} | E2EE Key: {fp}")

            elif text.startswith("/status "):
                st = text.split(" ", 1)[1].strip().lower()
                if st in ("online", "away", "busy"):
                    send_json_packet(sock, {"type": "STATUS", "status": st}, aes_cipher)
                    print_message(f"Status set to {BOLD}{st}{RESET}")
                else:
                    print_message(f"{YELLOW}Usage: /status <online|away|busy>{RESET}")

            elif text.startswith("/join "):
                r = text.split(" ", 1)[1].strip()
                if not r.startswith("#"):
                    r = "#" + r
                send_json_packet(sock, {"type": "ROOM_JOIN", "room": r}, aes_cipher)

            elif text.startswith("/leave "):
                r = text.split(" ", 1)[1].strip()
                if not r.startswith("#"):
                    r = "#" + r
                if r == "#general":
                    print_message(f"{YELLOW}Cannot leave #general room.{RESET}")
                else:
                    send_json_packet(sock, {"type": "ROOM_LEAVE", "room": r}, aes_cipher)
                    my_rooms.discard(r)
                    if current_room == r:
                        current_room = "#general"
                    print_message(f"Left {r}, switched to {current_room}")

            elif text.startswith("/msg "):
                try:
                    _, target, msg = text.split(" ", 2)
                except ValueError:
                    print_message(f"{YELLOW}Usage: /msg <username> <message>{RESET}")
                    continue

                shared_key = get_e2ee_shared_key(target)
                if not shared_key:
                    print_message(f"{RED}[Error] User '{target}' not found or has no E2EE public key.{RESET}")
                    continue

                enc_content = e2ee_encrypt_payload(shared_key, msg)
                pmsg_packet = {
                    "type": "PMSG",
                    "target": target,
                    "content": enc_content
                }
                send_json_packet(sock, pmsg_packet, aes_cipher)
                print_message(f"{GRAY}[{ts()}]{RESET} {MAGENTA}[E2EE Direct to @{target}]{RESET} {msg}")

            elif text.startswith("/fileto "):
                try:
                    _, target, path = text.split(" ", 2)
                except ValueError:
                    print_message(f"{YELLOW}Usage: /fileto <username> <filepath>{RESET}")
                    continue
                threading.Thread(target=send_file_stream, args=(path, target), daemon=True).start()

            elif text.startswith("/file "):
                path = text[6:].strip()
                threading.Thread(target=send_file_stream, args=(path, None), daemon=True).start()

            else:
                # Regular room message
                msg_packet = {
                    "type": "ROOM_MSG",
                    "room": current_room,
                    "content": text
                }
                send_json_packet(sock, msg_packet, aes_cipher)
                print_message(f"{GRAY}[{ts()}]{RESET} {CYAN}[{current_room}]{RESET} {BOLD}{my_username}{RESET}: {text}")

            render_prompt()

    except KeyboardInterrupt:
        print("\nExiting...")
    finally:
        if sock:
            try:
                sock.close()
            except OSError:
                pass


if __name__ == "__main__":
    main()
