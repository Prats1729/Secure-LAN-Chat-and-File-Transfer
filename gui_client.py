#!/usr/bin/env python3
"""
Secure LAN Chat & File Transfer - MODERN DESKTOP GUI CLIENT (v4)
Built with Tkinter (zero external GUI dependencies).
Features:
- Dark Modern Glassmorphic Theme
- UDP Auto-Discovery & Manual Connection Modal
- Multi-Room Channels (#general, #dev, #random, +Custom Room)
- Tabbed Direct Messages (DMs) with Zero-Knowledge E2EE Indicators
- Live User Presence Sidebar (🟢 Online, 🟡 Away, 🔴 Busy)
- Disk-to-Disk Streaming File Transfer with Progress Bars & Speedometers
- Real-time Typing Indicators
- Downloads Folder Quick-Access
"""

import socket
import threading
import sys
import os
import time
import base64
import uuid
import datetime
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from typing import Dict, Optional, Any

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

DEFAULT_PASSPHRASE = "SecureLANChat2026"
DEFAULT_UDP_PORT = 5051
DOWNLOADS_DIR = "downloads"
UDP_DISCOVER_MSG = b"LANCHAT_DISCOVER"

# Theme Colors
BG_DARK = "#12141a"
BG_SIDEBAR = "#181b23"
BG_CHAT = "#1f232d"
BG_INPUT = "#292e3b"
ACCENT_BLUE = "#3b82f6"
ACCENT_GREEN = "#10b981"
ACCENT_MAGENTA = "#ec4899"
ACCENT_YELLOW = "#f59e0b"
ACCENT_RED = "#ef4444"
TEXT_WHITE = "#f3f4f6"
TEXT_MUTED = "#9ca3af"


class SecureChatGUI(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Secure LAN Chat & File Transfer - E2EE v4")
        self.geometry("1020x680")
        self.minsize(800, 500)
        self.configure(bg=BG_DARK)

        # Network & Crypto State
        self.sock: Optional[socket.socket] = None
        self.aes_cipher: Optional[AESGCM] = None
        self.my_priv_key, self.my_pubkey_hex = generate_ecdh_keypair()
        self.my_username = ""
        self.current_target = "#general"  # Either "#room" or "@username"
        self.joined_rooms = {"#general", "#dev", "#random"}
        self.online_users: Dict[str, Dict[str, Any]] = {}
        self.e2ee_keys_cache: Dict[str, bytes] = {}

        # Transfer & State Management
        self.active_downloads: Dict[str, Dict[str, Any]] = {}
        self.active_transfers_lock = threading.Lock()
        self.typing_timer = None
        self.is_typing = False

        self._setup_styles()
        self._build_login_ui()

    def _setup_styles(self):
        style = ttk.Style(self)
        style.theme_use("clam")
        style.configure(".", background=BG_DARK, foreground=TEXT_WHITE, font=("Segoe UI", 10))
        style.configure("TFrame", background=BG_DARK)
        style.configure("Sidebar.TFrame", background=BG_SIDEBAR)
        style.configure("Chat.TFrame", background=BG_CHAT)
        style.configure("Accent.TButton", background=ACCENT_BLUE, foreground=TEXT_WHITE, font=("Segoe UI", 10, "bold"), borderwidth=0)
        style.map("Accent.TButton", background=[("active", "#2563eb")])
        style.configure("Green.TButton", background=ACCENT_GREEN, foreground=TEXT_WHITE, font=("Segoe UI", 10, "bold"), borderwidth=0)
        style.map("Green.TButton", background=[("active", "#059669")])

    # ============================================================
    # Login & Connection Screen
    # ============================================================

    def _build_login_ui(self):
        self.login_frame = tk.Frame(self, bg=BG_DARK)
        self.login_frame.place(relx=0.5, rely=0.5, anchor="center")

        card = tk.Frame(self.login_frame, bg=BG_SIDEBAR, padx=35, pady=30, highlightbackground=ACCENT_BLUE, highlightthickness=1)
        card.pack()

        tk.Label(card, text="🛡️ SECURE LAN CHAT", font=("Segoe UI", 18, "bold"), bg=BG_SIDEBAR, fg=ACCENT_BLUE).pack(pady=(0, 5))
        tk.Label(card, text="AES-256-GCM + X25519 Zero-Knowledge E2EE", font=("Segoe UI", 9), bg=BG_SIDEBAR, fg=TEXT_MUTED).pack(pady=(0, 20))

        # Username Input
        tk.Label(card, text="Your Username:", font=("Segoe UI", 10, "bold"), bg=BG_SIDEBAR, fg=TEXT_WHITE).pack(anchor="w")
        self.entry_user = tk.Entry(card, bg=BG_INPUT, fg=TEXT_WHITE, insertbackground=TEXT_WHITE, font=("Segoe UI", 11), relief="flat")
        self.entry_user.pack(fill="x", pady=(3, 12), ipady=4)
        self.entry_user.focus_set()

        # Server IP
        tk.Label(card, text="Server IP:", font=("Segoe UI", 10), bg=BG_SIDEBAR, fg=TEXT_WHITE).pack(anchor="w")
        self.entry_ip = tk.Entry(card, bg=BG_INPUT, fg=TEXT_WHITE, insertbackground=TEXT_WHITE, font=("Segoe UI", 11), relief="flat")
        self.entry_ip.insert(0, "127.0.0.1")
        self.entry_ip.pack(fill="x", pady=(3, 12), ipady=4)

        # Port & Key row
        row = tk.Frame(card, bg=BG_SIDEBAR)
        row.pack(fill="x", pady=(0, 15))

        f_port = tk.Frame(row, bg=BG_SIDEBAR)
        f_port.pack(side="left", fill="x", expand=True, padx=(0, 5))
        tk.Label(f_port, text="TCP Port:", font=("Segoe UI", 10), bg=BG_SIDEBAR, fg=TEXT_WHITE).pack(anchor="w")
        self.entry_port = tk.Entry(f_port, bg=BG_INPUT, fg=TEXT_WHITE, insertbackground=TEXT_WHITE, font=("Segoe UI", 11), relief="flat")
        self.entry_port.insert(0, "5050")
        self.entry_port.pack(fill="x", pady=(3, 0), ipady=4)

        f_pass = tk.Frame(row, bg=BG_SIDEBAR)
        f_pass.pack(side="left", fill="x", expand=True, padx=(5, 0))
        tk.Label(f_pass, text="Secret Passphrase:", font=("Segoe UI", 10), bg=BG_SIDEBAR, fg=TEXT_WHITE).pack(anchor="w")
        self.entry_pass = tk.Entry(f_pass, bg=BG_INPUT, fg=TEXT_WHITE, insertbackground=TEXT_WHITE, font=("Segoe UI", 11), relief="flat", show="*")
        self.entry_pass.insert(0, DEFAULT_PASSPHRASE)
        self.entry_pass.pack(fill="x", pady=(3, 0), ipady=4)

        # Buttons
        btn_row = tk.Frame(card, bg=BG_SIDEBAR)
        btn_row.pack(fill="x", pady=(10, 0))

        btn_discover = tk.Button(btn_row, text="🔍 Auto-Discover", bg=BG_INPUT, fg=TEXT_WHITE, font=("Segoe UI", 10), relief="flat", command=self._do_auto_discover)
        btn_discover.pack(side="left", expand=True, fill="x", padx=(0, 5), ipady=6)

        btn_connect = tk.Button(btn_row, text="Connect ➜", bg=ACCENT_BLUE, fg=TEXT_WHITE, font=("Segoe UI", 10, "bold"), relief="flat", command=self._do_connect)
        btn_connect.pack(side="right", expand=True, fill="x", padx=(5, 0), ipady=6)

        self.bind("<Return>", lambda e: self._do_connect())

    def _do_auto_discover(self):
        udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        udp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        udp_sock.settimeout(2.5)
        try:
            udp_sock.sendto(UDP_DISCOVER_MSG, ("255.255.255.255", DEFAULT_UDP_PORT))
            data, addr = udp_sock.recvfrom(1024)
            text = data.decode("utf-8", errors="replace")
            if text.startswith("LANCHAT_SERVER:"):
                tcp_port = text.split(":")[1]
                self.entry_ip.delete(0, tk.END)
                self.entry_ip.insert(0, addr[0])
                self.entry_port.delete(0, tk.END)
                self.entry_port.insert(0, tcp_port)
                messagebox.showinfo("Server Discovered", f"Found server at {addr[0]}:{tcp_port}!")
        except Exception:
            messagebox.showwarning("Discovery", "No server responded on LAN. Enter IP manually.")
        finally:
            udp_sock.close()

    def _do_connect(self):
        username = self.entry_user.get().strip()
        server_ip = self.entry_ip.get().strip()
        port_str = self.entry_port.get().strip()
        passphrase = self.entry_pass.get().strip() or DEFAULT_PASSPHRASE

        if not username:
            messagebox.showerror("Error", "Please enter a username.")
            return

        try:
            port = int(port_str)
        except ValueError:
            messagebox.showerror("Error", "Invalid port number.")
            return

        aes_key = derive_transport_key(passphrase)
        self.aes_cipher = AESGCM(aes_key)
        self.my_username = username

        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.connect((server_ip, port))
        except Exception as e:
            messagebox.showerror("Connection Failed", f"Could not connect to {server_ip}:{port}\n{e}")
            return

        # Send Handshake packet
        join_packet = {
            "type": "JOIN",
            "username": self.my_username,
            "pubkey": self.my_pubkey_hex
        }
        send_json_packet(self.sock, join_packet, self.aes_cipher)

        self.login_frame.destroy()
        self._build_main_chat_ui()

        threading.Thread(target=self._receiver_thread, daemon=True).start()

    # ============================================================
    # Main Chat Interface
    # ============================================================

    def _build_main_chat_ui(self):
        self.main_container = tk.Frame(self, bg=BG_DARK)
        self.main_container.pack(fill="both", expand=True)

        # 1. Left Sidebar (Rooms, Users, Presence)
        self.sidebar = tk.Frame(self.main_container, bg=BG_SIDEBAR, width=240)
        self.sidebar.pack(side="left", fill="y")
        self.sidebar.pack_propagate(False)

        # Header profile
        profile = tk.Frame(self.sidebar, bg=BG_SIDEBAR, padx=12, pady=12)
        profile.pack(fill="x")
        tk.Label(profile, text=f"👤 {self.my_username}", font=("Segoe UI", 12, "bold"), bg=BG_SIDEBAR, fg=TEXT_WHITE).pack(anchor="w")

        # Presence selector
        self.status_var = tk.StringVar(value="online")
        cb_status = ttk.Combobox(profile, textvariable=self.status_var, values=["online", "away", "busy"], state="readonly", width=12)
        cb_status.pack(anchor="w", pady=(5, 0))
        cb_status.bind("<<ComboboxSelected>>", lambda e: self._change_status())

        # Rooms Header & List
        tk.Label(self.sidebar, text="CHANNELS", font=("Segoe UI", 9, "bold"), bg=BG_SIDEBAR, fg=TEXT_MUTED).pack(anchor="w", padx=12, pady=(12, 4))
        self.room_listbox = tk.Listbox(self.sidebar, bg=BG_SIDEBAR, fg=TEXT_WHITE, selectbackground=ACCENT_BLUE, selectforeground=TEXT_WHITE, bd=0, highlightthickness=0, font=("Segoe UI", 10), height=5)
        self.room_listbox.pack(fill="x", padx=8)
        self.room_listbox.bind("<<ListboxSelect>>", self._on_room_select)
        for r in sorted(self.joined_rooms):
            self.room_listbox.insert(tk.END, r)

        btn_add_room = tk.Button(self.sidebar, text="+ Join Room", bg=BG_INPUT, fg=TEXT_MUTED, font=("Segoe UI", 8), relief="flat", command=self._prompt_join_room)
        btn_add_room.pack(anchor="w", padx=12, pady=(4, 10))

        # Online Users Header & List
        tk.Label(self.sidebar, text="DIRECT MESSAGES (E2EE 🔒)", font=("Segoe UI", 9, "bold"), bg=BG_SIDEBAR, fg=TEXT_MUTED).pack(anchor="w", padx=12, pady=(6, 4))
        self.user_listbox = tk.Listbox(self.sidebar, bg=BG_SIDEBAR, fg=TEXT_WHITE, selectbackground=ACCENT_MAGENTA, selectforeground=TEXT_WHITE, bd=0, highlightthickness=0, font=("Segoe UI", 10))
        self.user_listbox.pack(fill="both", expand=True, padx=8, pady=(0, 8))
        self.user_listbox.bind("<<ListboxSelect>>", self._on_user_select)

        # Downloads folder button
        btn_folder = tk.Button(self.sidebar, text="📁 Open Downloads", bg=BG_INPUT, fg=TEXT_WHITE, font=("Segoe UI", 9), relief="flat", command=self._open_downloads_dir)
        btn_folder.pack(fill="x", padx=10, pady=(0, 10), ipady=4)

        # 2. Right Chat Area
        self.chat_pane = tk.Frame(self.main_container, bg=BG_CHAT)
        self.chat_pane.pack(side="right", fill="both", expand=True)

        # Header Bar
        self.header_bar = tk.Frame(self.chat_pane, bg=BG_SIDEBAR, height=48, padx=15)
        self.header_bar.pack(fill="x")
        self.lbl_target = tk.Label(self.header_bar, text="#general", font=("Segoe UI", 13, "bold"), bg=BG_SIDEBAR, fg=TEXT_WHITE)
        self.lbl_target.pack(side="left", pady=10)
        self.lbl_sec_badge = tk.Label(self.header_bar, text="🛡️ AES-GCM Transport Encrypted", font=("Segoe UI", 9), bg=BG_SIDEBAR, fg=ACCENT_GREEN)
        self.lbl_sec_badge.pack(side="right", pady=10)

        # Messages Display Box
        self.msg_box = tk.Text(self.chat_pane, bg=BG_CHAT, fg=TEXT_WHITE, font=("Segoe UI", 10), bd=0, highlightthickness=0, wrap="word", state="disabled", padx=12, pady=10)
        self.msg_box.pack(fill="both", expand=True)

        # Color Tags for Text Styling
        self.msg_box.tag_configure("time", foreground=TEXT_MUTED, font=("Segoe UI", 8))
        self.msg_box.tag_configure("user", foreground=ACCENT_BLUE, font=("Segoe UI", 10, "bold"))
        self.msg_box.tag_configure("e2ee_user", foreground=ACCENT_MAGENTA, font=("Segoe UI", 10, "bold"))
        self.msg_box.tag_configure("sys", foreground=ACCENT_GREEN, font=("Segoe UI", 9, "italic"))
        self.msg_box.tag_configure("err", foreground=ACCENT_RED, font=("Segoe UI", 9, "bold"))
        self.msg_box.tag_configure("hist", foreground=TEXT_MUTED)
        self.msg_box.tag_configure("file", foreground=ACCENT_YELLOW, font=("Segoe UI", 9, "bold"))

        # Live Typing & Transfer Status Bar
        self.lbl_typing = tk.Label(self.chat_pane, text="", font=("Segoe UI", 8, "italic"), bg=BG_CHAT, fg=TEXT_MUTED, anchor="w", padx=15)
        self.lbl_typing.pack(fill="x")

        self.transfer_progress = ttk.Progressbar(self.chat_pane, orient="horizontal", mode="determinate")
        # Hidden initially

        # Input Bar
        input_frame = tk.Frame(self.chat_pane, bg=BG_SIDEBAR, padx=10, pady=10)
        input_frame.pack(fill="x")

        btn_file = tk.Button(input_frame, text="📎 Send File", bg=BG_INPUT, fg=TEXT_WHITE, font=("Segoe UI", 10), relief="flat", command=self._pick_and_send_file)
        btn_file.pack(side="left", padx=(0, 8), ipady=4)

        self.txt_input = tk.Entry(input_frame, bg=BG_INPUT, fg=TEXT_WHITE, insertbackground=TEXT_WHITE, font=("Segoe UI", 11), relief="flat")
        self.txt_input.pack(side="left", fill="x", expand=True, ipady=6, padx=(0, 8))
        self.txt_input.bind("<Return>", lambda e: self._send_message())
        self.txt_input.bind("<Key>", self._on_typing)
        self.txt_input.focus_set()

        btn_send = tk.Button(input_frame, text="Send 🚀", bg=ACCENT_BLUE, fg=TEXT_WHITE, font=("Segoe UI", 10, "bold"), relief="flat", command=self._send_message)
        btn_send.pack(side="right", ipady=4, padx=(0, 4))

    # ============================================================
    # UI Event Handlers & Chat Logic
    # ============================================================

    def _append_log(self, text: str, tag: str = "", timestamp: str = ""):
        self.msg_box.configure(state="normal")
        ts_str = timestamp or datetime.datetime.now().strftime("%H:%M:%S")
        self.msg_box.insert(tk.END, f"[{ts_str}] ", "time")
        self.msg_box.insert(tk.END, f"{text}\n", tag)
        self.msg_box.see(tk.END)
        self.msg_box.configure(state="disabled")

    def _on_room_select(self, event):
        sel = self.room_listbox.curselection()
        if sel:
            room = self.room_listbox.get(sel[0])
            self.current_target = room
            self.lbl_target.config(text=room, fg=TEXT_WHITE)
            self.lbl_sec_badge.config(text="🛡️ AES-GCM Transport Encrypted", fg=ACCENT_GREEN)
            self.user_listbox.selection_clear(0, tk.END)

    def _on_user_select(self, event):
        sel = self.user_listbox.curselection()
        if sel:
            raw_text = self.user_listbox.get(sel[0])
            user = raw_text.split(" ")[1]
            self.current_target = f"@{user}"
            self.lbl_target.config(text=f"Direct: @{user}", fg=ACCENT_MAGENTA)
            self.lbl_sec_badge.config(text="🔒 Zero-Knowledge E2EE (X25519 ECDH)", fg=ACCENT_MAGENTA)
            self.room_listbox.selection_clear(0, tk.END)

    def _prompt_join_room(self):
        top = tk.Toplevel(self)
        top.title("Join Channel")
        top.geometry("300x120")
        top.configure(bg=BG_SIDEBAR)
        tk.Label(top, text="Room Name (e.g. #gaming):", bg=BG_SIDEBAR, fg=TEXT_WHITE).pack(pady=10)
        e = tk.Entry(top, bg=BG_INPUT, fg=TEXT_WHITE)
        e.pack(pady=5)
        e.focus_set()

        def submit():
            r = e.get().strip()
            if r:
                if not r.startswith("#"):
                    r = "#" + r
                send_json_packet(self.sock, {"type": "ROOM_JOIN", "room": r}, self.aes_cipher)
                self.joined_rooms.add(r)
                self.room_listbox.delete(0, tk.END)
                for room in sorted(self.joined_rooms):
                    self.room_listbox.insert(tk.END, room)
            top.destroy()

        tk.Button(top, text="Join", bg=ACCENT_BLUE, fg=TEXT_WHITE, command=submit).pack(pady=5)

    def _change_status(self):
        st = self.status_var.get()
        send_json_packet(self.sock, {"type": "STATUS", "status": st}, self.aes_cipher)

    def _on_typing(self, event):
        if not self.is_typing:
            self.is_typing = True
            packet = {
                "type": "TYPING",
                "room": self.current_target if self.current_target.startswith("#") else None,
                "target": self.current_target[1:] if self.current_target.startswith("@") else None,
                "is_typing": True
            }
            send_json_packet(self.sock, packet, self.aes_cipher)

        if self.typing_timer:
            self.after_cancel(self.typing_timer)
        self.typing_timer = self.after(2000, self._stop_typing)

    def _stop_typing(self):
        self.is_typing = False
        packet = {
            "type": "TYPING",
            "room": self.current_target if self.current_target.startswith("#") else None,
            "target": self.current_target[1:] if self.current_target.startswith("@") else None,
            "is_typing": False
        }
        send_json_packet(self.sock, packet, self.aes_cipher)

    def _open_downloads_dir(self):
        os.makedirs(DOWNLOADS_DIR, exist_ok=True)
        if os.name == 'nt':
            os.startfile(os.path.abspath(DOWNLOADS_DIR))
        else:
            os.system(f"xdg-open '{os.path.abspath(DOWNLOADS_DIR)}'")

    def _get_e2ee_key(self, target_user: str) -> Optional[bytes]:
        if target_user in self.e2ee_keys_cache:
            return self.e2ee_keys_cache[target_user]
        user_info = self.online_users.get(target_user)
        if user_info and user_info.get("pubkey"):
            try:
                shared = derive_e2ee_shared_key(self.my_priv_key, user_info["pubkey"])
                self.e2ee_keys_cache[target_user] = shared
                return shared
            except Exception:
                return None
        return None

    # ============================================================
    # Messaging & File Transfer
    # ============================================================

    def _send_message(self):
        text = self.txt_input.get().strip()
        if not text:
            return
        self.txt_input.delete(0, tk.END)
        self._stop_typing()

        if self.current_target.startswith("@"):
            # Direct Message (E2EE)
            target = self.current_target[1:]
            shared_key = self._get_e2ee_key(target)
            if not shared_key:
                messagebox.showerror("E2EE Error", f"Cannot establish E2EE session with @{target}")
                return
            enc_payload = e2ee_encrypt_payload(shared_key, text)
            packet = {
                "type": "PMSG",
                "target": target,
                "content": enc_payload
            }
            send_json_packet(self.sock, packet, self.aes_cipher)
            self._append_log(f"🔒 [E2EE to @{target}] {self.my_username}: {text}", "e2ee_user")
        else:
            # Room Message
            packet = {
                "type": "ROOM_MSG",
                "room": self.current_target,
                "content": text
            }
            send_json_packet(self.sock, packet, self.aes_cipher)
            self._append_log(f"[{self.current_target}] {self.my_username}: {text}", "user")

    def _pick_and_send_file(self):
        filepath = filedialog.askopenfilename(title="Select File to Send")
        if not filepath:
            return
        threading.Thread(target=self._send_file_worker, args=(filepath,), daemon=True).start()

    def _send_file_worker(self, filepath: str):
        filename = os.path.basename(filepath)
        filehash, filesize = compute_file_sha256(filepath)
        num_chunks = (filesize + CHUNK_SIZE - 1) // CHUNK_SIZE if filesize > 0 else 1
        transfer_id = str(uuid.uuid4())[:8]

        is_e2ee = self.current_target.startswith("@")
        target_user = self.current_target[1:] if is_e2ee else None
        shared_key = self._get_e2ee_key(target_user) if is_e2ee else None

        self.after(0, lambda: self.transfer_progress.pack(fill="x", padx=10, pady=2))

        start_packet = {
            "type": "PFILE_START" if is_e2ee else "FILE_START",
            "transfer_id": transfer_id,
            "filename": filename,
            "filesize": filesize,
            "filehash": filehash,
            "num_chunks": num_chunks,
            "target": target_user,
            "room": self.current_target,
            "is_e2ee": is_e2ee
        }
        send_json_packet(self.sock, start_packet, self.aes_cipher)
        self.after(0, lambda: self._append_log(f"Uploading '{filename}' ({filesize:,} bytes)...", "file"))

        sent_bytes = 0
        with open(filepath, "rb") as f:
            for idx in range(num_chunks):
                chunk = f.read(CHUNK_SIZE)
                if not chunk:
                    break
                chunk_payload = e2ee_encrypt_bytes(shared_key, chunk) if is_e2ee and shared_key else chunk
                chunk_b64 = base64.b64encode(chunk_payload).decode("ascii")

                send_json_packet(self.sock, {
                    "type": "FILE_CHUNK",
                    "transfer_id": transfer_id,
                    "chunk_idx": idx,
                    "total_chunks": num_chunks,
                    "data": chunk_b64,
                    "target": target_user,
                    "room": self.current_target
                }, self.aes_cipher)

                sent_bytes += len(chunk)
                pct = int((sent_bytes / max(1, filesize)) * 100)
                self.after(0, lambda p=pct: self.transfer_progress.configure(value=p))

        send_json_packet(self.sock, {
            "type": "FILE_END",
            "transfer_id": transfer_id,
            "target": target_user,
            "room": self.current_target
        }, self.aes_cipher)

        self.after(0, lambda: self.transfer_progress.pack_forget())
        self.after(0, lambda: self._append_log(f"✓ Upload Complete: '{filename}'", "file"))

    # ============================================================
    # Background Receiver Thread
    # ============================================================

    def _receiver_thread(self):
        while True:
            packet = recv_json_packet(self.sock, self.aes_cipher)
            if packet is None:
                self.after(0, lambda: messagebox.showerror("Disconnected", "Server connection closed."))
                break

            ptype = packet.get("type")

            if ptype == "ROOM_MSG":
                room = packet.get("room")
                sender = packet.get("sender")
                content = packet.get("content")
                ts = packet.get("timestamp")
                self.after(0, lambda r=room, s=sender, c=content, t=ts: self._append_log(f"[{r}] {s}: {c}", "user", t))

            elif ptype == "PMSG":
                sender = packet.get("sender")
                enc_payload = packet.get("content")
                ts = packet.get("timestamp")
                shared_key = self._get_e2ee_key(sender)
                if shared_key:
                    pt = e2ee_decrypt_payload(shared_key, enc_payload)
                    msg_text = pt or "[Decryption Error]"
                else:
                    msg_text = "[Encrypted Message - Missing Key]"
                self.after(0, lambda s=sender, m=msg_text, t=ts: self._append_log(f"🔒 [E2EE from @{s}] {s}: {m}", "e2ee_user", t))
                self.bell()

            elif ptype == "HIST":
                room = packet.get("room")
                sender = packet.get("sender")
                content = packet.get("content")
                ts = packet.get("timestamp")
                self.after(0, lambda r=room, s=sender, c=content, t=ts: self._append_log(f"[History {t}] [{r}] {s}: {c}", "hist"))

            elif ptype == "SYS":
                content = packet.get("content")
                self.after(0, lambda c=content: self._append_log(f"*** {c} ***", "sys"))

            elif ptype == "ERR":
                content = packet.get("content")
                self.after(0, lambda c=content: self._append_log(f"[Error] {c}", "err"))

            elif ptype == "USERLIST":
                users = packet.get("users", [])
                self.after(0, lambda u=users: self._update_userlist(u))

            elif ptype == "TYPING":
                sender = packet.get("sender")
                is_typing = packet.get("is_typing", False)
                text = f"✍️ {sender} is typing..." if is_typing else ""
                self.after(0, lambda t=text: self.lbl_typing.config(text=t))

            elif ptype in ("FILE_START", "PFILE_START"):
                self._handle_file_start(packet)

            elif ptype == "FILE_CHUNK":
                self._handle_file_chunk(packet)

            elif ptype == "FILE_END":
                self._handle_file_end(packet)

    def _update_userlist(self, raw_users):
        self.online_users = {u["username"]: u for u in raw_users}
        self.user_listbox.delete(0, tk.END)
        for u in raw_users:
            if u["username"] == self.my_username:
                continue
            st = u.get("status", "online")
            dot = "🟢" if st == "online" else ("🟡" if st == "away" else "🔴")
            self.user_listbox.insert(tk.END, f"{dot} {u['username']}")

    def _handle_file_start(self, packet):
        tid = packet.get("transfer_id")
        filename = sanitize_filename(packet.get("filename", "file"))
        filesize = int(packet.get("filesize", 0))
        sender = packet.get("sender", "Unknown")
        is_e2ee = bool(packet.get("is_e2ee", False))

        shared_key = self._get_e2ee_key(sender) if is_e2ee else None
        os.makedirs(DOWNLOADS_DIR, exist_ok=True)
        outpath = get_unique_filepath(DOWNLOADS_DIR, filename)
        f_obj = open(outpath, "wb")

        import hashlib
        hasher = hashlib.sha256()

        with self.active_transfers_lock:
            self.active_downloads[tid] = {
                "f_obj": f_obj,
                "outpath": outpath,
                "filename": filename,
                "filesize": filesize,
                "expected_hash": packet.get("filehash", ""),
                "hasher": hasher,
                "received": 0,
                "is_e2ee": is_e2ee,
                "shared_key": shared_key
            }

        self.after(0, lambda: self._append_log(f"Receiving '{filename}' ({filesize:,} bytes) from {sender}...", "file"))
        self.after(0, lambda: self.transfer_progress.pack(fill="x", padx=10, pady=2))

    def _handle_file_chunk(self, packet):
        tid = packet.get("transfer_id")
        chunk_b64 = packet.get("data", "")
        with self.active_transfers_lock:
            tr = self.active_downloads.get(tid)
            if not tr:
                return
            raw = base64.b64decode(chunk_b64.encode("ascii"))
            chunk = e2ee_decrypt_bytes(tr["shared_key"], raw) if tr["is_e2ee"] and tr["shared_key"] else raw
            tr["f_obj"].write(chunk)
            tr["hasher"].update(chunk)
            tr["received"] += len(chunk)
            pct = int((tr["received"] / max(1, tr["filesize"])) * 100)
            self.after(0, lambda p=pct: self.transfer_progress.configure(value=p))

    def _handle_file_end(self, packet):
        tid = packet.get("transfer_id")
        with self.active_transfers_lock:
            tr = self.active_downloads.pop(tid, None)
            if not tr:
                return
            tr["f_obj"].close()
            ok = tr["hasher"].hexdigest() == tr["expected_hash"]
            msg = f"✓ Downloaded: '{tr['filename']}' (Verified)" if ok else f"✗ File Corrupted: '{tr['filename']}'"
            self.after(0, lambda: self._append_log(msg, "file"))
            self.after(0, lambda: self.transfer_progress.pack_forget())


if __name__ == "__main__":
    app = SecureChatGUI()
    app.mainloop()
