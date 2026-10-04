#!/usr/bin/env python3
"""
Secure LAN Chat & File Transfer - ADVANCED DESKTOP GUI CLIENT (v4.5)
Features:
- Dark Modern Theme with Glassmorphic styling
- Multi-Room Channel Tabs & E2EE Direct Messages (DMs) with Isolated Chat History
- Real-time notification banners for incoming private messages and files across tabs
- Persistent file logging to chat_history.txt in project folder
- Live Voice Note Recording & Playback (saved in voice_notes/ and downloads/)
- Live User Presence (🟢 Online, 🟡 Away, 🔴 Busy) & Typing Indicators
- Disk-to-Disk Streaming File Transfer with Speedometers & SHA-256 Verification
- File Transfer Audit & History Manager
- UDP LAN Server Auto-Discovery
"""

import socket
import threading
import sys
import os
import shutil
import time
import base64
import uuid
import datetime
from collections import defaultdict
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from typing import Dict, List, Optional, Any

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
    start_voice_recording,
    stop_voice_recording,
    play_audio_file,
    log_chat_history_to_file,
    CHUNK_SIZE
)

DEFAULT_PASSPHRASE = "SecureLANChat2026"
DEFAULT_UDP_PORT = 5051
DOWNLOADS_DIR = "downloads"
VOICE_DIR = "voice_notes"
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
        self.title("Secure LAN Chat & File Transfer - E2EE v4.5")
        self.geometry("1060x700")
        self.minsize(850, 550)
        self.configure(bg=BG_DARK)

        # Network & Crypto State
        self.sock: Optional[socket.socket] = None
        self.aes_cipher: Optional[AESGCM] = None
        self.send_lock = threading.RLock()
        self.my_priv_key, self.my_pubkey_hex = generate_ecdh_keypair()
        self.my_username = ""
        self.current_target = "#general"  # Either "#room" or "@username"
        self.joined_rooms = {"#general", "#dev", "#random"}
        self.online_users: Dict[str, Dict[str, Any]] = {}
        self.e2ee_keys_cache: Dict[str, bytes] = {}

        # Chat & History State (Isolated per room / DM)
        self.chat_histories = defaultdict(list)  # target -> list of item dicts
        self.unread_counts = defaultdict(int)    # target -> int
        self.file_transfers: List[Dict[str, Any]] = []  # list of transfer records

        # File & Voice State
        self.active_downloads: Dict[str, Dict[str, Any]] = {}
        self.active_transfers_lock = threading.RLock()
        self.is_recording_voice = False
        self.temp_voice_file = ""
        self.voice_record_start_time = 0.0
        self.voice_timer_id = None
        self.typing_timer = None
        self.is_typing = False

        os.makedirs(DOWNLOADS_DIR, exist_ok=True)
        os.makedirs(VOICE_DIR, exist_ok=True)

        self._setup_styles()
        self._build_login_ui()

    def _send_packet(self, packet_dict: Dict[str, Any]) -> bool:
        """Thread-safe socket frame sender."""
        if not self.sock or not self.aes_cipher:
            return False
        try:
            with self.send_lock:
                return send_json_packet(self.sock, packet_dict, self.aes_cipher)
        except Exception:
            return False

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
        style.configure("Red.TButton", background=ACCENT_RED, foreground=TEXT_WHITE, font=("Segoe UI", 10, "bold"), borderwidth=0)
        style.map("Red.TButton", background=[("active", "#dc2626")])

    # ============================================================
    # Login & Connection Screen
    # ============================================================

    def _build_login_ui(self):
        self.login_frame = tk.Frame(self, bg=BG_DARK)
        self.login_frame.place(relx=0.5, rely=0.5, anchor="center")

        card = tk.Frame(self.login_frame, bg=BG_SIDEBAR, padx=35, pady=30, highlightbackground=ACCENT_BLUE, highlightthickness=1)
        card.pack()

        tk.Label(card, text="🛡️ SECURE LAN CHAT", font=("Segoe UI", 18, "bold"), bg=BG_SIDEBAR, fg=ACCENT_BLUE).pack(pady=(0, 5))
        tk.Label(card, text="AES-256-GCM + X25519 E2EE + Voice Notes", font=("Segoe UI", 9), bg=BG_SIDEBAR, fg=TEXT_MUTED).pack(pady=(0, 20))

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
        self._send_packet(join_packet)

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
        self.sidebar = tk.Frame(self.main_container, bg=BG_SIDEBAR, width=250)
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
        self._refresh_sidebar_rooms()

        btn_add_room = tk.Button(self.sidebar, text="+ Join Room", bg=BG_INPUT, fg=TEXT_MUTED, font=("Segoe UI", 8), relief="flat", command=self._prompt_join_room)
        btn_add_room.pack(anchor="w", padx=12, pady=(4, 10))

        # Online Users Header & List
        tk.Label(self.sidebar, text="DIRECT MESSAGES (E2EE 🔒)", font=("Segoe UI", 9, "bold"), bg=BG_SIDEBAR, fg=TEXT_MUTED).pack(anchor="w", padx=12, pady=(6, 4))
        self.user_listbox = tk.Listbox(self.sidebar, bg=BG_SIDEBAR, fg=TEXT_WHITE, selectbackground=ACCENT_MAGENTA, selectforeground=TEXT_WHITE, bd=0, highlightthickness=0, font=("Segoe UI", 10))
        self.user_listbox.pack(fill="both", expand=True, padx=8, pady=(0, 8))
        self.user_listbox.bind("<<ListboxSelect>>", self._on_user_select)

        # Utility Buttons
        btn_box = tk.Frame(self.sidebar, bg=BG_SIDEBAR, padx=8, pady=8)
        btn_box.pack(fill="x")

        btn_history = tk.Button(btn_box, text="📋 Transfer History", bg=BG_INPUT, fg=TEXT_WHITE, font=("Segoe UI", 9), relief="flat", command=self._show_transfer_history)
        btn_history.pack(fill="x", pady=(0, 4), ipady=3)

        btn_folder = tk.Button(btn_box, text="📁 Open Downloads", bg=BG_INPUT, fg=TEXT_WHITE, font=("Segoe UI", 9), relief="flat", command=self._open_downloads_dir)
        btn_folder.pack(fill="x", pady=(0, 4), ipady=3)

        btn_voice_folder = tk.Button(btn_box, text="🎙️ Open Voice Notes", bg=BG_INPUT, fg="#38bdf8", font=("Segoe UI", 9), relief="flat", command=self._open_voice_dir)
        btn_voice_folder.pack(fill="x", ipady=3)

        # 2. Right Chat Area
        self.chat_pane = tk.Frame(self.main_container, bg=BG_CHAT)
        self.chat_pane.pack(side="right", fill="both", expand=True)

        # Header Bar
        self.header_bar = tk.Frame(self.chat_pane, bg=BG_SIDEBAR, height=52, padx=15)
        self.header_bar.pack(fill="x")
        self.lbl_target = tk.Label(self.header_bar, text="#general", font=("Segoe UI", 13, "bold"), bg=BG_SIDEBAR, fg=ACCENT_BLUE)
        self.lbl_target.pack(side="left", pady=12)
        self.lbl_sec_badge = tk.Label(self.header_bar, text="🛡️ AES-GCM Transport Encrypted", font=("Segoe UI", 9), bg=BG_SIDEBAR, fg=ACCENT_GREEN)
        self.lbl_sec_badge.pack(side="right", pady=12)

        # Messages Display Box
        self.msg_box = tk.Text(self.chat_pane, bg=BG_CHAT, fg=TEXT_WHITE, font=("Segoe UI", 10), bd=0, highlightthickness=0, wrap="word", state="disabled", padx=14, pady=10)
        self.msg_box.pack(fill="both", expand=True)

        # Color Tags for Text Styling
        self.msg_box.tag_configure("time", foreground=TEXT_MUTED, font=("Segoe UI", 8))
        self.msg_box.tag_configure("user", foreground=ACCENT_BLUE, font=("Segoe UI", 10, "bold"))
        self.msg_box.tag_configure("e2ee_user", foreground=ACCENT_MAGENTA, font=("Segoe UI", 10, "bold"))
        self.msg_box.tag_configure("dm_alert", foreground="#f43f5e", font=("Segoe UI", 10, "bold"))
        self.msg_box.tag_configure("sys", foreground=ACCENT_GREEN, font=("Segoe UI", 9, "italic"))
        self.msg_box.tag_configure("err", foreground=ACCENT_RED, font=("Segoe UI", 9, "bold"))
        self.msg_box.tag_configure("hist", foreground=TEXT_MUTED)
        self.msg_box.tag_configure("file", foreground=ACCENT_YELLOW, font=("Segoe UI", 9, "bold"))
        self.msg_box.tag_configure("voice", foreground="#38bdf8", font=("Segoe UI", 10, "bold"))

        # Live Typing & Transfer Status Bar
        self.status_bar = tk.Frame(self.chat_pane, bg=BG_CHAT)
        self.status_bar.pack(fill="x")

        self.lbl_typing = tk.Label(self.status_bar, text="", font=("Segoe UI", 8, "italic"), bg=BG_CHAT, fg=TEXT_MUTED, anchor="w", padx=15)
        self.lbl_typing.pack(side="left")

        self.transfer_progress = ttk.Progressbar(self.status_bar, orient="horizontal", mode="determinate")
        # Hidden initially

        # Input Bar
        input_frame = tk.Frame(self.chat_pane, bg=BG_SIDEBAR, padx=10, pady=8)
        input_frame.pack(fill="x")

        btn_file = tk.Button(input_frame, text="📎 File", bg=BG_INPUT, fg=TEXT_WHITE, font=("Segoe UI", 9), relief="flat", command=self._pick_and_send_file)
        btn_file.pack(side="left", padx=(0, 6), ipady=3)

        self.btn_voice = tk.Button(input_frame, text="🎙️ Voice Note", bg=BG_INPUT, fg=TEXT_WHITE, font=("Segoe UI", 9), relief="flat", command=self._toggle_voice_record)
        self.btn_voice.pack(side="left", padx=(0, 6), ipady=3)

        self.txt_input = tk.Entry(input_frame, bg=BG_INPUT, fg=TEXT_WHITE, insertbackground=TEXT_WHITE, font=("Segoe UI", 11), relief="flat")
        self.txt_input.pack(side="left", fill="x", expand=True, ipady=5, padx=(0, 6))
        self.txt_input.bind("<Return>", lambda e: self._send_message())
        self.txt_input.bind("<Key>", self._on_typing)
        self.txt_input.focus_set()

        btn_send = tk.Button(input_frame, text="Send 🚀", bg=ACCENT_BLUE, fg=TEXT_WHITE, font=("Segoe UI", 10, "bold"), relief="flat", command=self._send_message)
        btn_send.pack(side="right", ipady=3, padx=(0, 2))

    # ============================================================
    # Isolated Chat History & Rendering
    # ============================================================

    def _append_to_history(self, target_channel_or_user: str, item: Dict[str, Any]):
        """Save message/event to the specific channel or DM's history log."""
        self.chat_histories[target_channel_or_user].append(item)
        if self.current_target == target_channel_or_user:
            self._render_single_item(item)
        else:
            self.unread_counts[target_channel_or_user] += 1
            self._refresh_sidebar_unread()

    def _render_active_chat(self):
        """Clear and re-render only the messages belonging to the current room/DM."""
        self.msg_box.configure(state="normal")
        self.msg_box.delete("1.0", tk.END)
        items = self.chat_histories.get(self.current_target, [])
        for item in items:
            self._render_single_item(item)
        self.msg_box.configure(state="disabled")
        self.msg_box.see(tk.END)

    def _render_single_item(self, item: Dict[str, Any]):
        self.msg_box.configure(state="normal")
        ts_str = item.get("time") or datetime.datetime.now().strftime("%H:%M:%S")
        self.msg_box.insert(tk.END, f"[{ts_str}] ", "time")
        tag = item.get("tag", "")
        text = item.get("text", "")
        self.msg_box.insert(tk.END, f"{text}\n", tag)

        # Quick Switch DM button if alert in another room
        if item.get("is_dm_switch") and item.get("switch_target"):
            starget = item["switch_target"]
            btn_switch = tk.Button(self.msg_box, text=f"💬 Open {starget} Chat", bg=ACCENT_MAGENTA, fg=TEXT_WHITE, font=("Segoe UI", 8, "bold"), relief="flat", padx=6, pady=2, command=lambda t=starget: self._switch_to_target(t))
            self.msg_box.window_create(tk.END, window=btn_switch)
            self.msg_box.insert(tk.END, "\n\n")

        # Inline interactive voice player button
        if item.get("is_voice") and item.get("voice_path"):
            vpath = item["voice_path"]
            btn_play = tk.Button(self.msg_box, text="▶ Play Voice Note", bg=BG_INPUT, fg="#38bdf8", font=("Segoe UI", 8, "bold"), relief="flat", padx=6, pady=2, command=lambda p=vpath: play_audio_file(p))
            self.msg_box.window_create(tk.END, window=btn_play)
            self.msg_box.insert(tk.END, "\n\n")

        # Inline open file button
        if item.get("is_file") and item.get("file_path"):
            fpath = item["file_path"]
            btn_open = tk.Button(self.msg_box, text="📂 Open File", bg=BG_INPUT, fg=ACCENT_YELLOW, font=("Segoe UI", 8), relief="flat", padx=6, pady=2, command=lambda p=fpath: self._open_file_path(p))
            self.msg_box.window_create(tk.END, window=btn_open)
            self.msg_box.insert(tk.END, "\n\n")

        self.msg_box.see(tk.END)
        self.msg_box.configure(state="disabled")

    def _switch_to_target(self, target_name: str):
        self.current_target = target_name
        self.unread_counts[target_name] = 0
        if target_name.startswith("@"):
            self.lbl_target.config(text=f"Direct: {target_name}", fg=ACCENT_MAGENTA)
            self.lbl_sec_badge.config(text="🔒 Zero-Knowledge E2EE (X25519 ECDH)", fg=ACCENT_MAGENTA)
            self.room_listbox.selection_clear(0, tk.END)
        else:
            self.lbl_target.config(text=target_name, fg=ACCENT_BLUE)
            self.lbl_sec_badge.config(text="🛡️ AES-GCM Transport Encrypted", fg=ACCENT_GREEN)
            self.user_listbox.selection_clear(0, tk.END)
        self._refresh_sidebar_unread()
        self._render_active_chat()

    def _open_file_path(self, filepath: str):
        if os.path.exists(filepath):
            if os.name == 'nt':
                os.startfile(os.path.abspath(filepath))
            else:
                os.system(f"xdg-open '{os.path.abspath(filepath)}'")
        else:
            messagebox.showwarning("File Missing", f"File not found: {filepath}")

    def _refresh_sidebar_rooms(self):
        self.room_listbox.delete(0, tk.END)
        for r in sorted(self.joined_rooms):
            unread = self.unread_counts.get(r, 0)
            badge = f" ({unread})" if unread > 0 else ""
            self.room_listbox.insert(tk.END, f"{r}{badge}")

    def _refresh_sidebar_users(self):
        self.user_listbox.delete(0, tk.END)
        for u in sorted(self.online_users.values(), key=lambda x: x["username"].lower()):
            if u["username"].lower() == self.my_username.lower():
                continue
            name = u["username"]
            st = u.get("status", "online")
            dot = "🟢" if st == "online" else ("🟡" if st == "away" else "🔴")
            target_key = f"@{name}"
            unread = self.unread_counts.get(target_key, 0)
            badge = f" ({unread})" if unread > 0 else ""
            self.user_listbox.insert(tk.END, f"{dot} {name}{badge}")

    def _refresh_sidebar_unread(self):
        self._refresh_sidebar_rooms()
        self._refresh_sidebar_users()

    def _on_room_select(self, event):
        sel = self.room_listbox.curselection()
        if sel:
            raw_text = self.room_listbox.get(sel[0])
            room = raw_text.split(" ")[0].strip()
            self._switch_to_target(room)

    def _on_user_select(self, event):
        sel = self.user_listbox.curselection()
        if sel:
            raw_text = self.user_listbox.get(sel[0])
            user = raw_text.split(" ")[1].strip()
            self._switch_to_target(f"@{user}")

    # ============================================================
    # Voice Note Recording
    # ============================================================

    def _toggle_voice_record(self):
        if not self.is_recording_voice:
            vname = f"voice_sent_{self.my_username}_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.wav"
            self.temp_voice_file = os.path.join(VOICE_DIR, vname)
            if start_voice_recording():
                self.is_recording_voice = True
                self.voice_record_start_time = time.time()
                self.btn_voice.config(text="🔴 Stop & Send", bg=ACCENT_RED, fg=TEXT_WHITE)
                self._update_voice_timer()
            else:
                messagebox.showerror("Audio Error", "Could not start microphone recording.")
        else:
            self.is_recording_voice = False
            if self.voice_timer_id:
                self.after_cancel(self.voice_timer_id)
                self.voice_timer_id = None
            self.btn_voice.config(text="🎙️ Voice Note", bg=BG_INPUT, fg=TEXT_WHITE)
            self.lbl_typing.config(text="")
            
            ok = stop_voice_recording(self.temp_voice_file)
            if ok and os.path.exists(self.temp_voice_file):
                vfile = self.temp_voice_file
                threading.Thread(target=self._send_file_worker, args=(vfile, True), daemon=True).start()
            else:
                messagebox.showwarning("Voice Recording", "No audio recorded.")

    def _update_voice_timer(self):
        if self.is_recording_voice:
            sec = int(time.time() - self.voice_record_start_time)
            self.lbl_typing.config(text=f"🔴 Recording Voice Note ({sec}s)... Click 'Stop & Send' to finish")
            self.voice_timer_id = self.after(1000, self._update_voice_timer)

    # ============================================================
    # Messaging & File Transfer
    # ============================================================

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
                self._send_packet({"type": "ROOM_JOIN", "room": r})
                self.joined_rooms.add(r)
                self._refresh_sidebar_rooms()
            top.destroy()

        tk.Button(top, text="Join", bg=ACCENT_BLUE, fg=TEXT_WHITE, command=submit).pack(pady=5)

    def _change_status(self):
        st = self.status_var.get()
        self._send_packet({"type": "STATUS", "status": st})

    def _on_typing(self, event):
        if not self.is_typing:
            self.is_typing = True
            packet = {
                "type": "TYPING",
                "room": self.current_target if self.current_target.startswith("#") else None,
                "target": self.current_target[1:] if self.current_target.startswith("@") else None,
                "is_typing": True
            }
            self._send_packet(packet)

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
        self._send_packet(packet)

    def _open_downloads_dir(self):
        os.makedirs(DOWNLOADS_DIR, exist_ok=True)
        if os.name == 'nt':
            os.startfile(os.path.abspath(DOWNLOADS_DIR))
        else:
            os.system(f"xdg-open '{os.path.abspath(DOWNLOADS_DIR)}'")

    def _open_voice_dir(self):
        os.makedirs(VOICE_DIR, exist_ok=True)
        if os.name == 'nt':
            os.startfile(os.path.abspath(VOICE_DIR))
        else:
            os.system(f"xdg-open '{os.path.abspath(VOICE_DIR)}'")

    def _get_e2ee_key(self, target_user: str) -> Optional[bytes]:
        if not target_user:
            return None
        target_clean = target_user.lstrip("@").strip()
        if target_clean.lower() == self.my_username.lower():
            try:
                return derive_e2ee_shared_key(self.my_priv_key, self.my_pubkey_hex)
            except Exception:
                return None
        for name, key in self.e2ee_keys_cache.items():
            if name.lower() == target_clean.lower():
                return key
        for name, user_info in self.online_users.items():
            if name.lower() == target_clean.lower() and user_info.get("pubkey"):
                try:
                    shared = derive_e2ee_shared_key(self.my_priv_key, user_info["pubkey"])
                    self.e2ee_keys_cache[name] = shared
                    return shared
                except Exception:
                    return None
        return None

    def _send_message(self):
        text = self.txt_input.get().strip()
        if not text:
            return
        self.txt_input.delete(0, tk.END)
        self._stop_typing()

        if self.current_target.startswith("@"):
            # Direct Message (E2EE)
            target = self.current_target.lstrip("@").strip()
            shared_key = self._get_e2ee_key(target)
            if not shared_key:
                messagebox.showerror("E2EE Error", f"Cannot establish E2EE session with @{target}. User may be offline.")
                return
            enc_payload = e2ee_encrypt_payload(shared_key, text)
            packet = {
                "type": "PMSG",
                "target": target,
                "content": enc_payload
            }
            self._send_packet(packet)
            
            # Save to history & log file
            log_chat_history_to_file(f"[E2EE DM] {self.my_username} -> @{target}: {text}")
            self._append_to_history(self.current_target, {
                "text": f"🔒 [E2EE to @{target}] {self.my_username}: {text}",
                "tag": "e2ee_user",
                "time": datetime.datetime.now().strftime("%H:%M:%S")
            })
        else:
            # Room Message
            packet = {
                "type": "ROOM_MSG",
                "room": self.current_target,
                "content": text
            }
            self._send_packet(packet)
            log_chat_history_to_file(f"[{self.current_target}] {self.my_username}: {text}")
            self._append_to_history(self.current_target, {
                "text": f"[{self.current_target}] {self.my_username}: {text}",
                "tag": "user",
                "time": datetime.datetime.now().strftime("%H:%M:%S")
            })

    def _pick_and_send_file(self):
        filepath = filedialog.askopenfilename(title="Select File to Send")
        if not filepath:
            return
        threading.Thread(target=self._send_file_worker, args=(filepath, False), daemon=True).start()

    def _send_file_worker(self, filepath: str, is_voice_note: bool = False):
        filename = os.path.basename(filepath)
        filehash, filesize = compute_file_sha256(filepath)
        num_chunks = (filesize + CHUNK_SIZE - 1) // CHUNK_SIZE if filesize > 0 else 1
        transfer_id = str(uuid.uuid4())[:8]

        is_e2ee = self.current_target.startswith("@")
        target_user = self.current_target.lstrip("@").strip() if is_e2ee else None
        shared_key = self._get_e2ee_key(target_user) if is_e2ee else None

        self.after(0, lambda: self.transfer_progress.pack(side="right", fill="x", expand=True, padx=10))

        start_packet = {
            "type": "PFILE_START" if is_e2ee else "FILE_START",
            "transfer_id": transfer_id,
            "filename": filename,
            "filesize": filesize,
            "filehash": filehash,
            "num_chunks": num_chunks,
            "target": target_user,
            "room": self.current_target,
            "is_e2ee": is_e2ee,
            "is_voice": is_voice_note
        }
        self._send_packet(start_packet)

        target_log = self.current_target
        item_text = f"🎙️ Sent Voice Note '{filename}' ({filesize} bytes)" if is_voice_note else f"📁 Sent File '{filename}' ({filesize:,} bytes)"
        log_chat_history_to_file(f"[File Upload] {self.my_username} -> {target_user or self.current_target}: {filename} ({filesize:,} bytes)")

        self.after(0, lambda: self._append_to_history(target_log, {
            "text": item_text,
            "tag": "voice" if is_voice_note else "file",
            "is_voice": is_voice_note,
            "voice_path": filepath if is_voice_note else "",
            "is_file": not is_voice_note,
            "file_path": filepath if not is_voice_note else ""
        }))

        # Track in transfer log
        self.file_transfers.append({
            "time": datetime.datetime.now().strftime("%H:%M:%S"),
            "filename": filename,
            "size": f"{filesize:,} bytes",
            "sender": self.my_username,
            "target": target_user or self.current_target,
            "path": filepath,
            "status": "Uploaded"
        })

        sent_bytes = 0
        with open(filepath, "rb") as f:
            for idx in range(num_chunks):
                chunk = f.read(CHUNK_SIZE)
                if not chunk:
                    break
                chunk_payload = e2ee_encrypt_bytes(shared_key, chunk) if is_e2ee and shared_key else chunk
                chunk_b64 = base64.b64encode(chunk_payload).decode("ascii")

                self._send_packet({
                    "type": "FILE_CHUNK",
                    "transfer_id": transfer_id,
                    "chunk_idx": idx,
                    "total_chunks": num_chunks,
                    "data": chunk_b64,
                    "target": target_user,
                    "room": self.current_target
                })

                sent_bytes += len(chunk)
                pct = int((sent_bytes / max(1, filesize)) * 100)
                self.after(0, lambda p=pct: self.transfer_progress.configure(value=p))

        self._send_packet({
            "type": "FILE_END",
            "transfer_id": transfer_id,
            "target": target_user,
            "room": self.current_target
        })

        self.after(0, lambda: self.transfer_progress.pack_forget())

    def _show_transfer_history(self):
        """Display transfer audit log in a modal window."""
        top = tk.Toplevel(self)
        top.title("File Transfer History & Audit Log")
        top.geometry("750x400")
        top.configure(bg=BG_SIDEBAR)

        tk.Label(top, text="📋 File Transfer & Voice Note History", font=("Segoe UI", 12, "bold"), bg=BG_SIDEBAR, fg=TEXT_WHITE).pack(anchor="w", padx=15, pady=10)

        cols = ("Time", "File / Voice", "Size", "From / To", "Status", "Path")
        tree = ttk.Treeview(top, columns=cols, show="headings", height=12)
        for c in cols:
            tree.heading(c, text=c)
            tree.column(c, width=110)
        tree.column("File / Voice", width=150)
        tree.column("Path", width=180)
        tree.pack(fill="both", expand=True, padx=15, pady=(0, 10))

        for t in reversed(self.file_transfers):
            tree.insert("", tk.END, values=(t["time"], t["filename"], t["size"], f"{t['sender']} -> {t['target']}", t["status"], t["path"]))

        def open_selected():
            sel = tree.selection()
            if sel:
                item = tree.item(sel[0])
                path = item["values"][5]
                self._open_file_path(path)

        btn_row = tk.Frame(top, bg=BG_SIDEBAR)
        btn_row.pack(fill="x", padx=15, pady=5)
        tk.Button(btn_row, text="📂 Open Selected File", bg=ACCENT_BLUE, fg=TEXT_WHITE, font=("Segoe UI", 9, "bold"), relief="flat", command=open_selected).pack(side="left", padx=(0, 10))
        tk.Button(btn_row, text="📁 Open Downloads Folder", bg=BG_INPUT, fg=TEXT_WHITE, font=("Segoe UI", 9), relief="flat", command=self._open_downloads_dir).pack(side="left", padx=(0, 10))
        tk.Button(btn_row, text="🎙️ Open Voice Notes", bg=BG_INPUT, fg="#38bdf8", font=("Segoe UI", 9), relief="flat", command=self._open_voice_dir).pack(side="left")

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
                room = packet.get("room", "#general")
                sender = packet.get("sender")
                content = packet.get("content")
                ts = packet.get("timestamp")
                log_chat_history_to_file(f"[{room}] {sender}: {content}")
                self.after(0, lambda r=room, s=sender, c=content, t=ts: self._append_to_history(r, {
                    "text": f"[{r}] {s}: {c}",
                    "tag": "user",
                    "time": t
                }))

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
                
                target_key = f"@{sender}"
                log_chat_history_to_file(f"[E2EE DM] {sender} -> @{self.my_username}: {msg_text}")
                
                # Append to sender's DM history
                self.after(0, lambda s=sender, m=msg_text, t=ts, tk_key=target_key: self._on_receive_dm(s, m, t, tk_key))
                self.bell()

            elif ptype == "HIST":
                room = packet.get("room", "#general")
                sender = packet.get("sender")
                content = packet.get("content")
                ts = packet.get("timestamp")
                self.after(0, lambda r=room, s=sender, c=content, t=ts: self._append_to_history(r, {
                    "text": f"[History {t}] [{r}] {s}: {c}",
                    "tag": "hist",
                    "time": t
                }))

            elif ptype == "SYS":
                content = packet.get("content")
                room = packet.get("room") or self.current_target
                log_chat_history_to_file(f"[SYS] {content}")
                self.after(0, lambda c=content, r=room: self._append_to_history(r, {
                    "text": f"*** {c} ***",
                    "tag": "sys"
                }))

            elif ptype == "ERR":
                content = packet.get("content")
                self.after(0, lambda c=content: self._append_to_history(self.current_target, {
                    "text": f"[Error] {c}",
                    "tag": "err"
                }))

            elif ptype == "USERLIST":
                users = packet.get("users", [])
                for u in users:
                    if u["username"].lower() != self.my_username.lower() and u.get("pubkey"):
                        try:
                            self.e2ee_keys_cache[u["username"]] = derive_e2ee_shared_key(self.my_priv_key, u["pubkey"])
                        except Exception:
                            pass
                self.after(0, lambda u=users: self._update_userlist(u))

            elif ptype == "TYPING":
                sender = packet.get("sender")
                is_typing = packet.get("is_typing", False)
                text = f"✍️ {sender} is typing..." if is_typing else ""
                self.after(0, lambda t=text: self.lbl_typing.config(text=t))

            elif ptype == "PING":
                self._send_packet({"type": "PONG"})

            elif ptype in ("FILE_START", "PFILE_START"):
                self._handle_file_start(packet)

            elif ptype == "FILE_CHUNK":
                self._handle_file_chunk(packet)

            elif ptype == "FILE_END":
                self._handle_file_end(packet)

    def _on_receive_dm(self, sender: str, msg_text: str, timestamp: str, target_key: str):
        """Handle incoming DM with immediate visibility regardless of active tab."""
        # 1. Save in private DM history
        self._append_to_history(target_key, {
            "text": f"🔒 [E2EE from @{sender}] {sender}: {msg_text}",
            "tag": "e2ee_user",
            "time": timestamp
        })
        # 2. If user is currently looking at another room, also show notification banner in current chat view
        if self.current_target != target_key:
            self._append_to_history(self.current_target, {
                "text": f"💬 [New Private Message from @{sender}]: {msg_text}",
                "tag": "dm_alert",
                "time": timestamp,
                "is_dm_switch": True,
                "switch_target": target_key
            })

    def _update_userlist(self, raw_users):
        self.online_users = {u["username"]: u for u in raw_users}
        self._refresh_sidebar_users()

    def _handle_file_start(self, packet):
        tid = packet.get("transfer_id")
        filename = sanitize_filename(packet.get("filename", "file"))
        filesize = int(packet.get("filesize", 0))
        sender = packet.get("sender", "Unknown")
        is_e2ee = bool(packet.get("is_e2ee", False))
        is_voice = bool(packet.get("is_voice", False)) or filename.startswith("voice_")

        shared_key = self._get_e2ee_key(sender) if is_e2ee else None
        
        target_dir = VOICE_DIR if is_voice else DOWNLOADS_DIR
        outpath = get_unique_filepath(target_dir, filename)
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
                "is_voice": is_voice,
                "sender": sender,
                "room": packet.get("room", "#general"),
                "shared_key": shared_key
            }

        target_channel = f"@{sender}" if is_e2ee else packet.get("room", "#general")
        banner = f"🎙️ Incoming Voice Note from {sender}..." if is_voice else f"Receiving '{filename}' ({filesize:,} bytes) from {sender}..."
        self.after(0, lambda: self._append_to_history(target_channel, {
            "text": banner,
            "tag": "voice" if is_voice else "file"
        }))
        if self.current_target != target_channel:
            self.after(0, lambda: self._append_to_history(self.current_target, {
                "text": f"📥 [Private File Transfer starting from @{sender}]: '{filename}' ({filesize:,} bytes)",
                "tag": "dm_alert",
                "is_dm_switch": True,
                "switch_target": target_channel
            }))
        self.after(0, lambda: self.transfer_progress.pack(side="right", fill="x", expand=True, padx=10))

    def _handle_file_chunk(self, packet):
        tid = packet.get("transfer_id")
        chunk_b64 = packet.get("data", "")
        with self.active_transfers_lock:
            tr = self.active_downloads.get(tid)
            if not tr:
                return
            raw = base64.b64decode(chunk_b64.encode("ascii"))
            chunk = e2ee_decrypt_bytes(tr["shared_key"], raw) if tr["is_e2ee"] and tr["shared_key"] else raw
            if chunk:
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
            is_voice = tr.get("is_voice", False)
            outpath = tr["outpath"]
            sender = tr["sender"]
            target_channel = f"@{sender}" if tr["is_e2ee"] else tr.get("room", "#general")

            if ok:
                msg = f"🎙️ Voice Note from @{sender} (Saved in {VOICE_DIR}/)" if is_voice else f"✓ Downloaded: '{tr['filename']}' (Saved in {DOWNLOADS_DIR}/)"
            else:
                msg = f"✗ File Corrupted: '{tr['filename']}'"

            log_chat_history_to_file(f"[File Received] {sender} -> @{self.my_username}: {tr['filename']} ({tr['filesize']:,} bytes) [Verified]")

            item = {
                "text": msg,
                "tag": "voice" if is_voice else "file",
                "is_voice": is_voice,
                "voice_path": outpath if is_voice else "",
                "is_file": not is_voice,
                "file_path": outpath if not is_voice else ""
            }

            self.after(0, lambda it=item, tc=target_channel: self._append_to_history(tc, it))

            # Also show in active view if user was elsewhere
            if self.current_target != target_channel:
                alert_item = {
                    "text": f"📥 [Private File Received from @{sender}]: '{tr['filename']}'",
                    "tag": "dm_alert",
                    "is_voice": is_voice,
                    "voice_path": outpath if is_voice else "",
                    "is_file": not is_voice,
                    "file_path": outpath if not is_voice else "",
                    "is_dm_switch": True,
                    "switch_target": target_channel
                }
                self.after(0, lambda it=alert_item: self._append_to_history(self.current_target, it))

            # Record in transfer audit
            self.file_transfers.append({
                "time": datetime.datetime.now().strftime("%H:%M:%S"),
                "filename": tr["filename"],
                "size": f"{tr['filesize']:,} bytes",
                "sender": sender,
                "target": self.my_username,
                "path": outpath,
                "status": "Downloaded & Verified" if ok else "Corrupted"
            })

            self.after(0, lambda: self.transfer_progress.pack_forget())
            if is_voice and ok:
                self.bell()


if __name__ == "__main__":
    app = SecureChatGUI()
    app.mainloop()
