# 🛡️ Secure LAN Chat & File Transfer (v4 Advanced)

An enterprise-grade, high-performance local area network (LAN) communication suite written in Python. Built for speed, privacy, and reliability without external server dependencies.

![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)
![Security](https://img.shields.io/badge/encryption-AES--256--GCM-green.svg)
![E2EE](https://img.shields.io/badge/E2EE-X25519%20ECDH-magenta.svg)
![Interface](https://img.shields.io/badge/GUI-Tkinter-orange.svg)

---

## 🌟 Key Features

| Feature | Description |
| :--- | :--- |
| 🔒 **End-to-End Encryption (E2EE)** | 1-to-1 DMs and private files use **X25519 ECDH** key exchange + **HKDF** + **AES-256-GCM**. The server acts as a zero-knowledge relay and cannot decrypt private messages. |
| 🛡️ **AES-256-GCM Transport Layer** | Every TCP frame (chat, commands, file streams) is authenticated and encrypted with 256-bit keys derived via PBKDF2-HMAC-SHA256 (200k iterations). |
| ⚡ **Multiplexed Streaming File Transfer** | Disk-to-disk chunked transfer (64 KB chunks) prevents high RAM usage. Files of any size transfer smoothly without blocking chat. Includes live transfer speeds (MB/s), ETA, and streaming SHA-256 integrity verification. |
| 💬 **Multi-Channel Rooms** | Default channels (`#general`, `#dev`, `#random`) plus dynamic custom channels (`/join #room`). |
| 🖥️ **Dual Interface (GUI & CLI)** | Modern dark-themed Desktop GUI (`gui_client.py`) and an asynchronous, non-clobbering CLI client (`client.py`). |
| 🟢 **Live Presence & Typing Indicators** | Real-time status indicators (Online, Away, Busy) and live typing alerts. |
| 🔍 **UDP Auto-Discovery** | Zero-configuration connection. Clients broadcast UDP discovery queries to auto-detect active servers on the LAN subnet. |
| 🗄️ **Persistent SQLite History** | Server maintains room message history and file transfer audit logs in `lan_chat.db`. |

---

## 📐 Architecture Overview

```
+-------------------------------------------------------------------------+
|                                 CLIENT A                                |
|  [GUI / CLI] <---> [X25519 ECDH Keypair] <---> [Stream File Engine]     |
+-------------------------------------------------------------------------+
       |                                                    |
   UDP Discovery                                     AES-256-GCM TCP Frame
   (Port 5051)                                       (Port 5050)
       |                                                    |
       v                                                    v
+-------------------------------------------------------------------------+
|                              SERVER (v4)                                |
|  • Non-blocking Multiplexed Dispatcher                                  |
|  • Public Key Directory (X25519)                                        |
|  • Channel & Room Router (#general, #dev, #random)                      |
|  • SQLite History & Audit Database (lan_chat.db)                        |
|  • Heartbeat Watchdog & Dead-Client Pruning                             |
+-------------------------------------------------------------------------+
                                                            ^
                                                     AES-256-GCM TCP Frame
                                                     [E2EE Private Payload]
                                                            |
+-------------------------------------------------------------------------+
|                                 CLIENT B                                |
|  [GUI / CLI] <---> [Shared ECDH Key] <---> [Direct-to-Disk Downloader]  |
+-------------------------------------------------------------------------+
```

---

## 🚀 Quick Start

### 1. Installation
Clone the repository and install requirements:
```bash
git clone https://github.com/Prats1729/Secure-LAN-Chat-and-File-Transfer.git
cd Secure-LAN-Chat-and-File-Transfer
pip install -r requirements.txt
```

### 2. Start the Server
Run the server with default ports (TCP: 5050, UDP: 5051):
```bash
python server.py
```
*Optional custom ports:* `python server.py [tcp_port] [udp_discovery_port]`

### 3. Launch Clients

#### Option A: Modern Desktop GUI (Recommended)
```bash
python gui_client.py
```
*Features:* Click **"Auto-Discover"** to find the server, select channels, chat in DMs with E2EE locks, drag/select files with live progress meters, and open your `downloads/` directory directly.

#### Option B: Advanced Interactive CLI
```bash
python client.py
```
*With manual IP:* `python client.py 192.168.1.100 5050`

---

## ⌨️ CLI Command Cheatsheet

Once connected in `client.py`:

```text
  <message>                 Send broadcast message to your active room
  /msg <user> <message>     Send zero-knowledge E2EE private message to @user
  /file <filepath>          Stream file upload to current room
  /fileto <user> <filepath> Send zero-knowledge E2EE private file to @user
  /join <#room>             Join or switch to a room (#general, #dev, #gaming)
  /leave <#room>            Leave a room
  /rooms                    List your active rooms
  /status <online|away|busy> Change presence status
  /users or /list           View online users, statuses, and E2EE readiness
  /whoami                   Show your username, public key fingerprint & room
  /clear                    Clear terminal output
  /help                     Show command list
  /quit                     Disconnect and exit
```

---

## 🔬 Wireshark Network Inspection Guide

This project is designed for Computer Networks demonstrations:
1. **UDP Discovery:** Filter for `udp.port == 5051` to see client broadcast packets `LANCHAT_DISCOVER` and server responses.
2. **Encrypted Framing:** Filter for `tcp.port == 5050` to inspect payload bytes. Every frame begins with `[4 bytes length][12 bytes nonce]` followed by encrypted ciphertext.
3. **E2EE Privacy:** In Wireshark, even if a user knows the LAN passphrase to decrypt the transport layer, private messages (`PMSG`) and private files (`PFILE_START` / `FILE_CHUNK`) contain nested ciphertext only decryptable by the recipient's private X25519 key.

---

## 📁 File Structure

```
Secure-LAN-Chat-and-File-Transfer/
├── crypto_utils.py       # Core crypto primitives (AES-GCM, X25519 ECDH, HKDF, Stream I/O)
├── server.py             # Server with SQLite persistence, multiplexer, and room routing
├── client.py             # Asynchronous CLI client with non-clobbering prompt
├── gui_client.py         # Modern Desktop GUI with channel tabs & file progress cards
├── requirements.txt      # Project dependencies (cryptography)
├── .gitignore            # Git exclusion rules
└── README.md             # Project documentation
```

---

## 📜 License
This project is open-source and intended for local networking, privacy engineering, and educational use.
