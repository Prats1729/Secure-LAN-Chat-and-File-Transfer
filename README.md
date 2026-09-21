# Secure LAN Chat & File Transfer System

[![Python Version](https://img.shields.io/badge/Python-3.7%2B-blue.svg)](https://www.python.org/)
[![Protocol](https://img.shields.io/badge/Protocol-Custom%20TCP%20Application%20Layer-brightgreen.svg)](#protocol-specification)
[![Security](https://img.shields.io/badge/Integrity-SHA--256-orange.svg)](#features)
[![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey.svg)](#requirements)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

A lightweight, cross-platform client-server networking application built from scratch using Python's standard socket and threading libraries. It enables multi-user real-time broadcast messaging and reliable binary file transfer across a Local Area Network (LAN) with end-to-end cryptographic SHA-256 integrity verification.

---

## 📌 Table of Contents
- [Overview](#-overview)
- [Key Features](#-key-features)
- [Architecture & Design](#-architecture--design)
- [Protocol Specification](#-protocol-specification)
- [Repository Structure](#-repository-structure)
- [Requirements](#-requirements)
- [Getting Started & Setup](#-getting-started--setup)
  - [1. Running on a Single Machine (Localhost)](#1-running-on-a-single-machine-localhost)
  - [2. Running Across a Local Area Network (LAN)](#2-running-across-a-local-area-network-lan)
- [Commands & Usage](#-commands--usage)
- [Wireshark & Packet Inspection](#-wireshark--packet-inspection)
- [Project Roadmap / Optional Enhancements](#-project-roadmap--optional-enhancements)
- [Contributing](#-contributing)
- [License](#-license)

---

## 📖 Overview

This project was built as a Computer Networks (CN) mini-project to demonstrate practical implementations of core networking and distributed systems concepts:
- **Transport Layer**: Reliable stream-oriented transport using **TCP** (`SOCK_STREAM`), ensuring sequenced delivery without packet loss.
- **Application Layer Protocol**: A custom, human-readable ASCII control protocol for session management, message framing, and file streaming.
- **Concurrency & Multithreading**: Non-blocking I/O via worker threads (`threading.Thread`) and safe shared state updates with mutex locks (`threading.Lock`).
- **Data Integrity**: Cryptographic checksum computation via **SHA-256** prior to sending and validation upon receipt to detect any packet corruption or tampering.
- **Zero External Dependencies**: Implemented strictly using the Python standard library for maximum portability across operating systems.

---

## 🚀 Key Features

- **Multi-Client Real-Time Chat**: Broadcast chat messaging to all active clients connected to the server.
- **Presence Notifications**: System notices automatically alert connected users when a peer joins or disconnects (`SYS:<message>`).
- **Reliable File Streaming**: Binary-safe file transmission handled in chunked byte streams (`4096-byte` buffers) to prevent memory exhaustion on large transfers.
- **Cryptographic Hash Verification**: The sender computes the file's SHA-256 digest before transmission. The receiver computes the hash on arrival and compares it against the sender's digest, providing a clear integrity confirmation.
- **Cross-Platform Compatibility**: Cleanly runs on Windows, macOS, and Linux without platform-specific dependencies or compiler toolchain hassles.

---

## 🏗 Architecture & Design

The application follows a centralized **Client-Server Architecture**:

```
                          +-------------------+
                          |  Central Server   |
                          |    (server.py)    |
                          +---------+---------+
                                    |
          +-------------------------+-------------------------+
          |                         |                         |
    [Worker Thread 1]         [Worker Thread 2]         [Worker Thread 3]
          |                         |                         |
          v                         v                         v
   +--------------+          +--------------+          +--------------+
   |   Client A   |          |   Client B   |          |   Client C   |
   | (client.py)  |          | (client.py)  |          | (client.py)  |
   +--------------+          +--------------+          +--------------+
```

### Server Concurrency Model
1. The server binds to `0.0.0.0` on a specified port (default: `5050`) and listens for incoming connections.
2. When a client connects, the main server loop spawns a dedicated daemon `Thread` running `handle_client`.
3. The server maintains a synchronized client registry protected by `threading.Lock()` to prevent race conditions during message broadcast or client disconnection.

### Client Concurrency Model
1. The client establishes a TCP socket connection to the server.
2. A background daemon thread executes `receiver_loop`, listening continuously for incoming messages from the server.
3. The main thread handles interactive command-line user input without blocking the display of incoming messages.

---

## 📡 Protocol Specification

The custom application-layer wire protocol uses newline-delimited (`\n`) ASCII control messages and binary stream data:

| Stage / Message Type | Format | Description |
| :--- | :--- | :--- |
| **Handshake** | `<username>\n` | First line sent by client upon establishing TCP connection. |
| **System Event** | `SYS:<notice>\n` | Server-generated announcement broadcast when clients join or leave. |
| **Client Chat Message** | `MSG:<text>\n` | Sent by a client to the server for distribution. |
| **Broadcast Chat Message**| `CHAT:<sender>:<text>\n` | Relayed by the server to all other connected clients. |
| **File Header (Send)** | `FILE:<filename>:<filesize>:<sha256hex>\n` | Sent by the sender client, immediately followed by `<filesize>` raw bytes. |
| **File Header (Relay)**| `FILE:<sender>:<filename>:<filesize>:<sha256hex>\n` | Relayed by the server, followed by the identical `<filesize>` raw bytes. |

---

## 📂 Repository Structure

├── client.py               # Interactive TCP client (CLI chat, file sender & receiver)
├── server.py               # Multithreaded TCP broadcast and file-relay server
├── requirements.txt        # Dependency declaration (uses Python standard library)
├── .gitignore              # Git ignore rules for bytecode, temporary, and received files
└── README.md               # Comprehensive project documentation
```

---

## 💻 Requirements

- **Python 3.7 or higher**
- No external packages or `pip install` required. Standard library modules used:
  - `socket`
  - `threading`
  - `hashlib`
  - `os`
  - `sys`

Verify your Python installation:
```bash
python --version
# or
python3 --version
```

---

## ⚡ Getting Started & Setup

### Clone the Repository
```bash
git clone https://github.com/<your-username>/<your-repo-name>.git
cd <your-repo-name>
```

### Set Up Virtual Environment (Optional but Recommended)
```bash
# Windows (PowerShell)
python -m venv .venv
.\.venv\Scripts\Activate.ps1

# Linux / macOS
python3 -m venv .venv
source .venv/bin/activate
```

### 1. Running on a Single Machine (Localhost)

Open multiple terminal windows on your computer:

#### Step 1: Start Server (Terminal 1)
```bash
python server.py 5050
```

#### Step 2: Start First Client (Terminal 2)
```bash
python client.py 127.0.0.1 5050
```
Enter a username (e.g., `Alice`).

#### Step 3: Start Second Client (Terminal 3)
```bash
python client.py 127.0.0.1 5050
```
Enter a username (e.g., `Bob`).

---

### 2. Running Across a Local Area Network (LAN)

To run between two or more physical machines connected to the same Wi-Fi or router:

#### Step 1: Identify Server's Local IP Address
On the server computer, run:
- **Windows**: `ipconfig` (look for `IPv4 Address`, e.g., `192.168.1.45`)
- **Linux/macOS**: `ip addr` or `ifconfig`

> **Note**: If on Windows, ensure that Windows Defender Firewall allows incoming connections on the selected port (e.g., `5050`), or allow Python when prompted.

#### Step 2: Launch the Server
```bash
python server.py 5050
```

#### Step 3: Connect Clients from Other Machines
On any other machine on the same LAN:
```bash
python client.py <server_lan_ip> 5050
```
*Example:* `python client.py 192.168.1.45 5050`

---

## ⌨️ Commands & Usage

Once connected to a chat session, use the following commands in the prompt:

| Command | Action | Example |
| :--- | :--- | :--- |
| `<any text>` | Sends a public message to all connected peers. | `Hello everyone!` |
| `/file <path>` | Transmits a file with SHA-256 hash validation. | `/file sample.pdf` or `/file C:\data\notes.txt` |
| `/quit` | Closes socket connection and exits the application. | `/quit` |

### File Transfer Behavior
- When a file is sent, the sender prints the file size and computed SHA-256 hash.
- The receiving client saves the file automatically with a `received_` prefix (e.g., `received_notes.txt`) in its current directory.
- The receiver computes the hash of the received bytes and displays an integrity confirmation:
  ```
  [file received] 'test.txt' from Alice (1048 bytes)
    saved as: received_test.txt
    integrity check: OK (hash matches)
  ```

---

## 🔍 Wireshark & Packet Inspection

To demonstrate protocol operation for academic lab evaluations:
1. Open [Wireshark](https://www.wireshark.org/) and capture on your active network interface (Loopback adapter for `127.0.0.1` or Wi-Fi/Ethernet for LAN).
2. Set display filter to:
   ```wireshark
   tcp.port == 5050
   ```
3. Observe:
   - **TCP Three-Way Handshake** (`SYN` -> `SYN-ACK` -> `ACK`) during client connection.
   - **Data Transfer** (`PSH, ACK`) carrying ASCII protocol headers (`MSG:`, `CHAT:`, `FILE:`).
   - **Connection Teardown** (`FIN-ACK` or `RST`) on `/quit` or terminal termination.

---

## 🗺 Project Roadmap / Optional Enhancements

- [ ] **End-to-End Encryption (E2EE)**: Transport Layer Security (TLS) via Python's `ssl` module or symmetric encryption with AES-GCM.
- [ ] **Private Messaging**: Direct 1-to-1 whispering syntax (`/whisper <user> <message>`).
- [ ] **UDP Auto-Discovery**: Beacon broadcasting to detect active servers on LAN without manually entering IP addresses.
- [ ] **Graphical User Interface (GUI)**: Modern lightweight UI using Tkinter, PyQt, or a local webview.
- [ ] **Progress Indicators**: Real-time progress bar for large multi-megabyte file transfers.

---

## 🤝 Contributing

Contributions, issues, and feature requests are welcome! Feel free to check the [issues page](https://github.com/<your-username>/<your-repo-name>/issues).

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details (or use for academic/educational demonstration purposes).
