# Secure LAN Chat & File Transfer

A lightweight Python chat and file-sharing application designed for local-area networks. The project includes a server and a client, encrypted communication, LAN auto-discovery, private messaging, and file transfers with progress reporting.

## Features

- Encrypted chat traffic using AES-GCM
- Shared passphrase-based key derivation with PBKDF2-HMAC-SHA256
- LAN server discovery over UDP broadcast
- Broadcast and private messaging
- User list and duplicate username prevention
- File transfer with per-chunk progress updates
- Recent chat history replay for newly connected clients

## Project Structure

- `server.py` — socket server that handles chat, discovery, and file routing
- `client.py` — chat client with discovery, UI, file sending, and file receiving
- `requirements.txt` — dependency list
- `README.md` — project overview and usage instructions

## Requirements

- Python 3.8+
- `cryptography` package

Install dependencies:

```bash
pip install -r requirements.txt
```

If `requirements.txt` is empty in your environment, install the required package directly:

```bash
pip install cryptography
```

## Running the Server

Start the server with default ports:

```bash
python server.py
```

Or specify custom ports:

```bash
python server.py 5050 5051
```

- First value: TCP chat/file port
- Second value: UDP discovery port

## Running the Client

Auto-discovery mode (recommended):

```bash
python client.py
```

Manual connection mode:

```bash
python client.py 127.0.0.1 5050
```

## Available Commands

Once connected, use these commands in the client terminal:

```text
<text>                    Send a broadcast message
/msg <user> <text>        Send a private message
/file <path>              Send a file to everyone
/fileto <user> <path>     Send a file to one user
/list                     Show online users
/help                     Show command help
/quit                     Disconnect and exit
```

## Security Notes

The client and server must use the same shared passphrase. The key is derived from a hardcoded value in both files:

```python
SHARED_PASSPHRASE = "SecureLANChat2026"
```

If the passphrase does not match on both ends, decryption will fail and the connection will be rejected. Before a real demo or deployment, consider changing this to a custom secret.

## How It Works

- The server listens for TCP connections from clients.
- Clients can either connect directly to a known IP/port or discover the server using UDP broadcast.
- Chat and file payloads are encrypted before being sent over TCP.
- The server relays messages to the correct recipients and persists recent broadcast history for new users.
- File transfers are split into chunks so progress can be displayed during upload/download.

## Troubleshooting

- Ensure the server is running before starting the client.
- Confirm both programs use the same passphrase.
- If UDP discovery fails, connect to the server manually using its IP and TCP port.
- Check firewall or LAN restrictions if broadcast discovery does not work on the network.

## License

This project is intended for local networking and educational/demo use.

## Notes

This is a simple LAN application rather than a production-grade secure messaging platform. It demonstrates core concepts like encrypted transport, LAN discovery, and file transfer logic in a compact Python implementation.
