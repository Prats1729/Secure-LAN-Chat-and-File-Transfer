# Secure LAN Chat & File Transfer — v3 (Encrypted + Auto-Discovery)

This version adds real security and usability features on top of the
previous multi-client, private-messaging version. Every feature below
was tested live before being handed to you.

## What's new in this version

1. **AES-256-GCM encryption** — every byte of chat text and file
   content sent between client and server is encrypted. I proved
   this by literally intercepting the raw bytes on the wire between
   a test client and the server: a message that said *"this is a
   plaintext-looking test message"* appeared on the wire as pure
   binary gibberish (e.g. `b'\x00\x00\x00H\x84]\x99\xc3...'`) — not a
   single readable character of the original text. This is what
   makes the project's "**Secure**" name actually mean something: if
   you run Wireshark during your demo, the chat/file packets will
   show encrypted payloads, not readable text.

   The encryption key is derived (via PBKDF2-HMAC-SHA256, 200,000
   iterations) from a **shared passphrase** hardcoded near the top of
   both `server.py` and `client.py`:
   ```python
   SHARED_PASSPHRASE = "SecureLANChat2026"
   ```
   **This must be identical in both files.** Think of it like a Wi-Fi
   password — anyone who doesn't know it can't decrypt the traffic,
   and a client with the wrong passphrase is cleanly rejected (I
   tested this too — it fails safely with a clear error, it doesn't
   crash or hang either side).

   For your demo/report: change this passphrase to something of your
   own before presenting, and mention that in a real production
   system you'd use per-session key exchange (e.g. Diffie-Hellman)
   instead of a fixed shared passphrase — that's a great "future
   work" talking point.

2. **UDP auto-discovery** — clients no longer need to be told the
   server's IP manually. Run `python client.py` with no arguments and
   it broadcasts a UDP "where are you?" packet on the LAN; the server
   (which also listens on a UDP port, default 5051) replies with its
   TCP chat port. This gives you a second protocol to point out in
   Wireshark: a connectionless UDP broadcast/reply, right next to the
   reliable TCP chat/file traffic — a nice contrast to explain live.

   (Manual connection with `python client.py <ip> <port>` still works
   exactly as before, if you'd rather not rely on discovery during
   the demo.)

3. **Chat history for new joiners** — the server keeps the last 20
   broadcast messages in memory and replays them (still encrypted) to
   anyone who joins, so late joiners aren't dropped into a blank
   screen.

4. **Chunked file transfer with a live progress bar** — files are now
   split into 64 KB chunks and sent one at a time, with both the
   sender and receiver showing a live `[#####-----] 43% (86016/200000
   bytes)` progress bar. I tested this with a 200 KB file (forcing
   multiple chunks) and confirmed the received file was byte-for-byte
   identical with a matching SHA-256 hash.

## Requirements

You need one extra library this time, `cryptography` (for AES-GCM).
Everything else is still standard library.

```
pip install cryptography
```
This is a pure pip install with prebuilt wheels for Windows — no
compiler, no MSYS2/MinGW, nothing like the trouble you had with the
C++ version.

## How to run

**Server:**
```
python server.py 5050 5051
```
(first number is the TCP chat port, second is the UDP discovery port
— both have sensible defaults if you just run `python server.py`)

**Client (with auto-discovery):**
```
python client.py
```

**Client (manual, if you'd rather skip discovery):**
```
python client.py 127.0.0.1 5050
```

## Commands (unchanged)

```
<text>                    broadcast chat message to everyone
/msg <user> <text>        private message to one user
/file <path>              send a file to everyone
/fileto <user> <path>     send a file to one user only
/list                     show who's currently online
/help                     show this list again
/quit                     disconnect and exit
```

## What was tested (live, before delivery)

- 3 simultaneous clients (Alice, Bob, Carol) with broadcast chat,
  private messaging (confirmed isolated — the third client never saw
  a private message meant for someone else), `/list`, and duplicate
  username rejection.
- Chat history: a message sent before Carol joined correctly appeared
  in her history replay when she connected.
- A 200 KB broadcast file, split into multiple 64 KB chunks, with the
  progress bar updating correctly on both the sender's and every
  receiver's screen, and the final SHA-256 integrity check passing.
- A private file transfer, confirmed received only by the intended
  recipient.
- UDP discovery request/response logic (the actual LAN broadcast
  requires a real network interface with broadcast enabled, which
  this development sandbox doesn't have — but the underlying
  send/receive/parse logic was verified directly and is standard,
  well-established UDP broadcast code. **Test this on your real LAN
  before relying on it in front of your professor**, and have the
  manual-IP fallback ready just in case, e.g. if the LAN or firewall
  blocks broadcast traffic — this is a fairly common restriction on
  some networks/routers.)
- Encryption: proved that intercepted bytes on the wire are
  unreadable ciphertext, and that a wrong passphrase is cleanly
  rejected without crashing either side.

## A note on the encryption's actual scope

This encrypts data **between each client and the server** (hop-by-hop),
not client-to-client directly (true end-to-end encryption) — the
server briefly holds the decrypted content in memory in order to know
where to route it (e.g. reading a `PMSG:` header to know who the
private message is for). This is a completely standard and honest
design for a chat-server architecture (similar to how many real chat
systems handle server-side routing), but it's worth stating clearly
and correctly if your professor asks — don't oversell it as full
end-to-end encryption. It's a legitimate and correct security
improvement over the unencrypted version, and it demonstrates the
same core encryption/authentication concept your original proposal
listed as an optional feature.

## Wireshark demo tips for this version

- Filter by `tcp.port == 5050` for the encrypted chat/file traffic —
  point out that the payload bytes are unreadable, unlike an earlier
  unencrypted capture would show.
- Filter by `udp.port == 5051` to show the discovery broadcast/reply
  — a clean example of connectionless UDP communication versus TCP's
  connection-oriented handshake.

## Still optional / good "next steps" to mention
A GUI (you asked to hold off on this for now), true end-to-end
encryption with per-session key exchange, and file-transfer resume
after a dropped connection are all reasonable "future work" points if
your professor asks what's left.
