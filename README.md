# m

Encrypted TUI messenger over gRPC. Messages are encrypted end-to-end on the client; the server stores and routes ciphertext only.

## Install

```bash
./prepare.sh          # release build (default)
./prepare.sh --debug  # debug build
```

Installs:
- `m_client` → `~/.local/bin/m_client`
- `m_server` → `~/.local/share/m/deploy/m_server`
- Client config template → `~/.config/m/client.toml` (only if not already present)
- Server config template → `~/.local/share/m/deploy/m_server.template.toml`

---

## Server

### Configuration

The server reads a TOML config file. Pass the path as the first argument (default: `~/.config/m/server.toml`).

```toml
[host]
bind_address = "0.0.0.0:50051"      # optional — this is the default

[database]
path = "~/.local/share/m/db.redb"

[logging]
log_dir       = "~/.local/share/m/logs/"
max_files     = 5
max_file_size = 10485760             # bytes

[delivery]
ack_timeout_secs    = 10
max_retries         = 10
retry_interval_secs = 1

[performance]
channel_buffer_size = 128
dedup_cache_size    = 10000

[encryption]
user_key  = "<32 bytes as hex>"     # AES-256-GCM key for gRPC transport encryption
admin_key = "<32 bytes as hex>"     # key required for admin operations
server_id = <u128 decimal>          # unique server identifier
```

- `user_key` must match `shared_key` in the client's server card.
- `admin_key` must match `admin_key` in the client's server card.
- Both keys are 32 bytes encoded as a 64-character lowercase hex string.

See [`config/server.template.toml`](config/server.template.toml) for a working example.

### Running

```bash
~/.local/share/m/deploy/m_server ~/.config/m/server.toml
```

---

## Client

### Configuration

The client reads its own TOML config. Pass the path with `--config` (default: `~/.config/m/client.toml`).

```toml
[storage]
db_path = "~/.local/share/m/client.redb"

[logging]
log_dir       = "~/.local/share/m/client-logs/"
max_files     = 5
max_file_size = 10485760
```

See [`config/client.toml`](config/client.toml) for an example.

### Running

```bash
m_client
```

---

## TUI interface

The client uses a window-based TUI. Switch windows by typing the window name and pressing Enter.

```
contacts> _        ← contacts window
servers> _         ← servers window
servers/chats> _   ← chats of the selected server
share> _           ← Tor / sharing window
```

In **contacts** and **servers** windows use ↑/↓ arrows to move the cursor through the list. Commands act on the item under the cursor.

### Layout

#### contacts / servers

```
┌──────────────────────────────────────┐
│ ┌──────────────────────────────────┐ │
│ │  Name                  ID: ...   │ │  ← cursor (yellow)
│ └──────────────────────────────────┘ │
│ ┌──────────────────────────────────┐ │
│ │  Name                  ID: ...   │ │
│ └──────────────────────────────────┘ │
└──────────────────────────────────────┘
┌──────────────────────────────────────┐
│ contacts> _                          │
└──────────────────────────────────────┘
```

#### servers/chats

```
┌──────────┬─────────────────────────────┐
│ ┌──────┐ │                             │
│ │chat1 │ │  [live messages appear here]│
│ └──────┘ │                             │
│ ┌──────┐ │  Use 'live' to activate     │
│ │chat2 │ │                             │
└──────────┴─────────────────────────────┘
┌────────────────────────────────────────┐
│ servers/chats> _                       │
└────────────────────────────────────────┘
```

In **live mode** the prompt changes to `message>` and pressing Enter sends a message directly.
Use PageUp / PageDown to scroll the message panel. Messages from contacts with Dilithium2
signatures show a verification badge: `✓` verified, `?` cannot verify, `✗` tampered.

#### share

```
┌──────────────────────────────────────┐
│ Tor: off / starting 35% / running    │
│                                      │
│ Receiving data... (ESC to stop)      │
│   Server 'remote' saved              │
│   Chat 'remote/general' saved        │
└──────────────────────────────────────┘
┌──────────────────────────────────────┐
│ share> _                             │
└──────────────────────────────────────┘
```

---

## Commands

### Global (any window)

| Command | Description |
|---|---|
| `contacts` | Switch to contacts window |
| `servers` | Switch to servers window |
| `share` | Switch to share window |
| `quit` / `exit` / `q` | Exit |
| `help` | Show commands for the current window |

### contacts window

| Command | Description |
|---|---|
| ↑ / ↓ | Move cursor |
| `whoami` | Show own identity (ID, onion address, signing PK) |
| `export-self <path>` | Export own identity as a contact card (binary) |
| `export <path>` | Export selected contact to a binary file |
| `load <path> <name>` | Import contact from a binary file |
| `rename <new_name>` | Rename selected contact |
| `del` | Delete selected contact |

### servers window

| Command | Description |
|---|---|
| ↑ / ↓ | Move cursor |
| `chats` | Open chats of the selected server |
| `enable` | Enable selected server and connect |
| `disable` | Disable selected server and disconnect |
| `rename <new_name>` | Rename selected server |
| `del` | Delete selected server |
| `deploy <user> <ip> <pass> <name>` | Deploy server via SSH (auto-generates keys) |
| `remove <user> <ip> <pass>` | Remove server via SSH and delete locally |
| `admin create-chat <id>` | Create chat on server, generate encryption key, save locally |
| `admin delete-chat <id>` | Delete a chat from the selected server |
| `admin list-chats` | List all chats on the selected server |

### servers/chats window

Navigate here with `chats` from the servers window. The prompt shows `servers/chats>`.

| Command | Description |
|---|---|
| ↑ / ↓ | Move cursor |
| `set-name <name>` | Set your display name (used in outgoing messages) |
| `live` | Enter live mode for selected chat (right panel shows messages) |
| ESC | Exit live mode |
| `enable` | Enable selected chat |
| `disable` | Disable selected chat |
| `rename <new_name>` | Rename selected chat |
| `del` | Delete selected chat |
| `verify` | Toggle Dilithium2 signature mode on/off for selected chat |
| `send <message>` | Send message to selected (or live) chat |
| `history [--limit N]` | Fetch message history (default 50) |
| `admin create-chat <name>` | Create chat on server, generate encryption key, save locally |
| `admin delete-chat <id>` | Delete a chat from the server |
| `admin list-chats` | List all chats on the server |

### share window

| Command | Description |
|---|---|
| `run-tor` | Start Tor daemon — locks input, shows bootstrap %; ESC to cancel |
| `stop-tor` | Stop Tor daemon |
| `receiving-data` | Start onion listener — prints received items live; ESC to stop |
| `share-data` | Interactive wizard: pick contact → server → chat, then send |
| `gen-offer <contact> <path>` | Generate KEM offer file — step 1 of manual file-based share (you are B) |
| `respond-offer <contact> <offer> <response>` | Respond to an offer file — step 2 (you are A); writes a response file |
| `load-response <contact> <path>` | Import response file — step 3 (you are B); merges shared data |

---

## Workflow: first setup

### 1. Deploy or import a server

**Deploy via SSH** (server binary must be installed on the remote host):

```
servers> deploy root 192.168.1.10 mypassword my-server
Server 'my-server' (<hex-id>) deployed
  user_key:  <hex>
  admin_key: <hex>
```

### 2. Create a chat (admin)

Requires an admin key on the server. Generates a fresh AES-256-GCM encryption key, creates the chat on the server, then saves the chat locally. If either step fails nothing is written anywhere.

```
servers> admin create-chat general
Chat 'general' created
Key: <64-char hex>
```

The chat is saved locally in the `Disabled` state. Enable it and share the chat card with other users.

### 3. Enable and use the chat

```
servers> chats
servers/chats> enable
servers/chats> live
```

Other users can receive the chat via `share-data` / `receiving-data` (see the share workflow below) or via the manual KEM file flow (`gen-offer` / `respond-offer` / `load-response`).

### 4. Send a message

```
servers/chats> send Hello!
```

---

## Workflow: share server/chat with another user

Both users must have each other's contact cards first.

**Exchange contact cards:**

```
contacts> export-self ~/my_card.bin          # send to peer out-of-band
contacts> load ~/peer_card.bin Alice         # import peer's card
```

**Receiver** starts onion listener in the share window:

```
share> run-tor
share> receiving-data
Listening on <onion>:17777
```

**Sender** shares:

```
share> share-data
# wizard: pick contact (Alice) → pick server → pick chat → sends
```

The receiver's share window shows incoming items in real time. Once received, the server/chat appears locally (disabled by default). Enable it to start chatting.

---

## Identity

On first launch the client generates a persistent identity:

- **Dilithium2** signing keypair (post-quantum)
- **Tor v3** keypair (derives a unique `.onion` address)

The identity is stored in the local database and reused across sessions. A 16-character hex **contact ID** is derived from the public keys via BLAKE3.

```
contacts> whoami
ID:         a1b2c3d4e5f67890
Onion:      <56-char>.onion
Signing PK: <hex>
```

---

## Encryption

| Layer | Algorithm |
|---|---|
| Transport (gRPC) | AES-256-GCM with per-server shared key |
| Messages | AES-256-GCM with per-chat encryption key |
| Signatures | Dilithium2 (post-quantum) |
| Key exchange (sharing) | Kyber512 (post-quantum KEM) |
| Key derivation | BLAKE3 |

The server never sees plaintext messages or chat encryption keys.

---

## Binary card format

Credentials are exchanged as binary files (bincode-serialised structs). Server and chat data is shared via the `share-data` wizard or the manual KEM flow (`gen-offer` / `respond-offer` / `load-response`). Contact cards are exported with `export-self` / `export` and imported with `load` in the contacts window.

| File | Contains |
|---|---|
| Server card | `id`, `name`, `address`, `shared_key`, `admin_key` (optional) |
| Chat card | `server_id`, `chat_id`, `name`, `encryption_key` |
| Contact card | `signing_pk`, `tor_pk`, `onion_address` |
