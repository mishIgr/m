# m

Encrypted TUI messenger over gRPC. Messages are encrypted end-to-end on the client; the server stores and routes ciphertext only.

## Build

```bash
cargo build --release
# binaries: target/release/m_server, target/release/m_client
```

---

## Server

### Configuration

The server reads a TOML config file. Pass the path as the first argument (default: `~/.config/m/server.toml`).

```toml
[host]
bind_address = "0.0.0.0:50051"      # optional — this is the default

[database]
path = "~/.local/share/m/db.redb"   # redb database file (created if absent)

[logging]
path = "~/.local/share/m/logs/"     # log directory

[encryption]
user_key  = "<32 bytes as hex>"     # AES-256-GCM key for gRPC transport encryption
admin_key = "<32 bytes as hex>"     # key required for admin operations
```

**Key notes:**
- `user_key` must match `shared_key` in the client's server-import file.
- `admin_key` must match `admin_key` in the client's server-import file.
- Both keys are 32 bytes encoded as a 64-character lowercase hex string.

See [`config/server.toml`](config/server.toml) for a working example.

### Running

```bash
./target/release/m_server config/server.toml
```

---

## Client

### Configuration

The client reads its own TOML config. Pass the path with `--config` (default: `~/.config/m/client.toml`).

```toml
[storage]
db_path = "~/.local/share/m/client.redb"  # local redb database (created if absent)

[logging]          # optional
path = "~/.local/share/m/client-logs/"
```

See [`config/client.toml`](config/client.toml) for an example.

### Running

```bash
./target/release/m_client --config config/client.toml
```

This opens the interactive TUI. Type `help` inside the TUI to see all available commands.

### Layout

```
┌─ Output ──────────────┬─ Live ─────────────────────┐
│ > import-server ...   │ [10:01:02] [local/general] Hi│
│ Server 'local' imported│ [10:01:05] [local/general] Hey│
│                       │                              │
├─ Input ───────────────┴──────────────────────────────┤
│ > _                                                  │
└──────────────────────────────────────────────────────┘
```

- **Left pane** — output from all commands (always visible).
- **Right pane** — incoming live messages (visible when any server is enabled).
- **Input bar** — type commands here and press Enter.

### Multi-server and states

The client supports multiple servers simultaneously. Each server and each chat has a local state:

| State | Meaning |
|---|---|
| **Enabled** | Active — the client connects and subscribes automatically |
| **Disabled** | Inactive — no connection (default after import) |
| **Unavailable** | The server/chat stopped responding; set automatically on errors |

On startup the client auto-connects to all **Enabled** servers and subscribes to their **Enabled** chats. When a server becomes unreachable, it is marked **Unavailable**. To reconnect, use `enable server <id>`.

Each server has a short `id` (set during import) and a generated `name` (`id` + address hash).

### Initial setup

Before chatting you need to import a server connection and at least one chat, then enable them. Do this inside the TUI after launching it.

#### 1. Import server connection

Create a TOML file describing the server:

```toml
[connection]
id = "local"                       # short local identifier for this server
server_address = "http://127.0.0.1:50051"

[auth]
shared_key = "<64-char hex>"   # must equal user_key on the server
admin_key  = "<64-char hex>"   # must equal admin_key on the server (required for admin commands)
```

See [`config_test/client_server.toml`](config_test/client_server.toml) for an example.

Then inside the TUI:

```
> import-server config_test/client_server.toml
Server 'local' imported: http://127.0.0.1:50051
```

#### 2. Create a chat (admin)

```
> admin local create-chat general
Chat 'general' created on 'local'
```

#### 3. Import chat

Create a TOML file describing the chat:

```toml
server_id      = "local"           # must match the server id from step 1
chat_id        = "general"
name           = "General Chat"
encryption_key = "<64-char hex>"   # 32-byte key for end-to-end message encryption
```

`encryption_key` is a secret shared between chat participants. The server never sees it.

See [`config_test/client_chat.toml`](config_test/client_chat.toml) for an example.

Then inside the TUI:

```
> import-chat config_test/client_chat.toml
Chat imported: local/general (General Chat)
```

#### 4. Enable server and chat

After import, both server and chat are **Disabled** by default. Enable them to start receiving messages:

```
> enable server local
Server 'local' enabled and connected.

> enable chat local general
Chat 'local/general' enabled.
```

### Identity

On first launch the client generates a persistent identity:

- **Dilithium2** signing keypair (post-quantum digital signatures)
- **Tor v3** keypair (derives a unique `.onion` address)

The identity is stored in the local database and reused across sessions. A 16-character hex **contact ID** is derived from the public keys via BLAKE3.

```
> whoami
  ID:         a1b2c3d4e5f67890
  Onion:      <56-char>.onion
  Signing PK: <hex>
```

### Contacts

Contacts are exchanged out-of-band as binary files. Both clients must import each other's contact cards before they can share servers or chats.

```
> export-contact ~/my_card.bin
Contact card exported to ~/my_card.bin

> import-contact ~/alice_card.bin Alice
Contact 'Alice' (a1b2c3d4e5f67890) imported

> list contacts
  Alice (a1b2c3d4e5f67890) <56-char>.onion
```

### Sharing servers and chats

Two clients who have each other in contacts can share server and chat credentials directly over Tor, without any files.

**Receiver** starts a listener (requires a running Tor daemon with control port):

```
> share-listen
Share listener starting on <onion>:80 (local port 17777)
```

**Sender** connects via Tor SOCKS5 proxy and sends the data:

```
> share server local a1b2c3d4e5f67890
Shared server 'local' with a1b2c3d4e5f67890

> share chat local general a1b2c3d4e5f67890
Shared chat 'local/general' with a1b2c3d4e5f67890
```

The receiver's TUI shows incoming shares in the Live pane. Once received, the server/chat appears in the local database (disabled by default).

**Protocol (3 steps):**

1. Sender sends an `InviteMsg`: ephemeral Kyber512 public key signed with Dilithium2 + sender's contact ID.
2. Receiver verifies the sender is a known contact, encapsulates a shared secret with the KEM public key, signs the ciphertext with its own key, and replies with `InviteAck`.
3. Sender decapsulates the shared secret, encrypts the server/chat credentials with AES-256-GCM (key derived via BLAKE3), and sends the `SharePayload`.

**Merge logic:** if a server with the same `id` or `host` already exists locally, the record that grants more permissions is kept (i.e. admin key is never downgraded).

**Shared data:**

| Type | Fields |
|---|---|
| Server | `id`, `host`, `shared_key`, `admin_key` (optional) |
| Chat | `server_id`, `chat_id`, `name`, `encryption_key`, `server_admin_key` (optional) |

**Requirements:** a running Tor daemon with control port (default `127.0.0.1:9051`) and SOCKS5 proxy (default `127.0.0.1:9050`).

---

## TUI commands

```
m_client [--config <path>]
```

| Command | Description |
|---|---|
| **Identity & contacts** | |
| `whoami` | Show own identity (ID, onion address, signing PK) |
| `export-contact <path>` | Export contact card to binary file |
| `import-contact <path> [name]` | Import contact from binary file |
| `list contacts` | List all contacts |
| `rename-contact <id> <new_name>` | Rename a contact |
| `remove-contact <id>` | Remove a contact |
| **Sharing** | |
| `share-listen [port]` | Start Tor onion listener (default port 17777) |
| `share-stop` | Stop the share listener |
| `share server <server_id> <contact_id>` | Share server credentials with a contact |
| `share chat <server_id> <chat_id> <contact_id>` | Share chat credentials with a contact |
| **Servers & chats** | |
| `import-server <path>` | Import server connection from TOML |
| `import-chat <path>` | Import chat from TOML |
| `enable server <id>` | Enable server and connect |
| `disable server <id>` | Disable server and disconnect |
| `enable chat <server_id> <chat_id>` | Enable chat on a server |
| `disable chat <server_id> <chat_id>` | Disable chat on a server |
| `list servers` | List all servers with state |
| `list chats [server_id]` | List chats (optionally filtered by server) |
| `send <server_id> <chat_id> <message>` | Send a message |
| `history <server_id> <chat_id> [--limit N]` | Fetch message history (default limit 50) |
| **Admin** | |
| `admin <server_id> create-chat <id>` | Create a chat on the server |
| `admin <server_id> delete-chat <id>` | Delete a chat from the server |
| `admin <server_id> list-chats` | List all chats on the server |
| **General** | |
| `clear` | Clear the output pane |
| `help` | Show command list |
| `quit` | Exit |

### Example session

```
> whoami
  ID:         a1b2c3d4e5f67890
  Onion:      abcdef...xyz.onion
  Signing PK: 0123456789abcdef...

> export-contact ~/my_card.bin
Contact card exported to ~/my_card.bin

> import-contact ~/alice_card.bin Alice
Contact 'Alice' (f0e1d2c3b4a59687) imported

> import-server config_test/client_server.toml
Server 'local' imported: http://127.0.0.1:50051

> admin local create-chat general
Chat 'general' created on 'local'

> import-chat config_test/client_chat.toml
Chat imported: local/general (General Chat)

> enable server local
Server 'local' enabled and connected.

> enable chat local general
Chat 'local/general' enabled.

> send local general Hello!

> history local general --limit 10
[2024-01-01 10:00:00] Hello!

> share server local f0e1d2c3b4a59687
Shared server 'local' with f0e1d2c3b4a59687

> list servers
  local-a1b2c3d4 (http://127.0.0.1:50051) [enabled] [live]

> list contacts
  Alice (f0e1d2c3b4a59687) abcdef...xyz.onion

> quit
```
