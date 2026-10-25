# Carracho Protocol Reference

This document describes the network protocols used by Carracho (client 1.0b10r4,
server 1.0b13, tracker 1.1.1). Carracho was a Mac file sharing and chat
system published by Carracho Communications between 1997 and 2004. Everything
here was recovered from the original PowerPC binaries; each section lists the
functions it came from so it can be checked again.

| Part | Status |
|---|---|
| [Conventions](#1-conventions) | Done |
| [Tracker protocol](#3-tracker-protocol) | **Done**: implemented in `crates/carracho-tracker` |
| [Client/server protocol](#4-clientserver-protocol) | **Decoded.** A few field meanings are marked provisional. Session layer (4.1–4.4) implemented in `carracho-proto`. |

---

## 1. Conventions

- **Byte order:** big-endian (network order) for every integer. The originals
  ran on PowerPC and copied structs straight onto the wire.
- **Strings:** Pascal strings: one length byte, then that many bytes, with no
  terminator. The text is **Mac OS Roman**. (The release notes say a Unicode
  move was "prepared", but these versions still send Mac Roman.)
- **IP addresses:** IPv4 only, 4 bytes, network order.
- Integer types below are written `u8`, `u16` and `u32`; `pstr` means a Pascal
  string.

## 2. Components and ports

| Component | Default port | Transport | Purpose |
|---|---|---|---|
| Server | 6700 | TCP | Main client/server connection: login, chat, news, files |
| Server | 6701 (main port + 1) | TCP | Data connection: file transfers, news posting, log, banner, search (4.16) |
| Tracker | 6702 | UDP | Servers register themselves |
| Tracker | 6702 | TCP | Clients download the server list |

```
 ┌──────────┐  UDP 6702: "CTT\x01" registration, every 5 min  ┌─────────┐
 │  Server  │ ───────────────────────────────────────────────► │ Tracker │
 └──────────┘                                                   └─────────┘
      ▲                                                              ▲
      │ TCP 6700 (main protocol)       TCP 6702: "CTQ\x01QLI" query  │
      │                                then u32 count + entries      │
 ┌──────────┐ ───────────────────────────────────────────────────────┘
 │  Client  │
 └──────────┘
```

---

## 3. Tracker protocol

A tracker is a directory of servers. Servers announce themselves over UDP,
and clients fetch the current list over a short-lived TCP connection. The
tracker does not authenticate anything.

Sources:
- OS X tracker daemon (Mach-O, with C++ symbols): `RegistryServer::ProcessPacket`,
  `RegistryServer::BuildServerList`, `RegistryServer::ExpireServers`,
  `ClientSession::Run`, `main`.
- Classic tracker (PEF): the UDP handler at code offset `0xb54`, which does the
  input validation described below.
- Server 1.0b13: `TTrackerNotifier::RunThread`, `TTrackerNotifier::Pulse`.
- Client 1.0b10r4: `CTrackerInquiryThread::RunThread`,
  `CTrackerServerListView::DrawCell`, `TAdminManager::UploadTrackerList`.

### 3.1 Server registration (UDP, server → tracker)

A server sends one datagram to port 6702 on every tracker in its tracker list
when it starts, and again every 18,000 ticks (**5 minutes**).

| Offset | Size | Field | Notes |
|---|---|---|---|
| 0 | 4 | `magic` | `43 54 54 01`, i.e. `"CTT"` followed by version `0x01` |
| 4 | 4 | `address` | The server's own IPv4 address, from its listening socket |
| 8 | 2 | `port` | The server's main TCP port (default 6700) |
| 10 | 1+n | `name` | `pstr`: server name |
| … | 1+m | `description` | `pstr`: server description |
| … | 2 | `users` | Number of users currently connected |
| … | 4 | `flags` | See [3.3](#33-server-flags) |

The smallest valid datagram (both strings empty) is 18 bytes. The original
tracker reads at most 255 bytes per datagram.

**Tracker behaviour:**

1. **Validation.** The Classic tracker drops the datagram if any of these hold:
   - the total length is over 256 bytes,
   - the magic is not `CTT\x01`,
   - the name is longer than **40** bytes,
   - the description is longer than **100** bytes.

   The OS X tracker checks none of these; it stores whatever arrives.
2. **Address.** The OS X tracker (1.1+) **overwrites bytes 4–7 with the source
   IP of the datagram**. That way, servers behind NAT routers are listed under
   their public address (release notes: *"The tracker now lists servers behind
   routers like IPNetRouters which do not have a public IP address"*). The
   Classic tracker trusts the address in the packet.
3. **Key.** Servers are identified by `(address, port)`. A new datagram with an
   existing key replaces the old entry, and the replacement moves to the end of
   the list.
4. **Stored entry.** Bytes `4 … end` of the datagram, after the address is
   overwritten in step 2. The magic is dropped.
5. **Expiry.** An entry is removed once its last registration is more than
   **600 seconds** old. Expiry is checked whenever a list is built.

### 3.2 Server list query (TCP, client → tracker)

1. The client connects to tracker port 6702.
2. The client sends 7 bytes: `43 54 51 01 51 4C 49`, i.e. `"CTQ\x01"` + `"QLI"`.
   (The original client sends these as two writes, 4 bytes then 3. The
   tracker reads 4 bytes and then 3.)
3. If both parts match, the tracker replies:

   | Size | Field |
   |---|---|
   | 4 | `count`: `u32`, the number of entries |
   | … | `count` entries, each `u8 len` followed by `len` bytes |

   Each entry body is the stored registration from 3.1, step 4:

   | Offset | Size | Field |
   |---|---|---|
   | 0 | 4 | `address` (the observed source IP, on 1.1+ trackers) |
   | 4 | 2 | `port` |
   | 6 | 1+n | `name` (`pstr`) |
   | … | 1+m | `description` (`pstr`) |
   | … | 2 | `users` |
   | … | 4 | `flags` |

4. The Classic tracker then leaves the connection open until the client
   closes it (verified against the original tracker), so clients must parse
   the reply by `count` rather than read to end-of-stream. If the query
   doesn't match, the tracker closes without sending anything. The original
   tracker took about 3 s to answer under emulation; allow at least 10 s.

The Classic tracker gives up on reads after 600 ticks (10 s) and on writes
after 300 ticks (5 s).

The client parses each entry in field order and doesn't depend on `len`
beyond reading the entry body. It converts the name and description from Mac
Roman, and connects to `address:port` when the user opens an entry.

### 3.3 Server flags

`flags` is a `u32`, set by the server administrator in the client's
*Server Administration → Tracker* panel (`TAdminManager::UploadTrackerList`).
The server keeps the value in its preferences and sends it unchanged.

| Bits | Mask | Meaning |
|---|---|---|
| 31–24 | `0xFF000000` | Connection speed: an index into the client's `STR#` 130 resource (table below); 0 = unknown |
| 23 | `0x00800000` | *Register server with Carracho Trackers*. The server only sends registrations when this bit is set. |
| 22 | `0x00400000` | *Is private*. The client draws a padlock (`cicn` 269) next to the server. |
| 21–0 | | Unused (0) |

| Speed | Label | Speed | Label |
|---|---|---|---|
| 1 | 28.8K | 8 | Cable |
| 2 | 33.6K | 9 | DSL |
| 3 | 56K | 10 | T1 |
| 4 | 56K (duplicate in the original) | 11 | T3 |
| 5 | 64K | 12 | Ethernet |
| 6 | 112K | 13 | ATM |
| 7 | 128K | | |

### 3.4 Example

A server named `Retro` (description `Old Mac files`) at 192.0.2.10:6700, with
3 users, DSL, registered, not private:

```
43 54 54 01             magic "CTT\x01"
c0 00 02 0a             192.0.2.10
1a 2c                   port 6700
05 52 65 74 72 6f       "Retro"
0d 4f 6c 64 20 4d 61 63 20 66 69 6c 65 73   "Old Mac files"
00 03                   3 users
09 80 00 00             flags: speed 9 (DSL) | registered
```

The matching entry in a tracker's reply (when the datagram came from
198.51.100.7) would be:

```
00 00 00 01             count = 1
20                      len = 32
c6 33 64 07 1a 2c 05 52 65 74 72 6f 0d 4f 6c 64 20 4d 61 63 20 66 69 6c 65 73 00 03 09 80 00 00
```

### 3.5 Notes for the modern implementation

`carracho-tracker` does the following:

- It checks structure and limits the way the Classic tracker did (magic, 40-
  and 100-byte string limits, strings must fit inside the datagram) and drops
  anything that fails. Old servers never send malformed packets, so nothing
  that worked before is rejected.
- Like the OS X tracker, it stores the **source** IP rather than the claimed
  one.
- It expires entries after 600 s by default (configurable).
- It caps the number of listed servers, since the protocol has no
  authentication.
- It times out idle query connections after 10 s, as the Classic tracker did.

---

## 4. Client/server protocol

> **Status:** the whole command set is decoded. Connection setup, encryption,
> framing and login (4.1–4.4) have been checked by running the original code in
> an emulator; the rest comes from reading the code. Points that are
> provisional are marked as such: some field meanings in file search, the log
> and banner transfers, and newsgroup article headers.
>
> **Tested against the original server** (1.0b13 on Mac OS 9.2.1 under QEMU,
> with `carracho-probe`): greeting, login (admin and guest), re-keying, user
> list, user info, private messages, broadcast, nickname and state changes,
> server info, settings get, account list, transfers list, newsgroup lists,
> channel list, lobby join and chat, flat news get/post/delete, folder
> listing, create folder, file info, change file info, delete, and encrypted
> upload and download. Statements checked this way are marked *verified*.
> Not yet tested live: settings set, account changes, kick/ban, channel
> operator commands, newsgroup articles, search, log, banner.

Sources: server 1.0b13 `TResponderThread::*`, `TChannel::*`, `Tlci`/`Tlce`/`Tlcd`;
client 1.0b10r4 `TClientThread::DoAuthorization`, `TClientThread::ReceiveCommand`.
The `crypto` and `packet` modules of `carracho-proto` implement 4.2 and 4.3, and
their tests use vectors produced by running the original PowerPC code in an
emulator (`tools/pefemu.py`).

### 4.1 Connection setup

The client connects to the server's TCP port (default **6700**). Both sides
then exchange a 13-byte greeting **in the clear**:

| Bytes | Client sends | Server sends |
|---|---|---|
| 0–10 | `TCPCARRACHO` | `TCPCARRACHO` |
| 11–12 | `u16` client protocol version: **1** | `u16` server protocol version: **2** |

- The server checks only the first 11 bytes. If they're wrong, it logs
  "Unknown protocol" and disconnects.
- The client checks the 11 bytes and requires the server's version to be
  exactly 2. A higher version is error `0x32a` ("server is newer"); a lower
  one is `0x32c`.
- If the server is low on memory (`TServerApp::LowMemoryCallback`), it sends
  error 4 (see 4.5) and disconnects.

Everything after the greeting is framed and encrypted (4.2, 4.3). Login comes
next (4.4).

The server drops a connection when:
- it receives nothing (not even a keepalive) for 18,000 ticks (5 minutes);
- the source IP is banned or not allowed (`UServerUtils::CanAcceptIP`;
  logged as "Connection rejected");
- the source IP already has more connections than the per-IP limit ("Too
  many connections from this IP").

### 4.2 Encryption

Every frame is encrypted with **Blowfish** (standard π-digit tables, 16
rounds) in ECB mode, with an extra fixed XOR on each half of every block:

```
encrypt block (L, R):   R ^= 0x58022919;  (L, R) = Blowfish_encrypt(L, R);  L ^= 0x10576419
decrypt block (L, R):   L ^= 0x10576419;  (L, R) = Blowfish_decrypt(L, R);  R ^= 0x58022919
```

`L` and `R` are the block's two big-endian `u32` halves.

**Keys:**

1. Each connection starts with the 4-byte ASCII key **`YOYO`**, in both
   directions.
2. After a successful login, both sides re-key with the **session secret**
   (4.4). The server switches right after sending the login reply; the
   client switches right after receiving it.

Key expansion is the standard Blowfish schedule with no length limit: the
key bytes are cycled over the 18 P-array words, so only the first 72 bytes
matter.

### 4.3 Frames and packets

A frame on the wire is:

| Size | Field |
|---|---|
| 4 | `u32 L`: the length of what follows. **Not encrypted.** |
| L | Encrypted packet plus padding |

The sender appends 1 to 8 zero bytes so that `L` is a multiple of 8. It
always pads; a packet that's already a multiple of 8 gets 8 extra bytes.

The decrypted bytes are a **packet**: an 18-byte header, then the body.

| Offset | Size | Field |
|---|---|---|
| 0 | 4 | `command` |
| 4 | 4 | `task`: chosen by the requester and echoed in the reply; 0 in unsolicited packets |
| 8 | 4 | `length`: body length in bytes. The server rejects values over `0x20000` (128 KiB). |
| 12 | 4 | Reserved. The originals never set it (it holds stack garbage); ignore it. |
| 16 | 2 | `count`: number of fields in the body |

The body is `count` **fields**:

| Size | Field |
|---|---|
| 4 | `u32 tag` |
| 2 | `u16 n`: data length |
| n | data |

Field data is one of these:
- a big-endian integer (`u8`, `u16` or `u32`, sized by `n`);
- text: Mac Roman, `n` bytes, no length prefix and no terminator;
- a structure, described per command.

Each command's tags are separate; tag 1 in one command has nothing to do
with tag 1 in another. Receivers skip tags they don't know. The originals
generally read the fields they expect in any order.

**Missing fields.** When a request lacks a field the original server needs
(for example broadcast without its text, or change file info without the
name), it drops the connection rather than sending an error. A modern
server should send error 0 with a suitable code instead; old clients never
send such requests.

**Strings inside structures** are written as `u16` length plus bytes
(`Stream::WriteString`).

### 4.4 Login

After the greeting:

1. **Server → client, command 1 (challenge):**

   | Tag | Data |
   |---|---|
   | 1 | 12 random bytes: the challenge |

2. Both sides compute the **session secret** from the account password and
   the challenge. For `i` from 0 to `max(len(password), 12) − 1`, append two
   bytes:
   - `password[i] XOR 0x21`, or, once the password runs out,
     `(i + 1 − len(password)) XOR 0x21`;
   - `challenge[i]`, or, once the challenge runs out,
     `i + 1 − 12`.

   For example, with an empty password the secret is
   `21^1, c[0], 21^2, c[1], …, 21^12, c[11]` (24 bytes).

3. **Client → server, command 2 (login):**

   | Tag | Data |
   |---|---|
   | 1 | Login name (≤ 30 bytes) |
   | 2 | **Response**: MD5 of the session secret, as 32 lowercase hex characters |
   | 4 | Nickname (≤ 64 bytes) |
   | 5 | *Optional:* user icon, an opaque 636-byte (`0x27c`) blob |

   The server also accepts tag 3 and ignores it. Guests log in as
   **`anonymous`** with an empty password: the shipped `Accounts` file has two
   accounts, `admin` and `anonymous`, both without passwords. An empty login
   name gets error `0x64` (verified).

4. **Server checks**, in this order:
   - the account exists (otherwise error `0x64`, "Incorrect login");
   - the server isn't full: more than the maximum number of users is only
     allowed for accounts with privilege bit 0 (otherwise error `0x69`, "Too
     many connections");
   - the response matches (otherwise error `0x64`).

   On any error the server disconnects.

   The challenge, the login reply and any login error all carry **task 0**,
   not the login request's task (verified).

5. **Server → client, command 3 (login accepted):**

   | Tag | Data |
   |---|---|
   | 1 | 12 bytes: `u32` your user ID, then the 64-bit privilege mask as two `u32`s (high word first) (4.5) |
   | 2 | Server name |
   | 3 | User list (4.7) |
   | `0x21` | `u16`: most simultaneous file transfers per user |
   | 5 | `u16`: server protocol level, **2**. At level ≥ 2 the client encrypts file transfers. |
   | 4 | *Only if the server has an agreement:* agreement text, which the client shows before continuing |

6. Both sides switch to the session secret as the Blowfish key (4.2). The
   server tells everyone else the user has joined (push 7, 4.7).

After login the original client immediately sends command `0x16` (extended
user info, fields `0xb0`–`0xb2`) and asks for the flat news (`0xFD0001`).

### 4.5 Replies, errors and privileges

**Success replies.** A request is answered with one of:
- **command `0xFF` (task complete):** the request's `task`, no fields;
- a reply packet whose `command` is the request's command (or a
  command-specific reply command), with the request's `task`;
- for some commands, nothing at all. Each command's section says which.

**Errors.** Command **0**, with the request's `task`, carrying one field:

| Tag | Data |
|---|---|
| 1 | `u16` error code |

| Code | Meaning (from where the server sends it) |
|---|---|
| 2 | No privilege for this operation |
| 4 | Server is low on memory and refusing logins |
| `0x64` (100) | Incorrect login |
| `0x65` (101) | User not found |
| `0x69` (105) | Server full |
| `0xc8` (200) | Channel not found, or no channel name/ID given |
| `0xca` (202) | Wrong channel password |
| `0xcb` (203) | Channel is moderated and you have neither operator nor voice |
| `0xcc` (204) | You're not a channel operator |
| `0xcd` (205) | Only operators may change this channel's topic |
| `0xce` (206) | Already in this channel |
| `0xcf` (207) | Not a member of this channel |
| `0xd0` (208) | You're not in this channel |
| `0xd1` (209) | Already in the maximum number of channels (6) |
| `0x13e` (318) | Busy (an "empty trash" operation is already running) |
| `0x3e7` (999) | Unknown command |

The client has message text for each code (resource `ERR`); the meanings
above come from the server's behaviour.

**Privileges.** Each account has a 64-bit privilege mask, sent in the login
reply as two `u32`s. The original tests bits with the Mac OS `BitTst`
convention, where **bit 0 is the most significant bit of the first byte**:
bit *n* is mask `0x8000000000000000 >> n`.

Names come from the checkboxes in the client's account editor
(`TAccountEditor`). "File" and "folder" rights were matched to bits by the
checkboxes' positions on screen.

| Bit | Mask (high `u32`, low `u32`) | Meaning |
|---|---|---|
| 0 | `80000000 00000000` | Administrator (user mode). Can exceed the user limit, gets operator in the lobby, shown with flag `0x8000` in the user list |
| 1 | `40000000 00000000` | Account holder (user mode). With neither bit 0 nor bit 1 the user is a guest. |
| 3 | `10000000 00000000` | Personal directory nested in the root directory |
| 4 | `08000000 00000000` | Personal directory is the root directory (search disabled) |
| `0x0a` | `00200000 00000000` | Can download |
| `0x0b` | `00100000 00000000` | Can upload |
| `0x0c` | `00080000 00000000` | Can upload anywhere |
| `0x0d` | `00040000 00000000` | Can view drop boxes |
| `0x0e` | `00020000 00000000` | Can change folder mode |
| `0x0f` | `00010000 00000000` | Can move files |
| `0x10` | `00008000 00000000` | Can delete files |
| `0x11` | `00004000 00000000` | Can rename files |
| `0x12` | `00002000 00000000` | Can comment files |
| `0x13` | `00001000 00000000` | Can create folders |
| `0x14` | `00000800 00000000` | Can move folders |
| `0x15` | `00000400 00000000` | Can rename folders |
| `0x16` | `00000200 00000000` | Can delete folders |
| `0x17` | `00000100 00000000` | Can comment folders |
| `0x18` | `00000080 00000000` | Can disconnect users (4.13) |
| `0x19` | `00000040 00000000` | Can get extended user info (4.7) |
| `0x1c` | `00000008 00000000` | Can join chat rooms (4.10) |
| `0x21` | `00000000 40000000` | Account management (4.14) |
| `0x22` | `00000000 20000000` | Newsgroup management; news expiry setting |
| `0x23` | `00000000 10000000` | Can view server log |
| `0x24` | `00000000 08000000` | Edit server information (name, location, operator, description) |
| `0x25` | `00000000 04000000` | Can view statistics |
| `0x27` | `00000000 01000000` | Can empty server trash |
| `0x28` | `00000000 00800000` | Can broadcast messages (4.9) |
| `0x2a` | `00000000 00200000` | Can ban users (4.13) |
| `0x2c` | `00000000 00080000` | Edit server agreement |
| `0x2d` | `00000000 00040000` | Edit advanced settings (port, limits, IP list) |
| `0x2e` | `00000000 00020000` | Can edit trackers |
| `0x2f` | `00000000 00010000` | Can search for files |
| `0x30` | `00000000 00008000` | Can post to flat news |

Bits 2, 5–9, `0x1a`, `0x1b`, `0x1d`–`0x20`, `0x26`, `0x29`, `0x2b` and
`0x31`–`0x3f` aren't used by these versions.

### 4.6 Command table

From the server's dispatcher (`TResponderThread::WaitForCommands`). "Push"
means the server also sends this command unprompted.

| Command | Handler | Section |
|---|---|---|
| `0x00` | (error reply, server → client) | 4.5 |
| `0x01` | (login challenge, server → client) | 4.4 |
| `0x02` | Login | 4.4 |
| `0x03` | (login accepted, server → client) | 4.4 |
| `0x04` | Disconnect (kick) users | 4.13 |
| `0x05` | Ban users | 4.13 |
| `0x06` | `SendPrivateMessage` (push) | 4.8 |
| `0x07` | (push) user joined the server | 4.7 |
| `0x08` | (push) user left the server | 4.7 |
| `0x09` | List folder | 4.15 |
| `0x0c` | `DeclineInvitation` (push) | 4.10 |
| `0x0f` | `ChangeChannelUserMode` (push) | 4.10 |
| `0x10` | Create folder | 4.15 |
| `0x11` | Delete file or folder | 4.15 |
| `0x12` | Get file info (reply is command `0x14`) | 4.15 |
| `0x13` | Change file info | 4.15 |
| `0x14` | Move file or folder; also the file info reply | 4.15 |
| `0x15` | Empty trash | 4.15 |
| `0x16` | Set extended user info | 4.7 |
| `0x17` | Get user info | 4.7 |
| `0x18` | Change nickname/icon (push) | 4.7 |
| `0x40` | File search on the main connection (`CFileSearchThread`; the original client uses the data connection instead) | 4.16 |
| `0x80` | `JoinChannel` (push: channel info) | 4.10 |
| `0x81` | `LeaveChannel` | 4.10 |
| `0x82` | `DoChat` (push) | 4.10 |
| `0x84` | `SetChannelSettings` (push) | 4.10 |
| `0x86` | Channel list | 4.10 |
| `0x87` | (push) user joined a channel | 4.10 |
| `0x88` | (push) user left a channel | 4.10 |
| `0x89` | `InviteUser` (push) | 4.10 |
| `0xa0` | List newsgroups (reply `0xa1`) | 4.18 |
| `0xa1` | (newsgroup list / article reply, server → client) | 4.18 |
| `0xa2` | Read article (reply `0xa1`) | 4.18 |
| `0xa4` | (admin newsgroup list reply, server → client) | 4.18 |
| `0xa5` | Add newsgroup | 4.18 |
| `0xa6` | Delete newsgroup | 4.18 |
| `0xa7` | Change newsgroup | 4.18 |
| `0xa8` | List newsgroups for administration (reply `0xa4`) | 4.18 |
| `0xa9` | Delete article | 4.18 |
| `0xaa` | (push) newsgroup added, changed or deleted | 4.18 |
| `0xc0` | (settings reply, server → client) | 4.12 |
| `0xc1` | Get server settings | 4.12 |
| `0xc2` | Set server settings | 4.12 |
| `0xc3` | Server information | 4.11 |
| `0xca` | (account record reply, server → client) | 4.14 |
| `0xcb` | Create or change account | 4.14 |
| `0xcc` | Get account | 4.14 |
| `0xcd` | List accounts | 4.14 |
| `0xce` | (push) account created, changed or deleted | 4.14 |
| `0xcf` | Delete account | 4.14 |
| `0xd0` | `BroadcastMessage` (push) | 4.9 |
| `0xe0` | Transfers in progress | 4.15 |
| `0xff` | (task complete, server → client) | 4.5 |
| `0xFD0000` | Post flat news (push) | 4.17 |
| `0xFD0001` | Get flat news | 4.17 |
| `0xFD0002` | Delete one flat news article (push) | 4.17 |
| `0xFD0003` | Delete all flat news (push) | 4.17 |
| `0xF0000000` | Set user state (push) | 4.7 |
| `0xFFFFFFFF` | Keepalive: resets the 5-minute timeout without counting as activity for idle detection | |

The server marks a user idle (user flag `0x0100`) after 36,000 ticks
(10 minutes) without a non-keepalive command.

### 4.7 Users

**User list** (login reply tag 3): a `u32` count, then for each logged-in user:

| Size | Field |
|---|---|
| 2+n | Nickname (string) |
| 2 | `u16` flags: `0x8000` administrator (privilege bit 0); `0x0100` idle |
| 4 | `u32` user ID |
| 4 | `s32` icon length *k* (0 or 636) |
| k | Icon |

**Push 7: user joined the server.**

| Tag | Data |
|---|---|
| 1 | `u32` user ID |
| 2 | Nickname |
| 3 | `u16` flags (as in the user list) |
| `0xb4` | *If the user has an icon:* 636-byte icon |

**Push 8: user left the server.**

| Tag | Data |
|---|---|
| 1 | `u32` user ID |

**Push `0x18`: user changed nickname or icon.** Sent to everyone after a
`0x18` request (below).

| Tag | Data |
|---|---|
| 1 | `u32` user ID |
| 2 | Nickname |
| `0xb4` | *Only if the icon changed:* the new icon (empty if removed) |

**Push `0xF0000000`: user state changed.**

| Tag | Data |
|---|---|
| 1 | `u32` user ID |
| `0xF0000001` | `u8` state |

The server sends this when a client sets its state (command `0xF0000000`,
same `0xF0000001` field), when a user goes idle after 10 minutes (state 1),
and when an idle user becomes active again (state 0).

#### Change nickname or icon: `0x18`

| Tag | Data |
|---|---|
| 2 | New nickname (≤ 64) |
| 5 | New icon (≤ 636 bytes; length 0 removes the icon) |

There's no reply; everyone, the sender included, receives push `0x18`.

#### Set extended info: `0x16`

| Tag | Data |
|---|---|
| `0xb0` | Real name (≤ 64) |
| `0xb1` | E-mail address (≤ 64) |
| `0xb2` | "About me" (≤ 128) |

There's no reply. The original client sends this right after login, using the
values from its preferences.

#### Get user info: `0x17`

**Request:** tag 1 (`u32` user ID). An unknown user gets error `0x65`.

**Reply:** command `0x17` with the request's task:

| Tag | Data |
|---|---|
| `0xb4` | *If the user has an icon:* icon |
| 4 | Nickname |
| `0xb1` | E-mail address |
| `0xb2` | About me |
| `0xb0` | Real name |

If the **requester** has privilege bit `0x19`, the reply also has:

| Tag | Data |
|---|---|
| `0x85` | `u32` login time (Mac OS seconds since 1904) |
| `0x87` | `u32` ticks since the user's last activity |
| `0x84` | `u32` IP address |
| `0x88` | Account (login) name |
| `0x86` | The user's file transfers: `u16` count, then for each: `u32`, `s8`, file name (string), `s8` |

> **Original server bug:** tag `0x86`'s declared length assumes 11 bytes plus
> the name length per transfer; the entries are 3 bytes shorter. Parse the
> list by its count.

### 4.8 Private messages (command 6)

**Request:**

| Tag | Data |
|---|---|
| 1 | `u32` recipient's user ID |
| 2 | Message text (≤ 32 KiB, required) |
| 3 | *Optional:* second text (≤ 32 KiB), passed through unchanged |

**Server behaviour:**
- If the recipient doesn't exist, it sends error `0x65`.
- Otherwise it sends the recipient **command 6** with tag 1 set to the
  **sender's** user ID and tags 2/3 copied, then answers the sender with task
  complete (`0xFF`).

Easter egg: a message whose text is exactly `secret about box` comes back to
the sender as the server's credits.

### 4.9 Broadcast messages (command `0xd0`)

Needs privilege bit `0x28`; without it the server sends error 2.

**Request:**

| Tag | Data |
|---|---|
| 1 | Message text (1–512 bytes) |

The server sends **every** logged-in user command `0xd0` with tag 1 (the text)
and tag 2 (`u32` sender's user ID), then answers the sender with task
complete.

### 4.10 Chat channels

Users chat in **channels**. Channel 1 is the server's lobby; any other channel
is created when someone joins a name that doesn't exist yet. A user can be in
at most 6 channels.

**Channel flags** (`u16`, MSB-first bit numbers):

| Mask | Bit | Meaning |
|---|---|---|
| `0x8000` | 0 | Server channel: set only on the lobby (channel 1). It isn't deleted when empty, and administrators get operator status when they join. |
| `0x4000` | 1 | Kept as it was when settings change; meaning unknown |
| `0x2000` | 2 | Hidden: left out of the channel list |
| `0x1000` | 3 | Moderated: only operators and voiced members may talk |
| `0x0800` | 4 | Only operators may change the topic |

Clients may change the other bits freely.

**Member mode** (`u8`): `0x80` operator, `0x40` voice. The first user into a
new channel becomes its operator.

#### Join: `0x80`

Needs privilege bit `0x1c`.

| Tag | Data |
|---|---|
| 0 | `u32` channel ID, or 0 to join by name |
| 1 | Channel name (≤ 64) |
| 9 | Channel password (≤ 32) |

**Errors:** 2 (no privilege), `0xd1` (too many channels), `0xc8` (neither ID
nor name), `0xca` (wrong password), `0xce` (already a member).

**Reply:** command `0x80` with the request's task:

| Tag | Data |
|---|---|
| 1 | Channel name |
| 4 | Topic |
| 0 | `u32` channel ID |
| 6 | `u16` channel flags (but see below) |
| 5 | Members: `u32` count, then for each member `u32` user ID + `u8` mode |

> **Original server bug:** in this reply, tag 6 carries the *upper* half of a
> 32-bit copy of the flags, so it is always `0x0000` (verified: the lobby,
> whose flags are `0x8000`, reports `0x0000`). Clients get the real flags from
> push `0x84` and the channel list. A compatible server should send the real
> flags; old clients handle both.

All members, **the joiner included**, receive **push `0x87`**: tag 0 (`u32`
channel), tag 7 (`u32` user ID), tag 8 (`u8` mode). The joiner gets it just
before the join reply (verified). The original server names the lobby
`Public`.

#### Leave: `0x81`

| Tag | Data |
|---|---|
| 0 | `u32` channel ID |

The reply is command `0x81` with the request's task and no fields, even if the
channel doesn't exist. Remaining members receive **push `0x88`**: tag 0
(channel), tag 7 (user ID). When the last member leaves, a normal channel is
deleted; the lobby is kept and its topic reset to the default.

#### Chat: `0x82`

| Tag | Data |
|---|---|
| 0 | `u32` channel ID |
| 2 | Text (≤ 2048, required) |
| 3 | `u8` style; 1 is an "action" (the `/me` style) |

(Tag 1 is also read as a `u8` and ignored.)

**Rules:**
- The sender must be a member.
- In a moderated channel, the sender needs operator or voice (otherwise error
  `0xcb`).
- Messages to a channel that doesn't exist are silently dropped.

**Delivery:** every member, the sender included, receives command `0x82` with
tag 0 (channel), tag 7 (`u32` sender's user ID), tag 3 (style) and tag 2
(text). There is no separate reply.

#### Set member mode: `0x0f`

| Tag | Data |
|---|---|
| 0 | `u32` channel ID |
| 7 | `u32` target user ID |
| 8 | `u8` new mode |

The requester must be an operator in the channel (errors `0xd0` not in
channel, `0xcc` not an operator, `0xcf` target not a member). Members receive
**push `0x0f`** with the same three tags. There is no reply on success.

#### Channel settings: `0x84`

| Tag | Data |
|---|---|
| 0 | `u32` channel ID |
| 4 | Topic (≤ 256) |
| 6 | `u16` flags |

**Rules:**
- The requester must be a member (error `0xcf`).
- If the channel has flag `0x0800`, only an operator may change the topic
  (error `0xcd`).
- Only an operator may change the flags. The flags of channel 1 can't be
  changed, and flags `0x8000` and `0x4000` are always kept as they were.
- The server records who set the topic.

Members receive **push `0x84`**: tag 0 (channel), tag 4 (topic), tag 6 (flags).
There is no separate reply. An unknown channel gets error `0xc8`.

#### Channel list: `0x86`

No request fields. The reply is command `0x86` with the request's task and one
field:

| Tag | Data |
|---|---|
| `0xa` | `u32` count, then for each channel that isn't hidden: `u32` ID, `u32` member count, `s16` flags, name (string) |

#### Invite: `0x89`

| Tag | Data |
|---|---|
| 0 | `u32` channel ID |
| 7 | `u32` user ID to invite |

**Behaviour:**
- An unknown channel gets error `0xc8`.
- If the user exists and isn't already a member, they receive **push
  `0x89`**: tag 0 (channel), tag `0xb` (`u32` inviter's user ID), tag 1
  (channel name). The inviter gets task complete.
- Otherwise nothing is sent. The original doesn't check that the inviter is in
  the channel.

#### Decline invitation: `0x0c`

| Tag | Data |
|---|---|
| 0 | `u32` channel ID |
| `0xb` | `u32` user ID of whoever sent the invitation |

The inviter receives **push `0x0c`**: tag 0 (channel), tag 7 (`u32` user ID
of the user who declined). There is no reply.

### 4.11 Server information: `0xc3`

No request fields. Any user may ask. The reply is command `0xc3` with the
request's task:

| Tag | Data |
|---|---|
| 2 | Server name |
| 6 | Location |
| 7 | Operator |
| 8 | Description (≤ 255) |

The administrator sets these with command `0xc2` (4.12). Location and operator
default to `unknown`.

### 4.12 Server settings: `0xc1` (get) and `0xc2` (set)

Administrators read and change the server's settings with these two commands.
Each setting has a tag, and each tag needs a privilege bit (4.5).

**Get (`0xc1`):** the request lists the wanted tags as fields of **length 0**.
The reply is command **`0xc0`** with the request's task, holding a field for
each requested tag the user may read. Tags the user may not read are left out
without an error.

**Set (`0xc2`):** the request carries the new values. The server applies the
tags the user may change, saves its preferences and answers with task complete
(`0xFF`).

> **Original server bug:** when the user may not change a tag, the original
> moves on without skipping that field's data, so the rest of the request is
> misread. A compatible server should skip it.

| Tag | Privilege bit | Get | Set | Data |
|---|---|---|---|---|
| 4 | `0x2c` | ✓ | ✓ | Agreement text shown to users at login. With no agreement the original sends a single `0x00` byte. The original also stores whether an agreement is in use (`0x1000b488`); not yet decoded. |
| 5 | `0x24` | ✓ | ✓ | Server name |
| 6 | `0x24` | ✓ | ✓ | Location |
| 7 | `0x24` | ✓ | ✓ | Operator |
| 8 | `0x24` | ✓ | ✓ | Description |
| 9 | `0x2d` | ✓ | ✓ | `u16` server port |
| `0xc` | `0x22` | ✓ | ✓ | `u16` time of day to expire old news articles: `(hour << 8) \| minute`, **in GMT**. The server converts to and from its own time zone. |
| `0x20` | `0x2d` | ✓ | ✓ | `u16` most simultaneous file transfers (whole server) |
| `0x21` | `0x2d` | ✓ | ✓ | `u16` most simultaneous file transfers per user |
| `0x22` | `0x2d` | ✓ | ✓ | `u16` most connected users |
| `0x23` | `0x2d` | ✓ | ✓ | `u16` most connections per IP address |
| `0x35` | get `0x25`, set `0x2d` | ✓ | ✓ | `s16` deepest folder level for folder downloads |
| `0x2f` | `0x2d` | ✓ | ✓ | IP allow/deny list (below) |
| `0x30` | `0x2e` | ✓ | ✓ | Tracker list (below) |
| `0x32` | `0x2e` | ✓ | ✓ | `u32` tracker flags: speed, "register", "private" (3.3). See the bug note below. |
| `0x33` | `0x2e` | ✓ | ✓ | Description sent to trackers (≤ 100) |
| `0x24` | `0x25` | ✓ | | `u32` hits (total connections) |
| `0x2e` | `0x25` | ✓ | | `u32` currently connected |
| `0x25` | `0x25` | ✓ | | `u32` connection peak |
| `0x26` | `0x25` | ✓ | | `u32` incorrect logins |
| `0x27` | `0x25` | ✓ | | `u32` administrators connected |
| `0x28` | `0x25` | ✓ | | `u32` account holders connected |
| `0x29` | `0x25` | ✓ | | `u32` guests connected |
| `0x2a` | `0x25` | ✓ | | `u32` downloads in progress |
| `0x2b` | `0x25` | ✓ | | `u32` total downloads |
| `0x2c` | `0x25` | ✓ | | `u32` uploads in progress |
| `0x2d` | `0x25` | ✓ | | `u32` total uploads |
| `0x34` | `0x25` | ✓ | | `u32` total private messages |
| `0x36` | `0x25` | ✓ | | `u32` (another counter; not shown by the client) |

> **Original server bug:** in the get reply (`0xc0`), tag `0x32`'s length is
> declared as **3** but 4 bytes follow (verified). A client must special-case
> it, or the rest of the packet is misparsed; the packet's body length is
> correct. A compatible server should declare 4.

The get reply contains the requested tags in request order, leaving out tags
the server doesn't know (`0x31`).

**IP allow/deny list (tag `0x2f`):** a `u32` count, then 10-byte entries:

| Size | Field |
|---|---|
| 4 | `u32` address |
| 4 | `u32` mask |
| 1 | `u8` deny: nonzero blocks matching addresses |
| 1 | Padding |

A connecting address is checked against the entries in order; the first entry
where `(ip & mask) == address` decides. Addresses matching no entry are
allowed.

**Tracker list (tag `0x30`):** the trackers the server registers with (3.1). A
`u16` count, then for each tracker:

| Size | Field |
|---|---|
| 2+n | Name (≤ 32) |
| 2+n | Host name or address (≤ 64) |
| 2+n | Unused; empty |
| 4 | `u32`, unused; 0 |

### 4.13 Disconnecting and banning users

#### Disconnect (kick): `0x04`

Needs privilege bit `0x18` (error 2 otherwise).

| Tag | Data |
|---|---|
| 1 | `u32` user ID; may be repeated to kick several users |

Each named user is disconnected. The requester gets task complete, unless the
last ID was their own.

#### Ban: `0x05`

Needs privilege bit `0x2a`. The fields are the same as for disconnect. For each
user, the server inserts `{address = user's IP, mask = 0xFFFFFFFF, deny = 1}`
at the **front** of the IP allow/deny list (4.12), then disconnects them. The
requester gets task complete, as with disconnect.

### 4.14 Accounts

All account commands need privilege bit `0x21` (error 2 otherwise).

**Account record.** Single accounts travel as a raw 214-byte (`0xd6`) structure.
Strings are NUL-terminated within fixed-size areas; bytes after the
terminator are unspecified.

| Offset | Size | Field |
|---|---|---|
| `0x00` | 64 | Login name (1–31 characters, no `:`) |
| `0x40` | 65 | Real name |
| `0x81` | 65 | Password (see below) |
| `0xc2` | 4 | `u32` created (Mac OS seconds since 1904) |
| `0xc6` | 4 | `u32` last modified |
| `0xca` | 4 | `u32` last login |
| `0xce` | 8 | Privilege mask (4.5) |

**Passwords on the wire:**
- When the server sends a record, it replaces every password character with
  `0xA5` (•), keeping the length.
- When the client sends a record, the password is scrambled with the
  original's `EncryptDecryptPassword`: byte *i* is XORed with `0x88`, `0x44`,
  `0x12` for *i* mod 3 = 0, 1, 2, stopping at the first zero byte.
- When editing, a password whose **first byte is `0xAD`** means "keep the
  current password".

**Account list entry.** 136 (`0x88`) bytes:

| Offset | Size | Field |
|---|---|---|
| `0x00` | 64 | Login name |
| `0x40` | 66 | Real name |
| `0x82` | 4 | `u32` last login |
| `0x86` | 1 | `u8` class: 2 administrator, 1 account holder, 0 guest |
| `0x87` | 1 | Padding |

**Errors:** `0x66` (no such account), `0x67` (invalid login name), `0x6a` (an
account with that name already exists; names are compared
case-insensitively), plus file errors.

#### List accounts: `0xcd`

No request fields. The reply is command `0xcd` with the request's task:

| Tag | Data |
|---|---|
| `0x10` | `u32` count, then `count` list entries |

#### Get account: `0xcc`

**Request:** tag 2 (login name, ≤ 31).

**Reply:** command **`0xca`** with the request's task:

| Tag | Data |
|---|---|
| 1 | Account record (214 bytes), password masked |

#### Create or change account: `0xcb`

| Tag | Data |
|---|---|
| 3 | *When editing:* the account's current login name. Leave it out to create a new account. |
| 1 | Account record (214 bytes), password scrambled |
| 2 | Accepted and ignored |

**Behaviour:**
- **Editing:** the server replaces the account named by tag 3 with the
  record. A renamed login takes effect, and a password starting with `0xAD`
  keeps the old one.
- **Creating:** the server sets all three dates to now and creates the
  account's personal folder.
- On success it sends task complete, then **push `0xce`** to the requester:

  | Tag | Data |
  |---|---|
  | `0x11` | `u8`: 1 modified, 0 created |
  | 3 | Login name as given in the request |
  | 1 | List entry (136 bytes) for the account |

#### Delete account: `0xcf`

**Request:** tag 2 (login name, ≤ 31).

On success the requester gets task complete and **push `0xce`** with tag `0x11`
= 2 (deleted) and tag 3 (login name).

### 4.15 Files

The server shares one folder tree. Accounts with privilege bit 3 or 4 also
have a **personal folder**, which appears as `~login` (4.5).

**Paths** are strings of folder and file names separated by the byte **`0x01`**,
starting from the shared root: for example `Software 0x01 Games 0x01 Tetris`.
- Leading separators are ignored, and an empty path is the root.
- A first component `~login` (the requester's own login) means their personal
  folder.
- Components may not contain `:`, may not be `..`, and are at most 255 bytes.
  Whole paths are at most 4096 bytes.
- File and folder names, in paths and in listings, are **UTF-8**.

**Dates** throughout the protocol are `u32` Mac OS seconds since 1904-01-01,
**GMT**.

**Folder flags** (`u16`), stored per folder in a hidden `_FOLDER_INFO_` file:

| Mask | Meaning |
|---|---|
| `0x8000` | Ordinary folder: what `GetFolderFlags` reports when a folder has no stored flags. `SetFolderFlags` clears this bit before storing, so setting flags `0` gives back `0x8000` (verified). |
| `0x4000` | Upload folder |
| `0x2000` | Drop box: only users with privilege bit `0xd` may see inside |

Files have flags 0.

**Errors:** `0x12c` (300) item not found; `0x12d` (301) not allowed inside a
drop box; `0x12e` (302) no download privilege; `0x131` (305) destination
folder not found; `0x138` (312) can't download from a drop box; `0x13c`/`0x13d`
(316/317) no privilege to comment on files/folders; plus 2 for missing
privileges.

#### List folder: `0x09`

**Request:** tag 1 (path; empty or missing for the root).

**Reply:** command `0x09` with the request's task, one field:

| Tag | Data |
|---|---|
| 2 | Listing (below) |

**Listing:**
- the requested path (string), or a `u16` 0 for the root;
- a `u16` count;
- `count` entries:

| Size | Field |
|---|---|
| 2 | `u16` entry length: name length + 20 |
| 2 | `u16` name length *n* |
| n | Name (UTF-8) |
| 4 | `u32`: size in bytes (data + resource fork) for files; number of items for folders |
| 4 | `u32` modification date |
| 4 | `u32` Mac **creator** |
| 4 | `u32` Mac **type** (packages: the package's type) |
| 2 | `u16` folder flags (0 for files) |

Note the order: creator before type (verified: a `TEXT`/`ttxt` file lists as
`ttxt`, `TEXT`). Folders list `????` for both.

**What's left out:**
- invisible items and names starting with `.`;
- the hidden folder-info file;
- inside a drop box, for users without privilege bit `0xd`, every item except
  partial uploads.

Broken aliases are listed with type `CarS` and creator `BROK`. In the root, a
user with a nested personal folder (bit 3) also sees an entry `~login` with
flags `0xC000`.

#### Get file info: `0x12`

**Request:** tag 1 (path).

**Reply:** command **`0x14`** with the request's task:

| Tag | Data |
|---|---|
| 1 | Path, as requested |
| 2 | Name |
| 3 | 30 bytes: `u16` folder flags, `u32` size, `u32` created, `u32` modified, then the 16-byte Finder info (`u32` type, `u32` creator, `u16` Finder flags, `u32` icon position, `u16` folder) |
| 4 | Finder comment |

#### Change file info: `0x13`

| Tag | Data |
|---|---|
| 1 | Path |
| 2 | New name (≤ 255). **Required**: the original drops the connection without it. Send the current name to keep it. |
| 4 | New comment (≤ 512) |
| 3 | `u16` new folder flags |

**Rules:**
- Renaming needs privilege bit `0x15` for folders or `0x11` for files.
- Changing the comment needs `0x17` or `0x12` (errors `0x13d`/`0x13c`).
- Changing folder flags needs `0xe`; without it the change is silently
  ignored.
- Inside a drop box, a user without `0xd` gets error `0x12d`.

The reply is task complete.

#### Move: `0x14`

| Tag | Data |
|---|---|
| 1 | Path of the item to move |
| 2 | Path of the destination folder |

Moving needs privilege bit `0x14` for folders or `0xf` for files. The reply is
task complete; errors are `0x12c` (source) and `0x131` (destination).

#### Delete: `0x11`

**Request:** tag 1 (path). Deleting needs privilege bit `0x16` for folders or
`0x10` for files. Folders are deleted with their contents (verified). The
reply is task complete.

#### Create folder: `0x10`

Needs privilege bit `0x13`.

| Tag | Data |
|---|---|
| 1 | Path of the parent folder |
| 3 | New folder's name (≤ 250) |
| 2 | `u16` folder flags for the new folder |

The reply is task complete. Error `0x131` means the parent doesn't exist.

#### Empty trash: `0x15`

Needs privilege bit `0x27`. Empties the server's trash in the background.
Error `0x13e` means it's already running.

#### Transfers in progress: `0xe0`

Needs privilege bit `0x25`. The reply is command `0xe0` with the request's
task, with one tag 1 field per transfer on the server:

| Size | Field |
|---|---|
| 1 | `u8` direction |
| 4 | `u32` user ID |
| 2+n | File name (string) |
| 8 | `u64` |
| 8 | `u64` |
| 8 | `u64` |

The three 64-bit values are probably the total size, bytes transferred so far
and the start time; not yet confirmed.

### 4.16 The data connection

File transfers, and several other bulk operations, use a **second TCP
connection** to the server's **main port + 1** (6701 by default). Each data
connection does one job and then closes.

**Header.** The client sends 10 bytes **in the clear**:

| Size | Field |
|---|---|
| 4 | `u32` `0x01000000` (the server rejects values above it) |
| 2 | `s16` type (below) |
| 4 | `u32` the client's user ID on the main connection |

The user ID must belong to a user logged in from the same IP address. Each IP
address may have at most 6 data connections open at once.

| Type | Purpose |
|---|---|
| 1 | Download a file or folder |
| 10 | Download, encrypted |
| 2 | Upload |
| 11 | Upload, encrypted |
| 4 | Post a news article |
| 5 | Download a newsgroup's article index |
| 7 | Download the server log |
| 8 | Upload the server banner |
| 9 | File search (needs privilege bit `0x2f`) |
| 15 | Download the server banner |

The original client uses the encrypted types (10/11) when the server's
protocol level is ≥ 2 (login reply tag 5).

**Blocks.** After the header, data moves in **BF blocks**. On an encrypted
connection a block is:

| Size | Field |
|---|---|
| 4 | `u32 L`: length of the encrypted data, a multiple of 8 |
| 4 | `u32` 0 |
| 1 | `u8 p`: number of padding bytes at the end of the decrypted data |
| L | Data, encrypted with the **session secret** as the key |

The whitening is applied **the other way round** from frames (verified
against `SendBFBlock`/`ReadBFBlock` and the original server):

```
encrypt block (L, R):   L ^= 0x10576419;  (L, R) = Blowfish_encrypt(L, R);  R ^= 0x58022919
decrypt block (L, R):   R ^= 0x58022919;  (L, R) = Blowfish_decrypt(L, R);  L ^= 0x10576419
```

The data is padded with zeros to a multiple of 8 only if needed (no padding
when it's already aligned; unlike 4.3). The receiver keeps the first `L − p`
decrypted bytes. On an unencrypted connection the same bytes are sent raw,
without the 9-byte block header.

#### Download (types 1 and 10)

1. **Client → server:** a block with a `u16` path length and the path (4.15).
2. **Server checks:**
   - download privilege (bit `0xa`); otherwise error `0x12e` on the main
     connection;
   - the path exists (`0x12c`);
   - the item isn't in a drop box the user can't see into (`0x138`).

   On failure the data connection closes.
3. **Server → client:** a block with a `u32` queue position. If it's nonzero,
   the server later sends 1-byte blocks: `1` each time the client moves up one
   place, and `0` about every 30 seconds as a keepalive. Then the transfer
   starts.
4. **Server → client: transfer summary.**

   | Value | Size |
   |---|---|
   | Total bytes to transfer: high word (always 0), then low word | 4 + 4 |
   | Number of items | 4 |

   A file is one item. A folder is the folder itself, then every file and
   folder inside it, down to the folder-depth limit (4.12).
5. **For each item, server → client: item header.**

   | Value | Size |
   |---|---|
   | Path length *n* | 2 |
   | Path relative to the download, `0x01`-separated; for a single file, just its name | n |
   | Mac type (folders: `FLDR`) | 4 |
   | Mac creator (folders: `CarS`) | 4 |
   | Finder flags | 2 |
   | Extended Finder info (zeros where unavailable) | 16 |
   | `u32` count *k* of extra bytes | 4 |
   | Extra bytes (the original never sends any) | k |

   Folders end here: the client creates the folder, and the next item follows.
6. **For files, client → server: resume offsets.** These are how many bytes of
   the data fork and of the resource fork the client already has (0 for a
   fresh download). On type 10, each offset is 8 bytes (high word first); on
   type 1, 4 bytes. Data fork first.
7. **Server → client: fork sizes.** The data fork bytes still to come, then the
   resource fork bytes still to come; again 8 bytes each on type 10 and 4 on
   type 1.
8. **Server → client: the data.** The data fork from the resume offset, then
   the resource fork. Each is sent as however many blocks the server likes;
   the receiver reads until it has the announced number of bytes. There's no
   acknowledgement.
9. **Server → client: the comment.** The file's Finder comment (`u16` length
   plus text).

The connection closes after the last item. A download started while the user
is already at the per-user transfer limit had its connection dropped rather
than queued (observed when starting a second download straight after the
first).

#### Upload (types 2 and 11)

1. **Checks:**
   - upload privilege (bit `0xb`); otherwise error `0x134`;
   - the destination folder must exist (`0x131`);
   - outside an upload folder, the user also needs bit `0xc` ("upload
     anywhere"; otherwise `0x135`).
2. **Client → server:** a block with the destination folder's path (`u16`
   length plus path).
3. **Client → server:** the file or folder name (`u16` length plus name).
4. **Server → client:** one byte: 0 = no such item yet, 1 = it already exists,
   2 = a partial upload of it exists and can be resumed.
5. **Client → server:** one byte: 1 = replace the existing item (needs bit
   `0x10`, otherwise error `0x133`); anything else = resume or upload new.
6. **Client → server: transfer summary.** 8 bytes total size, then a 4-byte
   item count.
7. **For each item, client → server: item header.** The same as the
   download item header (step 5 above), including the extra-byte count
   (send 0). `FLDR`/`CarS` items create folders.
8. **For files, server → client: resume offsets.** The sizes of the data and
   resource forks already on the server (8 bytes each on type 11, 4 on type 2).
   While a file is being uploaded it has type `PART` and creator `CarC`. It
   gets its real type and creator once complete, so an interrupted upload can
   be resumed later.
9. **Client → server:** the remaining data fork and resource fork sizes, the
   fork data, then the Finder comment, mirroring download steps 7–9. The
   server then closes the connection (with a TCP reset).

Encrypted upload (type 11) and download (type 10) of a 49,590-byte file,
including the comment and a folder download, were verified byte for byte
against the original server.

> **Original server bug:** on an **unencrypted upload (type 2)**, the server
> reads the 4-byte fork sizes into the wrong variables (`DoXfer` at
> `0x1eea8`). A type 2 upload crashed the original server, and with it the
> whole Mac OS 9 machine. The original client uses type 11 against protocol
> level 2 servers, so a modern server may refuse type 2.

#### Other data connection types

These use plain length-prefixed values on the socket, not BF blocks.

| Type | Exchange |
|---|---|
| 4: post article | **Client:** `u32` length *n*, then *n* bytes of article (4.18). **Server:** posts it, or sends an error on the main connection. |
| 5: article index | **Client:** `u16` length + newsgroup name. **Server:** `u32` length + the index (4.18), then waits for the client to close. |
| 7: server log | **Server:** `u32` length + the log text. Needs privilege bit `0x23`. *(Provisional.)* |
| 8: banner upload | **Client:** `u32` length + PNG image, then the banner's link URL. Needs bit `0x24`. *(Provisional.)* |
| 9: file search | Below. |
| 15: banner download | **Server:** `u32` length + PNG image, `u8` length + URL. *(Provisional.)* |

**File search (type 9).** Needs privilege bit `0x2f`.
- **Client → server:** a `u16`, then criteria records: `u8` kind, `u8`
  operator, `u8`, `u32` length *n*. A record with kind 1 and operator 1 ("name
  contains") is followed by *n* bytes of search text (≤ 255) and ends the
  query. Other kinds aren't supported by this server.
- **Server → client:** `u32` 0, then one record per match, then `u8` 1 + `u32`
  0 when the search is done.
- **Result record:** `u8`, `u32`, `u32`, `u8`, the item's path, four `u32`s
  (size, dates and type/creator, by the look of the code), and a `u16`-length
  name. *(The meaning of each field is provisional.)*

### 4.17 Flat news

A single list of short articles, newest last.

#### Get all: `0xFD0001`

No request fields. The reply is command `0xFD0001` with the request's task,
with one field per article:

| Tag | Data |
|---|---|
| `0xFD0000` | Article text, including its header |

#### Post: `0xFD0000`

Needs privilege bit `0x30`.

| Tag | Data |
|---|---|
| `0xFD0000` | Article text |

**Server behaviour:**
1. Prepends the header `From: <nickname> (<login>)\rDate: <date>\r\r`
   (lines end with CR).
2. Appends the article to the list and saves it.
3. Sends **every** user, the poster included, push `0xFD0000` with the full
   article in tag `0xFD0000`.
4. Answers the poster with task complete.

#### Delete one: `0xFD0002`

Needs privilege bit `0x22`.

| Tag | Data |
|---|---|
| `0xFD0002` | `u32` article number, 1-based |

Everyone receives push `0xFD0002` with the same tag; the requester also gets
task complete. The original doesn't check the number is in range.

#### Delete all: `0xFD0003`

Needs privilege bit `0x22`. Everyone receives push `0xFD0003` with no fields;
the requester gets task complete.

### 4.18 Newsgroups (threaded news)

**Newsgroup permissions** (`u16`, MSB-first bit numbers):

| Mask | Bit | Allows |
|---|---|---|
| `0x8000` | 0 | Administrators to post |
| `0x4000` | 1 | Administrators to read |
| `0x2000` | 2 | Account holders to post |
| `0x1000` | 3 | Account holders to read |
| `0x0800` | 4 | Guests to post |
| `0x0400` | 5 | Guests to read |

"Administrator" and "account holder" are the user modes from privilege bits 0
and 1 (4.5).

#### List newsgroups: `0xa0`

No request fields. The reply is command **`0xa1`** with the request's task:

| Tag | Data |
|---|---|
| 1 | `s32` count, then the name (string) of each group the user may read or post to |

#### List newsgroups for administration: `0xa8`

Needs privilege bit `0x22`. The reply is command **`0xa4`** with the request's
task:

| Tag | Data |
|---|---|
| 2 | `s32` count, then for every group: name (string), `u32` number of articles, `u32` expiry setting, `u16` permissions |

#### Add newsgroup: `0xa5`

Needs privilege bit `0x22`.

| Tag | Data |
|---|---|
| 1 | Name (≤ 64) |
| 2 | `u32` expiry setting |
| 3 | `u16` permissions |

The requester gets task complete and **push `0xaa`**:

| Tag | Data |
|---|---|
| 5 | `u8` 0 (added) |
| 1 | Name |
| 2 | Expiry setting |
| 3 | Permissions |

#### Change newsgroup: `0xa7`

Needs privilege bit `0x22`.

| Tag | Data |
|---|---|
| 4 | Current name |
| 1 | New name |
| 2 | `u32` expiry setting |
| 3 | `u16` permissions |

The requester gets task complete and push `0xaa` with tag 5 = 1 (changed), plus
tags 4, 1, 2 and 3 as above.

#### Delete newsgroup: `0xa6`

Needs privilege bit `0x22`.

| Tag | Data |
|---|---|
| 1 | Name |

The requester gets task complete and push `0xaa` with tag 5 = 2 (deleted) and
tag 1 (name).

#### Read article: `0xa2`

| Tag | Data |
|---|---|
| 1 | Newsgroup name (≤ 64) |
| 2 | `u32` article ID |

The user needs read permission on the group. Error `0x192` (402) means no such
article.

**Reply:** command **`0xa1`** with the request's task:

| Tag | Data |
|---|---|
| 1 | Header: subject (string), `u32` article ID, two `u32`s, author (string), a string, `u32` *(order from the server code; field meanings beyond subject, ID and author are provisional)* |
| 2 | Article body |

#### Delete article: `0xa9`

Needs privilege bit `0x22`.

| Tag | Data |
|---|---|
| 1 | Newsgroup name |
| 2 | `u32` article ID |

The reply is task complete.

#### Article index (data connection type 5)

After the `u32` length:
- the newsgroup name (string);
- an `s32` count;
- for each article: `u32` article ID, subject (string), author (string), `u32`
  date, `s32` (the parent article ID, by the look of it; *provisional*).

#### Posting an article (data connection type 4)

The article the client sends:

| Size | Field |
|---|---|
| 2+n | Newsgroup name (string) |
| 2+n | Subject (string) |
| 4 | `u32` 0 |
| 4 | `u32` parent article ID, or `0xFFFFFFFF` to start a new thread |
| 4 | `u32` text length *t* |
| 4 | `u32` style length *s* |
| t | Text (Mac Roman, CR line endings) |
| s | Text styles, in the Mac OS `styl` scrap format |

The server records the poster's nickname and the date, and needs post
permission on the group.

---

## Appendix A: Reverse-engineering tools

The tools are in `tools/`. Run Python with `-I` so it never imports modules
from the directory being analysed.

| Tool | Purpose |
|---|---|
| `unpack.py`, `ndif.py` | Unwrap MacBinary, decompress NDIF/ADC Disk Copy images, and extract HFS volumes. (The client and server images are HFS+; decompress them and mount the raw `.hfs` read-only with `hdiutil`.) |
| `pef.py` | PEF loader: unpacks pattern-initialized data, applies loader relocations, recovers CodeWarrior traceback names, and prints annotated PowerPC disassembly (`--funcs`, `--imports`, `--hex ADDR LEN`, `--full` for the whole code section, or a function name substring) |
| `macho_annot.py` | Resolves stubs and PIC string references in `llvm-objdump` output for the PowerPC Mach-O tracker |
| `rsrc.py` | Dumps resource forks (`STR#`, `TEXT`, hex for everything else) |
| `pefemu.py` | Runs functions from a PEF binary under the Unicorn emulator. Produces the Blowfish and MD5 test vectors used in `carracho-proto`. |
| `names/*.txt` | Names for library functions that have no traceback name (`pef.py --names`) |
