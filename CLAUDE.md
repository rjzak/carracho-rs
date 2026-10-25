# Carracho rebuild

Modern reimplementation of Carracho (Classic Mac OS file sharing/chat, 1997–2004),
**wire-compatible with the original PowerPC client, server and tracker**. Rust for
the server and tracker, SwiftUI for the client (not started). Compatibility with
the originals beats tidiness: when unsure how something behaves, check the
original (disassembly or the test VM), not intuition.

`docs/protocol.md` is the specification and the source of truth. Update it
whenever you learn something new, and mark statements tested against the real
server as *verified*. Items still marked *provisional*: search result records,
newsgroup article header fields, the log and banner transfers, settings tag 0x36.

## Layout

- `crates/carracho-proto`: wire formats shared by everything. Covers Blowfish
  framing (`crypto.rs`), packets and the greeting (`packet.rs`), account records,
  Mac dates, Mac Roman text, tracker messages and `wire::Reader` plus the `put_*`
  helpers.
- `crates/carracho-tracker`: the tracker daemon, plus `carracho-trackerctl`.
- `crates/carracho-server`: the server.
  - `session.rs` handles the main connection and login.
  - `handlers/` has one module per area; `dispatch` is in `handlers/mod.rs`.
  - `transfer.rs` is the data connection on port+1.
  - `files.rs` maps protocol paths onto the shared folder tree. Mac metadata
    lives in hidden `.carracho-info` JSON sidecars and `.carracho-rsrc/`.
  - `store.rs` keeps settings, accounts and news as JSON in the data dir.
  - `state.rs` holds runtime state behind one `std::sync::Mutex`. Never hold it
    across `.await`.
- `crates/carracho-probe`: test clients.
  - `carracho-probe` is an interactive dump tool. `--raw CMD:TAG=...` sends any
    command.
  - `carracho-compare` runs scripted scenarios against two servers and diffs
    their normalized transcripts.
- `tools/`: Python reverse-engineering tools (PEF disassembler with traceback
  names, Unicorn emulator, NDIF/MacBinary unpackers). Function name lists are in
  `tools/names/`.
- `original/` (gitignored) holds the extracted original apps. The server binary
  is `original/Carracho Server 1.0b13/Carracho Server 1.0b13/Carracho Server 1.0b13`;
  the client is `original/Carracho 1.0b10r4/...`.

## Commands

```sh
cargo test                     # all crates
cargo clippy --all-targets     # keep it clean
cargo run --bin carracho-server -- --port 16700 --data /tmp/cdata   # data dir holds files/, homes/, trash/
cargo run --bin carracho-probe -- HOST[:PORT] --login anonymous --info --list / --channels
cargo run --bin carracho-compare -- 192.168.64.9 127.0.0.1:16700 --out /tmp/cmp [--only NAME] [--quiet-ms 700]
```

Python tools need the venv from `tools/requirements.txt`. Run them with
`python -I`. To disassemble:
`python -I tools/pef.py "<binary>" --names tools/names/server.txt --full > server.dis`.
In the disassembly, r2 is the TOC, `__ptr_glue` marks virtual calls, and the
stream vtable offsets are +0x1c write and +0x20 read.

## Testing against the original

The user runs the original server and tracker (1.0b13) on Mac OS 9.2.1 in UTM
(QEMU, Shared Network) at **192.168.64.9**, ports 6700/6701/6702. The Mac host is
192.168.64.1 as seen from the VM. The VM may be off; check with `nc -z -G 3 192.168.64.9 6700`.
The default accounts are `admin` and `anonymous`, both with empty passwords.

The goal is that `carracho-compare` reports no differences between the VM and
the Rust server, except the intentional ones below. Add a scenario when you add
or change behaviour. Scenarios must clean up after themselves (the prelude
deletes `CmpTest`, `zztest`, `CmpGroup`).

**Don't crash or lock out the VM:**
- Never send an unencrypted (type 2) upload to the original. It crashes the
  whole VM, and the user has to restart it.
- Never ban from a test client. The ban targets the Mac's own IP and locks you
  out.
- The original drops the connection when a request lacks a required field. Check
  the tags in `docs/protocol.md` first.

## Intentional differences from the original server

The Rust server sends what the original meant to send. The original client
tolerates all of these (checked in its code where noted):
- The join reply (0x80) tag 6 carries the real channel flags; the original
  always sends 0.
- The settings reply declares tag 0x32 as 4 bytes; the original says 3 but sends
  4. The client reads a u32 regardless of the declared length.
- A request missing a required field gets error 0x3e7 instead of a disconnect.
- Denied fields in set-settings are skipped. Plain type 1/2 transfers work
  correctly.

## Protocol facts that are easy to get wrong

- Privilege bits use BitTst numbering: bit 0 is the MSB of the 64-bit mask
  (`codes::privs::has`).
- The data connection whitens the other way round from frames:
  `encrypt_transfer` and `decrypt_transfer`, not `seal` and `open`.
- Folder listings put the creator *before* the type. File info and transfer item
  headers put the type first.
- Folder flag 0x8000 means "ordinary folder" (no stored flags), not "alias".
- In change-file-info (0x13), tag 2 is the new name (required) and tag 4 is the
  comment.
- Login replies and login errors use task 0. Other replies echo the request's
  task.
- File names and paths are UTF-8 with 0x01 separators. Every other string is Mac
  Roman. Dates are Mac seconds since 1904, GMT.

## Conventions

- Commit only when the user asks. Nothing has been committed so far.
- The user is fine with reverse engineering for this project; the original
  license forbids it, and the user made that call.
- Match the style of the surrounding code: concise doc comments that cite
  protocol.md sections, no needless abstractions, and tests next to the code they
  cover.
