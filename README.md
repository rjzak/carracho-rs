# Carracho, rebuilt

> [!NOTE]
> If this type of project is of interest, check out [Conclave](https://github.com/rjzak/conclave), a modern remake vs. a feature-for-feature remake.

A modern reimplementation of [Carracho](https://www.carracho.com/), a Mac file sharing and chat system
(client, server and tracker) from 1997–2004 by Jörn and Mirko Hartmann.
The new programs speak the original wire protocol, so they work with the
original PowerPC clients and servers. This work has been done almost entirely
with AI, as reverse engineering a project like this would probably take months.
Claude got something initially working in Rust that's compatible with the
original code in less than a day.

| Component | Language | Status |
|---|---|---|
| Protocol reference: [`docs/protocol.md`](docs/protocol.md) | | Tracker and client/server protocol decoded (a few fields provisional) |
| Tracker: `crates/carracho-tracker` | Rust | Done |
| Shared wire formats: `crates/carracho-proto` | Rust | Tracker messages; session encryption, login and packet framing |
| Test client: `crates/carracho-probe` | Rust | Logs in to a server, sends requests, dumps replies; tested against the original server |
| Server `crates/carracho-server` | Rust | Is able to receive logins from the original client, basic functionality seems to work. |
| Client | SwiftUI | Not started |

## Tracker

```sh
cargo run --release --bin carracho-tracker            # listens on UDP+TCP 6702
cargo run --release --bin carracho-tracker -- --help  # bind address, expiry, limits

# Inspect a tracker, or register a test server with it
cargo run --bin carracho-trackerctl -- query localhost
cargo run --bin carracho-trackerctl -- register localhost --name "My Server" --speed 9
```

Logging goes to stderr; set `RUST_LOG=debug` for more detail. The tracker runs
in the foreground and stops cleanly on SIGTERM, so it can run under launchd or
systemd.

## Test client

`carracho-probe` logs in to a server (original or new), runs a few requests
and prints every packet it receives, decoded where it knows the format.

```sh
cargo run --bin carracho-probe -- HOST --login anonymous --info --list / --channels --news --say "hello"
cargo run --bin carracho-probe -- HOST --login admin --raw 0xcd                 # any command, with fields
cargo run --bin carracho-probe -- HOST --login admin --upload FILE --upload-to /Folder
cargo run --bin carracho-probe -- HOST --login admin --download /Folder/FILE --save-dir out
```

See `--help` for the `--raw` field syntax. Don't use `--plain` (unencrypted
transfers) against the original server: a plain upload crashes it.

## Development

```sh
cargo test
```

The reverse-engineering tools are in `tools/` (see
[Appendix A of the protocol reference](docs/protocol.md#appendix-a-reverse-engineering-tools)).
They expect the extracted original software in `original/`, which is not
checked in.
