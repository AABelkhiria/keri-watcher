# keri-watcher

A KERI watcher: a service that observes identifiers on behalf of their controllers, polls their
witnesses for key state, keeps a verified copy of each log, answers queries about it, and reports
when witnesses disagree.

Protocol logic lives in the `keri-*` crates and is verified against
[keripy](https://github.com/WebOfTrust/keripy): [keri-protocol](https://crates.io/crates/keri-protocol)
reads and writes messages, and [keri-kel](https://crates.io/crates/keri-kel) validates logs, keeps
replies and registrations, and adjudicates key state. This workspace holds what only a watcher
needs.

## Crates

| Crate | Purpose |
|---|---|
| `keri-store-redb` | A keri-kel store on redb: the watcher's logs, escrows and replies in one database file |
| `keri-watch` | The watcher's decisions as pure functions over explicit inputs: when to poll each observed identifier, and which witnesses to ask first |
| `keri-watcher` | The watcher binary: its identity and configuration, HTTP routes to ingest messages, answer queries and serve its OOBI, the poller that keeps observed identifiers up to date from their witnesses, the OOBI resolver and the escrow sweeper |

## Prerequisites

- Rust 1.97 or newer (`rustup` installs the toolchain pinned in `rust-toolchain.toml`).

## Build and test

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets
cargo test --workspace
cargo deny check
```

## License

Either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option. Contributions are dual licensed the same way unless you say otherwise.
