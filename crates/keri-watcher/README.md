# keri-watcher

A KERI watcher. It keeps the key event logs it is sent, verified by
[keri-kel](https://crates.io/crates/keri-kel), in a redb database, and answers queries about them
over HTTP.

## Running

```bash
keri-watcher watcher.toml
```

Logs go to standard error, filtered by `RUST_LOG` (`info` by default).

## Configuration

```toml
listen = "127.0.0.1:5631"
database = "/var/lib/keri-watcher/watcher.redb"
# The salt the watcher's key is derived from; by default the database's path with `.salt`.
identity = "/var/lib/keri-watcher/watcher.salt"
# Keep key state notices only from the identifier itself, its witnesses, and these watchers.
# Without it, notices from any source are kept.
trusted_watchers = ["BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha"]
```

The database and the salt file are created on first start. The salt file is readable only by its
owner on Unix; whoever reads it can sign as the watcher. The watcher's identifier is its
non-transferable key, so it stays the same as long as the salt does.

## Routes

| Route | Answers |
|---|---|
| `POST /` | Processes a CESR stream of events, receipts, replies and queries, then the escrows. `204`, whatever was made of each message; `400` when the body is not a CESR stream |
| `POST /query` | Answers one `qry`: `logs` with the identifier's events as keripy replays them, `ksn` with a `/ksn/{watcher}` reply the watcher signed. `404` when the log does not hold what is asked for yet; `400` when the body is not a single query or it is refused; `501` for `mbx` |
| `GET /health` | The watcher's identifier |

A query the log cannot answer yet waits in keri-kel's escrow. Once the log catches up, its answer
has no one to send it to; it is logged and dropped.

## License

Either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option. Contributions are dual licensed the same way unless you say otherwise.
