# keri-watcher

A KERI watcher. It keeps the key event logs it is sent, verified by
[keri-kel](https://crates.io/crates/keri-kel), in a redb database, keeps the identifiers it is
asked to observe up to date from their witnesses, and answers queries about them over HTTP.

## Running

```bash
keri-watcher watcher.toml
```

Logs go to standard error, filtered by `RUST_LOG` (`info` by default).

## Configuration

```toml
listen = "127.0.0.1:5631"
# The URLs the watcher announces in its OOBI, `http` or `https`.
urls = ["http://127.0.0.1:5631"]
database = "/var/lib/keri-watcher/watcher.redb"
# The salt the watcher's key is derived from; by default the database's path with `.salt`.
identity = "/var/lib/keri-watcher/watcher.salt"
# Keep key state notices only from the identifier itself, its witnesses, and these watchers.
# Without it, notices from any source are kept.
trusted_watchers = ["BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha"]
# How often to poll an observed identifier's witnesses while its log changes; 0 disables polling.
poll_interval_seconds = 60
# How long to wait for a witness's answer, or an OOBI's.
witness_timeout_seconds = 5
# How long an escrowed event, receipt, reply or query waits before it is dropped.
escrow_timeout_seconds = 3600
```

The database and the salt file are created on first start. The salt file is readable only by its
owner on Unix; whoever reads it can sign as the watcher. The watcher's identifier is its
non-transferable key, so it stays the same as long as the salt does.

## Routes

| Route | Answers |
|---|---|
| `POST /`, `PUT /` | Processes a CESR stream of events, receipts, replies and queries, then the escrows. `204`, whatever was made of each message; `400` when the body is not a CESR stream |
| `POST /query` | Answers one `qry`: `logs` with the identifier's events as keripy replays them, `ksn` with a `/ksn/{watcher}` reply the watcher signed. `404` when the log does not hold what is asked for yet; `400` when the body is not a single query or it is refused; `501` for `mbx` |
| `GET /oobi/{aid}`, `/oobi/{aid}/{role}`, `/oobi/{aid}/{role}/{eid}` | The watcher's OOBI, when `aid`, and `eid` if given, are its own: a `/loc/scheme` reply for each URL in `urls` and an `/end/role/add` reply naming itself its own `controller`, all signed by the watcher, as `application/json+cesr` with a `KERI-AID` header. `404` for any other identifier, or when `urls` is empty |
| `GET /health` | JSON: the watcher's identifier, uptime, the identifiers it observes, what waits in its escrows, and how each witness asked has answered |
| `GET /metrics` | Prometheus text: messages processed and refused, observations by what they found, OOBIs by what became of them, escrows expired, the gauges `/health` reports, and each witness's successes, failures and response time |
| `GET /duplicity/{aid}` | JSON: for each sequence number duplicity was seen at, each source's event with when it was first seen; empty when there is none |

No route asks who is calling. `/health`, `/metrics` and `/duplicity` tell which identifiers the
watcher observes and which witnesses it asks; serve them only where their readers should be.

keripy posts one message at a time, its attachments in a `CESR-ATTACHMENT` header, and puts a
whole stream as the body; the watcher takes both, on `/` and `/query`.

With keripy, a controller resolves the watcher's OOBI and adds it with `kli watcher add`, which
sends the controller's log and the registration with `PUT /`. keripy finds where to send them
through the watcher's `controller` end role, which is why the OOBI carries it.

## Observing

A controller asks the watcher to observe an identifier with a `/watcher/{watcher}/add` reply sent
to `POST /`, and stops it with `/watcher/{watcher}/cut`. The watcher polls each observed
identifier's witnesses, every `poll_interval_seconds` while its log changes and less often, up to
ten times less, once it has been stable for an hour.

Each poll asks every witness the watcher has a location for, healthiest first, for its key state
(`GET /ksn?pre=`, as keripy's witnesses serve it). keri-kel verifies each answer and keeps it as a
key state notice. When the witnesses agree on a state the watcher's log has not reached, it fetches
the log from a witness reporting that state (`GET /log?pre=&fn=`) and ingests it. Witnesses
reporting different events at the same sequence number, or an event other than the one the watcher
holds, are duplicity: nothing is fetched, and each witness's event is recorded in the database
with when it was first seen, beside the watcher's own event when it holds one. The watcher never
replaces an event it has accepted because a witness reports another.

The watcher needs the identifier's log, at least its inception, to know its witnesses, and the
witnesses' `/loc/scheme` replies to reach them; until it has both, the identifier is skipped.

## OOBIs

A registration may carry an OOBI for the observed identifier. The watcher fetches it and ingests
what it serves: from a keripy witness's `/oobi/{identifier}/witness`, the identifier's log and the
witnesses' locations, which is what it needs to observe the identifier. The registration itself
is verified against the controller's log, so, as `kli watcher add` does, the controller sends its
log before the registration.

As keripy does, an OOBI answered `404` is asked again every 30 seconds, three times at most, and
one answered with another error status fails; a request that times out or cannot be sent is asked
again as a `404` is. What became of each OOBI is kept in memory, so after a restart the queued
OOBIs are fetched once more.

## Escrows

Every minute, the watcher drops what has waited in keri-kel's escrows longer than
`escrow_timeout_seconds`, then retries the rest. keripy gives each escrow its own timeout; here
one applies to all.

## Queries

A query the log cannot answer yet waits in keri-kel's escrow. Once the log catches up, its answer
has no one to send it to; it is logged and dropped.

## License

Either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option. Contributions are dual licensed the same way unless you say otherwise.
