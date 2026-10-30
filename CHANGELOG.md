# Changelog

> Following [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
> and [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-10-30

First release of the watcher: a standalone service that keeps an independent, verified copy of KERI
key event logs and reports when an identifier's witnesses disagree.

### Added

- **Identifier observation**: controllers register identifiers through `/watcher` replies; the
  watcher polls each identifier's witnesses and fetches the events its log lacks.
- **Duplicity detection**: conflicting witness reports are recorded by sequence number and source,
  and served at `GET /duplicity/{aid}`.
- **Verified storage**: every message goes through `keri-kel` before it is kept; what cannot be
  decided yet waits in escrow, retried and expired by a background sweeper.
- **Message ingest**: `POST /` and `PUT /` take CESR streams as keripy sends them.
- **Queries**: `POST /query` answers `logs` and `ksn` queries, the latter with a reply signed by the
  watcher; `mbx` is not supported and returns `501`.
- **OOBI support**: serves the watcher's own OOBI at `GET /oobi/{aid}`, and resolves the OOBIs
  registrations give.
- **keripy interoperability**: works with keripy-based controllers and witnesses.
- **Persistence**: logs, registrations and escrows are kept in one redb database, and the watcher's
  non-transferable identifier is derived from one salt file, so both survive restarts.
- **Operations**: one TOML configuration file, `GET /health`, and Prometheus metrics at
  `GET /metrics`.
- **Library crates**: `keri-watch` for the watcher's decision logic, and `keri-store-redb` for a
  persistent `keri-kel` store.
