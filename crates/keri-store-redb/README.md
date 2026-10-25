# keri-store-redb

A [keri-kel](https://crates.io/crates/keri-kel) store on [redb](https://www.redb.org), an embedded
key-value database: everything a `Kevery` holds, its key event logs, escrows, waiting receipts,
replies and queries, and the key state notices, end roles, locations and watcher registrations it
keeps, in one database file, with the duplicity a watcher records.

```rust,no_run
use keri_kel::Kevery;
use keri_store_redb::RedbStore;

# fn main() -> Result<(), Box<dyn std::error::Error>> {
let kevery = Kevery::with_store(RedbStore::create("watcher.redb")?);
# Ok(())
# }
```

## Tables

One table per kind of record, named after keripy's tables so a dump reads like keripy's: `kevers`,
`kels`, `sups` (superseded events), `escrows`, `receipts`, `ksns`, `ends`, `locs`, `obvs`, `oobis`,
`rpes` and `qnfs`, and `dups`, the duplicity a watcher sees, which keri-kel does not keep: each
event reported at a sequence number, with its source and when it was first seen. Keys are their parts joined by `.`, as keripy joins its keys, with sequence
numbers as 32 hexadecimal digits so a log reads in order; values are keri-kel's `Record` encoding,
readable JSON.

Each store method is one transaction: accepting an event, with moving the events it supersedes
aside, commits together, but the several writes one message causes do not.

## Testing

A `Kevery` on this store is offered a pool of real signed messages, events, witness receipts, a
contradicting event, a recovery rotation, replies and a query, in random orders, beside a `Kevery`
on keri-kel's in-memory store; both must reach the same outcomes and hold the same after every
message. What the store holds must also survive closing the database and opening it again.

## License

Either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option. Contributions are dual licensed the same way unless you say otherwise.
