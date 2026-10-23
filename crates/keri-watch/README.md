# keri-watch

A KERI watcher's decisions, as pure functions over explicit inputs: no clock, no network, no
storage. The watcher binary in this workspace supplies the time, the registrations and the poll
results, and acts on what these functions return.

## Modules

| Module | Purpose |
|---|---|
| `poll` | When each observed identifier is due to be polled, at a rate that slows while its log is stable |

## Polling

Each observed identifier is polled at a base interval while its log is changing. Once its log has
not changed for a while, the interval grows linearly, up to a multiple of the base for a log stable
for an hour or more. A subscribed identifier is always polled at the base interval. A base interval
of zero disables polling. Times are durations from a clock origin the caller chooses, so the
planner can be driven by a monotonic clock in production and a fixed one in tests.

## License

Either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option. Contributions are dual licensed the same way unless you say otherwise.
