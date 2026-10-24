# Changelog

> Following [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
> and [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `keri-watch`: poll planning, deciding when each observed identifier is due to be polled.
- `keri-watch`: witness health, tracking how each witness answers and ordering witnesses to ask.
- `keri-watch`: merging witnesses' reports about an identifier, detecting duplicity among them, and
  the range of events the local copy lacks.
