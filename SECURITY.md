# Security Policy

## Supported versions

Security fixes go to the latest `0.x` release. Older `0.x` versions are not patched.

## Reporting a vulnerability

Please don't open a public issue for something you think is exploitable.

Use GitHub's [private vulnerability reporting][gh-pvr] on this repository instead: *Security* →
*Report a vulnerability*.

[gh-pvr]: https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability

Useful things to include: the version, something we can run to reproduce it, and what you think the
impact is.

## Threat model

Every message a watcher receives, from controllers, witnesses and other watchers, is assumed
hostile. Validation, signature checks and duplicity detection are keri-kel's; this workspace decides
what to observe and when, and must never let a hostile input change those decisions beyond what a
verified registration allows. Crate-owned code has no `unsafe`, `unwrap`, `expect`, panicking macro
or indexing that can fail.
