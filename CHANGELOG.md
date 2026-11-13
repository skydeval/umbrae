# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [Unreleased]

### Changed
- Rebuilt on atproto spaces. Hidden posts now live in space repos on each member's own PDS, so they are portable between PDSes. The standalone server, member module, deployment profiles and `tools.umbrae.*` payload schemas are removed from `main`; the last standalone build is tagged `standalone-final`.

- The Rust workspace moved into `umbrae/`; the repo root holds the README, changelog, license and docs.

### Added
- `umbrae-core`, atproto spaces protocol primitives:
  - space URI and space-ref parsing and formatting, strict, with DID, NSID and record-key syntax checks;
  - the LtHash set hash for commit digests, checked against the spec's empty-repo digest and the reference implementation's snapshot vector.
