
# HSU change log

All notable changes to HSU will be documented here. This project adheres to [Semantic Versioning](http://semver.org/).

## Unreleased

- Fixed an issue with password resets.

## [2.1.0] - 2016-02-11

### Added

- `ttl` options so that signed URLs are now also timed. By default they expire within one hour.

## [2.0.1] - 2016-02-11

- Corrected the license within `package.json`.

## [2.0.0] - 2016-02-11

### Breaking

- Rewrote the API considerably to make the process more specific and to allow for concurrent HSUs (see below for more detail).

### Changed

- `hsu(options)` now returns a scoping function (i.e. `hsuProtect`) which must be called to access to the various middleware.

### Added

- `hsuProtect(id).setup` is the setup middleware which adds `req.signUrl(urlToSign)`.
- `hsuProtect(id).verify` is the middleware to verify a particular HSU process (scoped by `id`).
- `hsuProtect(id).complete` is the middleware which adds `req.hsuComplete()` which should be called to signal the HSU is no longer required and render it unusable.

## [1.0.0] - 2016-02-10

- Created first version.
