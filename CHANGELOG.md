# Changelog

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

- No unreleased changes.

## [0.1.0]

### Security
- Both scripts now lock a validated, owner-checked `/run/lock` directory opened read-only
  (whole ancestor chain validated; group/world-writable non-sticky ancestors refused),
  replacing predictable lock files opened with `>` that a local user could redirect at an
  arbitrary root-writable file (CWE-59). Lock env vars: `CF_ORIGIN_LOCK_DIR`,
  `OLS_WIRE_LOCK_DIR`. `cf-origin-issue.sh` also refuses a symlinked, foreign-owned, or
  group/world-writable `--out` directory (private keys need an owner-only directory).

### Fixed
- `cf-origin-issue.sh` publishes the certificate/key pair with `INT`/`TERM`/`HUP` blocked
  across staging and both renames, so an interruption can no longer leave the new
  certificate paired with the old key.
- `ols-ssl-wire.sh` traps signals during `--apply` and rolls back every file it touched if
  interrupted mid-batch, instead of leaving a partially applied live config.
- `ols-ssl-wire.sh` now reports failure when the config-test binary is missing (the changes
  are live but unproven) unless `OLS_ALLOW_UNVALIDATED=1`, instead of exiting 0.

### Added
- Initial public release.
- `cf-origin-issue.sh`: bulk Origin CA issuance from a domain list or arguments, credential from the
  environment only, JSON request and response handled by a real encoder, `--dry-run`, mode-600
  output.
- `ols-ssl-wire.sh`: dry run by default, `--apply` to write, `--restart` to reload, per-file backup,
  and `vhssl`-scoped rewriting of `keyFile`/`certFile`.
- Offline test suite (13 assertions) including regressions for scope-limited editing and idempotent
  re-runs.
- CI: shellcheck, offline tests, and a credential-shaped-string scan over the tree.
