# Changelog

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [0.1.0] - Unreleased

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
