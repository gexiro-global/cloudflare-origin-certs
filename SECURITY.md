# Security Policy

## Supported Versions

Maintained on the latest v0.x release line.

## Reporting a Vulnerability

Use GitHub private vulnerability reporting if enabled on this repository, otherwise email
`admin@gexiro.com`.

Never include a real Origin CA key, certificate, or private key in a report. Reproduce against the
synthetic tree built by `tests/run_tests.sh`.

## Threat model

These scripts handle private key material. Specific properties you should verify for yourself before
trusting them:

- The Origin CA key is read from the environment only. It is never written to disk, never passed as
  a command-line argument (where it would be visible in `ps`), and never logged.
- Keys and CSRs are generated in a `mktemp -d` directory under `umask 077` and removed afterwards.
- Output files are created with mode 600 before content is written.
- `.gitignore` excludes `*.key`, `*.crt`, `*.pem` and `domains.txt`, and CI fails on any long
  hex-looking string in the tree. Neither is a substitute for reviewing your own commits.
- `ols-ssl-wire.sh` edits configuration only under `--apply`, backs up each file first, and confines
  its rewrite to the `vhssl` block.

The origin private key sits on the web server for the lifetime of the certificate. With the default
15-year validity, a single origin compromise yields a key that stays valid for a very long time.
Choose `--days` accordingly.

An Origin CA certificate authenticates the origin to Cloudflare. It does not stop anyone from
reaching your origin directly. Restrict inbound 80/443 to Cloudflare's published ranges as well.
