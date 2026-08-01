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

- The Origin CA key is read from the environment only. It is never passed as a command-line
  argument - process arguments are readable by other local users through `/proc` - never written
  to disk, and never logged. It reaches `curl` as a config stream on **stdin** (`curl -K -`).
- The key is interpolated into curl config syntax, so a value containing a quote, backslash or
  newline could inject further curl directives. Keys that are not plain credential tokens are
  rejected before use.
- The work directory holds a freshly generated private key. A trap removes it on `EXIT`, and
  `INT`, `TERM` and `HUP` clean up and then terminate the run rather than continuing to the
  next domain, so an interrupted run neither leaves key material behind nor keeps issuing.
- Every output write is checked. A certificate is only counted as issued once both files exist
  and were written successfully.
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
