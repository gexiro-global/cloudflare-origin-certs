# Contributing

Support for other web servers (nginx, Caddy, Apache) in the wiring step is the most useful
contribution, followed by bug reports with a reproducible vhost layout.

## Ground rules

- No credential may ever reach a command-line argument, a file on disk, or a log line. The
  only accepted channel is an environment variable read into a stream the child process
  consumes on stdin.
- Dry run stays the default for anything that writes. A pull request that makes `--apply` implicit
  will be closed.
- Nothing restarts a web server without an explicit flag.
- `shellcheck` must pass clean, and the offline suite must stay offline — no test may call the
  Cloudflare API.
- New behaviour needs an assertion in `tests/run_tests.sh`.

## Support expectations

Best-effort maintenance, no SLA, no commercial support. These scripts touch TLS on production web
servers; read them before you run them.
