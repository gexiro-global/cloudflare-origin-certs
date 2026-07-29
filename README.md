# cloudflare-origin-certs

[![CI](https://github.com/gexiro-global/cloudflare-origin-certs/actions/workflows/ci.yml/badge.svg)](https://github.com/gexiro-global/cloudflare-origin-certs/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

Issue Cloudflare Origin CA certificates for many domains at once, and wire them into
OpenLiteSpeed vhosts - without a restart you did not ask for.

| Script | What it does |
|---|---|
| `cf-origin-issue.sh` | Generates a key and CSR per domain, requests an Origin CA certificate, writes both with mode 600. |
| `ols-ssl-wire.sh` | Points each OpenLiteSpeed vhost at its certificate. Dry run by default. |

## Why

Cloudflare's "Full (strict)" mode requires a valid certificate on the origin. Let's Encrypt works,
but on a proxied origin it means solving challenges through the proxy and renewing every 90 days for
a certificate no browser will ever see. Origin CA certificates exist exactly for this hop: only
Cloudflare needs to trust them.

Doing that for one domain is a five-minute dashboard task. Doing it for thirty is a script, and the
scripts people write for it tend to share two flaws — a hardcoded API key, and an automatic
`lswsctrl restart` at the end.

## Safety choices

**No credential in the file.** The Origin CA key comes from `CF_ORIGIN_CA_KEY` in the environment.
The script refuses to start without it and never writes it anywhere.

**Dry run is the default for the wiring step.** `ols-ssl-wire.sh` prints what it would change and
exits. Nothing is written until you pass `--apply`.

**It does not restart your web server.** Not unless you pass `--restart`. A bad vhost edit affects
one site; a restart into a bad config takes every site on the box down together, usually at the
exact moment you have stopped watching.

**Edits are scoped and reversible.** Each vhost config is backed up before it is touched, and
`keyFile`/`certFile` are rewritten *only inside the `vhssl` block* — a global substitution on
`/keyFile.*/` also rewrites unrelated blocks in the same file, which is a genuinely unpleasant way
to discover that your context configuration has changed.

## Install

```bash
git clone https://github.com/gexiro-global/cloudflare-origin-certs.git
cd cloudflare-origin-certs
cp examples/domains.example.txt domains.txt   # then edit it
```

Requires `bash`, `openssl`, `curl`, `python3`. The wiring script additionally expects an
OpenLiteSpeed or CyberPanel vhost layout.

## Usage

```bash
# 1. see what would be requested
./cf-origin-issue.sh --dry-run --domains domains.txt

# 2. supply the credential without putting it in shell history or a file
read -rs CF_ORIGIN_CA_KEY && export CF_ORIGIN_CA_KEY

# 3. issue
./cf-origin-issue.sh --domains domains.txt --out /usr/local/lsws/conf/cert/origin-certs

# 4. see what wiring would change, then do it
sudo ./ols-ssl-wire.sh
sudo ./ols-ssl-wire.sh --apply
sudo /usr/local/lsws/bin/lswsctrl restart    # when you are ready
```

Finally, set each zone to **Full (strict)** in the Cloudflare dashboard. The certificates do nothing
until you do.

### Options

| Flag / variable | Applies to | Default |
|---|---|---|
| `--domains FILE` | issue | — (or list domains as arguments) |
| `--out DIR` / `CF_ORIGIN_OUT` | issue | `./origin-certs` |
| `--days N` / `CF_ORIGIN_DAYS` | issue | `5475` (Cloudflare's own default, 15 years) |
| `--dry-run` | issue | off |
| `CF_ORIGIN_CA_KEY` | issue | **required** |
| `--certs DIR` / `OLS_CERT_DIR` | wire | `/usr/local/lsws/conf/cert/origin-certs` |
| `--vhosts DIR` / `OLS_VHOST_DIR` | wire | `/usr/local/lsws/conf/vhosts` |
| `--apply` | wire | off (dry run) |
| `--restart` | wire | off |

## What these scripts do NOT do

- They do not configure Cloudflare. Setting SSL mode to Full (strict) is a dashboard step you do
  yourself, per zone, deliberately.
- They do not renew anything. Origin CA certificates are long-lived; there is no renewal daemon here
  and you should track expiry yourself.
- They do not give you a publicly trusted certificate. Reaching the origin directly over HTTPS will
  still produce a browser warning, by design.
- They do not protect the origin from direct access. A certificate is not an allowlist — pair this
  with firewall rules restricting 80/443 to Cloudflare's ranges.
- They do not manage DNS, vhost creation, or anything else about your web server.

## About the 15-year default

Cloudflare's own default validity is 15 years, and that is what this uses. It is a long time for a
private key to live on a web server. If your threat model includes origin compromise, issue shorter
certificates with `--days` and put the expiry in your calendar — an expired origin certificate breaks
Full (strict) for that zone.

## Testing

```bash
./tests/run_tests.sh
```

Thirteen assertions, fully offline: no Cloudflare API calls, no OpenLiteSpeed, no root. The wiring
tests run against a synthetic vhost tree, including a regression test that a `keyFile` line outside
the `vhssl` block is left alone.

## License

Apache-2.0. See [LICENSE](LICENSE).

Built and maintained by Gexiro Global Enterprises Ltd.
