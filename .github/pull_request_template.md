## Summary

Describe the change and why it is needed.

## Verification

- [ ] `shellcheck cf-origin-issue.sh ols-ssl-wire.sh tests/run_tests.sh tests/fake-origin-ca.sh` is clean
- [ ] `./tests/run_tests.sh` passes
- [ ] Any new fail-open path, or a change to the cert/key install or config-swap transaction,
      has a regression test

## Safety

These tools run as root and write private keys, certificates, and live web-server config.

- [ ] The certificate/key pair is still published atomically (an interruption cannot leave a
      new cert with the old key), and vhost edits still stage + swap and roll back on failure.
- [ ] Dry run stays the default for wiring; the server is never restarted on an unvalidated config.
- [ ] The Cloudflare Origin CA key never reaches argv or disk.
- [ ] `Signed-off-by:` (DCO) present.
