# Authorized Use

These scripts request certificates for domains under a Cloudflare account you control, and modify the
web server configuration of the machine they run on.

Run them only for zones you own or administer, and only on hosts you are authorized to change.
Requesting certificates for a domain you do not control is not something the Cloudflare API will let
you do, but it is worth stating that this tool assumes ownership rather than checking it.

The only outbound connection is to the Cloudflare API, using the credential you supply.
