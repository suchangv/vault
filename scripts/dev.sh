#!/bin/sh
# Local development: apply local D1 migrations, then start `wrangler dev`.
#
# `.dev.vars` must contain:
#   DEV_AUTH_BYPASS=true
#   DEV_AUTH_EMAIL=you@example.com
# so you can open http://localhost:8787 without a Cloudflare Access round-trip.
set -e
cd "$(dirname "$0")/.."

npx wrangler d1 migrations apply vault-db --local
exec npx wrangler dev "$@"
