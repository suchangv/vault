#!/bin/sh
# Deploy: apply remote D1 migrations, then the Worker + assets.
set -e
cd "$(dirname "$0")/.."

if [ ! -f wrangler.jsonc ] && [ ! -f wrangler.toml ]; then
	echo "run from the project root" >&2
	exit 1
fi

npx wrangler d1 migrations apply vault-db --remote
exec npx wrangler deploy "$@"
