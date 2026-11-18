-- cf-vault schema
-- One encrypted vault row per owner (e-mail from the Cloudflare Access JWT).
-- The server only ever stores ciphertext + KDF parameters; it never sees the
-- master password or any plaintext credential.

CREATE TABLE IF NOT EXISTS vaults (
	owner TEXT PRIMARY KEY,
	version INTEGER NOT NULL DEFAULT 1,
	kdf TEXT NOT NULL,
	ciphertext TEXT NOT NULL,
	created_at TEXT NOT NULL,
	updated_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_vaults_updated_at ON vaults (updated_at);
