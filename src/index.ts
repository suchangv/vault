import { authenticate, type AccessEnv } from "./access";

interface Env extends AccessEnv {
	DB: D1Database;
	ASSETS: Fetcher;
}

const MAX_CIPHERTEXT_BYTES = 4 * 1024 * 1024; // 4 MiB, generous for a personal vault
const MAX_BODY_BYTES = 5 * 1024 * 1024;

const SECURITY_HEADERS: Record<string, string> = {
	"X-Content-Type-Options": "nosniff",
	"X-Frame-Options": "DENY",
	"Referrer-Policy": "no-referrer",
	"X-Robots-Tag": "noindex, nofollow, noarchive",
	"Strict-Transport-Security": "max-age=15552000",
	"Permissions-Policy":
		"accelerometer=(), camera=(), geolocation=(), gyroscope=(), microphone=(), payment=(), usb=()",
	"Cross-Origin-Opener-Policy": "same-origin",
	"Cross-Origin-Resource-Policy": "same-origin",
	"Content-Security-Policy":
		"default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
};

function withSecurityHeaders(response: Response, extra?: Record<string, string>) {
	const headers = new Headers(response.headers);
	for (const [key, value] of Object.entries(SECURITY_HEADERS)) {
		headers.set(key, value);
	}
	for (const [key, value] of Object.entries(extra ?? {})) {
		headers.set(key, value);
	}
	return new Response(response.body, {
		status: response.status,
		statusText: response.statusText,
		headers,
	});
}

function json(body: unknown, status = 200, extra?: Record<string, string>) {
	return new Response(JSON.stringify(body), {
		status,
		headers: {
			"Content-Type": "application/json; charset=utf-8",
			"Cache-Control": "no-store",
			...SECURITY_HEADERS,
			...extra,
		},
	});
}

interface VaultRow {
	owner: string;
	version: number;
	kdf: string;
	ciphertext: string;
	created_at: string;
	updated_at: string;
}

function isKdf(value: unknown): value is { salt: string; iterations: number; algorithm?: string } {
	if (!value || typeof value !== "object") return false;
	const kdf = value as Record<string, unknown>;
	return (
		typeof kdf.salt === "string" &&
		kdf.salt.length > 0 &&
		kdf.salt.length < 128 &&
		typeof kdf.iterations === "number" &&
		Number.isFinite(kdf.iterations) &&
		kdf.iterations >= 100_000 &&
		kdf.iterations <= 5_000_000
	);
}

async function handleApi(request: Request, env: Env, url: URL): Promise<Response> {
	const method = request.method;
	const path = url.pathname;

	if (path === "/api/me" && method === "GET") {
		const auth = await authenticate(request, env);
		if (!auth.ok) return json({ error: auth.reason }, auth.status);
		return json({
			email: auth.identity.email,
			authMethod: auth.identity.authMethod ?? null,
			expiresAt: auth.identity.expiresAt,
		});
	}

	const auth = await authenticate(request, env);
	if (!auth.ok) return json({ error: auth.reason }, auth.status);
	const owner = auth.identity.email;

	if (path === "/api/vault" && method === "GET") {
		const row = await env.DB.prepare(
			"SELECT version, kdf, ciphertext, updated_at FROM vaults WHERE owner = ?",
		)
			.bind(owner)
			.first<Pick<VaultRow, "version" | "kdf" | "ciphertext" | "updated_at">>();

		if (!row) return json({ error: "no_vault" }, 404);
		return json({
			version: row.version,
			kdf: JSON.parse(row.kdf),
			ciphertext: row.ciphertext,
			updatedAt: row.updated_at,
		});
	}

	if (path === "/api/vault" && method === "PUT") {
		const raw = await request.text();
		if (raw.length > MAX_BODY_BYTES) return json({ error: "payload_too_large" }, 413);

		let body: unknown;
		try {
			body = JSON.parse(raw);
		} catch {
			return json({ error: "invalid_json" }, 400);
		}

		const payload = body as {
			version?: unknown;
			kdf?: unknown;
			ciphertext?: unknown;
		};
		if (typeof payload.ciphertext !== "string" || payload.ciphertext.length === 0) {
			return json({ error: "invalid_ciphertext" }, 400);
		}
		if (payload.ciphertext.length > MAX_CIPHERTEXT_BYTES) {
			return json({ error: "payload_too_large" }, 413);
		}
		if (!isKdf(payload.kdf)) return json({ error: "invalid_kdf" }, 400);
		if (typeof payload.version !== "number" || !Number.isInteger(payload.version)) {
			return json({ error: "invalid_version" }, 400);
		}

		const now = new Date().toISOString();
		const kdf = JSON.stringify({
			algorithm: "PBKDF2-SHA256",
			salt: (payload.kdf as { salt: string }).salt,
			iterations: (payload.kdf as { iterations: number }).iterations,
		});

		const existing = await env.DB.prepare(
			"SELECT version FROM vaults WHERE owner = ?",
		)
			.bind(owner)
			.first<{ version: number }>();

		if (!existing) {
			if (payload.version !== 0) {
				return json({ error: "conflict", version: 0 }, 409);
			}
			await env.DB.prepare(
				"INSERT INTO vaults (owner, version, kdf, ciphertext, created_at, updated_at) VALUES (?, 1, ?, ?, ?, ?)",
			)
				.bind(owner, kdf, payload.ciphertext, now, now)
				.run();
			return json({ version: 1, updatedAt: now });
		}

		if (existing.version !== payload.version) {
			const current = await env.DB.prepare(
				"SELECT version, kdf, ciphertext, updated_at FROM vaults WHERE owner = ?",
			)
				.bind(owner)
				.first<Pick<VaultRow, "version" | "kdf" | "ciphertext" | "updated_at">>();
			return json(
				{
					error: "conflict",
					version: current?.version ?? existing.version,
					kdf: current ? JSON.parse(current.kdf) : null,
					ciphertext: current?.ciphertext ?? null,
					updatedAt: current?.updated_at ?? null,
				},
				409,
			);
		}

		const result = await env.DB.prepare(
			"UPDATE vaults SET version = version + 1, kdf = ?, ciphertext = ?, updated_at = ? WHERE owner = ? AND version = ?",
		)
			.bind(kdf, payload.ciphertext, now, owner, payload.version)
			.run();

		if (!result.meta.changes) return json({ error: "conflict" }, 409);
		return json({ version: payload.version + 1, updatedAt: now });
	}

	if (path === "/api/vault" && method === "DELETE") {
		await env.DB.prepare("DELETE FROM vaults WHERE owner = ?").bind(owner).run();
		return json({ ok: true });
	}

	if (path === "/api/health" && method === "GET") {
		return json({ ok: true, email: owner });
	}

	return json({ error: "not_found" }, 404);
}

export default {
	async fetch(request: Request, env: Env): Promise<Response> {
		const url = new URL(request.url);

		if (url.pathname.startsWith("/api/")) {
			try {
				return await handleApi(request, env, url);
			} catch (error) {
				console.error("api error", error);
				return json({ error: "internal_error" }, 500);
			}
		}

		// Static assets are gated too: no HTML/JS is served without a valid
		// Access identity, so the app surface is never publicly reachable.
		const auth = await authenticate(request, env);
		if (!auth.ok) {
			return json(
				{
					error: "unauthorized",
					reason: auth.reason,
					hint: "This app must be reached through Cloudflare Access.",
				},
				auth.status,
			);
		}

		const response = await env.ASSETS.fetch(request);
		return withSecurityHeaders(response, {
			"Cache-Control": response.headers.get("Cache-Control") ?? "public, max-age=300",
		});
	},
} satisfies ExportedHandler<Env>;
