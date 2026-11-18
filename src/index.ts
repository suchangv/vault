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

function htmlPage(status: number, title: string, message: string) {
	const body = `<!doctype html>
<html lang="zh-CN">
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<meta name="robots" content="noindex, nofollow" />
<title>${title}</title>
<style>
	:root { color-scheme: dark light }
	body { margin:0; min-height:100dvh; display:grid; place-items:center; padding:24px;
		font:15px/1.6 system-ui,-apple-system,"Segoe UI","PingFang SC","Microsoft YaHei",sans-serif;
		background:#070d11; color:#e7f2f5 }
	.card { width:min(460px,100%); background:#0b1419; border:1px solid #1b2c35; border-radius:20px;
		padding:28px; box-shadow:0 40px 90px -55px rgba(0,0,0,.95) }
	.mark { width:42px;height:42px;border-radius:13px;display:grid;place-items:center;font-weight:700;
		background:linear-gradient(160deg,#f99389,#f27c72);color:#2a0b08 }
	h1 { font-size:20px; margin:18px 0 8px; letter-spacing:-.01em }
	p { margin:0 0 14px; color:#8ba5ae; font-size:13.5px }
	code { font-family:ui-monospace,Menlo,monospace; font-size:12.5px; background:#16252e; padding:2px 6px; border-radius:6px }
	.actions { display:flex; gap:10px; flex-wrap:wrap; margin-top:18px }
	a.btn { display:inline-flex; align-items:center; height:42px; padding:0 16px; border-radius:10px;
		font-size:13.5px; font-weight:550; text-decoration:none; background:linear-gradient(160deg,#43d7ba,#2ec4a6); color:#032019 }
	a.ghost { background:#101c23; border:1px solid #1b2c35; color:#e7f2f5 }
</style>
<div class="card">
	<div class="mark">!</div>
	<h1>${title}</h1>
	<p>${message}</p>
	<p>原因代码：<code>${status}</code></p>
	<div class="actions">
		<a class="btn" href="/">重新加载</a>
		<a class="btn ghost" href="/cdn-cgi/access/logout">退出 Access 会话</a>
	</div>
</div>
</html>`;
	return new Response(body, {
		status,
		headers: {
			...SECURITY_HEADERS,
			// Fully server-generated, static markup: allow the inline <style> only
			// on this error document so it renders without a second request.
			"Content-Security-Policy":
				"default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
			"Content-Type": "text/html; charset=utf-8",
			"Cache-Control": "no-store",
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
			const messages: Record<string, string> = {
				missing_access_token:
					"这个请求没有被 Cloudflare Access 保护。<code>vault.suchangv.com</code> 应该只允许通过 Access 应用访问。",
				email_not_allowed: "当前登录的 Google 账号不在白名单（suchangv@gmail.com）中。",
				bad_audience: "Access 应用与 Worker 配置的 AUD 不一致。",
				bad_issuer: "令牌签发者与团队域名不一致。",
				"token expired": "Access 会话已过期，请重新登录。",
			};
			return htmlPage(
				auth.status,
				"无法访问 Vault",
				messages[auth.reason] ?? `身份验证失败：${auth.reason.replace(/[&<>"']/g, (c) => `&#${c.charCodeAt(0)};`)}`,
			);
		}

		const response = await env.ASSETS.fetch(request);
		const assetHeaders: Record<string, string> = {
			"Cache-Control": response.headers.get("Cache-Control") ?? "public, max-age=300",
		};

		// The service worker must always revalidate so a new deploy is picked up.
		if (url.pathname === "/sw.js") {
			assetHeaders["Cache-Control"] = "no-cache";
			assetHeaders["Service-Worker-Allowed"] = "/";
			assetHeaders["Content-Type"] = "text/javascript; charset=utf-8";
		}
		if (url.pathname === "/manifest.webmanifest") {
			assetHeaders["Content-Type"] = "application/manifest+json; charset=utf-8";
		}

		return withSecurityHeaders(response, assetHeaders);
	},
} satisfies ExportedHandler<Env>;
