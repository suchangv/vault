/* ==========================================================================
 * cf-vault service worker
 *
 * Only the *app shell* is cached (HTML/CSS/JS/icons). API responses are never
 * cached — the vault ciphertext and any decrypted data stay out of the Cache
 * Storage API. Being offline therefore only gives you the UI (plus a clear
 * "无法连接服务器" state), never stale credentials.
 * ========================================================================== */

const VERSION = "1";
const CACHE_NAME = `vault-shell-v${VERSION}`;
const SHELL_FALLBACK = "/index.html";

const PRECACHE = [
	"/",
	"/index.html",
	"/app.css",
	"/app.js",
	"/favicon.svg",
	"/manifest.webmanifest",
	"/icons/icon-192.png",
	"/icons/icon-512.png",
	"/icons/icon-maskable-512.png",
	"/icons/apple-touch-icon.png",
];

self.addEventListener("install", (event) => {
	event.waitUntil(
		(async () => {
			const cache = await caches.open(CACHE_NAME);
			await Promise.allSettled(
				PRECACHE.map((url) => cache.add(new Request(url, { cache: "reload" }))),
			);
			await self.skipWaiting();
		})(),
	);
});

self.addEventListener("activate", (event) => {
	event.waitUntil(
		(async () => {
			const keys = await caches.keys();
			await Promise.all(keys.filter((key) => key !== CACHE_NAME).map((key) => caches.delete(key)));
			await self.clients.claim();
		})(),
	);
});

self.addEventListener("message", (event) => {
	if (event.data?.type === "SKIP_WAITING") self.skipWaiting();
});

self.addEventListener("fetch", (event) => {
	const request = event.request;
	if (request.method !== "GET") return;

	const url = new URL(request.url);
	if (url.origin !== self.location.origin) return;
	// Never touch Access endpoints or the vault API.
	if (url.pathname.startsWith("/api/") || url.pathname.startsWith("/cdn-cgi/")) return;

	if (request.mode === "navigate") {
		event.respondWith(networkFirst(request, { timeout: 5000, fallback: SHELL_FALLBACK }));
		return;
	}
	event.respondWith(networkFirst(request, { timeout: 0 }));
});

const OFFLINE_HTML = `<!doctype html>
<html lang="zh-CN"><meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>Vault · 离线</title>
<style>
	body{margin:0;min-height:100dvh;display:grid;place-items:center;padding:24px;
		font:15px/1.6 system-ui,-apple-system,"PingFang SC",sans-serif;background:#070d11;color:#e7f2f5}
	.card{width:min(420px,100%);background:#0b1419;border:1px solid #1b2c35;border-radius:20px;padding:28px}
	h1{font-size:19px;margin:0 0 8px}
	p{margin:0;color:#8ba5ae;font-size:13.5px}
</style>
<div class="card">
	<h1>当前处于离线状态</h1>
	<p>Vault 没有缓存任何凭据。请恢复网络连接后重新打开；保险库需要从服务器取回密文才能解密。</p>
</div>
</html>`;

async function networkFirst(request, { timeout = 0, fallback = null } = {}) {
	const cache = await caches.open(CACHE_NAME);
	try {
		const response =
			timeout > 0
				? await Promise.race([
						fetch(request),
						new Promise((_, reject) => setTimeout(() => reject(new Error("timeout")), timeout)),
					])
				: await fetch(request);

		if (response && response.ok) {
			cache.put(request, response.clone()).catch(() => {});
		}
		return response;
	} catch {
		const cached = await cache.match(request, { ignoreSearch: true });
		if (cached) return cached;

		if (fallback) {
			const shell = await cache.match(fallback, { ignoreSearch: true });
			if (shell) return shell;
		}

		return new Response(OFFLINE_HTML, {
			status: 503,
			headers: { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store" },
		});
	}
}
