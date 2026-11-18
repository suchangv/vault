/* ==========================================================================
 * cf-vault — client
 *
 * Zero-knowledge: the master password never leaves this file's scope, the
 * derived AES-GCM key is non-extractable and only lives in memory. The server
 * (and Cloudflare) only ever sees ciphertext + KDF parameters.
 * ========================================================================== */

const $ = (selector, root = document) => root.querySelector(selector);
const $$ = (selector, root = document) => [...root.querySelectorAll(selector)];

const KDF_ITERATIONS = 600_000;
const KDF_ALGORITHM = "PBKDF2-SHA256";
const AAD = new TextEncoder().encode("cf-vault:v1");
const SAVE_DEBOUNCE_MS = 700;
const AUTOLOCK_OPTIONS = [
	{ value: 60_000, label: "1 分钟" },
	{ value: 5 * 60_000, label: "5 分钟" },
	{ value: 15 * 60_000, label: "15 分钟" },
	{ value: 30 * 60_000, label: "30 分钟" },
	{ value: 60 * 60_000, label: "1 小时" },
	{ value: 0, label: "永不自动锁定" },
];
const LS_KEYS = {
	theme: "vault.theme",
	autolock: "vault.autolock",
	hint: "vault.hint",
	filter: "vault.filter",
	remember: "vault.remember",
};

const DEVICE_DB = "vault-device";
const DEVICE_STORE = "device";
const DEVICE_KEY_ENTRY = "device-key";
const DEVICE_TOKEN_ENTRY = "token";
const DEVICE_AAD = new TextEncoder().encode("cf-vault:device:v1");
const REMEMBER_DEFAULT_DAYS = 7;

const state = {
	email: "",
	vault: null,
	key: null,
	data: null,
	selectedId: null,
	filter: "all",
	query: "",
	revealed: new Set(),
	locked: true,
	dirty: false,
	saving: false,
	saveTimer: null,
	retryTimer: null,
	lastActivity: Date.now(),
	autolockMs: 5 * 60_000,
	theme: "auto",
	accessExpiresAt: null,
	pendingNew: null,
	deviceRemember: null,
};

let deferredInstallPrompt = null;
let swRegistration = null;

/* --------------------------------------------------------------------------
 * Icons
 * -------------------------------------------------------------------------- */

const ICONS = {
	copy: '<rect x="9" y="9" width="12" height="12" rx="2.5"/><path d="M5 15H4a1 1 0 0 1-1-1V4a1 1 0 0 1 1-1h10a1 1 0 0 1 1 1v1"/>',
	eye: '<path d="M2.5 12S6 5.5 12 5.5 21.5 12 21.5 12 18 18.5 12 18.5 2.5 12 2.5 12Z"/><circle cx="12" cy="12" r="3"/>',
	"eye-off":
		'<path d="M4 4l16 16"/><path d="M9.9 5.9A9.6 9.6 0 0 1 12 5.5c6 0 9.5 6.5 9.5 6.5a17 17 0 0 1-3 3.8"/><path d="M6.2 7.8A17.4 17.4 0 0 0 2.5 12S6 18.5 12 18.5a9.6 9.6 0 0 0 3.9-.85"/><path d="M9.9 9.9a3 3 0 0 0 4.2 4.2"/>',
	star: '<path d="M12 3.6l2.6 5.3 5.9.9-4.3 4.1 1 5.8-5.2-2.7-5.2 2.7 1-5.8L3.5 9.8l5.9-.9z"/>',
	lock: '<rect x="4.5" y="10.5" width="15" height="10" rx="2.5"/><path d="M8 10.5V7.8a4 4 0 0 1 8 0v2.7"/>',
	unlock: '<rect x="4.5" y="10.5" width="15" height="10" rx="2.5"/><path d="M8 10.5V7.8a4 4 0 0 1 7.6-1.6"/>',
	plus: '<path d="M12 5v14M5 12h14"/>',
	edit: '<path d="M12 20h9"/><path d="M16.5 3.5a2.1 2.1 0 0 1 3 3L7 19l-4 1 1-4Z"/>',
	trash: '<path d="M3.5 6.5h17"/><path d="M8.5 6.5V4.8A1.3 1.3 0 0 1 9.8 3.5h4.4a1.3 1.3 0 0 1 1.3 1.3v1.7"/><path d="M6.5 6.5l.8 12.4a1.7 1.7 0 0 0 1.7 1.6h6a1.7 1.7 0 0 0 1.7-1.6l.8-12.4"/>',
	back: '<path d="M15 5l-7 7 7 7"/>',
	close: '<path d="M6 6l12 12M18 6L6 18"/>',
	settings:
		'<circle cx="12" cy="12" r="3.2"/><path d="M19.4 15a1.7 1.7 0 0 0 .34 1.87l.06.06a2 2 0 1 1-2.83 2.83l-.06-.06a1.7 1.7 0 0 0-1.87-.34 1.7 1.7 0 0 0-1 1.55V21a2 2 0 1 1-4 0v-.09A1.7 1.7 0 0 0 9 19.4a1.7 1.7 0 0 0-1.87.34l-.06.06a2 2 0 1 1-2.83-2.83l.06-.06A1.7 1.7 0 0 0 4.6 15a1.7 1.7 0 0 0-1.55-1H3a2 2 0 1 1 0-4h.09A1.7 1.7 0 0 0 4.6 9a1.7 1.7 0 0 0-.34-1.87l-.06-.06a2 2 0 1 1 2.83-2.83l.06.06A1.7 1.7 0 0 0 9 4.6h.09A1.7 1.7 0 0 0 10 3.05V3a2 2 0 1 1 4 0v.09a1.7 1.7 0 0 0 1 1.55 1.7 1.7 0 0 0 1.87-.34l.06-.06a2 2 0 1 1 2.83 2.83l-.06.06A1.7 1.7 0 0 0 19.4 9v.09a1.7 1.7 0 0 0 1.55 1H21a2 2 0 1 1 0 4h-.09a1.7 1.7 0 0 0-1.51 1z"/>',
	download: '<path d="M12 3.5v12"/><path d="M7.5 11l4.5 4.5 4.5-4.5"/><path d="M4 20h16"/>',
	upload: '<path d="M12 20.5v-12"/><path d="M7.5 13L12 8.5l4.5 4.5"/><path d="M4 4h16"/>',
	key: '<circle cx="8" cy="15" r="4"/><path d="M10.8 12.2L20 3"/><path d="M16 7l3 3"/><path d="M18.5 4.5l2 2"/>',
	shield: '<path d="M12 3.2l7.5 3v5.5c0 4.4-3.1 8.2-7.5 9.3-4.4-1.1-7.5-4.9-7.5-9.3V6.2Z"/><path d="M9 12.2l2 2 4-4.2"/>',
	check: '<path d="M4.5 12.5l5 5 10-11"/>',
	alert: '<path d="M12 3.5l9 16H3Z"/><path d="M12 9.5v5"/><path d="M12 17.3v.2"/>',
	globe: '<circle cx="12" cy="12" r="8.5"/><path d="M3.5 12h17"/><path d="M12 3.5c2.4 2.3 3.7 5.3 3.7 8.5S14.4 18.2 12 20.5c-2.4-2.3-3.7-5.3-3.7-8.5S9.6 5.8 12 3.5Z"/>',
	user: '<circle cx="12" cy="8.5" r="3.6"/><path d="M4.8 20a7.2 7.2 0 0 1 14.4 0"/>',
	card: '<rect x="2.8" y="5.5" width="18.4" height="13" rx="2.6"/><path d="M2.8 10h18.4"/><path d="M6.5 14.6h3.6"/>',
	note: '<path d="M14 3.5H6.8A1.8 1.8 0 0 0 5 5.3v13.4a1.8 1.8 0 0 0 1.8 1.8h10.4a1.8 1.8 0 0 0 1.8-1.8V8Z"/><path d="M14 3.5V8h5"/><path d="M8.5 12.5h7"/><path d="M8.5 16h4.5"/>',
	chevron: '<path d="M9 5l7 7-7 7"/>',
	logout: '<path d="M14.5 8V5.8A1.8 1.8 0 0 0 12.7 4H5.8A1.8 1.8 0 0 0 4 5.8v12.4A1.8 1.8 0 0 0 5.8 20h6.9a1.8 1.8 0 0 0 1.8-1.8V16"/><path d="M9.5 12h11"/><path d="M17.5 8.5L21 12l-3.5 3.5"/>',
	refresh: '<path d="M20 11.5a8 8 0 1 0-2.6 6.2"/><path d="M20 4.5v7h-7"/>',
	moon: '<path d="M20 14.5A8.5 8.5 0 0 1 9.5 4a8.5 8.5 0 1 0 10.5 10.5Z"/>',
	sun: '<circle cx="12" cy="12" r="4"/><path d="M12 2.5v2M12 19.5v2M2.5 12h2M19.5 12h2M5.2 5.2l1.4 1.4M17.4 17.4l1.4 1.4M18.8 5.2l-1.4 1.4M6.6 17.4l-1.4 1.4"/>',
	save: '<path d="M5 4h11l3 3v13H5Z"/><path d="M8 4v5h7V4"/><path d="M8 14h8"/>',
	search: '<circle cx="11" cy="11" r="6.5"/><path d="M16 16l4.5 4.5"/>',
	warn: '<path d="M12 4l8.5 15h-17Z"/><path d="M12 9.5v4.5"/><path d="M12 16.8v.2"/>',
};

function icon(name, className = "") {
	return `<svg class="${className}" viewBox="0 0 24 24" aria-hidden="true">${ICONS[name] ?? ""}</svg>`;
}

/* --------------------------------------------------------------------------
 * Small utilities
 * -------------------------------------------------------------------------- */

const escapeHtml = (value) =>
	String(value ?? "").replace(
		/[&<>"']/g,
		(char) =>
			({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[
				char
			],
	);

const uid = () =>
	crypto.randomUUID ? crypto.randomUUID() : `id-${Date.now()}-${Math.random().toString(16).slice(2)}`;

function bytesToB64(bytes) {
	let binary = "";
	const chunk = 0x8000;
	for (let i = 0; i < bytes.length; i += chunk) {
		binary += String.fromCharCode(...bytes.subarray(i, i + chunk));
	}
	return btoa(binary);
}

function b64ToBytes(value) {
	const binary = atob(value);
	const bytes = new Uint8Array(binary.length);
	for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
	return bytes;
}

function randomBytes(length) {
	const bytes = new Uint8Array(length);
	crypto.getRandomValues(bytes);
	return bytes;
}

function randomInt(max) {
	if (max <= 0) return 0;
	const limit = Math.floor(0xffffffff / max) * max;
	const buf = new Uint32Array(1);
	do {
		crypto.getRandomValues(buf);
	} while (buf[0] >= limit);
	return buf[0] % max;
}

const pick = (list) => list[randomInt(list.length)];

function formatDate(value) {
	if (!value) return "—";
	const date = new Date(value);
	if (Number.isNaN(date.getTime())) return "—";
	const pad = (n) => String(n).padStart(2, "0");
	return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())} ${pad(date.getHours())}:${pad(date.getMinutes())}`;
}

function hostOf(url) {
	if (!url) return "";
	try {
		const parsed = new URL(/^https?:\/\//i.test(url) ? url : `https://${url}`);
		return parsed.host;
	} catch {
		return url;
	}
}

/* --------------------------------------------------------------------------
 * Crypto
 * -------------------------------------------------------------------------- */

async function deriveKey(password, saltB64, iterations) {
	const baseKey = await crypto.subtle.importKey(
		"raw",
		new TextEncoder().encode(password.normalize("NFKC")),
		"PBKDF2",
		false,
		["deriveKey"],
	);
	return crypto.subtle.deriveKey(
		{
			name: "PBKDF2",
			salt: b64ToBytes(saltB64),
			iterations,
			hash: "SHA-256",
		},
		baseKey,
		{ name: "AES-GCM", length: 256 },
		false,
		["encrypt", "decrypt"],
	);
}

/**
 * Same PBKDF2 derivation, but keeps the raw key bytes long enough to wrap them
 * under the device key so the user can skip the master password on refresh.
 * The session key handed to the app is still non-extractable.
 */
async function deriveKeyMaterial(password, saltB64, iterations) {
	const baseKey = await crypto.subtle.importKey(
		"raw",
		new TextEncoder().encode(password.normalize("NFKC")),
		"PBKDF2",
		false,
		["deriveKey"],
	);
	const extractable = await crypto.subtle.deriveKey(
		{
			name: "PBKDF2",
			salt: b64ToBytes(saltB64),
			iterations,
			hash: "SHA-256",
		},
		baseKey,
		{ name: "AES-GCM", length: 256 },
		true,
		["encrypt", "decrypt"],
	);
	const raw = new Uint8Array(await crypto.subtle.exportKey("raw", extractable));
	const sessionKey = await crypto.subtle.importKey("raw", raw, { name: "AES-GCM" }, false, [
		"encrypt",
		"decrypt",
	]);
	return { sessionKey, raw };
}

async function encryptJson(key, value) {
	const iv = randomBytes(12);
	const ciphertext = await crypto.subtle.encrypt(
		{ name: "AES-GCM", iv, additionalData: AAD },
		key,
		new TextEncoder().encode(JSON.stringify(value)),
	);
	return `v1.${bytesToB64(iv)}.${bytesToB64(new Uint8Array(ciphertext))}`;
}

async function decryptJson(key, payload) {
	const [version, ivB64, dataB64] = String(payload).split(".");
	if (version !== "v1" || !ivB64 || !dataB64) throw new Error("unsupported_payload");
	const plaintext = await crypto.subtle.decrypt(
		{ name: "AES-GCM", iv: b64ToBytes(ivB64), additionalData: AAD },
		key,
		b64ToBytes(dataB64),
	);
	return JSON.parse(new TextDecoder().decode(plaintext));
}

/* --------------------------------------------------------------------------
 * Trusted device ("remember me")
 *
 * The vault key is wrapped with a non-extractable AES-GCM CryptoKey that lives
 * in IndexedDB. Only the wrapped blob + expiry are stored; the vault key bytes
 * are never persisted in clear. IndexedDB is origin-bound and the CryptoKey is
 * non-exportable, so copying localStorage/cookies does not carry the vault to
 * another machine. Manual / idle lock drops the token.
 * -------------------------------------------------------------------------- */

let deviceDbPromise = null;

function openDeviceDb() {
	if (deviceDbPromise) return deviceDbPromise;
	deviceDbPromise = new Promise((resolve, reject) => {
		if (!("indexedDB" in window)) {
			reject(new Error("indexeddb_unavailable"));
			return;
		}
		const request = indexedDB.open(DEVICE_DB, 1);
		request.onupgradeneeded = () => request.result.createObjectStore(DEVICE_STORE);
		request.onsuccess = () => resolve(request.result);
		request.onerror = () => reject(request.error);
	}).catch((error) => {
		deviceDbPromise = null;
		throw error;
	});
	return deviceDbPromise;
}

async function deviceGet(key) {
	try {
		const db = await openDeviceDb();
		return await new Promise((resolve, reject) => {
			const tx = db.transaction(DEVICE_STORE, "readonly");
			const request = tx.objectStore(DEVICE_STORE).get(key);
			request.onsuccess = () => resolve(request.result ?? null);
			request.onerror = () => reject(request.error);
		});
	} catch {
		return null;
	}
}

async function deviceSet(key, value) {
	try {
		const db = await openDeviceDb();
		await new Promise((resolve, reject) => {
			const tx = db.transaction(DEVICE_STORE, "readwrite");
			tx.objectStore(DEVICE_STORE).put(value, key);
			tx.oncomplete = () => resolve();
			tx.onerror = () => reject(tx.error);
		});
		return true;
	} catch {
		return false;
	}
}

async function deviceDelete(key) {
	try {
		const db = await openDeviceDb();
		await new Promise((resolve, reject) => {
			const tx = db.transaction(DEVICE_STORE, "readwrite");
			tx.objectStore(DEVICE_STORE).delete(key);
			tx.oncomplete = () => resolve();
			tx.onerror = () => reject(tx.error);
		});
	} catch {
		/* ignore */
	}
}

function rememberDays() {
	const stored = localStorage.getItem(LS_KEYS.remember);
	const days = stored === null ? REMEMBER_DEFAULT_DAYS : Number(stored);
	return Number.isFinite(days) && days > 0 ? days : 0;
}

async function getDeviceKey(create) {
	let key = await deviceGet(DEVICE_KEY_ENTRY);
	if (key || !create) return key ?? null;
	try {
		key = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, false, [
			"encrypt",
			"decrypt",
		]);
	} catch {
		return null;
	}
	await deviceSet(DEVICE_KEY_ENTRY, key);
	return key;
}

async function wrapVaultKey(rawBytes) {
	const deviceKey = await getDeviceKey(true);
	if (!deviceKey) return null;
	const iv = randomBytes(12);
	const ciphertext = await crypto.subtle.encrypt(
		{ name: "AES-GCM", iv, additionalData: DEVICE_AAD },
		deviceKey,
		rawBytes,
	);
	return `v1.${bytesToB64(iv)}.${bytesToB64(new Uint8Array(ciphertext))}`;
}

async function unwrapVaultKey(payload) {
	if (typeof payload !== "string") return null;
	const deviceKey = await getDeviceKey(false);
	if (!deviceKey) return null;
	const [version, ivB64, dataB64] = payload.split(".");
	if (version !== "v1" || !ivB64 || !dataB64) return null;
	try {
		const raw = await crypto.subtle.decrypt(
			{ name: "AES-GCM", iv: b64ToBytes(ivB64), additionalData: DEVICE_AAD },
			deviceKey,
			b64ToBytes(dataB64),
		);
		return await crypto.subtle.importKey("raw", raw, { name: "AES-GCM" }, false, [
			"encrypt",
			"decrypt",
		]);
	} catch {
		return null;
	}
}

async function rememberDevice(rawBytes) {
	const days = rememberDays();
	if (!days) {
		await clearRememberToken();
		return;
	}
	const wrapped = await wrapVaultKey(rawBytes);
	if (!wrapped) return;
	const record = {
		owner: state.email,
		wrapped,
		expiresAt: Date.now() + days * 86_400_000,
		createdAt: new Date().toISOString(),
	};
	if (await deviceSet(DEVICE_TOKEN_ENTRY, record)) state.deviceRemember = record;
}

async function readRememberToken() {
	const record = await deviceGet(DEVICE_TOKEN_ENTRY);
	if (!record || typeof record !== "object" || !record.wrapped) return null;
	if (record.owner !== state.email || !(record.expiresAt > Date.now())) {
		await clearRememberToken();
		return null;
	}
	return record;
}

async function renewRememberToken(record) {
	const days = rememberDays();
	if (!days) return;
	const next = { ...record, expiresAt: Date.now() + days * 86_400_000 };
	if (await deviceSet(DEVICE_TOKEN_ENTRY, next)) state.deviceRemember = next;
}

async function clearRememberToken() {
	state.deviceRemember = null;
	await deviceDelete(DEVICE_TOKEN_ENTRY);
}

async function forgetDevice() {
	state.deviceRemember = null;
	await deviceDelete(DEVICE_TOKEN_ENTRY);
	await deviceDelete(DEVICE_KEY_ENTRY);
}

function rememberStatusText() {
	const days = rememberDays();
	if (!days) return "已关闭：每次刷新或重新打开都需要输入主密码。";
	if (state.deviceRemember?.expiresAt) {
		return `本设备已记住，免密有效至 ${formatDate(state.deviceRemember.expiresAt)}；手动或闲置锁定后会失效。`;
	}
	return `已开启 ${days} 天免密解锁，成功解锁一次后生效。`;
}

/* --------------------------------------------------------------------------
 * API
 * -------------------------------------------------------------------------- */

class ApiError extends Error {
	constructor(status, body) {
		super(body?.error ?? `http_${status}`);
		this.status = status;
		this.body = body;
	}
}

async function api(path, options = {}) {
	const response = await fetch(path, {
		credentials: "same-origin",
		cache: "no-store",
		headers: { "Content-Type": "application/json", ...(options.headers ?? {}) },
		...options,
	});
	let body = null;
	const text = await response.text();
	if (text) {
		try {
			body = JSON.parse(text);
		} catch {
			body = null;
		}
	}
	if (!response.ok) throw new ApiError(response.status, body);
	return body;
}

/* --------------------------------------------------------------------------
 * Theme
 * -------------------------------------------------------------------------- */

function applyTheme(theme = state.theme) {
	state.theme = theme;
	localStorage.setItem(LS_KEYS.theme, theme);
	const resolved =
		theme === "auto"
			? window.matchMedia("(prefers-color-scheme: light)").matches
				? "light"
				: "dark"
			: theme;
	document.documentElement.dataset.theme = resolved;
	const meta = document.getElementById("theme-color-meta");
	if (meta) meta.setAttribute("content", resolved === "light" ? "#eef3f4" : "#070d11");
}

/**
 * Installed desktop PWAs can use the Window Controls Overlay display mode: the
 * OS window buttons are drawn on top of the page and the title bar can blend
 * into the app background. We reserve the reported height and expose it as
 * `--wco-height` so CSS can keep that band clear and draggable.
 */
function setupWindowControlsOverlay() {
	const overlay = navigator.windowControlsOverlay;
	if (!overlay) return;

	const sync = () => {
		const visible = overlay.visible === true;
		document.documentElement.classList.toggle("wco", visible);
		if (!visible) {
			document.documentElement.style.removeProperty("--wco-height");
			return;
		}
		try {
			const rect = overlay.getTitlebarAreaRect?.();
			if (rect?.height) {
				document.documentElement.style.setProperty("--wco-height", `${Math.round(rect.height)}px`);
			}
		} catch {
			/* geometry is best-effort */
		}
	};

	sync();
	overlay.addEventListener?.("geometrychange", sync);
}

/* --------------------------------------------------------------------------
 * Toasts
 * -------------------------------------------------------------------------- */

function toast(message, kind = "info", timeout = 3000) {
	const root = $("#toasts");
	const el = document.createElement("div");
	el.className = `toast${kind === "error" ? " is-error" : kind === "ok" ? " is-ok" : ""}`;
	const glyph = kind === "error" ? "alert" : kind === "ok" ? "check" : "shield";
	el.innerHTML = `${icon(glyph)}<span>${escapeHtml(message)}</span>`;
	root.appendChild(el);
	setTimeout(() => {
		el.classList.add("is-out");
		setTimeout(() => el.remove(), 200);
	}, timeout);
}

/* --------------------------------------------------------------------------
 * Modal plumbing
 * -------------------------------------------------------------------------- */

function openModal({ title, body, footer = "", size = "", onMount, closable = true }) {
	const root = $("#modal-root");
	const backdrop = document.createElement("div");
	backdrop.className = "modal-backdrop";
	backdrop.innerHTML = `
		<div class="modal ${size}" role="dialog" aria-modal="true" aria-label="${escapeHtml(title)}">
			<header class="modal-head">
				<h2>${escapeHtml(title)}</h2>
				${closable ? `<button class="icon-btn" type="button" data-close aria-label="关闭">${icon("close")}</button>` : ""}
			</header>
			<div class="modal-body">${body}</div>
			${footer ? `<footer class="modal-foot">${footer}</footer>` : ""}
		</div>`;

	const previousActive = document.activeElement;
	const close = () => {
		backdrop.remove();
		document.removeEventListener("keydown", onKey);
		if (previousActive instanceof HTMLElement) previousActive.focus?.();
	};
	const onKey = (event) => {
		if (event.key === "Escape" && closable) {
			event.stopPropagation();
			close();
		}
	};

	backdrop.addEventListener("click", (event) => {
		if (event.target === backdrop && closable) close();
	});
	backdrop.querySelector("[data-close]")?.addEventListener("click", close);
	document.addEventListener("keydown", onKey);
	root.appendChild(backdrop);

	const modal = { root: backdrop, element: backdrop.querySelector(".modal"), body: backdrop.querySelector(".modal-body"), close };
	onMount?.(modal);

	const focusTarget = backdrop.querySelector("input, textarea, select, button");
	focusTarget?.focus();
	return modal;
}

function confirmDialog({ title, message, confirmLabel = "确认", danger = false, requireText = "" }) {
	return new Promise((resolve) => {
		const modal = openModal({
			title,
			size: "modal-sm",
			body: `
				<p class="modal-text">${message}</p>
				${requireText ? `<div class="field field-spaced"><label for="confirm-text">输入 <b>${escapeHtml(requireText)}</b> 以继续</label><input id="confirm-text" type="text" autocomplete="off" spellcheck="false" /></div>` : ""}
			`,
			footer: `<button class="btn btn-ghost" type="button" data-cancel>取消</button>
				<button class="btn ${danger ? "btn-danger" : "btn-primary"}" type="button" data-ok>${escapeHtml(confirmLabel)}</button>`,
			onMount(m) {
				const ok = m.element.querySelector("[data-ok]");
				const cancel = m.element.querySelector("[data-cancel]");
				const input = m.element.querySelector("#confirm-text");
				if (requireText) {
					ok.disabled = true;
					input.addEventListener("input", () => {
						ok.disabled = input.value.trim() !== requireText;
					});
				}
				cancel.addEventListener("click", () => {
					m.close();
					resolve(false);
				});
				ok.addEventListener("click", () => {
					m.close();
					resolve(true);
				});
			},
		});
		void modal;
	});
}

function askPassword({ title, message, confirmLabel = "继续" }) {
	return new Promise((resolve) => {
		openModal({
			title,
			size: "modal-sm",
			body: `
				<p class="modal-text">${message}</p>
				<div class="field field-spaced">
					<label for="ask-password">主密码</label>
					<div class="input-wrap">
						<input id="ask-password" type="password" autocomplete="current-password" spellcheck="false" />
						<button type="button" class="icon-btn eye" data-target="ask-password" aria-label="显示密码"></button>
					</div>
				</div>
				<p class="auth-error" id="ask-error" role="alert" hidden></p>
			`,
			footer: `<button class="btn btn-ghost" type="button" data-cancel>取消</button>
				<button class="btn btn-primary" type="button" data-ok>${escapeHtml(confirmLabel)}</button>`,
			onMount(m) {
				const input = m.element.querySelector("#ask-password");
				const error = m.element.querySelector("#ask-error");
				const ok = m.element.querySelector("[data-ok]");
				bindPasswordToggle(m.element);
				const finish = (value) => {
					m.close();
					resolve(value);
				};
				m.element.querySelector("[data-cancel]").addEventListener("click", () => finish(null));
				ok.addEventListener("click", () => {
					if (!input.value) {
						error.textContent = "请输入主密码";
						error.hidden = false;
						return;
					}
					finish(input.value);
				});
				input.addEventListener("keydown", (event) => {
					if (event.key === "Enter") {
						event.preventDefault();
						ok.click();
					}
				});
			},
		});
	});
}

function bindPasswordToggle(root) {
	$$(".eye", root).forEach((button) => {
		if (button.dataset.bound) return;
		button.dataset.bound = "1";
		button.innerHTML = icon("eye");
		button.addEventListener("click", () => {
			const input = root.querySelector(`#${button.dataset.target}`);
			if (!input) return;
			const show = input.type === "password";
			input.type = show ? "text" : "password";
			button.innerHTML = icon(show ? "eye-off" : "eye");
			button.classList.toggle("is-active", show);
		});
	});
}

/* --------------------------------------------------------------------------
 * Password strength & generator
 * -------------------------------------------------------------------------- */

function passwordStrength(password) {
	if (!password) return { score: 0, label: "密码强度", pct: 0 };
	let pool = 0;
	if (/[a-z]/.test(password)) pool += 26;
	if (/[A-Z]/.test(password)) pool += 26;
	if (/[0-9]/.test(password)) pool += 10;
	if (/[^A-Za-z0-9]/.test(password)) pool += 33;
	const unique = new Set(password).size;
	const entropy = password.length * Math.log2(Math.max(pool, 2)) * Math.min(1, unique / Math.max(4, password.length * 0.6));
	let score = entropy < 30 ? 1 : entropy < 50 ? 2 : entropy < 75 ? 3 : 4;
	if (password.length < 8) score = Math.min(score, 1);
	if (/^(.)\1+$/.test(password) || /^(?:12345|qwerty|password|admin)/i.test(password)) score = 1;
	const labels = ["", "太弱", "较弱", "不错", "很强"];
	return { score, label: labels[score], pct: [0, 20, 45, 72, 100][score] };
}

function renderStrength(container, password) {
	const { score, label, pct } = passwordStrength(password);
	container.dataset.score = String(score);
	container.querySelector("i").style.width = `${pct}%`;
	const labelEl = container.querySelector(".strength-label");
	if (labelEl) labelEl.textContent = password ? label : "密码强度";
}

const GEN_SETS = {
	lower: "abcdefghijklmnopqrstuvwxyz",
	upper: "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
	digits: "0123456789",
	symbols: "!@#$%^&*()-_=+[]{};:,.?/~",
};

function generatePassword({
	length = 20,
	lower = true,
	upper = true,
	digits = true,
	symbols = true,
	avoidAmbiguous = true,
} = {}) {
	const ambiguous = "Il1O0o";
	const sets = [];
	const clean = (value) => (avoidAmbiguous ? [...value].filter((c) => !ambiguous.includes(c)).join("") : value);
	if (lower) sets.push(clean(GEN_SETS.lower));
	if (upper) sets.push(clean(GEN_SETS.upper));
	if (digits) sets.push(clean(GEN_SETS.digits));
	if (symbols) sets.push(clean(GEN_SETS.symbols));
	if (sets.length === 0) sets.push(GEN_SETS.lower);

	const all = sets.join("");
	const chars = sets.map((set) => set[randomInt(set.length)]);
	while (chars.length < length) chars.push(all[randomInt(all.length)]);
	for (let i = chars.length - 1; i > 0; i--) {
		const j = randomInt(i + 1);
		[chars[i], chars[j]] = [chars[j], chars[i]];
	}
	return chars.slice(0, Math.max(length, sets.length)).join("");
}

function openGenerator(onUse) {
	const options = { length: 20, lower: true, upper: true, digits: true, symbols: true, avoidAmbiguous: true };
	const body = `
		<div class="gen-output">
			<input id="gen-value" type="text" readonly spellcheck="false" aria-label="生成的密码" />
			<div class="gen-buttons">
				<button class="icon-btn" type="button" id="gen-refresh" title="重新生成" aria-label="重新生成">${icon("refresh")}</button>
				<button class="icon-btn" type="button" id="gen-copy" title="复制" aria-label="复制">${icon("copy")}</button>
			</div>
		</div>
		<div class="strength" id="gen-strength"><div class="strength-bar"><i></i></div><span class="strength-label">密码强度</span></div>
		<div class="gen-controls">
			<label for="gen-len">长度</label>
			<input id="gen-len" type="range" min="8" max="64" step="1" value="20" />
			<span class="gen-len" id="gen-len-value">20</span>
		</div>
		<div class="check-grid">
			<label class="check"><input type="checkbox" data-set="lower" checked />小写字母</label>
			<label class="check"><input type="checkbox" data-set="upper" checked />大写字母</label>
			<label class="check"><input type="checkbox" data-set="digits" checked />数字</label>
			<label class="check"><input type="checkbox" data-set="symbols" checked />符号</label>
		</div>
		<label class="check"><input type="checkbox" data-set="avoidAmbiguous" checked />避免易混淆字符（I l 1 O 0 o）</label>
	`;
	openModal({
		title: "生成密码",
		size: "modal-sm",
		body,
		footer: `<button class="btn btn-ghost" type="button" data-cancel>取消</button>
			<button class="btn btn-primary" type="button" data-use>使用此密码</button>`,
		onMount(m) {
			const input = m.element.querySelector("#gen-value");
			const strength = m.element.querySelector("#gen-strength");
			const lenInput = m.element.querySelector("#gen-len");
			const lenValue = m.element.querySelector("#gen-len-value");
			const regenerate = () => {
				input.value = generatePassword(options);
				renderStrength(strength, input.value);
			};
			regenerate();

			lenInput.addEventListener("input", () => {
				options.length = Number(lenInput.value);
				lenValue.textContent = lenInput.value;
				regenerate();
			});
			$$("[data-set]", m.element).forEach((checkbox) => {
				checkbox.addEventListener("change", () => {
					options[checkbox.dataset.set] = checkbox.checked;
					regenerate();
				});
			});
			m.element.querySelector("#gen-refresh").addEventListener("click", regenerate);
			m.element.querySelector("#gen-copy").addEventListener("click", () => {
				copySecret(input.value, "生成的密码");
			});
			m.element.querySelector("[data-cancel]").addEventListener("click", () => m.close());
			m.element.querySelector("[data-use]").addEventListener("click", () => {
				onUse?.(input.value);
				m.close();
			});
		},
	});
}

/* --------------------------------------------------------------------------
 * Clipboard
 * -------------------------------------------------------------------------- */

async function copySecret(value, label = "内容") {
	if (!value) {
		toast(`${label}为空`, "error");
		return;
	}
	try {
		await navigator.clipboard.writeText(value);
	} catch {
		toast("浏览器拒绝了剪贴板访问", "error");
		return;
	}
	toast(`已复制${label} · 30 秒后自动清除`, "ok");
	setTimeout(async () => {
		try {
			const current = await navigator.clipboard.readText();
			if (current === value) await navigator.clipboard.writeText("");
		} catch {
			/* clipboard read may be blocked; ignore */
		}
	}, 30_000);
}

/* --------------------------------------------------------------------------
 * Data helpers
 * -------------------------------------------------------------------------- */

function normalizeData(raw) {
	const data = raw && typeof raw === "object" ? raw : {};
	data.schemaVersion = 1;
	if (!Array.isArray(data.items)) data.items = [];
	data.items = data.items
		.filter((item) => item && typeof item === "object")
		.map((item) => ({
			id: item.id || uid(),
			type: ["login", "card", "note"].includes(item.type) ? item.type : "login",
			title: String(item.title ?? "").slice(0, 200),
			username: String(item.username ?? ""),
			password: String(item.password ?? ""),
			url: String(item.url ?? ""),
			notes: String(item.notes ?? ""),
			cardholder: String(item.cardholder ?? ""),
			number: String(item.number ?? ""),
			expiry: String(item.expiry ?? ""),
			cvv: String(item.cvv ?? ""),
			tags: Array.isArray(item.tags) ? item.tags.map(String).slice(0, 12) : [],
			favorite: Boolean(item.favorite),
			createdAt: item.createdAt || new Date().toISOString(),
			updatedAt: item.updatedAt || new Date().toISOString(),
		}));
	data.createdAt = data.createdAt || new Date().toISOString();
	return data;
}

const items = () => state.data?.items ?? [];
const itemById = (id) => items().find((item) => item.id === id) ?? null;

const TYPE_META = {
	login: { label: "登录", icon: "key" },
	card: { label: "银行卡", icon: "card" },
	note: { label: "笔记", icon: "note" },
};

function itemIcon(item) {
	if (item.type === "card") return icon("card");
	if (item.type === "note") return icon("note");
	const initials = (item.title || "?").trim().slice(0, 1).toUpperCase();
	return escapeHtml(initials);
}

function itemSubtitle(item) {
	if (item.type === "card") {
		const last4 = item.number.replace(/\s+/g, "").slice(-4);
		return last4 ? `•••• ${last4}` : "银行卡";
	}
	if (item.type === "note") {
		return item.notes ? item.notes.split("\n")[0].slice(0, 48) : "安全笔记";
	}
	return item.username || hostOf(item.url) || "登录";
}

/* --------------------------------------------------------------------------
 * Filtering & list rendering
 * -------------------------------------------------------------------------- */

function visibleItems() {
	const query = state.query.trim().toLowerCase();
	return items()
		.filter((item) => {
			if (state.filter === "favorite" && !item.favorite) return false;
			if (["login", "card", "note"].includes(state.filter) && item.type !== state.filter) return false;
			if (state.filter.startsWith("tag:") && !item.tags.includes(state.filter.slice(4))) return false;
			if (!query) return true;
			return [item.title, item.username, item.url, item.notes, item.cardholder, item.tags.join(" ")]
				.join(" ")
				.toLowerCase()
				.includes(query);
		})
		.sort((a, b) => {
			if (a.favorite !== b.favorite) return a.favorite ? -1 : 1;
			return a.title.localeCompare(b.title, "zh-Hans-CN");
		});
}

function renderList() {
	const list = $("#item-list");
	list.innerHTML = "";
	const visible = visibleItems();

	$("#empty-list").hidden = visible.length > 0;
	$("#empty-list .empty-title").textContent = items().length === 0 ? "这里空空如也" : "没有匹配的条目";
	$("#empty-list .empty-sub").textContent =
		items().length === 0 ? "点击右上角 + 添加第一条凭据。" : "换个关键词或筛选条件试试。";

	const fragment = document.createDocumentFragment();
	for (const item of visible) {
		const li = document.createElement("li");
		li.className = `item${item.id === state.selectedId ? " is-active" : ""}`;
		li.dataset.id = item.id;
		li.setAttribute("role", "option");
		li.setAttribute("aria-selected", String(item.id === state.selectedId));
		li.innerHTML = `
			<span class="item-icon">${itemIcon(item)}</span>
			<span class="item-main">
				<span class="item-title">${escapeHtml(item.title || "未命名")}</span>
				<span class="item-sub">${escapeHtml(itemSubtitle(item))}</span>
			</span>
			<button class="item-fav${item.favorite ? " is-on" : ""}" type="button" data-fav="${item.id}" aria-label="${item.favorite ? "取消收藏" : "收藏"}">
				${icon("star")}
			</button>`;
		fragment.appendChild(li);
	}
	list.appendChild(fragment);
	renderTagChips();
}

function allTags() {
	const counts = new Map();
	for (const item of items()) {
		for (const tag of item.tags) counts.set(tag, (counts.get(tag) ?? 0) + 1);
	}
	return [...counts.entries()].sort(
		(a, b) => b[1] - a[1] || a[0].localeCompare(b[0], "zh-Hans-CN"),
	);
}

function renderTagChips() {
	const wrap = $("#tag-chips");
	if (!wrap) return;
	const tags = allTags();
	if (tags.length === 0) {
		wrap.hidden = true;
		wrap.innerHTML = "";
		return;
	}
	wrap.hidden = false;
	const activeTag = state.filter.startsWith("tag:") ? state.filter.slice(4) : null;
	wrap.innerHTML =
		tags
			.slice(0, 30)
			.map(
				([tag, count]) => `
				<button class="tag-chip${tag === activeTag ? " is-active" : ""}" type="button" data-tag="${escapeHtml(tag)}">
					${escapeHtml(tag)}<span>${count}</span>
				</button>`,
			)
			.join("") +
		`<button class="tag-chip tag-manage" type="button" data-manage-tags title="管理标签" aria-label="管理标签">${icon("settings")}</button>`;
}

function applyTagChanges(mapping) {
	let changed = 0;
	for (const item of items()) {
		if (!item.tags.length) continue;
		const next = [];
		for (const tag of item.tags) {
			const mapped = mapping.has(tag) ? mapping.get(tag) : tag;
			if (mapped && !next.includes(mapped)) next.push(mapped);
		}
		const isDifferent =
			next.length !== item.tags.length || next.some((tag, index) => tag !== item.tags[index]);
		if (isDifferent) {
			item.tags = next;
			item.updatedAt = new Date().toISOString();
			changed++;
		}
	}

	if (state.filter.startsWith("tag:")) {
		const active = state.filter.slice(4);
		if (!allTags().some(([tag]) => tag === active)) state.filter = "all";
	}

	if (changed) {
		markDirty();
		renderAll();
		toast(`已更新 ${changed} 个条目的标签`, "ok");
	} else {
		renderAll();
		toast("标签没有变化");
	}
}

function openTagManager() {
	const tags = allTags();
	const rows = tags.length
		? tags
				.map(
					([tag, count]) => `
					<div class="tag-row" data-old="${escapeHtml(tag)}">
						<input type="text" value="${escapeHtml(tag)}" maxlength="40" spellcheck="false" autocomplete="off" aria-label="标签名" />
						<span class="tag-count">${count} 条</span>
						<button class="icon-btn" type="button" data-remove aria-label="移除标签">${icon("trash")}</button>
					</div>`,
				)
				.join("")
		: `<p class="modal-text">还没有标签。在编辑条目时填写「标签」，之后就能在这里统一改名、合并或删除。</p>`;

	openModal({
		title: "管理标签",
		size: "modal-sm",
		body: `${tags.length ? `<div class="tag-rows" id="tag-rows">${rows}</div>` : rows}
			${tags.length ? '<p class="field-hint">改名会同步更新所有条目；清空输入框或点垃圾桶表示从所有条目中移除。合并到同名标签会自动去重。</p>' : ""}`,
		footer: tags.length
			? `<button class="btn btn-ghost" type="button" data-cancel>取消</button>
				<button class="btn btn-primary" type="button" data-save>保存修改</button>`
			: `<button class="btn btn-ghost" type="button" data-cancel>关闭</button>`,
		onMount(m) {
			m.element.querySelector("[data-cancel]").addEventListener("click", () => m.close());
			$$("[data-remove]", m.element).forEach((button) => {
				button.addEventListener("click", () => {
					const row = button.closest(".tag-row");
					const input = row.querySelector("input");
					input.value = "";
					row.classList.add("is-removing");
					input.focus();
				});
			});
			m.element.querySelector("[data-save]")?.addEventListener("click", () => {
				const mapping = new Map();
				$$(".tag-row", m.element).forEach((row) => {
					const oldTag = row.dataset.old;
					const next = row.querySelector("input").value.trim();
					if (!next) {
						mapping.set(oldTag, null);
					} else if (next !== oldTag) {
						mapping.set(oldTag, next);
					}
				});
				m.close();
				if (mapping.size === 0) {
					toast("标签没有变化");
					return;
				}
				applyTagChanges(mapping);
			});
		},
	});
}

/* --------------------------------------------------------------------------
 * Detail rendering
 * -------------------------------------------------------------------------- */

function kvRow(key, label, value, { secret = false, mono = true, href = false } = {}) {
	if (!value) return "";
	const revealed = state.revealed.has(key);
	return `
		<div class="kv">
			<span class="kv-label">${escapeHtml(label)}</span>
			<span class="kv-value${secret && !revealed ? " is-secret" : ""}${mono ? "" : " is-empty"}" data-kv="${key}">${
				secret && !revealed ? "••••••••••••" : escapeHtml(value)
			}</span>
			<span class="kv-actions">
				${
					secret
						? `<button class="icon-btn" type="button" data-reveal="${key}" aria-label="${revealed ? "隐藏" : "显示"}">${icon(revealed ? "eye-off" : "eye")}</button>`
						: ""
				}
				${
					href
						? `<a class="icon-btn" href="${escapeHtml(/^https?:\/\//i.test(value) ? value : `https://${value}`)}" target="_blank" rel="noreferrer noopener" aria-label="打开链接">${icon("globe")}</a>`
						: ""
				}
				<button class="icon-btn" type="button" data-copy="${key}" aria-label="复制">${icon("copy")}</button>
			</span>
		</div>`;
}

function renderDetail() {
	const item = itemById(state.selectedId);
	const body = $("#detail-body");
	const empty = $("#detail-empty");

	if (!item) {
		state.selectedId = null;
		empty.hidden = false;
		body.hidden = true;
		body.innerHTML = "";
		setView("list");
		return;
	}

	empty.hidden = true;
	body.hidden = false;
	setView("detail");

	const meta = TYPE_META[item.type];
	const fields = [];

	if (item.type === "login") {
		fields.push(kvRow("url", "网址", item.url, { href: true }));
		fields.push(kvRow("username", "用户名", item.username));
		fields.push(kvRow("password", "密码", item.password, { secret: true }));
	} else if (item.type === "card") {
		fields.push(kvRow("cardholder", "持卡人", item.cardholder, { mono: false }));
		fields.push(kvRow("number", "卡号", item.number, { secret: true }));
		fields.push(kvRow("expiry", "有效期", item.expiry));
		fields.push(kvRow("cvv", "CVV", item.cvv, { secret: true }));
	}

	body.innerHTML = `
		<div class="detail-top">
			<button class="icon-btn mobile-only" type="button" data-back aria-label="返回列表">${icon("back")}</button>
			<span class="spacer"></span>
			<button class="icon-btn${item.favorite ? " is-active" : ""}" type="button" data-fav-detail="${
				item.favorite ? "off" : "on"
			}" aria-label="收藏" title="收藏">${icon("star")}</button>
			<button class="btn btn-ghost btn-sm" type="button" data-edit>${icon("edit")}编辑</button>
			<button class="icon-btn" type="button" data-delete aria-label="删除" title="删除">${icon("trash")}</button>
		</div>
		<header class="detail-head">
			<span class="detail-icon">${itemIcon(item)}</span>
			<div class="detail-title-wrap">
				<h1 class="detail-title">${escapeHtml(item.title || "未命名")}</h1>
				<p class="detail-sub"><span class="type-badge">${meta.label}</span>${
					item.tags.length ? item.tags.map((tag) => `<span class="tag">${escapeHtml(tag)}</span>`).join("") : ""
				}</p>
			</div>
		</header>

		${fields.length ? `<div class="kv-list">${fields.join("")}</div>` : ""}

		${
			item.notes
				? `<p class="section-label">备注</p><div class="notes-block">${escapeHtml(item.notes)}</div>`
				: ""
		}

		<div class="detail-meta">
			<span>创建于 ${formatDate(item.createdAt)}</span>
			<span>更新于 ${formatDate(item.updatedAt)}</span>
		</div>`;
}

function renderAll() {
	renderList();
	renderDetail();
}

function setView(view) {
	const screen = $("#screen-vault");
	screen.dataset.view = view;
}

function selectItem(id) {
	state.selectedId = id;
	state.revealed.clear();
	renderAll();
	if (id) setView("detail");
	$("#detail").scrollTop = 0;
}

/* --------------------------------------------------------------------------
 * Item editor
 * -------------------------------------------------------------------------- */

function openEditor(item = null, initialType = "login") {
	const isNew = !item;
	const base = item ?? {
		id: uid(),
		type: ["login", "card", "note"].includes(initialType) ? initialType : "login",
		title: "",
		username: "",
		password: "",
		url: "",
		notes: "",
		cardholder: "",
		number: "",
		expiry: "",
		cvv: "",
		tags: [],
		favorite: false,
		createdAt: new Date().toISOString(),
		updatedAt: new Date().toISOString(),
	};
	let type = base.type;

	const fieldHtml = (id, label, value, opts = {}) => `
		<div class="field">
			<label for="edit-${id}">${label}${opts.optional ? ' <span class="muted">（可选）</span>' : ""}</label>
			${
				opts.textarea
					? `<textarea id="edit-${id}" data-field="${id}" placeholder="${escapeHtml(opts.placeholder ?? "")}">${escapeHtml(value)}</textarea>`
					: `<input id="edit-${id}" data-field="${id}" type="${opts.type ?? "text"}" value="${escapeHtml(value)}" autocomplete="off" spellcheck="false" placeholder="${escapeHtml(opts.placeholder ?? "")}" />`
			}
		</div>`;

	const loginHtml = `
		${fieldHtml("url", "网址", base.url, { optional: true, placeholder: "https://example.com" })}
		${fieldHtml("username", "用户名 / 邮箱", base.username, { optional: true })}
		<div class="field">
			<label for="edit-password">密码</label>
			<div class="input-wrap">
				<input id="edit-password" data-field="password" type="password" value="${escapeHtml(base.password)}" autocomplete="off" spellcheck="false" />
				<button class="icon-btn eye" type="button" data-target="edit-password" aria-label="显示密码"></button>
			</div>
			<div class="strength" id="edit-strength"><div class="strength-bar"><i></i></div><span class="strength-label">密码强度</span></div>
		</div>`;

	const cardHtml = `
		${fieldHtml("cardholder", "持卡人", base.cardholder, { optional: true })}
		${fieldHtml("number", "卡号", base.number, { optional: true, placeholder: "1234 5678 9012 3456" })}
		<div class="row-2">
			${fieldHtml("expiry", "有效期", base.expiry, { optional: true, placeholder: "08/29" })}
			${fieldHtml("cvv", "CVV", base.cvv, { optional: true })}
		</div>`;

	const body = `
		<div class="seg" id="type-seg">
			<button type="button" data-type="login" class="${type === "login" ? "is-active" : ""}">登录</button>
			<button type="button" data-type="card" class="${type === "card" ? "is-active" : ""}">银行卡</button>
			<button type="button" data-type="note" class="${type === "note" ? "is-active" : ""}">笔记</button>
		</div>
		<div class="field">
			<label for="edit-title">标题</label>
			<input id="edit-title" data-field="title" type="text" value="${escapeHtml(base.title)}" autocomplete="off" placeholder="例如：GitHub" />
		</div>
		<div id="type-fields"></div>
		${fieldHtml("notes", "备注", base.notes, { textarea: true, optional: true, placeholder: "安全笔记、恢复码、额外说明…" })}
		<div class="field">
			<label for="edit-tags">标签 <span class="muted">（逗号分隔）</span></label>
			<input id="edit-tags" type="text" value="${escapeHtml(base.tags.join(", "))}" autocomplete="off" placeholder="工作, 个人" list="tag-suggestions" />
		</div>
		<datalist id="tag-suggestions">
			${allTags().map(([tag]) => `<option value="${escapeHtml(tag)}"></option>`).join("")}
		</datalist>
		<label class="check"><input type="checkbox" id="edit-favorite" ${base.favorite ? "checked" : ""} />收藏此条目</label>
		<p class="auth-error" id="edit-error" role="alert" hidden></p>
	`;

	const modal = openModal({
		title: isNew ? "新建条目" : "编辑条目",
		body,
		footer: `<button class="btn btn-ghost" type="button" data-cancel>取消</button>
			<button class="btn btn-primary" type="button" data-save>保存</button>`,
		onMount(m) {
			const fieldsRoot = m.element.querySelector("#type-fields");
			const strength = () => m.element.querySelector("#edit-strength");
			const passwordInput = () => m.element.querySelector('[data-field="password"]');
			const error = m.element.querySelector("#edit-error");

			const mountType = (nextType) => {
				fieldsRoot.innerHTML = nextType === "card" ? cardHtml : nextType === "note" ? "" : loginHtml;
				if (nextType === "login") {
					bindPasswordToggle(m.element);
					const input = passwordInput();
					input?.addEventListener("input", () => renderStrength(strength(), input.value));
					renderStrength(strength(), input?.value ?? "");
					m.element.querySelector('[data-field="password"]')?.addEventListener("keydown", (event) => {
						if (event.key === "Enter") {
							event.preventDefault();
							m.element.querySelector("[data-save]").click();
						}
					});
					const generateBtn = document.createElement("button");
					generateBtn.type = "button";
					generateBtn.className = "btn btn-ghost btn-sm gen-trigger";
					generateBtn.textContent = "生成强密码";
					generateBtn.addEventListener("click", () => {
						openGenerator((password) => {
							const target = passwordInput();
							if (target) {
								target.value = password;
								target.type = "text";
								renderStrength(strength(), password);
							}
						});
					});
					strength()?.after(generateBtn);
				}
			};

			mountType(type);
			$$("#type-seg button", m.element).forEach((button) => {
				button.addEventListener("click", () => {
					type = button.dataset.type;
					$$("#type-seg button", m.element).forEach((b) => b.classList.toggle("is-active", b === button));
					mountType(type);
				});
			});

			const read = () => {
				const get = (name) => m.element.querySelector(`[data-field="${name}"]`)?.value ?? "";
				return {
					type,
					title: get("title").trim(),
					url: get("url").trim(),
					username: get("username").trim(),
					password: get("password"),
					cardholder: get("cardholder").trim(),
					number: get("number").trim(),
					expiry: get("expiry").trim(),
					cvv: get("cvv").trim(),
					notes: get("notes"),
					tags: m.element
						.querySelector("#edit-tags")
						.value.split(/[,，]/)
						.map((tag) => tag.trim())
						.filter(Boolean)
						.slice(0, 12),
					favorite: m.element.querySelector("#edit-favorite").checked,
				};
			};

			m.element.querySelector("[data-cancel]").addEventListener("click", () => m.close());
			m.element.querySelector("[data-save]").addEventListener("click", () => {
				const values = read();
				if (!values.title) {
					error.textContent = "请填写标题";
					error.hidden = false;
					m.element.querySelector("#edit-title").focus();
					return;
				}
				if (values.type === "login" && !values.password && !values.username) {
					error.textContent = "登录条目至少需要用户名或密码";
					error.hidden = false;
					return;
				}
				if (items().some((entry) => entry.id !== base.id && entry.title.toLowerCase() === values.title.toLowerCase() && entry.username === values.username)) {
					error.textContent = "已存在同名同账号的条目";
					error.hidden = false;
					return;
				}

				const now = new Date().toISOString();
				if (isNew) {
					state.data.items.push({ ...base, ...values, createdAt: now, updatedAt: now });
				} else {
					const target = itemById(base.id);
					if (target) Object.assign(target, values, { updatedAt: now });
				}
				state.selectedId = base.id;
				m.close();
				markDirty();
				renderAll();
				toast(isNew ? "已创建条目" : "已更新条目", "ok");
			});
		},
	});
	void modal;
}

async function deleteSelected() {
	const item = itemById(state.selectedId);
	if (!item) return;
	const ok = await confirmDialog({
		title: "删除条目",
		message: `确定要删除「${escapeHtml(item.title || "未命名")}」吗？此操作不可撤销。`,
		confirmLabel: "删除",
		danger: true,
	});
	if (!ok) return;
	state.data.items = state.data.items.filter((entry) => entry.id !== item.id);
	state.selectedId = null;
	markDirty();
	renderAll();
	toast("已删除条目", "ok");
}

/* --------------------------------------------------------------------------
 * Persistence
 * -------------------------------------------------------------------------- */

function setSaveState(mode, text) {
	const el = $("#save-state");
	el.dataset.state = mode;
	el.querySelector(".save-text").textContent =
		text ??
		{ saved: "已保存", dirty: "未保存", saving: "保存中…", error: "保存失败" }[mode] ??
		"";
}

function markDirty() {
	if (state.locked || !state.data) return;
	state.dirty = true;
	setSaveState("dirty");
	clearTimeout(state.saveTimer);
	state.saveTimer = setTimeout(() => void flushSave(), SAVE_DEBOUNCE_MS);
}

async function flushSave() {
	if (!state.dirty || state.saving || state.locked || !state.key || !state.data) return;
	state.saving = true;
	clearTimeout(state.retryTimer);
	setSaveState("saving");

	try {
		state.data.updatedAt = new Date().toISOString();
		const ciphertext = await encryptJson(state.key, state.data);
		const result = await api("/api/vault", {
			method: "PUT",
			body: JSON.stringify({
				version: state.vault.version,
				kdf: state.vault.kdf,
				ciphertext,
			}),
		});
		state.vault.version = result.version;
		state.vault.ciphertext = ciphertext;
		state.vault.updatedAt = result.updatedAt;
		state.dirty = false;
		setSaveState("saved");
	} catch (error) {
		if (error instanceof ApiError && error.status === 409) {
			state.saving = false;
			await resolveConflict(error.body);
			return;
		}
		console.error(error);
		setSaveState("error");
		toast(error instanceof ApiError && error.status === 403 ? "会话已过期，请重新解锁" : "保存失败，稍后重试", "error");
		state.retryTimer = setTimeout(() => void flushSave(), 4000);
	} finally {
		state.saving = false;
		if (state.dirty && !state.retryTimer) {
			clearTimeout(state.saveTimer);
			state.saveTimer = setTimeout(() => void flushSave(), SAVE_DEBOUNCE_MS);
		}
	}
}

async function resolveConflict(conflict) {
	try {
		let remote = null;
		if (conflict?.ciphertext && state.key) {
			remote = normalizeData(await decryptJson(state.key, conflict.ciphertext));
		}
		if (!remote) {
			toast("保险库已在其他地方被修改，请重新解锁", "error", 5000);
			await lockVault({ force: true, skipSave: true });
			return;
		}

		const merged = new Map(remote.items.map((item) => [item.id, item]));
		for (const local of state.data.items) {
			const other = merged.get(local.id);
			if (!other) {
				merged.set(local.id, local);
			} else if (new Date(local.updatedAt).getTime() > new Date(other.updatedAt).getTime()) {
				merged.set(local.id, local);
			}
		}
		state.data.items = [...merged.values()];
		state.vault = { ...state.vault, ...conflict, version: conflict.version };
		state.dirty = true;
		setSaveState("dirty");
		toast("已合并另一处窗口的更改", "ok");
		renderAll();
		await flushSave();
	} catch (error) {
		console.error(error);
		toast("合并失败，请重新解锁", "error", 5000);
		await lockVault({ force: true, skipSave: true });
	}
}

/* --------------------------------------------------------------------------
 * Settings
 * -------------------------------------------------------------------------- */

function isStandalone() {
	return (
		window.matchMedia("(display-mode: standalone)").matches ||
		window.matchMedia("(display-mode: minimal-ui)").matches ||
		navigator.standalone === true
	);
}

function installApp() {
	if (isStandalone()) {
		toast("已经在独立窗口中运行了", "ok");
		return;
	}
	if (deferredInstallPrompt) {
		deferredInstallPrompt.prompt();
		deferredInstallPrompt.userChoice
			?.then((choice) => {
				if (choice?.outcome === "accepted") toast("正在安装 Vault…", "ok");
			})
			.catch(() => {});
		deferredInstallPrompt = null;
		return;
	}
	const isIos =
		/iphone|ipad|ipod/i.test(navigator.userAgent) ||
		(navigator.platform === "MacIntel" && navigator.maxTouchPoints > 1);
	openModal({
		title: "安装到桌面",
		size: "modal-sm",
		body: `<p class="modal-text">${
			isIos
				? "在 Safari 中点按「分享」按钮，然后选择<strong>添加到主屏幕</strong>，Vault 就会以独立应用窗口打开。"
				: "在浏览器菜单中选择「安装应用」/「安装 Vault」或「创建快捷方式」，之后即可像原生应用一样打开。"
		}</p>`,
		footer: `<button class="btn btn-primary" type="button" data-ok>知道了</button>`,
		onMount(m) {
			m.element.querySelector("[data-ok]").addEventListener("click", () => m.close());
		},
	});
}

function openSettings() {
	const autolock = AUTOLOCK_OPTIONS.map(
		(option) =>
			`<option value="${option.value}" ${option.value === state.autolockMs ? "selected" : ""}>${option.label}</option>`,
	).join("");

	const body = `
		<div class="settings-group-label">外观</div>
		<div class="field">
			<label for="set-theme">主题</label>
			<select id="set-theme">
				<option value="auto" ${state.theme === "auto" ? "selected" : ""}>跟随系统</option>
				<option value="dark" ${state.theme === "dark" ? "selected" : ""}>深色</option>
				<option value="light" ${state.theme === "light" ? "selected" : ""}>浅色</option>
			</select>
		</div>
		<div class="field">
			<label for="set-autolock">闲置自动锁定</label>
			<select id="set-autolock">${autolock}</select>
		</div>

		<div class="settings-group-label">安全</div>
		<div class="field">
			<label for="set-remember">免密解锁（本设备）</label>
			<select id="set-remember">
				<option value="0" ${rememberDays() === 0 ? "selected" : ""}>关闭（每次刷新都要主密码）</option>
				<option value="7" ${rememberDays() === 7 ? "selected" : ""}>7 天</option>
				<option value="30" ${rememberDays() === 30 ? "selected" : ""}>30 天</option>
				<option value="90" ${rememberDays() === 90 ? "selected" : ""}>90 天</option>
			</select>
			<p class="field-hint" id="remember-status">${escapeHtml(rememberStatusText())}</p>
		</div>
		<div class="settings-list">
			<button class="settings-item" type="button" data-action="forget-device">
				<span class="s-icon">${icon("unlock")}</span>
				<span class="s-text"><strong>忘记此设备</strong><span>立即清除本机的免密凭证与设备密钥</span></span>
				<span class="s-chev">${icon("chevron")}</span>
			</button>
		</div>

		<div class="settings-group-label">标签</div>
		<div class="settings-list">
			<button class="settings-item" type="button" data-action="manage-tags">
				<span class="s-icon">${icon("note")}</span>
				<span class="s-text"><strong>管理标签</strong><span>${allTags().length ? `${allTags().length} 个标签，可改名、合并或删除` : "还没有标签"}</span></span>
				<span class="s-chev">${icon("chevron")}</span>
			</button>
		</div>

		<div class="settings-group-label">应用</div>
		<div class="settings-list">
			<button class="settings-item" type="button" data-action="install">
				<span class="s-icon">${icon("download")}</span>
				<span class="s-text"><strong>${isStandalone() ? "已安装为独立应用" : "安装到桌面"}</strong><span>${
					isStandalone() ? "当前正以 PWA 模式运行" : "像原生应用一样打开，支持离线加载界面"
				}</span></span>
				<span class="s-chev">${icon("chevron")}</span>
			</button>
		</div>

		<div class="settings-group-label">数据</div>
		<div class="settings-list">
			<button class="settings-item" type="button" data-action="export">
				<span class="s-icon">${icon("download")}</span>
				<span class="s-text"><strong>导出备份</strong><span>导出为明文 JSON（需再次验证主密码）</span></span>
				<span class="s-chev">${icon("chevron")}</span>
			</button>
			<button class="settings-item" type="button" data-action="import">
				<span class="s-icon">${icon("upload")}</span>
				<span class="s-text"><strong>导入条目</strong><span>支持 Vault JSON / Bitwarden CSV / Chrome CSV</span></span>
				<span class="s-chev">${icon("chevron")}</span>
			</button>
			<button class="settings-item" type="button" data-action="change-password">
				<span class="s-icon">${icon("key")}</span>
				<span class="s-text"><strong>修改主密码</strong><span>使用新盐值重新加密整个保险库</span></span>
				<span class="s-chev">${icon("chevron")}</span>
			</button>
		</div>

		<div class="settings-group-label">账号</div>
		<div class="settings-list">
			<div class="settings-item">
				<span class="s-icon">${icon("user")}</span>
				<span class="s-text"><strong>${escapeHtml(state.email)}</strong><span>通过 Cloudflare Access 验证${
					state.accessExpiresAt ? ` · 会话有效至 ${formatDate(state.accessExpiresAt * 1000)}` : ""
				}</span></span>
			</div>
			<button class="settings-item is-danger" type="button" data-action="logout">
				<span class="s-icon">${icon("logout")}</span>
				<span class="s-text"><strong>退出登录</strong><span>结束 Cloudflare Access 会话</span></span>
				<span class="s-chev">${icon("chevron")}</span>
			</button>
		</div>

		<div class="settings-sep"></div>
		<div class="settings-list">
			<button class="settings-item is-danger" type="button" data-action="delete-vault">
				<span class="s-icon">${icon("trash")}</span>
				<span class="s-text"><strong>删除保险库</strong><span>永久移除服务器上的加密数据</span></span>
				<span class="s-chev">${icon("chevron")}</span>
			</button>
		</div>
	`;

	openModal({
		title: "设置",
		body,
		onMount(m) {
			m.element.querySelector("#set-theme").addEventListener("change", (event) => {
				applyTheme(event.target.value);
			});
			m.element.querySelector("#set-autolock").addEventListener("change", (event) => {
				state.autolockMs = Number(event.target.value);
				localStorage.setItem(LS_KEYS.autolock, String(state.autolockMs));
				toast("已更新自动锁定时间", "ok");
			});
			m.element.querySelector("#set-remember").addEventListener("change", async (event) => {
				const days = Number(event.target.value);
				localStorage.setItem(LS_KEYS.remember, String(days));
				await clearRememberToken();
				const status = m.element.querySelector("#remember-status");
				if (status) status.textContent = rememberStatusText();
				toast(
					days
						? `已设置为 ${days} 天免密解锁，重新解锁一次后生效`
						: "已关闭免密解锁",
					"ok",
				);
			});
			$$("[data-action]", m.element).forEach((button) => {
				button.addEventListener("click", async () => {
					const action = button.dataset.action;
					m.close();
					if (action === "install") installApp();
					if (action === "export") void exportVault();
					if (action === "import") void importVault();
					if (action === "change-password") void changeMasterPassword();
					if (action === "manage-tags") openTagManager();
					if (action === "forget-device") {
						await forgetDevice();
						toast("已清除本机的免密凭证", "ok");
					}
					if (action === "logout") {
						await clearRememberToken();
						localStorage.removeItem(LS_KEYS.hint);
						location.href = "/cdn-cgi/access/logout";
					}
					if (action === "delete-vault") void deleteVault();
				});
			});
		},
	});
}

async function exportVault() {
	const password = await askPassword({
		title: "导出备份",
		message: "备份文件是<b>明文</b>的。请确认主密码，并把它保存到安全的地方。",
		confirmLabel: "验证并导出",
	});
	if (!password) return;

	try {
		const key = await deriveKey(password, state.vault.kdf.salt, state.vault.kdf.iterations);
		const latest = await api("/api/vault");
		await decryptJson(key, latest.ciphertext);
	} catch {
		toast("主密码不正确", "error");
		return;
	}

	const payload = {
		format: "cf-vault",
		version: 1,
		exportedAt: new Date().toISOString(),
		items: state.data.items,
	};
	const blob = new Blob([JSON.stringify(payload, null, 2)], { type: "application/json" });
	const url = URL.createObjectURL(blob);
	const link = document.createElement("a");
	link.href = url;
	link.download = `vault-backup-${new Date().toISOString().slice(0, 10)}.json`;
	link.click();
	setTimeout(() => URL.revokeObjectURL(url), 1000);
	toast("备份已导出，请妥善保管", "ok");
}

function parseCsv(text) {
	const rows = [];
	let row = [];
	let value = "";
	let quoted = false;
	for (let i = 0; i < text.length; i++) {
		const char = text[i];
		if (quoted) {
			if (char === '"' && text[i + 1] === '"') {
				value += '"';
				i++;
			} else if (char === '"') {
				quoted = false;
			} else {
				value += char;
			}
		} else if (char === '"') {
			quoted = true;
		} else if (char === ",") {
			row.push(value);
			value = "";
		} else if (char === "\n") {
			row.push(value);
			rows.push(row);
			row = [];
			value = "";
		} else if (char !== "\r") {
			value += char;
		}
	}
	if (value || row.length) {
		row.push(value);
		rows.push(row);
	}
	return rows.filter((cells) => cells.some((cell) => cell.trim() !== ""));
}

function csvToItems(text) {
	const rows = parseCsv(text);
	if (rows.length < 2) return [];
	const headers = rows[0].map((header) => header.trim().toLowerCase());
	const find = (...names) => {
		for (const name of names) {
			const index = headers.indexOf(name);
			if (index >= 0) return index;
		}
		return -1;
	};
	const iTitle = find("name", "title", "login_name");
	const iUrl = find("login_uri", "url", "website");
	const iUser = find("login_username", "username", "user");
	const iPass = find("login_password", "password");
	const iNotes = find("notes", "note", "comments");
	const iFolder = find("folder", "grouping", "collection");
	if (iTitle < 0 && iUser < 0) return [];

	const now = new Date().toISOString();
	return rows
		.slice(1)
		.map((cells) => {
			const cell = (index) => (index >= 0 ? (cells[index] ?? "").trim() : "");
			const title = cell(iTitle) || hostOf(cell(iUrl)) || cell(iUser) || "导入的条目";
			return {
				id: uid(),
				type: "login",
				title,
				username: cell(iUser),
				password: cell(iPass),
				url: cell(iUrl),
				notes: cell(iNotes),
				cardholder: "",
				number: "",
				expiry: "",
				cvv: "",
				tags: cell(iFolder) ? [cell(iFolder)] : [],
				favorite: false,
				createdAt: now,
				updatedAt: now,
			};
		})
		.filter((item) => item.title || item.username || item.password);
}

function importVault() {
	const input = document.createElement("input");
	input.type = "file";
	input.accept = ".json,.csv,application/json,text/csv";
	input.addEventListener("change", async () => {
		const file = input.files?.[0];
		if (!file) return;
		const text = await file.text();
		let imported = [];

		try {
			if (/\.csv$/i.test(file.name) || text.trim().startsWith("name,") || /login_uri/i.test(text.slice(0, 300))) {
				imported = csvToItems(text);
			} else {
				const parsed = JSON.parse(text);
				const list = Array.isArray(parsed) ? parsed : Array.isArray(parsed?.items) ? parsed.items : null;
				if (!list) throw new Error("unsupported");
				imported = normalizeData({ items: list }).items;
			}
		} catch {
			toast("无法识别这个文件", "error");
			return;
		}

		if (imported.length === 0) {
			toast("文件中没有可导入的条目", "error");
			return;
		}

		const ok = await confirmDialog({
			title: "导入条目",
			message: `将导入 <b>${imported.length}</b> 个条目到当前保险库。是否继续？`,
			confirmLabel: "导入",
		});
		if (!ok) return;

		const existing = new Set(
			items().map((item) => `${item.title.toLowerCase()}|${item.username.toLowerCase()}`),
		);
		const fresh = imported.filter(
			(item) => !existing.has(`${item.title.toLowerCase()}|${item.username.toLowerCase()}`),
		);
		state.data.items.push(...fresh);
		markDirty();
		renderAll();
		toast(`已导入 ${fresh.length} 个条目${fresh.length !== imported.length ? "（跳过重复）" : ""}`, "ok");
	});
	input.click();
}

async function changeMasterPassword() {
	const current = await askPassword({
		title: "修改主密码",
		message: "先输入当前主密码。修改后，其他已解锁的窗口需要重新解锁。",
	});
	if (!current) return;

	let currentKey;
	try {
		currentKey = await deriveKey(current, state.vault.kdf.salt, state.vault.kdf.iterations);
		const latest = await api("/api/vault");
		await decryptJson(currentKey, latest.ciphertext);
	} catch {
		toast("当前主密码不正确", "error");
		return;
	}

	openModal({
		title: "设置新的主密码",
		size: "modal-sm",
		body: `
			<div class="field">
				<label for="new-password">新主密码</label>
				<div class="input-wrap">
					<input id="new-password" type="password" autocomplete="new-password" spellcheck="false" placeholder="至少 10 位" />
					<button class="icon-btn eye" type="button" data-target="new-password" aria-label="显示密码"></button>
				</div>
			</div>
			<div class="field">
				<label for="new-confirm">再次输入</label>
				<input id="new-confirm" type="password" autocomplete="new-password" spellcheck="false" placeholder="确认新主密码" />
			</div>
			<div class="strength" id="new-strength"><div class="strength-bar"><i></i></div><span class="strength-label">密码强度</span></div>
			<p class="auth-error" id="new-error" role="alert" hidden></p>
		`,
		footer: `<button class="btn btn-ghost" type="button" data-cancel>取消</button>
			<button class="btn btn-primary" type="button" data-ok>保存新密码</button>`,
		onMount(m) {
			bindPasswordToggle(m.element);
			const password = m.element.querySelector("#new-password");
			const confirm = m.element.querySelector("#new-confirm");
			const error = m.element.querySelector("#new-error");
			const strength = m.element.querySelector("#new-strength");
			password.addEventListener("input", () => renderStrength(strength, password.value));
			m.element.querySelector("[data-cancel]").addEventListener("click", () => m.close());
			m.element.querySelector("[data-ok]").addEventListener("click", async () => {
				if (password.value.length < 10) {
					error.textContent = "新主密码至少需要 10 位";
					error.hidden = false;
					return;
				}
				if (password.value !== confirm.value) {
					error.textContent = "两次输入的密码不一致";
					error.hidden = false;
					return;
				}

				const button = m.element.querySelector("[data-ok]");
				button.disabled = true;
				button.textContent = "加密中…";
				try {
					const salt = bytesToB64(randomBytes(16));
					const iterations = KDF_ITERATIONS;
					const { sessionKey: key, raw } = await deriveKeyMaterial(password.value, salt, iterations);
					const ciphertext = await encryptJson(key, state.data);
					const result = await api("/api/vault", {
						method: "PUT",
						body: JSON.stringify({
							version: state.vault.version,
							kdf: { algorithm: KDF_ALGORITHM, salt, iterations },
							ciphertext,
						}),
					});
					state.key = key;
					state.vault = {
						version: result.version,
						updatedAt: result.updatedAt,
						kdf: { algorithm: KDF_ALGORITHM, salt, iterations },
						ciphertext,
					};
					state.dirty = false;
					await rememberDevice(raw);
					raw.fill(0);
					setSaveState("saved");
					m.close();
					toast("主密码已更新", "ok");
				} catch (changeError) {
					console.error(changeError);
					error.textContent = "更新失败，请稍后再试";
					error.hidden = false;
					button.disabled = false;
					button.textContent = "保存新密码";
				}
			});
		},
	});
}

async function deleteVault() {
	const password = await askPassword({
		title: "删除保险库",
		message: "这将<b>永久删除</b>服务器上的加密保险库，且无法恢复。请输入主密码确认。",
		confirmLabel: "验证",
	});
	if (!password) return;

	try {
		const key = await deriveKey(password, state.vault.kdf.salt, state.vault.kdf.iterations);
		const latest = await api("/api/vault");
		await decryptJson(key, latest.ciphertext);
	} catch {
		toast("主密码不正确", "error");
		return;
	}

	const ok = await confirmDialog({
		title: "确认删除",
		message: "删除后所有条目都会消失。确定继续吗？",
		confirmLabel: "永久删除",
		danger: true,
		requireText: "DELETE",
	});
	if (!ok) return;

	try {
		await api("/api/vault", { method: "DELETE" });
		state.key = null;
		state.data = null;
		state.vault = null;
		state.locked = true;
		state.dirty = false;
		await forgetDevice();
		localStorage.removeItem(LS_KEYS.hint);
		showSetup();
		toast("保险库已删除", "ok");
	} catch (error) {
		console.error(error);
		toast("删除失败，请稍后再试", "error");
	}
}

/* --------------------------------------------------------------------------
 * Screens
 * -------------------------------------------------------------------------- */

function showScreen(id) {
	$$(".screen").forEach((screen) => {
		screen.hidden = screen.id !== id;
	});
}

function showSetup() {
	state.locked = true;
	showScreen("screen-setup");
	bindPasswordToggle($("#screen-setup"));
	const hint = localStorage.getItem(LS_KEYS.hint);
	if (hint) $("#setup-hint").value = hint;
	$("#setup-password").focus();
}

function showUnlock(message = "") {
	state.locked = true;
	showScreen("screen-unlock");
	bindPasswordToggle($("#screen-unlock"));
	$("#unlock-email").textContent = state.email || "Vault";
	const hint = localStorage.getItem(LS_KEYS.hint);
	$("#unlock-sub").innerHTML = message
		? escapeHtml(message)
		: hint
			? `提示：${escapeHtml(hint)}`
			: "输入主密码以解密你的凭据。";
	const meta = state.vault?.updatedAt ? `上次更新 ${formatDate(state.vault.updatedAt)}` : "";
	$("#unlock-meta").textContent = meta;
	$("#unlock-password").value = "";
	$("#unlock-password").focus();
}

function showError(error) {
	showScreen("screen-error");
	const messages = {
		missing_access_token: "请求没有携带 Cloudflare Access 令牌。请确认这个域名已经接入 Access。",
		email_not_allowed: "当前登录账号不在白名单中。",
		bad_audience: "Access 应用的 AUD 与配置不一致。",
		bad_issuer: "令牌签发者与团队域名不一致。",
		"token expired": "Access 会话已过期，请重新登录。",
	};
	const reason = error instanceof ApiError ? (error.body?.reason ?? error.body?.error) : null;
	const text =
		error instanceof ApiError
			? messages[reason] ?? reason ?? `HTTP ${error.status}`
			: error instanceof TypeError
				? "无法连接服务器，请检查网络后重试。"
				: (error?.message ?? "未知错误");
	$("#error-message").textContent = `${text}${error instanceof ApiError && error.status ? `（HTTP ${error.status}）` : ""}`;
	$("#error-allow").textContent = state.email || "suchangv@gmail.com";

	const isNetwork = error instanceof TypeError;
	$("#error-title").textContent = isNetwork ? "网络连接中断" : "身份验证失败";
	$("#error-note").hidden = isNetwork;
	$("#error-logout").hidden = isNetwork;
}

async function enterVault() {
	state.locked = false;
	state.lastActivity = Date.now();
	showScreen("screen-vault");
	$("#screen-vault").dataset.view = "list";
	$("#account-email").textContent = state.email;
	if (state.filter.startsWith("tag:")) {
		const active = state.filter.slice(4);
		if (!allTags().some(([tag]) => tag === active)) {
			state.filter = "all";
			localStorage.setItem(LS_KEYS.filter, "all");
		}
	}
	$$(".chip").forEach((chip) => chip.classList.toggle("is-active", chip.dataset.filter === state.filter));

	const isMobile = window.matchMedia("(max-width: 860px)").matches;
	state.selectedId = !isMobile ? (visibleItems()[0]?.id ?? null) : null;
	renderAll();
	if (isMobile) setView("list");
	setSaveState("saved");

	if (state.pendingNew) {
		const pending = state.pendingNew;
		state.pendingNew = null;
		openEditor(null, pending);
	}
}

/* --------------------------------------------------------------------------
 * Locking
 * -------------------------------------------------------------------------- */

function wipeSensitiveDom() {
	$("#item-list").innerHTML = "";
	$("#tag-chips").innerHTML = "";
	$("#tag-chips").hidden = true;
	$("#detail-body").innerHTML = "";
	$("#detail-body").hidden = true;
	$("#detail-empty").hidden = false;
	state.revealed.clear();
	state.selectedId = null;
	state.query = "";
	$("#search-input").value = "";
}

async function lockVault({ force = false, skipSave = false, message = "" } = {}) {
	if (state.locked && !force) return;
	clearTimeout(state.saveTimer);
	clearTimeout(state.retryTimer);
	if (!skipSave && state.dirty && !state.saving) {
		try {
			await flushSave();
		} catch {
			/* ignore */
		}
	}
	state.key = null;
	state.data = null;
	state.locked = true;
	state.dirty = false;
	state.saving = false;
	await clearRememberToken();
	wipeSensitiveDom();
	showScreen("screen-loading");
	try {
		const vault = await api("/api/vault").catch((error) => {
			if (error instanceof ApiError && error.status === 404) return null;
			throw error;
		});
		state.vault = vault;
		if (!vault) showSetup();
		else showUnlock(message || (skipSave ? "" : "已锁定保险库。"));
	} catch (error) {
		showError(error);
	}
}

function startAutolockWatcher() {
	setInterval(() => {
		if (state.locked || state.autolockMs === 0) return;
		if (Date.now() - state.lastActivity > state.autolockMs) {
			void lockVault({ message: "因闲置已自动锁定。" });
		}
	}, 10_000);
}

/* --------------------------------------------------------------------------
 * Boot & events
 * -------------------------------------------------------------------------- */

async function boot() {
	state.theme = localStorage.getItem(LS_KEYS.theme) ?? "auto";
	applyTheme(state.theme);
	const storedAutolock = localStorage.getItem(LS_KEYS.autolock);
	const parsedAutolock = storedAutolock === null ? 5 * 60_000 : Number(storedAutolock);
	state.autolockMs =
		Number.isFinite(parsedAutolock) && parsedAutolock >= 0 ? parsedAutolock : 5 * 60_000;
	state.filter = localStorage.getItem(LS_KEYS.filter) ?? "all";

	bindStatic();
	startAutolockWatcher();
	setupWindowControlsOverlay();

	const shortcut = new URL(location.href).searchParams.get("new");
	if (shortcut) {
		state.pendingNew = ["login", "card", "note"].includes(shortcut) ? shortcut : "login";
		history.replaceState(null, "", location.pathname);
	}

	void registerServiceWorker();

	try {
		const me = await api("/api/me");
		state.email = me.email;
		state.accessExpiresAt = me.expiresAt;
		const vault = await api("/api/vault").catch((error) => {
			if (error instanceof ApiError && error.status === 404) return null;
			throw error;
		});
		state.vault = vault;
		if (!vault) {
			await clearRememberToken();
			showSetup();
			return;
		}

		// Trusted-device auto unlock: unwrap the vault key with the device key.
		const token = await readRememberToken();
		if (token) {
			const key = await unwrapVaultKey(token.wrapped);
			if (key) {
				try {
					const data = normalizeData(await decryptJson(key, vault.ciphertext));
					state.key = key;
					state.data = data;
					state.dirty = false;
					await enterVault();
					await renewRememberToken(token);
					toast("已通过受信任设备解锁", "ok");
					return;
				} catch {
					/* fall through to password unlock */
				}
			}
			await clearRememberToken();
			showUnlock("此设备的免密凭证已失效，请输入主密码。");
			return;
		}

		showUnlock();
	} catch (error) {
		console.error(error);
		showError(error);
	}
}

function bindStatic() {
	bindPasswordToggle($("#screen-setup"));
	bindPasswordToggle($("#screen-unlock"));

	// ---- setup ----
	const setupPassword = $("#setup-password");
	setupPassword.addEventListener("input", () => {
		renderStrength($("#setup-strength"), setupPassword.value);
	});

	$("#setup-form").addEventListener("submit", async (event) => {
		event.preventDefault();
		const password = $("#setup-password").value;
		const confirm = $("#setup-confirm").value;
		const error = $("#setup-error");
		const button = $("#setup-submit");

		const fail = (message) => {
			error.textContent = message;
			error.hidden = false;
		};

		error.hidden = true;
		if (password.length < 10) return fail("主密码至少需要 10 位");
		if (password !== confirm) return fail("两次输入的密码不一致");
		if (passwordStrength(password).score < 2) return fail("主密码太弱，请换一个更长的密码短语");

		button.disabled = true;
		button.textContent = "正在加密…";
		try {
			const salt = bytesToB64(randomBytes(16));
			const { sessionKey: key, raw } = await deriveKeyMaterial(password, salt, KDF_ITERATIONS);
			const data = normalizeData({
				items: [],
				createdAt: new Date().toISOString(),
				updatedAt: new Date().toISOString(),
			});
			const ciphertext = await encryptJson(key, data);
			const result = await api("/api/vault", {
				method: "PUT",
				body: JSON.stringify({
					version: 0,
					kdf: { algorithm: KDF_ALGORITHM, salt, iterations: KDF_ITERATIONS },
					ciphertext,
				}),
			});

			state.vault = {
				version: result.version,
				updatedAt: result.updatedAt,
				kdf: { algorithm: KDF_ALGORITHM, salt, iterations: KDF_ITERATIONS },
				ciphertext,
			};
			state.key = key;
			state.data = data;
			state.dirty = false;
			await rememberDevice(raw);
			raw.fill(0);

			const hint = $("#setup-hint").value.trim();
			if (hint) localStorage.setItem(LS_KEYS.hint, hint);
			else localStorage.removeItem(LS_KEYS.hint);

			await enterVault();
			toast("保险库已创建", "ok");
		} catch (submitError) {
			console.error(submitError);
			if (submitError instanceof ApiError && submitError.status === 409) {
				fail("保险库已存在，请刷新页面后解锁");
			} else {
				fail("创建失败，请检查网络后重试");
			}
		} finally {
			button.disabled = false;
			button.textContent = "创建保险库";
		}
	});

	// ---- unlock ----
	$("#unlock-form").addEventListener("submit", async (event) => {
		event.preventDefault();
		const password = $("#unlock-password").value;
		const error = $("#unlock-error");
		const button = $("#unlock-submit");
		error.hidden = true;

		if (!password) {
			error.textContent = "请输入主密码";
			error.hidden = false;
			return;
		}
		if (!state.vault) {
			error.textContent = "找不到保险库，请刷新页面";
			error.hidden = false;
			return;
		}

		button.disabled = true;
		button.textContent = "正在解密…";
		try {
			const { sessionKey: key, raw } = await deriveKeyMaterial(
				password,
				state.vault.kdf.salt,
				state.vault.kdf.iterations,
			);
			const data = normalizeData(await decryptJson(key, state.vault.ciphertext));
			state.key = key;
			state.data = data;
			state.dirty = false;
			await rememberDevice(raw);
			raw.fill(0);
			await enterVault();
			toast("保险库已解锁", "ok");
		} catch {
			error.textContent = "主密码不正确";
			error.hidden = false;
			$("#unlock-password").select();
		} finally {
			button.disabled = false;
			button.textContent = "解锁";
		}
	});

	$("#unlock-reset").addEventListener("click", () => {
		openModal({
			title: "忘记主密码",
			size: "modal-sm",
			body: `<p class="modal-text">服务器上只保存密文，主密码无法找回。唯一的办法是删除旧保险库并重新创建，<b>原有条目将永久丢失</b>。</p>`,
			footer: `<button class="btn btn-ghost" type="button" data-cancel>取消</button>
				<button class="btn btn-danger" type="button" data-reset>删除并重新开始</button>`,
			onMount(m) {
				m.element.querySelector("[data-cancel]").addEventListener("click", () => m.close());
				m.element.querySelector("[data-reset]").addEventListener("click", async () => {
					const ok = await confirmDialog({
						title: "确认删除",
						message: "此操作不可撤销。输入 <b>DELETE</b> 继续。",
						confirmLabel: "永久删除",
						danger: true,
						requireText: "DELETE",
					});
					if (!ok) return;
					try {
						await api("/api/vault", { method: "DELETE" });
						localStorage.removeItem(LS_KEYS.hint);
						m.close();
						showSetup();
						toast("已删除旧保险库", "ok");
					} catch {
						toast("删除失败，请稍后再试", "error");
					}
				});
			},
		});
	});

	// ---- error screen ----
	$("#error-reload").addEventListener("click", () => location.reload());
	$("#error-logout").addEventListener("click", () => {
		location.href = "/cdn-cgi/access/logout";
	});

	// ---- search & filters ----
	$("#search-input").addEventListener("input", (event) => {
		state.query = event.target.value;
		renderList();
	});

	$("#filter-chips").addEventListener("click", (event) => {
		const button = event.target.closest(".chip");
		if (!button) return;
		state.filter = button.dataset.filter;
		localStorage.setItem(LS_KEYS.filter, state.filter);
		$$(".chip").forEach((chip) => chip.classList.toggle("is-active", chip === button));
		renderList();
	});

	// ---- item list ----
	$("#tag-chips").addEventListener("click", (event) => {
		const manage = event.target.closest("[data-manage-tags]");
		if (manage) {
			openTagManager();
			return;
		}
		const chip = event.target.closest("[data-tag]");
		if (!chip) return;
		const tag = chip.dataset.tag;
		state.filter = state.filter === `tag:${tag}` ? "all" : `tag:${tag}`;
		localStorage.setItem(LS_KEYS.filter, state.filter);
		$$(".chip").forEach((item) => item.classList.toggle("is-active", item.dataset.filter === state.filter));
		renderList();
	});

	$("#item-list").addEventListener("click", (event) => {
		const fav = event.target.closest("[data-fav]");
		const row = event.target.closest(".item");
		if (fav) {
			event.stopPropagation();
			const item = itemById(fav.dataset.fav);
			if (item) {
				item.favorite = !item.favorite;
				item.updatedAt = new Date().toISOString();
				markDirty();
				renderAll();
			}
			return;
		}
		if (row) selectItem(row.dataset.id);
	});

	// ---- detail actions ----
	$("#detail").addEventListener("click", async (event) => {
		const item = itemById(state.selectedId);
		if (!item) return;

		const copyTarget = event.target.closest("[data-copy]");
		if (copyTarget) {
			const field = copyTarget.dataset.copy;
			const labels = { username: "用户名", password: "密码", url: "网址", number: "卡号", cvv: "CVV", expiry: "有效期", cardholder: "持卡人" };
			await copySecret(item[field], labels[field] ?? "内容");
			return;
		}

		const reveal = event.target.closest("[data-reveal]");
		if (reveal) {
			const field = reveal.dataset.reveal;
			if (state.revealed.has(field)) state.revealed.delete(field);
			else state.revealed.add(field);
			renderDetail();
			return;
		}

		if (event.target.closest("[data-back]")) {
			state.selectedId = null;
			renderAll();
			return;
		}
		if (event.target.closest("[data-edit]")) {
			openEditor(item);
			return;
		}
		if (event.target.closest("[data-delete]")) {
			await deleteSelected();
			return;
		}
		const favToggle = event.target.closest("[data-fav-detail]");
		if (favToggle) {
			item.favorite = !item.favorite;
			item.updatedAt = new Date().toISOString();
			markDirty();
			renderAll();
		}
	});

	// ---- new / settings / lock ----
	$("#btn-new").addEventListener("click", () => openEditor(null));
	$("#btn-settings").addEventListener("click", () => openSettings());
	$("#btn-lock").addEventListener("click", () => void lockVault());

	// ---- keyboard ----
	document.addEventListener("keydown", (event) => {
		const inField = ["INPUT", "TEXTAREA", "SELECT"].includes(document.activeElement?.tagName ?? "");
		const mod = event.metaKey || event.ctrlKey;
		if (mod && event.key.toLowerCase() === "l" && !state.locked) {
			event.preventDefault();
			void lockVault();
			return;
		}
		if (state.locked) return;
		if (mod && event.key.toLowerCase() === "k") {
			event.preventDefault();
			$("#search-input").focus();
			$("#search-input").select();
			return;
		}
		if (event.key === "Escape") {
			$("#search-input").blur();
			return;
		}
		if (!inField && event.key === "n" && !mod && !event.altKey) {
			event.preventDefault();
			openEditor(null);
		}
		if (!inField && event.key === "/" && !mod) {
			event.preventDefault();
			$("#search-input").focus();
		}
	});

	// ---- activity tracking ----
	const bump = () => {
		state.lastActivity = Date.now();
	};
	["pointerdown", "keydown", "wheel", "touchstart"].forEach((type) => {
		document.addEventListener(type, bump, { passive: true });
	});

	// ---- theme change ----
	window.matchMedia("(prefers-color-scheme: light)").addEventListener("change", () => {
		if (state.theme === "auto") applyTheme("auto");
	});

	$$(".chip").forEach((chip) => {
		chip.classList.toggle("is-active", chip.dataset.filter === state.filter);
	});

	// ---- PWA ----
	window.addEventListener("beforeinstallprompt", (event) => {
		event.preventDefault();
		deferredInstallPrompt = event;
	});
	window.addEventListener("appinstalled", () => {
		deferredInstallPrompt = null;
		toast("Vault 已安装到桌面", "ok");
	});

	// ---- connectivity ----
	window.addEventListener("offline", () => toast("网络已断开", "error", 4000));
	window.addEventListener("online", () => toast("网络已恢复", "ok"));
}

async function registerServiceWorker() {
	if (!("serviceWorker" in navigator)) return;
	try {
		swRegistration = await navigator.serviceWorker.register("/sw.js", { scope: "/" });
		swRegistration.addEventListener("updatefound", () => {
			const worker = swRegistration.installing;
			worker?.addEventListener("statechange", () => {
				if (worker.state === "installed" && navigator.serviceWorker.controller) {
					toast("应用已更新，下次打开生效", "ok", 4000);
				}
			});
		});
	} catch (error) {
		console.warn("service worker registration failed", error);
	}
}

boot();
