/**
 * Cloudflare Access (Zero Trust) JWT verification.
 *
 * Every request that reaches this Worker should carry a signed
 * `Cf-Access-Jwt-Assertion` header (or `CF_Authorization` cookie) issued by the
 * Access application that fronts it. We verify the RS256 signature against the
 * team's JWKS, check the audience, expiry and the e-mail allow-list.
 *
 * Nothing here is trusted from the client: on any error we fail closed.
 */

export interface AccessEnv {
	ACCESS_TEAM_DOMAIN: string;
	ACCESS_AUD: string;
	ALLOWED_EMAILS: string;
	DEV_AUTH_BYPASS?: string | boolean;
	/** Local-only fake identity. Never set in production. */
	DEV_AUTH_EMAIL?: string;
}

export interface AccessIdentity {
	email: string;
	subject?: string;
	expiresAt: number;
	authMethod?: string;
}

export type AccessResult =
	| { ok: true; identity: AccessIdentity }
	| { ok: false; status: number; reason: string };

interface Jwk extends JsonWebKey {
	kid?: string;
}

interface JwksCacheEntry {
	keys: Jwk[];
	fetchedAt: number;
}

const JWKS_TTL_MS = 60 * 60 * 1000; // 1 hour
const CLOCK_SKEW_SECONDS = 60;
const jwksCache = new Map<string, JwksCacheEntry>();

const encoder = new TextEncoder();

function b64urlToBytes(value: string): Uint8Array {
	const padded = value.replace(/-/g, "+").replace(/_/g, "/");
	const pad = padded.length % 4 === 0 ? "" : "=".repeat(4 - (padded.length % 4));
	const binary = atob(padded + pad);
	const bytes = new Uint8Array(binary.length);
	for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
	return bytes;
}

function b64urlToText(value: string): string {
	return new TextDecoder().decode(b64urlToBytes(value));
}

async function loadJwks(teamDomain: string): Promise<Jwk[]> {
	const cached = jwksCache.get(teamDomain);
	const now = Date.now();
	if (cached && now - cached.fetchedAt < JWKS_TTL_MS) return cached.keys;

	const res = await fetch(`https://${teamDomain}/cdn-cgi/access/certs`, {
		cf: { cacheTtl: 300, cacheEverything: true },
	});
	if (!res.ok) throw new Error(`jwks fetch failed: ${res.status}`);
	const body = (await res.json()) as { keys?: Jwk[] };
	const keys = Array.isArray(body.keys) ? body.keys : [];
	if (keys.length === 0) throw new Error("jwks empty");
	jwksCache.set(teamDomain, { keys, fetchedAt: now });
	return keys;
}

export async function verifyAccessJwt(
	token: string,
	env: AccessEnv,
): Promise<AccessIdentity> {
	const parts = token.split(".");
	if (parts.length !== 3) throw new Error("malformed token");
	const [rawHeader, rawPayload, rawSignature] = parts;

	const header = JSON.parse(b64urlToText(rawHeader)) as {
		alg?: string;
		kid?: string;
	};
	if (header.alg !== "RS256") throw new Error("unexpected alg");

	const keys = await loadJwks(env.ACCESS_TEAM_DOMAIN);
	const jwk = keys.find((k) => k.kid === header.kid) ?? keys[0];

	const key = await crypto.subtle.importKey(
		"jwk",
		jwk,
		{ name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
		false,
		["verify"],
	);

	const valid = await crypto.subtle.verify(
		"RSASSA-PKCS1-v1_5",
		key,
		b64urlToBytes(rawSignature),
		encoder.encode(`${rawHeader}.${rawPayload}`),
	);
	if (!valid) throw new Error("bad signature");

	const payload = JSON.parse(b64urlToText(rawPayload)) as {
		aud?: string | string[];
		iss?: string;
		exp?: number;
		nbf?: number;
		email?: string;
		sub?: string;
		type?: string;
	};

	const now = Math.floor(Date.now() / 1000);
	if (typeof payload.exp !== "number" || payload.exp + CLOCK_SKEW_SECONDS < now) {
		throw new Error("token expired");
	}
	if (typeof payload.nbf === "number" && payload.nbf - CLOCK_SKEW_SECONDS > now) {
		throw new Error("token not yet valid");
	}
	if (payload.iss !== `https://${env.ACCESS_TEAM_DOMAIN}`) {
		throw new Error("bad issuer");
	}
	const audiences = Array.isArray(payload.aud)
		? payload.aud
		: payload.aud
			? [payload.aud]
			: [];
	if (!env.ACCESS_AUD || !audiences.includes(env.ACCESS_AUD)) {
		throw new Error("bad audience");
	}
	if (!payload.email) throw new Error("no email claim");

	return {
		email: payload.email.toLowerCase(),
		subject: payload.sub,
		expiresAt: payload.exp,
		authMethod: payload.type,
	};
}

function allowedEmails(env: AccessEnv): string[] {
	return env.ALLOWED_EMAILS.split(",")
		.map((value) => value.trim().toLowerCase())
		.filter(Boolean);
}

function readCookie(request: Request, name: string): string | null {
	const header = request.headers.get("Cookie");
	if (!header) return null;
	for (const part of header.split(";")) {
		const [key, ...rest] = part.trim().split("=");
		if (key === name) return rest.join("=");
	}
	return null;
}


/**
 * Authenticates the request. The development bypass needs DEV_AUTH_BYPASS=true
 * *and* DEV_AUTH_EMAIL, both of which only exist in the git-ignored `.dev.vars`.
 */
export async function authenticate(
	request: Request,
	env: AccessEnv,
): Promise<AccessResult> {
	// Local development bypass. It requires two variables that only exist in the
	// git-ignored `.dev.vars` file: DEV_AUTH_BYPASS=true and DEV_AUTH_EMAIL.
	// Production config declares DEV_AUTH_BYPASS="false" and no DEV_AUTH_EMAIL,
	// so this path can never open in production.
	const devEmail = env.DEV_AUTH_EMAIL?.trim().toLowerCase();
	if (String(env.DEV_AUTH_BYPASS) === "true" && devEmail) {
		const allow = allowedEmails(env);
		if (allow.length > 0 && !allow.includes(devEmail)) {
			return { ok: false, status: 403, reason: "email_not_allowed" };
		}
		return {
			ok: true,
			identity: {
				email: devEmail,
				expiresAt: Math.floor(Date.now() / 1000) + 3600,
				authMethod: "dev-bypass",
			},
		};
	}

	const token =
		request.headers.get("Cf-Access-Jwt-Assertion") ??
		readCookie(request, "CF_Authorization");

	if (!token) {
		return { ok: false, status: 403, reason: "missing_access_token" };
	}

	try {
		const identity = await verifyAccessJwt(token, env);
		const allow = allowedEmails(env);
		if (allow.length > 0 && !allow.includes(identity.email)) {
			return { ok: false, status: 403, reason: "email_not_allowed" };
		}
		return { ok: true, identity };
	} catch (error) {
		return {
			ok: false,
			status: 403,
			reason: error instanceof Error ? error.message : "invalid_token",
		};
	}
}
