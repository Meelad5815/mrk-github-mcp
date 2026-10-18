import { createHmac, timingSafeEqual } from "node:crypto";

export function secret() {
  const value = process.env.OAUTH_SIGNING_SECRET;
  if (!value || value.length < 32) throw new Error("OAUTH_SIGNING_SECRET must be set to a random secret of at least 32 characters");
  return value;
}
const b64 = (s: string) => Buffer.from(s, "utf8").toString("base64url");
const unb64 = (s: string) => Buffer.from(s, "base64url").toString("utf8");
const mac = (value: string) => createHmac("sha256", secret()).update(value).digest("base64url");

export function signPayload(payload: Record<string, unknown>) {
  const body = b64(JSON.stringify(payload));
  return body + "." + mac(body);
}
export function verifyPayload<T extends Record<string, any>>(token: string): T | null {
  const parts = token.split(".");
  if (parts.length !== 2) return null;
  const expected = Buffer.from(mac(parts[0]));
  const actual = Buffer.from(parts[1]);
  if (expected.length !== actual.length || !timingSafeEqual(expected, actual)) return null;
  try {
    const value = JSON.parse(unb64(parts[0])) as T;
    if (typeof value.exp === "number" && value.exp < Math.floor(Date.now() / 1000)) return null;
    return value;
  } catch { return null; }
}

// Derive a stable per-client secret without storing client records in serverless memory.
export function makeClientSecret(clientId: string) {
  return mac("client-secret:" + clientId);
}
export function verifyClientSecret(clientId: string, clientSecret: string) {
  const expected = Buffer.from(makeClientSecret(clientId));
  const actual = Buffer.from(clientSecret);
  return expected.length === actual.length && timingSafeEqual(expected, actual);
}

// Bind each dynamic client ID to the full set of redirect URIs it registered.
export function makeClientId(redirectUris: string | string[]) {
  const list = (Array.isArray(redirectUris) ? redirectUris : [redirectUris]).slice().sort();
  const encoded = b64(JSON.stringify(list));
  return "mrk_" + encoded + "." + mac("client:" + encoded);
}
export function verifyClientId(clientId: string, redirectUri: string) {
  const match = /^mrk_([A-Za-z0-9_-]+)\.([A-Za-z0-9_-]+)$/.exec(clientId);
  if (!match) return false;
  const expected = Buffer.from(mac("client:" + match[1]));
  const actual = Buffer.from(match[2]);
  if (expected.length !== actual.length || !timingSafeEqual(expected, actual)) return false;
  try {
    const redirects = JSON.parse(unb64(match[1]));
    return Array.isArray(redirects) && redirects.length > 0 && redirects.every((x) => typeof x === "string") && redirects.includes(redirectUri);
  } catch { return false; }
}
export function validRedirect(uri: string) {
  try {
    const u = new URL(uri);
    return u.protocol === "https:" || (u.protocol === "http:" && ["localhost", "127.0.0.1"].includes(u.hostname));
  } catch { return false; }
}
