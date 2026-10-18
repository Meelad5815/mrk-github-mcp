import { signPayload, verifyPayload } from "../../../../lib/oauth";
export const runtime = "nodejs";
export const dynamic = "force-dynamic";
export async function GET(request: Request) {
  const u = new URL(request.url);
  const code = u.searchParams.get("code");
  const state = u.searchParams.get("state") || "";
  const p = verifyPayload<{clientId:string;redirectUri:string;state:string;challenge:string;exp:number}>(state);
  if (!code || !p) return Response.json({ error: "invalid_request" }, { status: 400 });
  const clientId = process.env.GITHUB_OAUTH_CLIENT_ID;
  const clientSecret = process.env.GITHUB_OAUTH_CLIENT_SECRET;
  const allowedLogin = (process.env.GITHUB_OAUTH_ALLOWED_LOGIN || "").toLowerCase();
  if (!clientId || !clientSecret || !allowedLogin) return Response.json({ error: "server_error", error_description: "OAuth provider credentials or allowed login are not configured." }, { status: 503 });
  const exchange = await fetch("https://github.com/login/oauth/access_token", {
    method: "POST", headers: { Accept: "application/json", "Content-Type": "application/json" },
    body: JSON.stringify({ client_id: clientId, client_secret: clientSecret, code }), cache: "no-store"
  });
  const token = await exchange.json().catch(() => ({}));
  if (!exchange.ok || !token.access_token) return Response.json({ error: "access_denied" }, { status: 401 });
  const userResponse = await fetch("https://api.github.com/user", { headers: { Authorization: "Bearer " + token.access_token, Accept: "application/vnd.github+json" }, cache: "no-store" });
  const user = await userResponse.json().catch(() => ({}));
  if (!userResponse.ok || typeof user.login !== "string" || user.login.toLowerCase() !== allowedLogin) return Response.json({ error: "access_denied", error_description: "This MCP server is restricted to its configured GitHub account." }, { status: 403 });
  const authCode = signPayload({ typ: "oauth_code", login: user.login, clientId: p.clientId, redirectUri: p.redirectUri, challenge: p.challenge, exp: Math.floor(Date.now()/1000)+120 });
  const redirect = new URL(p.redirectUri);
  redirect.searchParams.set("code", authCode);
  redirect.searchParams.set("state", p.state);
  return Response.redirect(redirect.toString(), 302);
}
