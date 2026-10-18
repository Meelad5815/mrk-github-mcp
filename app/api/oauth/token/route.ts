import { createHash, timingSafeEqual } from "node:crypto";
import { signPayload, verifyPayload, verifyClientId } from "../../../../lib/oauth";
export const runtime = "nodejs";
export const dynamic = "force-dynamic";
export async function POST(request: Request) {
  const contentType = request.headers.get("content-type") || "";
  let body: Record<string,string>;
  try {
    if (contentType.includes("application/json")) body = await request.json();
    else body = Object.fromEntries(new URLSearchParams(await request.text()).entries());
  } catch { return Response.json({ error: "invalid_request" }, { status: 400 }); }
  if (body.grant_type !== "authorization_code" || !body.code || !body.redirect_uri || !body.client_id || !body.code_verifier) {
    return Response.json({ error: "invalid_request", error_description: "grant_type, code, client_id, redirect_uri and code_verifier are required." }, { status: 400 });
  }
  const payload = verifyPayload<{typ:string;sub:string;login:string;clientId:string;redirectUri:string;challenge:string;exp:number}>(body.code);
  if (!payload || payload.typ !== "oauth_code" || payload.clientId !== body.client_id || payload.redirectUri !== body.redirect_uri || !verifyClientId(body.client_id, body.redirect_uri)) {
    return Response.json({ error: "invalid_grant" }, { status: 400 });
  }
  const verifier = body.code_verifier;
  if (!/^[A-Za-z0-9._~-]{43,128}$/.test(verifier)) return Response.json({ error: "invalid_grant" }, { status: 400 });
  const challenge = createHash("sha256").update(verifier).digest("base64url");
  const expected = Buffer.from(payload.challenge);
  const actual = Buffer.from(challenge);
  if (expected.length !== actual.length || !timingSafeEqual(expected, actual)) return Response.json({ error: "invalid_grant" }, { status: 400 });
  const accessToken = signPayload({ typ: "access", sub: payload.sub, login: payload.login, scope: "github", exp: Math.floor(Date.now()/1000)+3600 });
  return Response.json({ access_token: accessToken, token_type: "Bearer", expires_in: 3600, scope: "github" }, { headers: { "Cache-Control": "no-store", Pragma: "no-cache" } });
}
