import { createHash, timingSafeEqual } from "node:crypto";
import { signPayload, verifyPayload, verifyClientId, verifyClientSecret } from "../../../../lib/oauth";
export const runtime = "nodejs";
export const dynamic = "force-dynamic";
export async function POST(request: Request) {
  let body: Record<string, string>;
  try {
    const type = request.headers.get("content-type") || "";
    body = type.includes("application/json") ? await request.json() : Object.fromEntries(new URLSearchParams(await request.text()).entries());
  } catch { return Response.json({ error: "invalid_request" }, { status: 400 }); }
  if (body.grant_type !== "authorization_code" || !body.code || !body.redirect_uri || !body.client_id || !body.code_verifier) return Response.json({ error: "invalid_request" }, { status: 400 });
  if (!body.client_secret || !verifyClientSecret(body.client_id, body.client_secret)) return Response.json({ error: "invalid_client" }, { status: 401, headers: { "Cache-Control": "no-store" } });
  const p = verifyPayload<{typ:string;login:string;clientId:string;redirectUri:string;challenge:string;exp:number}>(body.code);
  if (!p || p.typ !== "oauth_code" || p.clientId !== body.client_id || p.redirectUri !== body.redirect_uri || !verifyClientId(body.client_id, body.redirect_uri)) return Response.json({ error: "invalid_grant" }, { status: 400 });
  if (!/^[A-Za-z0-9._~-]{43,128}$/.test(body.code_verifier)) return Response.json({ error: "invalid_grant" }, { status: 400 });
  const challenge = createHash("sha256").update(body.code_verifier).digest("base64url");
  const expected = Buffer.from(p.challenge);
  const actual = Buffer.from(challenge);
  if (expected.length !== actual.length || !timingSafeEqual(expected, actual)) return Response.json({ error: "invalid_grant" }, { status: 400 });
  const token = signPayload({ typ: "access", login: p.login, scope: "github", exp: Math.floor(Date.now()/1000)+3600 });
  return Response.json({ access_token: token, token_type: "Bearer", expires_in: 3600, scope: "github" }, { headers: { "Cache-Control": "no-store", Pragma: "no-cache" } });
}
