import { createHash, timingSafeEqual } from "node:crypto";
import { signPayload, verifyPayload, verifyClientId, verifyClientSecret } from "../../../../lib/oauth";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

function decodeBasicCredential(value: string) {
  // OAuth 2.0 client_secret_basic applies form-url-encoding before Base64.
  return decodeURIComponent(value.replace(/\+/g, "%20"));
}

export async function POST(request: Request) {
  let body: Record<string, string>;
  try {
    const type = request.headers.get("content-type") || "";
    body = type.toLowerCase().includes("application/json")
      ? await request.json()
      : Object.fromEntries(new URLSearchParams(await request.text()).entries());
  } catch {
    return Response.json({ error: "invalid_request" }, { status: 400, headers: { "Cache-Control": "no-store" } });
  }

  const authorization = request.headers.get("authorization") || "";
  let clientId = body.client_id || "";
  let clientSecret = body.client_secret || "";

  if (authorization.startsWith("Basic ")) {
    try {
      const decoded = Buffer.from(authorization.slice(6).trim(), "base64").toString("utf8");
      const separator = decoded.indexOf(":");
      if (separator < 1) throw new Error("Malformed Basic credentials");
      clientId = decodeBasicCredential(decoded.slice(0, separator));
      clientSecret = decodeBasicCredential(decoded.slice(separator + 1));
    } catch {
      return Response.json({ error: "invalid_client" }, { status: 401, headers: { "Cache-Control": "no-store", "WWW-Authenticate": 'Basic realm="oauth-token"' } });
    }
  }

  if (body.grant_type !== "authorization_code" || !body.code || !body.redirect_uri || !clientId || !body.code_verifier) {
    return Response.json({ error: "invalid_request" }, { status: 400, headers: { "Cache-Control": "no-store" } });
  }
  if (!clientSecret || !verifyClientSecret(clientId, clientSecret)) {
    return Response.json({ error: "invalid_client" }, { status: 401, headers: { "Cache-Control": "no-store", "WWW-Authenticate": 'Basic realm="oauth-token"' } });
  }

  const p = verifyPayload<{typ:string;login:string;clientId:string;redirectUri:string;challenge:string;exp:number}>(body.code);
  if (!p || p.typ !== "oauth_code" || p.clientId !== clientId || p.redirectUri !== body.redirect_uri || !verifyClientId(clientId, body.redirect_uri)) {
    return Response.json({ error: "invalid_grant" }, { status: 400, headers: { "Cache-Control": "no-store" } });
  }
  if (!/^[A-Za-z0-9._~-]{43,128}$/.test(body.code_verifier)) {
    return Response.json({ error: "invalid_grant" }, { status: 400, headers: { "Cache-Control": "no-store" } });
  }

  const challenge = createHash("sha256").update(body.code_verifier).digest("base64url");
  const expected = Buffer.from(p.challenge);
  const actual = Buffer.from(challenge);
  if (expected.length !== actual.length || !timingSafeEqual(expected, actual)) {
    return Response.json({ error: "invalid_grant" }, { status: 400, headers: { "Cache-Control": "no-store" } });
  }

  const token = signPayload({ typ: "access", login: p.login, scope: "github", exp: Math.floor(Date.now() / 1000) + 3600 });
  return Response.json(
    { access_token: token, token_type: "Bearer", expires_in: 3600, scope: "github" },
    { headers: { "Cache-Control": "no-store", Pragma: "no-cache" } }
  );
}
