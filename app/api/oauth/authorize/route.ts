import { signPayload, verifyClientId, validRedirect } from "../../../../lib/oauth";
export const runtime = "nodejs";
export const dynamic = "force-dynamic";
export async function GET(request: Request) {
  const u = new URL(request.url);
  const clientId = u.searchParams.get("client_id") || "";
  const redirectUri = u.searchParams.get("redirect_uri") || "";
  const state = u.searchParams.get("state") || "";
  const challenge = u.searchParams.get("code_challenge") || "";
  if (u.searchParams.get("response_type") !== "code" || !state || !validRedirect(redirectUri) || !verifyClientId(clientId, redirectUri) || u.searchParams.get("code_challenge_method") !== "S256" || !/^[A-Za-z0-9_-]{43}$/.test(challenge)) {
    return Response.json({ error: "invalid_request" }, { status: 400 });
  }
  const ghClient = process.env.GITHUB_OAUTH_CLIENT_ID;
  if (!ghClient) return Response.json({ error: "server_error", error_description: "OAuth provider credentials are not configured." }, { status: 503 });
  const signedState = signPayload({ clientId, redirectUri, state, challenge, exp: Math.floor(Date.now()/1000)+600 });
  const github = new URL("https://github.com/login/oauth/authorize");
  github.searchParams.set("client_id", ghClient);
  github.searchParams.set("redirect_uri", new URL("/api/oauth/callback", u.origin).toString());
  github.searchParams.set("scope", "read:user");
  github.searchParams.set("state", signedState);
  return Response.redirect(github.toString(), 302);
}
