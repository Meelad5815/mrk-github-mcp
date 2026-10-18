import { makeClientId, validRedirect } from "../../../../lib/oauth";
export const runtime = "nodejs";
export async function POST(request: Request) {
  try {
    const body = await request.json();
    const redirects = body?.redirect_uris;
    if (!Array.isArray(redirects) || redirects.length < 1 || redirects.length > 10 || redirects.some((x: unknown) => typeof x !== "string" || !validRedirect(x)) || new Set(redirects).size !== redirects.length) {
      return Response.json({ error: "invalid_client_metadata", error_description: "Provide 1-10 unique valid HTTPS redirect_uris (localhost HTTP is allowed for local clients)." }, { status: 400 });
    }
    const redirectUris = redirects as string[];
    return Response.json({
      client_id: makeClientId(redirectUris),
      client_name: typeof body.client_name === "string" ? body.client_name : "Gemini MCP client",
      redirect_uris: redirectUris,
      grant_types: ["authorization_code"],
      response_types: ["code"],
      token_endpoint_auth_method: "none",
    }, { status: 201, headers: { "Cache-Control": "no-store" } });
  } catch {
    return Response.json({ error: "invalid_client_metadata" }, { status: 400 });
  }
}
