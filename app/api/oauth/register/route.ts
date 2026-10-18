import { makeClientId, validRedirect } from "../../../../lib/oauth";
export const runtime = "nodejs";
export async function POST(request: Request) {
  try {
    const body = await request.json();
    const redirects = body?.redirect_uris;
    if (!Array.isArray(redirects) || redirects.length < 1 || redirects.length > 10 || redirects.some((x: unknown) => typeof x !== "string" || !validRedirect(x))) {
      return Response.json({ error: "invalid_client_metadata", error_description: "Provide 1-10 valid HTTPS redirect_uris (localhost HTTP is allowed for local clients)." }, { status: 400 });
    }
    const redirectUri = redirects[0] as string;
    return Response.json({
      client_id: makeClientId(redirectUri),
      client_name: typeof body.client_name === "string" ? body.client_name : "Gemini MCP client",
      redirect_uris: [redirectUri],
      grant_types: ["authorization_code"],
      response_types: ["code"],
      token_endpoint_auth_method: "none",
    }, { status: 201, headers: { "Cache-Control": "no-store" } });
  } catch {
    return Response.json({ error: "invalid_client_metadata" }, { status: 400 });
  }
}
