import { makeClientId, makeClientSecret, validRedirect } from "../../../../lib/oauth";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function POST(request: Request) {
  const contentType = request.headers.get("content-type") || "";
  if (!contentType.toLowerCase().includes("application/json")) {
    return Response.json(
      { error: "invalid_client_metadata", error_description: "Dynamic client registration requires Content-Type: application/json." },
      { status: 400, headers: { "Cache-Control": "no-store" } }
    );
  }

  let body: any;
  try {
    body = await request.json();
  } catch {
    return Response.json(
      { error: "invalid_client_metadata", error_description: "Send a valid JSON registration request." },
      { status: 400, headers: { "Cache-Control": "no-store" } }
    );
  }

  const redirects = body?.redirect_uris;
  if (
    !Array.isArray(redirects) ||
    redirects.length < 1 ||
    redirects.length > 10 ||
    redirects.some((x: unknown) => typeof x !== "string" || !validRedirect(x)) ||
    new Set(redirects).size !== redirects.length
  ) {
    return Response.json(
      { error: "invalid_client_metadata", error_description: "Provide 1-10 unique HTTPS redirect_uris (HTTP is allowed only for localhost/127.0.0.1)." },
      { status: 400, headers: { "Cache-Control": "no-store" } }
    );
  }

  try {
    const redirectUris = redirects as string[];
    const clientId = makeClientId(redirectUris);
    const clientSecret = makeClientSecret(clientId);
    return Response.json(
      {
        client_id: clientId,
        client_id_issued_at: Math.floor(Date.now() / 1000),
        client_secret: clientSecret,
        client_secret_expires_at: 0,
        client_name: typeof body.client_name === "string" && body.client_name.trim()
          ? body.client_name.trim().slice(0, 128)
          : "Gemini MCP client",
        redirect_uris: redirectUris,
        grant_types: ["authorization_code"],
        response_types: ["code"],
        token_endpoint_auth_method: "client_secret_post"
      },
      { status: 201, headers: { "Cache-Control": "no-store", Pragma: "no-cache" } }
    );
  } catch (error) {
    console.error("OAuth dynamic client registration failed:", error instanceof Error ? error.message : "unknown error");
    return Response.json(
      { error: "server_error", error_description: "OAuth server configuration is incomplete. Check the OAuth signing secret in deployment environment variables." },
      { status: 500, headers: { "Cache-Control": "no-store" } }
    );
  }
}
