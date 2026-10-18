import { makeClientId, makeClientSecret, validRedirect } from "../../../../lib/oauth";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function POST(request: Request) {
  try {
    const contentType = request.headers.get("content-type") || "";
    if (!contentType.toLowerCase().includes("application/json")) {
      return Response.json(
        { error: "invalid_client_metadata", error_description: "Dynamic client registration requires Content-Type: application/json." },
        { status: 400, headers: { "Cache-Control": "no-store" } }
      );
    }

    const body = await request.json();
    const redirects = body?.redirect_uris;

    // Gemini Spark may register several production, test, and sandbox callback URIs.
    if (
      !Array.isArray(redirects) ||
      redirects.length < 1 ||
      redirects.length > 10 ||
      redirects.some((x: unknown) => typeof x !== "string" || !validRedirect(x)) ||
      new Set(redirects).size !== redirects.length
    ) {
      return Response.json(
        {
          error: "invalid_client_metadata",
          error_description: "Provide 1-10 unique HTTPS redirect_uris (HTTP is allowed only for localhost/127.0.0.1)."
        },
        { status: 400, headers: { "Cache-Control": "no-store" } }
      );
    }

    const redirectUris = redirects as string[];
    const clientId = makeClientId(redirectUris);
    const clientSecret = makeClientSecret(clientId);

    // Include RFC 7591 response fields used by stricter OAuth clients.
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
  } catch {
    return Response.json(
      { error: "invalid_client_metadata", error_description: "Send a valid JSON registration request." },
      { status: 400, headers: { "Cache-Control": "no-store" } }
    );
  }
}
