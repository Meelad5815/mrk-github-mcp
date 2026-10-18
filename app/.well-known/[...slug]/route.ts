export const dynamic = "force-dynamic";
export async function GET(request: Request, context: { params: Promise<{ slug: string[] }> }) {
  const { slug } = await context.params;
  const base = new URL(request.url).origin;
  const name = slug.join("/");
  if (name === "oauth-authorization-server") {
    return Response.json({
      issuer: base,
      authorization_endpoint: base + "/api/oauth/authorize",
      token_endpoint: base + "/api/oauth/token",
      registration_endpoint: base + "/api/oauth/register",
      response_types_supported: ["code"],
      grant_types_supported: ["authorization_code"],
      code_challenge_methods_supported: ["S256"],
      token_endpoint_auth_methods_supported: ["none", "client_secret_post"],
      scopes_supported: ["github"]
    }, { headers: { "Cache-Control": "no-store" } });
  }
  if (name === "oauth-protected-resource") {
    return Response.json({
      resource: base + "/api/mcp",
      authorization_servers: [base],
      bearer_methods_supported: ["header"],
      scopes_supported: ["github"]
    }, { headers: { "Cache-Control": "no-store" } });
  }
  return Response.json({ error: "not_found" }, { status: 404 });
}
