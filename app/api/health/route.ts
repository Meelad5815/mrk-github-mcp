export const dynamic = "force-dynamic";

export async function GET() {
  const signingSecret = process.env.OAUTH_SIGNING_SECRET || "";
  const githubClientId = process.env.GITHUB_OAUTH_CLIENT_ID || "";
  const githubClientSecret = process.env.GITHUB_OAUTH_CLIENT_SECRET || "";
  return Response.json({
    service: "MRK GitHub MCP",
    status: "ok",
    endpoint: "/api/mcp",
    transport: "Streamable HTTP",
    authConfigured: Boolean(process.env.MCP_API_KEY),
    githubTokenConfigured: Boolean(process.env.GITHUB_TOKEN),
    oauthSigningSecretConfigured: signingSecret.length >= 32,
    githubOAuthConfigured: Boolean(githubClientId && githubClientSecret),
    allowedGithubLoginConfigured: Boolean(process.env.GITHUB_OAUTH_ALLOWED_LOGIN)
  }, { headers: { "Cache-Control": "no-store" } });
}
