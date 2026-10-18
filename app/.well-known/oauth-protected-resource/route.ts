export const dynamic = "force-dynamic";
export async function GET(request: Request) {
  const base = new URL(request.url).origin;
  return Response.json({
    resource: base + "/api/mcp",
    authorization_servers: [base],
    bearer_methods_supported: ["header"],
    scopes_supported: ["github"],
  }, { headers: { "Cache-Control": "no-store" } });
}
