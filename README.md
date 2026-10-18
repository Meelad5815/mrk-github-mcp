# MRK GitHub MCP Server

Standalone Next.js MCP server for GitHub repository operations over Streamable HTTP. This repository is separate from `Meelad5815/mcpserver` (WordPress/Blogger).

## MCP tools
- `list_repositories`
- `get_file_contents`
- `create_or_update_file`
- `create_branch`
- `create_issue`
- `create_repository`

## Deploy to Vercel
1. Import `https://github.com/Meelad5815/mrk-github-mcp` into Vercel.
2. Use the repository root as the Root Directory.
3. Set server-side environment variables for Production and Preview:
   - `MCP_API_KEY`: long random secret used for Bearer authentication.
   - `GITHUB_TOKEN`: fine-grained GitHub personal access token, limited to only the repositories and permissions required.
4. Deploy and check `/api/health`; MCP endpoint is `/api/mcp`.

Never commit real tokens or paste them into public chat. The endpoint requires `Authorization: Bearer <MCP_API_KEY>`. Gemini Custom MCP may require OAuth or a supported way to send bearer credentials; do not disable authentication if the Gemini client cannot send this header.
