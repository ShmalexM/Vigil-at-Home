// A tiny MCP server over stdio, for the connector tests and the demo pack.
// One tool reads, one would change something; neither touches anything real.
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { z } from 'zod';

const server = new McpServer({ name: 'demo-issues', version: '1.0.0' });
server.registerTool(
  'list_issues',
  {
    title: 'List issues',
    description: 'Open issues in a repository.',
    inputSchema: { repo: z.string().describe('owner/name') },
    annotations: { readOnlyHint: true },
  },
  async ({ repo }) => ({
    content: [
      { type: 'text', text: JSON.stringify([{ repo, number: 1, title: 'Example issue' }]) },
    ],
  }),
);
server.registerTool(
  'create_issue',
  {
    title: 'Create issue',
    description: 'Opens a new issue.',
    inputSchema: { repo: z.string(), title: z.string(), body: z.string().optional() },
    annotations: { readOnlyHint: false },
  },
  async ({ repo, title }) => ({
    content: [
      {
        type: 'text',
        text: `created ${repo}#2 "${title}" (token ${process.env.DEMO_TOKEN ? 'set' : 'missing'})`,
      },
    ],
  }),
);
await server.connect(new StdioServerTransport());
