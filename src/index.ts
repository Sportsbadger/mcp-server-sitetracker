#!/usr/bin/env node
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { CallToolRequestSchema, ListToolsRequestSchema } from '@modelcontextprotocol/sdk/types.js';
import { randomUUID } from 'node:crypto';
import { loadPolicy, read, resultText, tools, validateRequest, type Policy } from './security/readOnly.js';

// Runtime credentials and policy are provided by the operator, not the MCP client.
// No dotenv loading: a stray local .env must not choose the organisation.
let policy: Policy | undefined;
const credentials = { clientId: process.env.SALESFORCE_CLIENT_ID ?? '', clientSecret: process.env.SALESFORCE_CLIENT_SECRET ?? '' };
try {
  if (!credentials.clientId || !credentials.clientSecret) throw new Error();
  policy = loadPolicy(process.env);
} catch {
  console.error('Sitetracker MCP: configuration invalid; no tools enabled.');
}

const server = new Server({ name: 'sitetracker-mcp-read-only', version: '0.1.0' }, { capabilities: { tools: {} } });
let active = false;
const denied = () => ({ content: [{ type: 'text' as const, text: 'Request denied or unavailable.' }], isError: true });

server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools: policy ? tools : [] }));
server.setRequestHandler(CallToolRequestSchema, async request => {
  const started = Date.now();
  const correlationId = randomUUID();
  const toolName = tools.some(t => t.name === request.params.name) ? request.params.name : 'unknown';
  let acquired = false;
  let outcome = 'denied';
  try {
    if (!policy || active) return denied();
    const validated = validateRequest(policy, request.params.name, request.params.arguments);
    active = acquired = true;
    const value = await read(policy, validated, credentials);
    const text = resultText(value);
    outcome = 'allowed';
    return { content: [{ type: 'text' as const, text }], isError: false };
  } catch {
    return denied();
  } finally {
    if (acquired) active = false;
    console.error(JSON.stringify({ correlationId, toolName, outcome, timestamp: new Date().toISOString(), durationMs: Date.now() - started }));
  }
});

server.connect(new StdioServerTransport()).catch(() => {
  console.error('Sitetracker MCP: server startup failed.');
  process.exitCode = 1;
});
