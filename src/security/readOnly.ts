/** Sitetracker v0.1: a deliberately narrow, fail-closed read-only boundary. */
export type JsonObject = Record<string, unknown>;
export interface Policy {
  origin: string;
  orgId: string;
  userId: string;
  apiVersion: string;
  objects: ReadonlyMap<string, ReadonlySet<string>>;
}
const identifier = /^[A-Za-z][A-Za-z0-9_]{0,79}$/;
const id = /^[A-Za-z0-9]{15}(?:[A-Za-z0-9]{3})?$/;
const MAX_RESPONSE = 64 * 1024;
const MAX_UPSTREAM = 2 * 1024 * 1024;
const fail = (): never => { throw new Error('Request denied or unavailable.'); };
const object = (value: unknown): JsonObject => {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return fail();
  return value as JsonObject;
};
const string = (value: unknown): string => typeof value === 'string' ? value : fail();
const keys = (value: JsonObject, allowed: string[]) => {
  if (Object.keys(value).some(k => !allowed.includes(k))) fail();
};

/** Parse operator configuration once; no default org or implicit grants. */
export function loadPolicy(env: Record<string, string | undefined>): Policy {
  if (env.SITETRACKER_MODE !== 'sandbox-read-only') return fail();
  if (env.SALESFORCE_CONNECTION_TYPE !== 'OAuth_2.0_Client_Credentials') return fail();
  const origin = string(env.SALESFORCE_INSTANCE_URL);
  const url = new URL(origin);
  if (url.origin !== origin || url.protocol !== 'https:' || url.port || url.username || url.password ||
      !url.hostname.endsWith('.sandbox.my.salesforce.com')) return fail();
  const orgId = string(env.SITETRACKER_ORG_ID);
  const userId = string(env.SITETRACKER_USER_ID);
  if (!id.test(orgId) || !orgId.startsWith('00D') || !id.test(userId) || !userId.startsWith('005')) return fail();
  const apiVersion = string(env.SALESFORCE_API_VERSION);
  if (!/^\d{2}\.0$/.test(apiVersion)) return fail();
  const raw = object(JSON.parse(string(env.SITETRACKER_ALLOWED_FIELDS)));
  const objects = new Map<string, ReadonlySet<string>>();
  if (!Object.keys(raw).length || Object.keys(raw).length > 50) return fail();
  for (const [name, fields] of Object.entries(raw)) {
    if (!identifier.test(name) || !Array.isArray(fields) || !fields.length || fields.length > 100 ||
        !fields.every(f => typeof f === 'string' && identifier.test(f))) return fail();
    objects.set(name, new Set(fields as string[]));
  }
  return { origin, orgId, userId, apiVersion, objects };
}

/** Only these three tools are wired to the custom entry point. */
const schema = (properties: JsonObject, required: string[]) => ({ type: 'object' as const, properties, required, additionalProperties: false });
const text = { type: 'string' };
export const tools = [
  { name: 'salesforce_search_objects', description: 'Find approved Salesforce object API names.', inputSchema: schema({ searchPattern: text }, ['searchPattern']), annotations: { readOnlyHint: true } },
  { name: 'salesforce_describe_object', description: 'Describe explicitly approved fields on an approved object.', inputSchema: schema({ objectName: text }, ['objectName']), annotations: { readOnlyHint: true } },
  { name: 'salesforce_query_records', description: 'Read a bounded sample of approved direct fields. Filters, ordering, relationships and arbitrary query text are not supported in this release.', inputSchema: schema({ objectName: text, fields: { type: 'array', items: text, minItems: 1, maxItems: 25 }, limit: { type: 'integer', minimum: 1, maximum: 100 } }, ['objectName', 'fields']), annotations: { readOnlyHint: true } },
];

type Request = { kind: 'search'; pattern: string } | { kind: 'describe'; name: string } | { kind: 'query'; name: string; fields: string[]; limit: number };
export function validateRequest(policy: Policy, name: string, input: unknown): Request {
  if (!tools.some(t => t.name === name)) return fail();
  const args = object(input);
  if (name === 'salesforce_search_objects') {
    keys(args, ['searchPattern']);
    const pattern = string(args.searchPattern).trim();
    if (!pattern || pattern.length > 80) return fail();
    return { kind: 'search', pattern: pattern.toLowerCase() };
  }
  const nameOfObject = string(args.objectName);
  const allowed = policy.objects.get(nameOfObject);
  if (!allowed) return fail();
  if (name === 'salesforce_describe_object') {
    keys(args, ['objectName']);
    return { kind: 'describe', name: nameOfObject };
  }
  keys(args, ['objectName', 'fields', 'limit']);
  const fields = args.fields;
  if (!Array.isArray(fields) || fields.length < 1 || fields.length > 25 ||
      !fields.every(f => typeof f === 'string' && allowed.has(f))) return fail();
  if (new Set(fields).size !== fields.length) return fail();
  const limit = args.limit === undefined ? 25 : args.limit;
  if (typeof limit !== 'number' || !Number.isInteger(limit) || limit < 1 || limit > 100) return fail();
  return { kind: 'query', name: nameOfObject, fields: fields as string[], limit };
}

/** Bounded response parsing; redirects disabled to keep credentials on the approved origin. */
async function json(fetcher: typeof fetch, url: URL, init: RequestInit): Promise<JsonObject> {
  const response = await fetcher(url, { ...init, redirect: 'error' });
  if (!response.ok || !response.body) return fail();
  const reader = response.body.getReader();
  const decoder = new TextDecoder('utf-8', { fatal: true });
  let size = 0;
  let result = '';
  try {
    while (true) {
      const { value, done } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > MAX_UPSTREAM) { await reader.cancel(); return fail(); }
      result += decoder.decode(value, { stream: true });
    }
    return object(JSON.parse(result + decoder.decode()));
  } finally { reader.releaseLock(); }
}

/** A narrow REST adapter: token POST, then only fixed/validated GET requests. */
export async function read(policy: Policy, request: Request, credentials: { clientId: string; clientSecret: string }, fetcher: typeof fetch = fetch): Promise<unknown> {
  if (!credentials.clientId || !credentials.clientSecret) return fail();
  const signal = AbortSignal.timeout(30_000);
  const token = await json(fetcher, new URL('/services/oauth2/token', policy.origin), {
    method: 'POST', signal, body: new URLSearchParams({ grant_type: 'client_credentials', client_id: credentials.clientId, client_secret: credentials.clientSecret }),
  });
  if (token.instance_url !== policy.origin || typeof token.access_token !== 'string' || !token.access_token) return fail();
  const headers = { Authorization: `Bearer ${token.access_token}` };
  const get = (path: string) => json(fetcher, new URL(path, policy.origin), { method: 'GET', headers, signal });
  // Userinfo may require an additional approved identity scope. If unavailable, fail closed.
  const identity = await get('/services/oauth2/userinfo');
  const sameId = (actual: unknown, expected: string) => typeof actual === 'string' && id.test(actual) && actual.slice(0, 15) === expected.slice(0, 15);
  if (!sameId(identity.organization_id, policy.orgId) || !sameId(identity.user_id, policy.userId)) return fail();
  const base = `/services/data/v${policy.apiVersion}`;
  const query = (soql: string) => get(`${base}/query?${new URLSearchParams({ q: soql })}`);
  const org = await query('SELECT Id, IsSandbox FROM Organization LIMIT 1');
  if (!Array.isArray(org.records) || org.records.length !== 1) return fail();
  const row = object(org.records[0]);
  if (!sameId(row.Id, policy.orgId) || row.IsSandbox !== true) return fail();
  if (request.kind === 'search') {
    return { objects: [...policy.objects.keys()].filter(n => n.toLowerCase().includes(request.pattern)), scope: 'approved API names only' };
  }
  const allowed = policy.objects.get(request.name);
  if (!allowed) return fail();
  const describe = await get(`${base}/sobjects/${request.name}/describe`);
  if (describe.name !== request.name || !Array.isArray(describe.fields)) return fail();
  const visible = describe.fields.map(object).filter(f => typeof f.name === 'string' && allowed.has(f.name));
  if (request.kind === 'describe') {
    return { objectName: request.name, fields: visible.map(f => ({ name: f.name, label: f.label, type: f.type, nillable: f.nillable })), scope: 'approved visible fields only' };
  }
  if (describe.queryable !== true || !request.fields.every(f => visible.some(v => v.name === f))) return fail();
  const result = await query(`SELECT ${request.fields.join(', ')} FROM ${request.name} LIMIT ${request.limit}`);
  if (!Array.isArray(result.records) || result.records.length > request.limit || typeof result.done !== 'boolean') return fail();
  const records = result.records.map(r => {
    const original = object(r);
    return Object.fromEntries(request.fields.map(f => {
      const value = original[f];
      if (value !== null && typeof value !== 'string' && typeof value !== 'number' && typeof value !== 'boolean') return fail();
      return [f, value];
    }));
  });
  return { records, returnedCount: records.length, limit: request.limit, complete: result.done && records.length < request.limit, sample: true };
}

/** Do not emit raw upstream errors or partial payloads. */
export function resultText(value: unknown): string {
  const encoded = JSON.stringify(value);
  if (typeof encoded !== 'string' || Buffer.byteLength(encoded, 'utf8') > MAX_RESPONSE) return fail();
  return encoded;
}
