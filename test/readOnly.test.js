import { test } from 'node:test';
import assert from 'node:assert/strict';
import { loadPolicy, validateRequest, read, resultText, tools } from '../dist/security/readOnly.js';

const origin = 'https://example--test.sandbox.my.salesforce.com';
const orgId = '00D000000000001';
const userId = '005000000000001';
const name = 'Example__c';
const env = {
  SITETRACKER_MODE: 'sandbox-read-only',
  SALESFORCE_CONNECTION_TYPE: 'OAuth_2.0_Client_Credentials',
  SALESFORCE_INSTANCE_URL: origin,
  SITETRACKER_ORG_ID: orgId,
  SITETRACKER_USER_ID: userId,
  SALESFORCE_API_VERSION: '62.0',
  SITETRACKER_ALLOWED_FIELDS: JSON.stringify({ [name]: ['Id', 'Name'] }),
};
const policy = loadPolicy(env);
const credentials = { clientId: 'mock-client', clientSecret: 'mock-secret' };
const args = { objectName: name, fields: ['Id', 'Name'] };

function fixture({ identity = { organization_id: orgId, user_id: userId }, sandbox = true, instance = origin, records = [{ Id: 'mock', Name: 'Example', Hidden__c: 'excluded' }] } = {}) {
  const calls = [];
  const fetcher = async (url, init) => {
    calls.push({ url: url.toString(), method: init.method });
    assert.equal(url.origin, origin);
    assert.equal(init.redirect, 'error');
    let body;
    if (url.pathname === '/services/oauth2/token') body = { instance_url: instance, access_token: 'mock-token' };
    else if (url.pathname === '/services/oauth2/userinfo') body = identity;
    else if (url.searchParams.get('q') === 'SELECT Id, IsSandbox FROM Organization LIMIT 1') body = { records: [{ Id: orgId, IsSandbox: sandbox }] };
    else if (url.pathname.endsWith('/describe')) body = { name, queryable: true, fields: [{ name: 'Id', type: 'id' }, { name: 'Name', type: 'string' }, { name: 'Hidden__c', type: 'string' }] };
    else { assert.equal(url.searchParams.get('q'), 'SELECT Id, Name FROM Example__c LIMIT 25'); body = { records, done: true }; }
    return new Response(JSON.stringify(body), { status: 200 });
  };
  return { calls, fetcher };
}

test('invalid/missing policy is rejected', () => {
  assert.throws(() => loadPolicy({}));
  assert.throws(() => loadPolicy({ ...env, SITETRACKER_MODE: 'production' }));
  assert.throws(() => loadPolicy({ ...env, SITETRACKER_ALLOWED_FIELDS: '{}' }));
});
test('registry is restricted to three read-only tools', () => {
  assert.equal(tools.length, 3);
  assert.ok(tools.every(t => t.annotations.readOnlyHint));
  assert.throws(() => validateRequest(policy, 'salesforce_dml_records', {}));
});
test('unapproved fields, objects and unsupported query options are rejected', () => {
  assert.throws(() => validateRequest(policy, 'salesforce_query_records', { ...args, fields: ['Hidden__c'] }));
  assert.throws(() => validateRequest(policy, 'salesforce_query_records', { ...args, objectName: 'Other__c' }));
  assert.throws(() => validateRequest(policy, 'salesforce_query_records', { ...args, limit: 101 }));
  assert.throws(() => validateRequest(policy, 'salesforce_query_records', { ...args, orderBy: 'Name' }));
});
test('approved query is bounded, projected and read-only', async () => {
  const { calls, fetcher } = fixture();
  const value = await read(policy, validateRequest(policy, 'salesforce_query_records', args), credentials, fetcher);
  assert.deepEqual(value.records, [{ Id: 'mock', Name: 'Example' }]);
  assert.equal(value.limit, 25);
  assert.deepEqual(calls.map(c => c.method), ['POST', 'GET', 'GET', 'GET', 'GET']);
});
test('identity mismatch stops before business query', async () => {
  const { calls, fetcher } = fixture({ identity: { organization_id: '00D000000000002', user_id: userId } });
  await assert.rejects(read(policy, validateRequest(policy, 'salesforce_query_records', args), credentials, fetcher));
  assert.equal(calls.length, 2);
});
test('non-sandbox classification stops before business query', async () => {
  const { calls, fetcher } = fixture({ sandbox: false });
  await assert.rejects(read(policy, validateRequest(policy, 'salesforce_query_records', args), credentials, fetcher));
  assert.equal(calls.length, 3);
});
test('unexpected token endpoint origin stops before identity request', async () => {
  const { calls, fetcher } = fixture({ instance: 'https://other.example.com' });
  await assert.rejects(read(policy, validateRequest(policy, 'salesforce_query_records', args), credentials, fetcher));
  assert.equal(calls.length, 1);
});
test('describe only returns approved fields', async () => {
  const { fetcher } = fixture();
  const value = await read(policy, validateRequest(policy, 'salesforce_describe_object', { objectName: name }), credentials, fetcher);
  assert.deepEqual(value.fields.map(f => f.name), ['Id', 'Name']);
});
test('oversized result is rejected instead of leaking partial content', () => {
  assert.throws(() => resultText({ value: 'x'.repeat(65536) }));
});
