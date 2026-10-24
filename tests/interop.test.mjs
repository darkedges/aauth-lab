// Interop: the lab's person server and resources driven by the reference
// agent client from @aauth/agent instead of the lab's own agent code.
import test from 'node:test';
import assert from 'node:assert/strict';
import { createAAuthFetch, createSignedFetch, requestPersonToken, exchangeToken } from '@aauth/agent';
import { parseRequirementHeader } from '@aauth/resource';
import { runDemo } from '../lib/relay.js';

async function read(response) {
  const text = await response.text();
  try { return JSON.parse(text); } catch { return text; }
}
function psRefusal(error, record) {
  if (!Number.isInteger(error.status)) throw error;
  return { status: error.status, data: { error: error.error, detail: error.detail }, record, boundary: 'ps' };
}

// One reference client per agent, as a real deployment would hold.
function referenceAgents() {
  const used = { root: 0, chained: 0 };
  const clients = new WeakMap();
  async function call(agent, to, path, body, { upstream, mission, loginHint, cacheKey }) {
    const target = agent.demo.parties[to];
    const url = `${target.id}${path}`;
    const init = { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) };
    const keys = jwt => async () => ({ signingKey: agent.signingPrivate, signatureKey: { type: 'jwt', jwt } });
    const record = {};
    if (!upstream) {
      // The original request: createAAuthFetch drives the whole three-party flow.
      used.root++;
      if (!clients.has(agent)) clients.set(agent, createAAuthFetch({ getKeyMaterial: keys(agent.agentToken), personServerUrl: agent.demo.ps.id,
        missionS256: mission, loginHint, onPersonToken: token => { record.person_token = token; }, onAuthToken: token => { record.auth_token = token; } }));
      try {
        const response = await clients.get(agent)(url, init);
        return { status: response.status, data: await read(response), record, boundary: to };
      } catch (error) { return psRefusal(error, record); }
    }
    // Call chaining: createAAuthFetch has no upstream option, so compose the
    // same library pieces it uses, adding upstreamToken to the person token request.
    used.chained++;
    agent.referenceTokens ??= new Map();
    const cached = agent.referenceTokens.get(cacheKey);
    if (cached) {
      const response = await createSignedFetch(keys(cached))(url, init);
      if (response.status !== 401) return { status: response.status, data: await read(response), record: { auth_token: cached }, boundary: to };
    }
    const psFetch = createSignedFetch(keys(agent.agentToken), { signBody: true });
    const identity = await createSignedFetch(keys(agent.agentToken))(url, init);
    const first = identity.headers.get('aauth-requirement');
    if (!first || parseRequirementHeader(first).requirement !== 'person-token') return { status: identity.status, data: await read(identity), record, boundary: to };
    try {
      ({ personToken: record.person_token } = await requestPersonToken({ signedFetch: psFetch, personServerUrl: agent.demo.ps.id, resource: target.id, upstreamToken: upstream }));
    } catch (error) { return psRefusal(error, record); }
    const challenge = await createSignedFetch(keys(record.person_token))(url, init);
    const second = challenge.headers.get('aauth-requirement');
    if (!second || parseRequirementHeader(second).requirement !== 'auth-token') return { status: challenge.status, data: await read(challenge), record, boundary: to };
    record.resource_token = parseRequirementHeader(second).resourceToken;
    try {
      ({ authToken: record.auth_token } = await exchangeToken({ signedFetch: psFetch, authServerUrl: agent.demo.ps.id, resourceToken: record.resource_token, presentedToken: record.person_token }));
    } catch (error) { return psRefusal(error, record); }
    const response = await createSignedFetch(keys(record.auth_token))(url, init);
    if (response.status < 400) agent.referenceTokens.set(cacheKey, record.auth_token);
    return { status: response.status, data: await read(response), record, boundary: to };
  }
  return { used, call };
}

const expected = { happy: 40, payer_swap: 30, forbidden: 30, untrusted: 30, overspend: 65, retry: 40, failure: 30 };

for (const [scenario, settled] of Object.entries(expected)) {
  test(`reference @aauth/agent client: ${scenario} settles ${settled}`, async () => {
    const reference = referenceAgents();
    const run = await runDemo({ scenario }, { call: reference.call });
    assert.equal(run.root_decision.permitted, true);
    assert.equal(run.ledger.settled, settled);
    assert.equal(reference.used.root, 1, 'createAAuthFetch made the original request');
    assert.ok(reference.used.chained >= 4, 'every downstream hop used the reference client');
    assert.ok(run.mission.log.some(entry => entry.type === 'person_token' && entry.chained && entry.decision === 'issued'));
  });
}

test('reference client: PS refusals reach the agent as protocol errors', async () => {
  for (const scenario of ['payer_swap', 'forbidden']) {
    const run = await runDemo({ scenario }, { call: referenceAgents().call });
    const denied = run.tasks.find(task => task.status === 'denied');
    assert.equal(denied.decision.phase, 'ps');
    assert.match(denied.error, /Mission evaluation failed/);
  }
});

test('reference client: caller trust and requester policy', async () => {
  const noEdge = await runDemo({ edges: [['planner', 'research'], ['planner', 'compute']] }, { call: referenceAgents().call });
  assert.equal(noEdge.tasks.find(task => task.provider === 'search').decision.phase, 'identity');
  const bob = await runDemo({ requester: 'bob', accepts: { planner: ['alice'], research: ['bob'], search: ['bob'], compute: ['bob'] } }, { call: referenceAgents().call });
  assert.equal(bob.root_decision.permitted, false);
  assert.equal(bob.tasks.length, 0);
});
