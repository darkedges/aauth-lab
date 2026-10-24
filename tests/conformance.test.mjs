// Person server and resource checks from draft-hardt-oauth-aauth-protocol-11,
// exercised directly against the lab's parties.
import test from 'node:test';
import assert from 'node:assert/strict';
import { SignJWT, decodeJwt } from 'jose';
import { createResourceToken } from '@aauth/resource';
import { createLab, runDemo } from '../lib/relay.js';

async function withMission(work) {
  const lab = await createLab();
  try {
    const { assistant, planner, ps } = lab.parties;
    ps.bind(assistant.sub, 'alice');
    const scopes = Object.fromEntries(['planner', 'research', 'search', 'compute', 'clearinghouse'].map(name => [lab.parties[name].id, [name === 'clearinghouse' ? 'billing' : name === 'planner' ? 'plan' : name]]));
    const proposal = await lab.proposeMission(assistant, { description: 'test', tools: [], resources: [planner.id], relay: { payer: 'alice-org', budget: 100, scopes } });
    assert.equal(proposal.status, 200);
    await work({ lab, ...lab.parties, mission: proposal.data.s256, plannerPersonToken: proposal.data.person_tokens[planner.id] });
  } finally { lab.close(); }
}
const mint = (resource, options) => createResourceToken({ resource: resource.id, kid: resource.kid, scope: 'plan email', ...options },
  (payload, header) => new SignJWT(payload).setProtectedHeader(header).sign(resource.issuerKey));
const thumbprintOf = async agent => (await import('jose')).calculateJwkThumbprint(agent.signingPublic);
const errorOf = response => [response.status, response.data.error];

test('§8.2 mission approval returns the blob bytes, s256 and person tokens for named resources', async () => {
  await withMission(async ({ planner, mission, plannerPersonToken }) => {
    const claims = decodeJwt(plannerPersonToken);
    assert.equal(claims.aud, planner.id);
    assert.equal(claims.mission_s256, mission);
    assert.equal(claims.scope, undefined, 'a person token carries no scope (§7.1.2)');
  });
});

test('§7.1 a mission_s256 must belong to the requesting agent', async () => {
  await withMission(async ({ ps, research, search, mission }) => {
    ps.bind(research.sub, 'alice');
    const response = await research.send('ps', '/person-token', { ps: true, token: research.agentToken, step: 'person_token_request', body: { resource: search.id, mission_s256: mission } });
    assert.deepEqual(errorOf(response), [400, 'invalid_request']);
    assert.match(response.data.detail, /does not belong to this agent/);
  });
});

test('§8.2 an expired mission is treated as terminated on every decision path', async () => {
  await withMission(async ({ ps, assistant, planner, mission }) => {
    ps.missions.get(mission).blob.expires_at = new Date(Date.now() - 1000).toISOString();
    const response = await assistant.send('ps', '/person-token', { ps: true, token: assistant.agentToken, step: 'person_token_request', body: { resource: planner.id, mission_s256: mission } });
    assert.deepEqual(errorOf(response), [403, 'mission_terminated']);
  });
});

test('§6.7.2 a resource token that drops mission_s256 is rejected (mission stripping)', async () => {
  await withMission(async ({ assistant, planner, plannerPersonToken }) => {
    const presented = decodeJwt(plannerPersonToken);
    const stripped = await mint(planner, { audience: presented.iss, agentJkt: await thumbprintOf(assistant),
      presentedToken: { iss: presented.iss, sub: presented.sub, jti: presented.jti } });
    const response = await assistant.send('ps', '/auth-token', { ps: true, token: assistant.agentToken, step: 'auth_token_request',
      body: { resource_token: stripped, presented_token: plannerPersonToken } });
    assert.deepEqual(errorOf(response), [400, 'invalid_resource_token']);
    assert.match(response.data.detail, /mission_s256/);
  });
});

test('§6.7.2 the presented token must be addressed to the resource that issued the resource token', async () => {
  await withMission(async ({ assistant, research, plannerPersonToken }) => {
    const presented = decodeJwt(plannerPersonToken);
    const wrongResource = await mint(research, { audience: presented.iss, agentJkt: await thumbprintOf(assistant), presentedToken: { ...presented } });
    const response = await assistant.send('ps', '/auth-token', { ps: true, token: assistant.agentToken, step: 'auth_token_request',
      body: { resource_token: wrongResource, presented_token: plannerPersonToken } });
    assert.deepEqual(errorOf(response), [400, 'invalid_presented_token']);
  });
});

test('§9.4.5 an upstream token must be addressed to the signing intermediary and traceable to an agent', async () => {
  await withMission(async ({ ps, research, search, plannerPersonToken }) => {
    // aud is PlannerCo, but ResearchCo is signing.
    const misaddressed = await research.send('ps', '/person-token', { ps: true, token: research.agentToken, step: 'person_token_request',
      body: { resource: search.id, upstream_token: plannerPersonToken } });
    assert.deepEqual(errorOf(misaddressed), [400, 'invalid_upstream_token']);
    // Signed by the PS key, addressed correctly, but never issued to any agent.
    const claims = decodeJwt(plannerPersonToken);
    const unrecorded = await ps.sign({ ...claims, aud: research.id, jti: 'pt-unrecorded' }, 'aa-person+jwt');
    const unknown = await research.send('ps', '/person-token', { ps: true, token: research.agentToken, step: 'person_token_request',
      body: { resource: search.id, upstream_token: unrecorded } });
    assert.deepEqual(errorOf(unknown), [400, 'invalid_upstream_token']);
    assert.match(unknown.data.detail, /cannot identify the calling agent/);
  });
});

test('§11.9.2 errors are problem details; policy refusals use denied', async () => {
  const run = await runDemo({ scenario: 'forbidden' });
  const refusal = run.debug.find(entry => entry.stage === 'auth_token_request' && entry.status === 403);
  assert.equal(refusal.response_headers['content-type'], 'application/problem+json');
  assert.equal(JSON.parse(refusal.response_text).error, 'denied');
  const challenge = run.debug.find(entry => entry.outcome === 'challenge');
  assert.equal(challenge.response_headers['content-type'], 'application/problem+json');
});

test('§8.2 approved_tools records the agent’s tools; the PS enforces its own lab extension', async () => {
  const run = await runDemo({ scenario: 'happy' });
  assert.deepEqual(run.mission.blob.approved_tools, [{ name: 'Delegate', description: 'Hand research tasks to Relay operators' }]);
  assert.deepEqual(run.mission.blob.approved_resources, [run.parties.planner.id]);
  assert.deepEqual(run.mission.blob.relay.scopes[run.parties.search.id], ['search']);
});

test('§C.1.6 caller trust holds only on agent-token requests; an agent that skips that request is not identified', async () => {
  // ResearchCo goes straight to a person token at SearchCo, which does not trust it.
  const call = async (agent, to, path, body, { upstream, mission }) => {
    const target = agent.demo.parties[to];
    let personToken = upstream ? undefined : agent.personTokens.get(target.id);
    if (to !== 'search') {
      const identity = await agent.send(to, path, { body, token: agent.agentToken, step: 'agent_token_call' });
      if (identity.status !== 401) return { ...identity, record: {}, boundary: to };
    }
    if (!personToken) {
      const person = await agent.send('ps', '/person-token', { ps: true, token: agent.agentToken, step: 'person_token_request',
        body: { resource: target.id, ...(upstream ? { upstream_token: upstream } : { mission_s256: mission }) } });
      if (person.status !== 200) return { ...person, record: {}, boundary: 'ps' };
      personToken = person.data.person_token;
    }
    const challenge = await agent.send(to, path, { body, token: personToken, step: 'person_token_call' });
    const resourceToken = challenge.requirement?.resourceToken;
    const exchange = await agent.send('ps', '/auth-token', { ps: true, token: agent.agentToken, step: 'auth_token_request',
      body: { resource_token: resourceToken, presented_token: personToken, ...(upstream ? { upstream_token: upstream } : {}) } });
    if (exchange.status !== 200) return { ...exchange, record: {}, boundary: 'ps' };
    const final = await agent.send(to, path, { body, token: exchange.data.auth_token, step: 'auth_token_call' });
    return { ...final, record: { person_token: personToken, resource_token: resourceToken, auth_token: exchange.data.auth_token }, boundary: to };
  };
  const run = await runDemo({ edges: [['planner', 'research'], ['planner', 'compute']] }, { call });
  assert.equal(run.tasks.find(task => task.provider === 'search').status, 'settled');
  assert.ok(!run.debug.some(entry => entry.from === 'research' && entry.to === 'search' && entry.stage === 'agent_token_call'));
});

test('§11.6.3 / §11.8 mission consent is deferred: 202 + interaction, signed GET polls, then the approval', async () => {
  const run = await runDemo({ scenario: 'happy' });
  const [proposal, ...polls] = run.debug.filter(entry => ['mission_proposal', 'consent_poll'].includes(entry.stage));
  assert.equal(proposal.status, 202);
  assert.match(proposal.response_headers['aauth-requirement'], /^requirement=interaction; url="https:\/\/[^"?#]+"; code="[0-9A-HJKMNP-TV-Z]{4}-[0-9A-HJKMNP-TV-Z]{4}"$/);
  assert.equal(new URL(proposal.response_headers.location).origin, run.parties.ps.id, 'Location is on the PS origin');
  assert.equal(proposal.response_headers['retry-after'], '0');
  assert.equal(proposal.response_headers['cache-control'], 'no-store');
  assert.deepEqual(polls.map(entry => [entry.request.method, entry.status, JSON.parse(entry.response_text).status ?? 'approved']), [['GET', 202, 'interacting'], ['GET', 200, 'approved']]);
  assert.ok(polls.every(entry => /^sig=jwt;jwt="/.test(entry.request.headers['signature-key'])), 'every poll is signed');
  assert.deepEqual(run.debug.filter(entry => entry.transport === 'person').map(entry => entry.summary), ['Alice opens the interaction URL and signs in at the PS', 'Alice approves the mission at the PS']);
});

test('§13.2 a pending URL answers only the agent that asked, and 410 once it is done', async () => {
  const lab = await createLab();
  try {
    const { assistant, research, planner, ps } = lab.parties;
    ps.bind(assistant.sub, 'alice');
    const proposal = await assistant.send('ps', '/missions', { ps: true, token: assistant.agentToken, step: 'mission_proposal',
      body: { description: 'test', tools: [], resources: [planner.id], relay: { payer: 'alice-org', budget: 100, scopes: {} } } });
    assert.equal(proposal.status, 202);
    const path = new URL(proposal.location).pathname;
    const other = await research.send('ps', path, { method: 'GET', token: research.agentToken, ps: true, step: 'consent_poll' });
    assert.deepEqual(errorOf(other), [403, 'invalid_request']);
    ps.interact(proposal.requirement.code, 'alice'); ps.decide(proposal.requirement.code, 'alice', true);
    const done = await assistant.send('ps', path, { method: 'GET', token: assistant.agentToken, ps: true, step: 'consent_poll' });
    assert.equal(done.status, 200);
    const again = await assistant.send('ps', path, { method: 'GET', token: assistant.agentToken, ps: true, step: 'consent_poll' });
    assert.equal(again.status, 410);
  } finally { lab.close(); }
});

test('§11.8.4 a declined mission ends polling with 403 denied and nothing runs', async () => {
  const run = await runDemo({ consent: 'decline' });
  const last = run.debug.filter(entry => entry.stage === 'consent_poll').at(-1);
  assert.deepEqual([last.status, JSON.parse(last.response_text).error], [403, 'denied']);
  assert.equal(run.tasks.length, 0);
  assert.equal(run.ledger.settled, 0);
  assert.equal(run.mission, null);
});
