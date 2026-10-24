import test from 'node:test';
import assert from 'node:assert/strict';
import { runDemo } from '../lib/relay.js';

const failed = task => task.decision.rows.filter(row => !row.present).map(row => row.logic);

test('valid delegation settles across three independent operators', async () => {
  const run = await runDemo({ scenario: 'happy' });
  assert.equal(run.root_decision.permitted, true);
  assert.deepEqual(run.tasks.map(task => task.status), ['settled', 'settled', 'settled']);
  assert.equal(run.ledger.settled, 40);
  assert.deepEqual(run.grant.rights, ['billing', 'compute', 'plan', 'research', 'search']);
  const search = run.tasks.find(task => task.provider === 'search');
  assert.equal(search.decision.identity_rows.find(row => row.logic === 'trusts_caller(ResearchCo, SearchCo)').present, true);
  assert.ok(!search.decision.rows.some(row => row.logic.startsWith('trusts_caller')), 'no agent identity reaches the auth-token stage (§C.1.6)');
  assert.equal(search.tokens.auth_token.header.typ, 'aa-auth+jwt');
  assert.equal(search.tokens.auth_token.payload.account, 'alice-org');
  assert.equal(search.tokens.auth_token.payload.mission_s256, run.mission.s256);
});

test('every hop is a real signed HTTP exchange chained through the person server', async () => {
  const run = await runDemo({ scenario: 'happy' });
  const signed = run.debug.filter(entry => entry.transport === 'virtual-http' && entry.stage !== 'discovery');
  assert.ok(signed.every(entry => entry.request.headers['signature-input']?.includes('"signature-key"')));
  assert.ok(signed.every(entry => /^sig=jwt;jwt="/.test(entry.request.headers['signature-key'])));
  const chained = signed.filter(entry => entry.stage === 'person_token_request' && JSON.parse(entry.request.body).upstream_token);
  assert.ok(chained.length >= 5, 'intermediaries pass upstream_token');
  assert.ok(signed.filter(entry => entry.to === 'ps' && entry.request.method === 'POST').every(entry => entry.request.headers['signature-input'].includes('"content-digest"')));
  assert.ok(run.debug.every(entry => entry.summary && Number.isFinite(entry.duration_ms)));
  assert.equal(run.stats.signed_requests, signed.length);
  assert.ok(!JSON.stringify(run).includes('"d":'), 'private keys must never be exported');
});

test('payer change and forbidden action are refused by the person server before billing', async () => {
  for (const scenario of ['payer_swap', 'forbidden']) {
    const run = await runDemo({ scenario });
    const denied = run.tasks.find(task => task.status === 'denied');
    assert.equal(denied.provider, 'search');
    assert.equal(denied.decision.phase, 'ps');
    assert.ok(denied.decision.ps_checks.some(check => !check.present));
    assert.equal(run.ledger.settled, 30);
    assert.equal(run.mission.log.filter(entry => entry.decision === 'denied').length, 1);
  }
});

test('auth token from an untrusted signer is rejected before policy evaluation', async () => {
  const run = await runDemo({ scenario: 'untrusted' });
  const denied = run.tasks.find(task => task.status === 'denied');
  assert.equal(denied.decision.phase, 'verification');
  assert.match(denied.error, /signature verification failed/);
  assert.equal(run.ledger.settled, 30);
});

test('custom caller trust and original requester acceptance affect the receiver', async () => {
  const noEdge = await runDemo({ edges: [['planner', 'research'], ['planner', 'compute']] });
  const search = noEdge.tasks.find(task => task.provider === 'search');
  assert.equal(search.status, 'denied');
  assert.equal(search.decision.phase, 'identity');
  assert.deepEqual(failed(search), ['trusts_caller(ResearchCo, SearchCo)']);
  assert.ok(!noEdge.debug.some(entry => entry.task_index === search.index && entry.to === 'ps'), 'no PS call when caller trust fails');
  const rejected = await runDemo({ accepts: { planner: ['alice', 'bob'], research: ['alice', 'bob'], search: ['bob'], compute: ['alice', 'bob'] } });
  assert.deepEqual(failed(rejected.tasks.find(task => task.provider === 'search')), ['accepts_requester("alice@alice-org.example")']);
  const rejectedRoot = await runDemo({ requester: 'bob', accepts: { planner: ['alice'], research: ['alice', 'bob'], search: ['alice', 'bob'], compute: ['alice', 'bob'] } });
  assert.equal(rejectedRoot.root_decision.permitted, false);
  assert.equal(rejectedRoot.tasks.length, 0);
});

test('concurrent reservations cannot spend more than the budget', async () => {
  const run = await runDemo({ scenario: 'overspend', budget: 100 });
  assert.equal(run.ledger.settled, 65);
  const denied = run.tasks.filter(task => task.status === 'denied');
  assert.equal(denied.length, 1);
  assert.equal(denied[0].decision.billing.passed, false);
  assert.ok(run.debug.some(entry => entry.status === 402));
  assert.equal((await runDemo({ scenario: 'overspend', budget: 125 })).ledger.settled, 125);
});

test('retry reuses settlement and failed work releases its reservation', async () => {
  const retry = await runDemo({ scenario: 'retry' });
  assert.equal(retry.tasks.filter(task => task.status === 'reused').length, 1);
  assert.equal(retry.ledger.operations.length, 3);
  assert.equal(retry.ledger.settled, 40);
  const reused = retry.tasks.find(task => task.status === 'reused');
  assert.ok(retry.debug.some(entry => entry.task_index === reused.index && entry.to === 'search' && entry.stage === 'auth_token_call'
    && entry.presented_token.header.typ === 'aa-auth+jwt'), 'the retry presents the cached auth token');
  const failure = await runDemo({ scenario: 'failure' });
  assert.equal(failure.tasks.find(task => task.provider === 'search').status, 'released');
  assert.equal(failure.ledger.settled, 30);
  assert.equal(failure.ledger.available, 70);
});

test('invalid settings are rejected', async () => {
  await assert.rejects(runDemo({ budget: -1 }), /Budget must/);
  await assert.rejects(runDemo({ edges: [['planner', 'unknown']] }), /Trust edges/);
});

test('replay snapshots preserve reservation and release balances', async () => {
  const run = await runDemo({ scenario: 'failure' });
  const reserved = run.events.find(event => event.kind === 'reserved' && event.operator === 'search');
  const released = run.events.find(event => event.kind === 'released');
  assert.equal(reserved.snapshot.ledger.reserved, 10);
  assert.equal(released.snapshot.ledger.reserved, 0);
  for (const event of run.events) {
    const ledger = event.snapshot.ledger;
    assert.equal(ledger.available + ledger.settled + ledger.reserved, ledger.budget);
  }
  assert.equal(run.events.at(-1).snapshot.ledger.settled, run.ledger.settled);
});

test('concurrent runs stay isolated on their own virtual hosts', async () => {
  const runs = await Promise.all(['happy', 'payer_swap', 'retry'].map(scenario => runDemo({ scenario })));
  assert.deepEqual(runs.map(run => run.ledger.settled), [40, 30, 40]);
  assert.equal(new Set(runs.map(run => run.parties.ps.id)).size, 3);
});
