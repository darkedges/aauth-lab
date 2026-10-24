import { SignJWT, jwtVerify, exportJWK, generateKeyPair, calculateJwkThumbprint, createLocalJWKSet, decodeJwt, decodeProtectedHeader, base64url } from 'jose';
import { createSignedFetch } from '@aauth/agent';
import { verify as verifySignature } from '@hellocoop/httpsig';
import { verifyToken, createResourceToken, buildAAuthHeader, parseRequirementHeader, discoverJwks, clearMetadataCache, isServerIdentifier, TOKEN_TYP, DWK, SIGNING_ALG } from '@aauth/resource';

const OPERATORS = { planner: 'PlannerCo', research: 'ResearchCo', search: 'SearchCo', compute: 'ComputeCo' };
const PARTIES = { ...OPERATORS, assistant: 'Assistant', ps: 'Person server', clearinghouse: 'Clearinghouse' };
const DEFAULT_EDGES = [['planner', 'research'], ['research', 'search'], ['planner', 'compute']];
const SCENARIOS = new Set(['happy', 'payer_swap', 'forbidden', 'untrusted', 'overspend', 'retry', 'failure']);
// SearchCo really exposes delete. Only the PS's policy over Alice's mission keeps an agent from using it.
const OFFERS = { planner: ['plan'], research: ['research'], search: ['search', 'delete'], compute: ['compute'] };
const PEOPLE = {
  alice: { name: 'Alice', email: 'alice@alice-org.example', payer: 'alice-org' },
  bob: { name: 'Bob', email: 'bob@bob-org.example', payer: 'bob-org' },
};
// Lab extension member of the mission blob (§8.2 allows additional members): the scopes the PS will
// issue per resource, the payer and the budget. approved_tools only records the agent's own tools.
const SCOPES = { planner: ['plan'], research: ['research'], search: ['search'], compute: ['compute'], clearinghouse: ['billing'] };
const AGENT_TOOLS = [{ name: 'Delegate', description: 'Hand research tasks to Relay operators' }];
const IDENTITY_SCOPES = new Set(['openid', 'email', 'profile']);
const encoder = new TextEncoder();

class ValidationError extends Error { constructor(message) { super(message); this.name = 'ValidationError'; } }
function stable(value) {
  if (Array.isArray(value)) return `[${value.map(stable).join(',')}]`;
  if (value && typeof value === 'object') return `{${Object.keys(value).sort().map(key => `${JSON.stringify(key)}:${stable(value[key])}`).join(',')}}`;
  return JSON.stringify(value);
}
async function sha256(text) { return new Uint8Array(await crypto.subtle.digest('SHA-256', encoder.encode(text))); }
async function digest(value) { return base64url.encode(await sha256(typeof value === 'string' ? value : stable(value))); }
function id(prefix) { return `${prefix}-${crypto.randomUUID().replaceAll('-', '').slice(0, 8)}`; }
function now() { return Math.floor(Date.now() / 1000); }
function claims(jwt) { try { return { header: decodeProtectedHeader(jwt), payload: decodeJwt(jwt) }; } catch { return null; } }
function json(body, status = 200, headers = {}) { return Response.json(body, { status, headers: { 'cache-control': 'no-store', ...headers } }); }
// §11.9.2: errors are RFC 9457 problem details with an AAuth `error` member.
function problem(error, detail, status, headers = {}, extra = {}) {
  return new Response(JSON.stringify({ error, ...(detail ? { detail } : {}), ...extra }), { status,
    headers: { 'content-type': 'application/problem+json', 'cache-control': 'no-store', ...headers } });
}
function row(logic, present, source, available = []) { return { logic, present, source, available }; }

// ── Virtual network ─────────────────────────────────────────────────────────
// Every party is a real HTTP handler on its own origin. @hellocoop/httpsig and
// @aauth/resource call globalThis.fetch, so requests to *.relay.example hosts
// are routed to the run that registered them. Each run uses a fresh host tag,
// which keeps concurrent runs and the libraries' JWKS caches apart.
const routes = new Map();
const upstreamFetch = globalThis.fetch.bind(globalThis);
globalThis.fetch = async (input, init) => {
  const request = new Request(input, init);
  const route = routes.get(new URL(request.url).host);
  return route ? route(request) : upstreamFetch(input, init);
};

class Party {
  constructor(demo, name) {
    Object.assign(this, { demo, name, label: PARTIES[name] });
    this.host = `${name}.${demo.tag}.relay.example`;
    this.id = `https://${this.host}`;
    this.kid = `${name}-1`;
  }
  async init() {
    const issuer = await generateKeyPair(SIGNING_ALG, { extractable: true });
    this.issuerKey = issuer.privateKey;
    this.jwks = { keys: [{ ...(await exportJWK(issuer.publicKey)), kid: this.kid, alg: SIGNING_ALG, use: 'sig' }] };
    routes.set(this.host, request => this.dispatch(request));
    return this;
  }
  sign(payload, typ) { return new SignJWT(payload).setProtectedHeader({ alg: SIGNING_ALG, typ, kid: this.kid }).sign(this.issuerKey); }
  metadata() { return {}; }
  async dispatch(request) {
    const path = new URL(request.url).pathname;
    if (request.method === 'GET' && path === '/jwks.json') return this.demo.discovery(this, request, json(this.jwks));
    if (request.method === 'GET' && path.startsWith('/.well-known/')) {
      const document = this.metadata()[path.slice('/.well-known/'.length)];
      return this.demo.discovery(this, request, document ? json(document) : problem('not_found', 'Unknown metadata document', 404));
    }
    return this.handle(request);
  }
  async handle() { return problem('not_found', 'Unknown endpoint', 404); }
}

// An agent is its own agent provider: it publishes aauth-agent.json and signs
// requests with an ephemeral key bound into a self-issued agent token.
class Agent extends Party {
  async init() {
    await super.init();
    const signing = await generateKeyPair(SIGNING_ALG, { extractable: true });
    this.signingPrivate = { ...(await exportJWK(signing.privateKey)), alg: SIGNING_ALG };
    this.signingPublic = { ...(await exportJWK(signing.publicKey)), alg: SIGNING_ALG };
    this.sub = `aauth:${this.name}@${this.host}`;
    this.agentToken = await this.sign({ iss: this.id, dwk: DWK.agent, sub: this.sub, ps: this.demo.ps.id,
      cnf: { jwk: this.signingPublic }, jti: id('agt'), iat: now(), exp: now() + 3600 }, TOKEN_TYP.agent);
    this.authTokens = new Map(); this.personTokens = new Map();
    return this;
  }
  metadata() { return { 'aauth-agent.json': { issuer: this.id, jwks_uri: `${this.id}/jwks.json`, name: this.label } }; }

  async send(to, path, { body, token, ps = false, step, taskIndex = null, method = 'POST' }) {
    const target = this.demo.parties[to];
    let sent;
    const signedFetch = createSignedFetch(async () => ({ signingKey: this.signingPrivate, signatureKey: { type: 'jwt', jwt: token } }),
      { signBody: ps && method !== 'GET', onSigned: value => { sent = value; } });
    const started = performance.now(), startedAt = new Date().toISOString(), seq = this.demo.seq++;
    const response = await signedFetch(`${target.id}${path}`, method === 'GET' ? { method }
      : { method, headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) });
    const text = await response.text();
    let data; try { data = JSON.parse(text); } catch { data = text; }
    const header = response.headers.get('aauth-requirement');
    const requirement = header ? parseRequirementHeader(header) : null;
    this.demo.trace({ seq, step, from: this.name, to, task_index: taskIndex, started_at: startedAt, started,
      request: { method, url: `${target.id}${path}`, headers: sent?.headers ?? {}, body: sent?.body ?? null },
      status: response.status, response_headers: Object.fromEntries(response.headers), response_text: text,
      presented: claims(token), requirement });
    return { status: response.status, data, requirement, location: response.headers.get('location') };
  }
  // §11.8 Deferred responses: poll the pending URL with signed GETs until a non-202 answer.
  async deferred(response, { to, step, taskIndex = null, onPending }) {
    for (let polls = 0; response.status === 202 && response.location && polls < 10; polls++) {
      await onPending?.(response);
      response = await this.send(to, new URL(response.location).pathname, { method: 'GET', token: this.agentToken, ps: to === 'ps', step, taskIndex });
    }
    return response;
  }

  // The three-party flow (identity → person token → resource token → auth
  // token → retry), with call chaining when this agent holds an upstream token.
  async authorizedCall(to, path, body, { upstream, mission, loginHint, taskIndex = null, cacheKey = `${to}${path}`, forge } = {}) {
    // Interop tests replace this agent-side flow with the reference client.
    if (this.demo.hooks.call && !forge) return this.demo.hooks.call(this, to, path, body, { upstream, mission, loginHint, cacheKey });
    const record = {};
    const cached = this.authTokens.get(cacheKey);
    if (cached) {
      const reuse = await this.send(to, path, { body, token: cached, step: 'auth_token_call', taskIndex });
      if (reuse.status !== 401) return { ...reuse, record: { auth_token: cached, reused_token: true }, boundary: to };
      this.authTokens.delete(cacheKey);
    }
    const target = this.demo.parties[to];
    const identity = await this.send(to, path, { body, token: this.agentToken, step: 'agent_token_call', taskIndex });
    if (identity.requirement?.requirement !== 'person-token') return { ...identity, record, boundary: to };
    // A mission approval returns person tokens for the resources it named (§8.2).
    record.person_token = upstream ? undefined : this.personTokens.get(target.id);
    if (!record.person_token) {
      const personRequest = { resource: target.id, ...(upstream ? { upstream_token: upstream } : { mission_s256: mission }),
        ...(loginHint ? { login_hint: loginHint } : {}) };
      const person = await this.send('ps', '/person-token', { body: personRequest, token: this.agentToken, ps: true, step: 'person_token_request', taskIndex });
      if (person.status !== 200) return { ...person, record, boundary: 'ps' };
      record.person_token = person.data.person_token;
    }
    const challenge = await this.send(to, path, { body, token: record.person_token, step: 'person_token_call', taskIndex });
    if (challenge.requirement?.requirement !== 'auth-token') return { ...challenge, record, boundary: to };
    record.resource_token = challenge.requirement.resourceToken;
    // §6.7.3 Resource Challenge Verification, by the agent.
    const issued = decodeJwt(record.resource_token), presented = decodeJwt(record.person_token);
    const problems = [['iss', issued.iss === target.id], ['agent_jkt', issued.agent_jkt === await calculateJwkThumbprint(this.signingPublic)],
      ['ps', issued.ps === this.demo.ps.id], ['sub', issued.sub === presented.sub], ['presented_jti', issued.presented_jti === presented.jti],
      ['exp', issued.exp > now()]].filter(([, ok]) => !ok).map(([name]) => name);
    if (problems.length) return { status: 0, data: { error: 'invalid_resource_token', detail: `Agent rejected the resource token: ${problems.join(', ')}` }, record, boundary: this.name };
    if (forge) record.auth_token = await forge(issued, record.person_token);
    else {
      const exchange = await this.send('ps', '/auth-token', { body: { resource_token: record.resource_token, presented_token: record.person_token,
        ...(upstream ? { upstream_token: upstream } : {}) }, token: this.agentToken, ps: true, step: 'auth_token_request', taskIndex });
      if (exchange.status !== 200) return { ...exchange, record, boundary: 'ps' };
      record.auth_token = exchange.data.auth_token;
    }
    const final = await this.send(to, path, { body, token: record.auth_token, step: 'auth_token_call', taskIndex });
    if (final.status < 400 && !forge) this.authTokens.set(cacheKey, record.auth_token);
    return { ...final, record, boundary: to };
  }
}

// ── Person server ───────────────────────────────────────────────────────────
class Refusal extends Error {
  constructor(error, detail, status = 400) { super(detail); Object.assign(this, { error, status }); }
}
class PersonServer extends Party {
  async init() {
    await super.init();
    // bindings: agent → person (§13.14). issued: jti → agent, for upstream tokens (§9.4.5 step 4).
    this.missions = new Map(); this.directed = new Map(); this.bindings = new Map(); this.issued = new Map(); this.log = [];
    // Deferred requests waiting on the person (§11.8), by pending id and by interaction code.
    this.pending = new Map(); this.codes = new Map();
    this.publicKey = createLocalJWKSet(this.jwks);
    return this;
  }
  metadata() {
    return { 'aauth-person.json': { issuer: this.id, jwks_uri: `${this.id}/jwks.json`, person_token_endpoint: `${this.id}/person-token`,
      auth_token_endpoint: `${this.id}/auth-token`, mission_endpoint: `${this.id}/missions` } };
  }
  // The person connects an agent to their PS before it acts for them. Simulated.
  bind(agentSub, person) {
    this.bindings.set(agentSub, person);
    this.log.push({ at: new Date().toISOString(), type: 'binding', agent: agentSub, decision: 'bound', person: PEOPLE[person].email });
  }
  async subject(person, audience) {
    const sub = (await digest(`${person}|${audience}`)).slice(0, 22);
    this.directed.set(`${audience}|${sub}`, person);
    return sub;
  }
  // A person or auth token this PS issued. Failures carry the parameter's error codes (§11.9.3).
  async ownToken(jwt, parameter) {
    let verified;
    try { verified = await jwtVerify(jwt, this.publicKey, { issuer: this.id }); }
    catch (error) { throw new Refusal(error.code === 'ERR_JWT_EXPIRED' ? `expired_${parameter}` : `invalid_${parameter}`, `${parameter}: ${error.message}`); }
    const { payload, protectedHeader: { typ } } = verified;
    if (typ !== TOKEN_TYP.person && typ !== TOKEN_TYP.auth) throw new Refusal(`invalid_${parameter}`, `${parameter} must be ${TOKEN_TYP.person} or ${TOKEN_TYP.auth}`);
    const jwk = payload.cnf?.jwk;
    if (!jwk?.kty || !jwk.crv || !jwk.x) throw new Refusal(`invalid_${parameter}`, `${parameter} cnf.jwk is structurally incomplete`);
    return { payload, typ, ps: typ === TOKEN_TYP.person ? payload.iss : payload.ps };
  }
  // §8.2: every decision path that acts on a mission checks it is active and unexpired.
  activeMission(s256) {
    const mission = this.missions.get(s256);
    if (!mission) throw new Refusal('invalid_request', 'Unknown mission_s256');
    if (mission.state !== 'active' || Date.now() >= Date.parse(mission.blob.expires_at)) throw new Refusal('mission_terminated', 'The mission is no longer active', 403);
    return mission;
  }
  missionExp(mission) { return Math.floor(Date.parse(mission.blob.expires_at) / 1000); }
  // §9.4.5 Upstream Token Verification.
  async upstream(caller, raw) {
    const { payload, ps } = await this.ownToken(raw, 'upstream_token');
    if (ps !== this.id) throw new Refusal('invalid_upstream_token', 'upstream_token does not name this PS');
    if (payload.aud !== caller.agent.iss) throw new Refusal('invalid_upstream_token', `upstream_token aud ${payload.aud} is not the signing intermediary ${caller.agent.iss}`);
    const record = this.issued.get(payload.jti);
    if (!record) throw new Refusal('invalid_upstream_token', 'This PS cannot identify the calling agent the upstream token was issued to');
    const person = this.directed.get(`${payload.aud}|${payload.sub}`);
    if (!person) throw new Refusal('invalid_upstream_token', 'This PS holds no record of the person at the upstream resource');
    return { payload, person, callingAgent: record.agent };
  }
  // §11.6.3 Interaction Required. The person finishes at the interaction URL; the
  // agent polls Location. complete() runs once the person approves.
  defer(caller, entry, complete) {
    const pendingId = base64url.encode(crypto.getRandomValues(new Uint8Array(16)));
    // §11.6.3.1: 8 Crockford base32 symbols (40 bits), grouped for reading aloud.
    const symbols = '0123456789ABCDEFGHJKMNPQRSTVWXYZ', bytes = crypto.getRandomValues(new Uint8Array(8));
    const raw = [...bytes].map(byte => symbols[byte % 32]).join(''), code = `${raw.slice(0, 4)}-${raw.slice(4)}`;
    const pending = { id: pendingId, code, agent: caller.agent.sub, state: 'pending', entry, complete, expires: Date.now() + 600_000 };
    this.pending.set(pendingId, pending); this.codes.set(code, pending);
    Object.assign(entry, { decision: 'pending', interaction_code: code });
    return json({ status: 'pending', requirement: 'interaction', code, timeout: 600 }, 202, {
      'aauth-requirement': `requirement=interaction; url="${this.id}/interact"; code="${code}"`,
      location: `${this.id}/pending/${pendingId}`, 'retry-after': '0' });
  }
  // The person's side, in their browser (simulated): open the interaction URL, then decide.
  interact(code, person) {
    const pending = this.codes.get(code);
    if (!pending || pending.state !== 'pending') return false;
    pending.state = 'interacting';
    this.demo.personStep(this, `${this.id}/interact?code=${code}`, `${PEOPLE[person].name} opens the interaction URL and signs in at the PS`,
      `The person enters code ${code} (or follows the link) and authenticates at their PS. The agent never sees this exchange. Its next poll answers 202 with status "interacting".`);
    return true;
  }
  decide(code, person, approve) {
    const pending = this.codes.get(code);
    if (!pending || pending.state !== 'interacting') return false;
    pending.state = approve ? 'approved' : 'declined';
    this.demo.personStep(this, `${this.id}/interact?code=${code}`, `${PEOPLE[person].name} ${approve ? 'approves' : 'declines'} the mission at the PS`,
      approve ? 'The person reviews the mission (description, tools, resources, payer and budget) and approves it. The PS holds the result for the agent\'s next poll.'
        : 'The person declines the mission. The next poll answers 403 denied, and the agent stops polling.');
    return true;
  }
  // GET {pending URL}: §11.8.4 state machine. §13.2: the polling agent must be the one that asked.
  async poll(caller, pendingId) {
    const pending = this.pending.get(pendingId);
    if (!pending) return problem('invalid_request', 'Unknown pending URL', 404);
    if (pending.agent !== caller.agent.sub) return problem('invalid_request', 'This pending URL belongs to another agent', 403);
    if (pending.state === 'done') return problem('invalid_request', 'This pending request has already completed', 410);
    if (Date.now() > pending.expires) { pending.state = 'done'; return problem('expired', 'The person did not act in time', 408); }
    if (pending.state === 'pending' || pending.state === 'interacting') {
      return json({ status: pending.state }, 202, { location: `${this.id}/pending/${pendingId}`, 'retry-after': '0' });
    }
    const approved = pending.state === 'approved';
    pending.state = 'done';
    if (!approved) {
      Object.assign(pending.entry, { decision: 'denied', error: 'denied', detail: 'The person declined the mission' });
      return problem('denied', 'The person declined the mission', 403);
    }
    return pending.complete();
  }
  async caller(request, text) {
    const url = new URL(request.url);
    const signature = await verifySignature({ method: request.method, authority: url.host, path: url.pathname, headers: request.headers, body: text },
      { requireContentDigest: request.method !== 'GET' });
    if (!signature.verified) throw Object.assign(new Refusal('invalid_signature', signature.error ?? 'invalid_signature', 401), { header: signature.signatureError?.error ?? 'invalid_signature' });
    let agent;
    try { agent = await verifyToken({ jwt: signature.jwt.raw, httpSignatureThumbprint: signature.thumbprint, resource: this.id, accept: ['agent'] }); }
    catch (error) { throw Object.assign(new Refusal(error.code ?? 'invalid_agent_token', error.message, 401), { header: error.code ?? 'invalid_jwt' }); }
    return { agent, thumbprint: signature.thumbprint, jwk: signature.publicKey };
  }
  async handle(request) {
    const path = new URL(request.url).pathname;
    const missionPath = path.match(/^\/missions\/([\w-]+)$/);
    if (request.method === 'GET' && missionPath) {
      const mission = this.missions.get(missionPath[1]);
      return this.demo.discovery(this, request, mission ? new Response(mission.bytes, { headers: { 'content-type': 'application/json' } }) : problem('not_found', 'Unknown mission', 404));
    }
    const text = await request.text();
    let caller;
    try { caller = await this.caller(request, text); }
    catch (error) { return problem(error.error, error.message, error.status, { 'signature-error': `error=${error.header}` }); }
    const pendingPath = path.match(/^\/pending\/([\w-]+)$/);
    if (request.method === 'GET' && pendingPath) return this.poll(caller, pendingPath[1]);
    let body;
    try { body = JSON.parse(text || '{}'); } catch { return problem('invalid_request', 'Body must be JSON', 400); }
    const endpoint = { '/missions': 'approveMission', '/person-token': 'personToken', '/auth-token': 'authToken' }[path];
    if (!endpoint) return problem('not_found', 'Unknown endpoint', 404);
    const entry = { at: new Date().toISOString(), type: endpoint === 'approveMission' ? 'mission' : endpoint === 'personToken' ? 'person_token' : 'auth_token',
      agent: caller.agent.sub, chained: Boolean(body.upstream_token), checks: [] };
    this.log.push(entry);
    try { return await this[endpoint](caller, body, entry); }
    catch (error) {
      if (!(error instanceof Refusal)) throw error;
      Object.assign(entry, { decision: 'denied', error: error.error, detail: error.message });
      return problem(error.error, error.message, error.status, {}, entry.checks.length ? { mission_checks: entry.checks } : {});
    }
  }
  async issuePersonToken(person, resource, jwk, agentSub, exp, missionS256) {
    const jti = id('pt');
    const token = await this.sign({ iss: this.id, dwk: DWK.person, aud: resource, sub: await this.subject(person, resource), jti, iat: now(), exp,
      cnf: { jwk }, ...(missionS256 ? { mission_s256: missionS256 } : {}) }, TOKEN_TYP.person);
    this.issued.set(jti, { agent: agentSub, kind: 'person', aud: resource, exp });
    return token;
  }
  // §8.1–8.2. The PS checks the proposal, then defers to the person (202 +
  // requirement=interaction). The person's browser session is simulated.
  async approveMission(caller, body, entry) {
    const person = this.bindings.get(caller.agent.sub);
    if (!person) throw new Refusal('user_unreachable', 'No person is bound to this agent', 403);
    if (typeof body.description !== 'string' || !Array.isArray(body.tools ?? []) || !Array.isArray(body.resources ?? []) || (body.resources ?? []).some(value => !isServerIdentifier(value))) {
      throw new Refusal('invalid_request', 'A proposal needs a description, and tools and resources as arrays');
    }
    const relay = body.relay ?? {};
    if (relay.payer !== PEOPLE[person].payer) throw new Refusal('denied', `${PEOPLE[person].name} cannot authorize spending from ${relay.payer}`, 403);
    return this.defer(caller, entry, () => this.recordMission(caller, body, entry, person));
  }
  async recordMission(caller, body, entry, person) {
    const relay = body.relay;
    const blob ={ agent: caller.agent.sub, approved_at: new Date().toISOString(), expires_at: new Date(Date.now() + 15 * 60_000).toISOString(),
      description: body.description, approved_tools: body.tools ?? [], approved_resources: body.resources ?? [],
      relay: { payer: relay.payer, budget: relay.budget, scopes: relay.scopes } };
    const bytes = JSON.stringify(blob);
    const s256 = await digest(bytes);
    const mission = { s256, bytes, blob, person, state: 'active' };
    this.missions.set(s256, mission);
    const exp = Math.min(now() + 3600, caller.agent.exp, this.missionExp(mission));
    const personTokens = Object.fromEntries(await Promise.all(blob.approved_resources.map(async resource =>
      [resource, await this.issuePersonToken(person, resource, caller.jwk, caller.agent.sub, exp, s256)])));
    Object.assign(entry, { decision: 'approved', person: PEOPLE[person].email, detail: `${PEOPLE[person].name} approved ${relay.budget} credits from ${relay.payer}` });
    return json({ s256, mission: base64url.encode(bytes), capabilities: [], person_tokens: personTokens });
  }
  // §7.1 Person Token Endpoint.
  async personToken(caller, body, entry) {
    entry.resource = body.resource;
    if (!isServerIdentifier(body.resource)) throw new Refusal('invalid_request', 'resource must be an HTTPS server identifier');
    let person, mission = null, exp = Math.min(now() + 3600, caller.agent.exp);
    if (body.upstream_token) {
      const chain = await this.upstream(caller, body.upstream_token);
      person = chain.person; entry.calling_agent = chain.callingAgent;
      exp = Math.min(exp, chain.payload.exp);
      if (chain.payload.mission_s256) mission = this.activeMission(chain.payload.mission_s256);
    } else {
      person = this.bindings.get(caller.agent.sub);
      if (!person) throw new Refusal('user_unreachable', 'No person is bound to this agent', 403);
      if (body.mission_s256) {
        mission = this.activeMission(body.mission_s256);
        if (mission.blob.agent !== caller.agent.sub) throw new Refusal('invalid_request', 'mission_s256 does not belong to this agent');
      }
    }
    if (mission) exp = Math.min(exp, this.missionExp(mission));
    const personToken = await this.issuePersonToken(person, body.resource, caller.jwk, caller.agent.sub, exp, mission?.s256);
    Object.assign(entry, { decision: 'issued', person: PEOPLE[person].email });
    return json({ person_token: personToken, expires_in: exp - now() });
  }
  // §7.2 Auth Token Endpoint: §6.7.2 resource token verification, §9.4.5 upstream
  // verification, then this PS's supervision policy over the mission.
  async authToken(caller, body, entry) {
    if (typeof body.resource_token !== 'string' || typeof body.presented_token !== 'string') throw new Refusal('invalid_request', 'resource_token and presented_token are required');
    let resourceToken;
    try {
      const keys = createLocalJWKSet(await discoverJwks({ iss: decodeJwt(body.resource_token).iss, dwk: DWK.resource }));
      ({ payload: resourceToken } = await jwtVerify(body.resource_token, keys, { typ: TOKEN_TYP.resource, audience: this.id }));
    } catch (error) { throw new Refusal('invalid_resource_token', error.message); }
    Object.assign(entry, { resource: resourceToken.iss, scope: resourceToken.scope, account: resourceToken.account ?? null, resource_token_jti: resourceToken.jti });
    if (resourceToken.agent_jkt !== caller.thumbprint) throw new Refusal('invalid_resource_token', 'agent_jkt does not name the key that signed this request');
    const presented = await this.ownToken(body.presented_token, 'presented_token');
    if (presented.payload.aud !== resourceToken.iss) throw new Refusal('invalid_presented_token', 'presented_token aud is not the resource that issued the resource token');
    if (await calculateJwkThumbprint(presented.payload.cnf.jwk) !== resourceToken.agent_jkt) throw new Refusal('invalid_presented_token', 'presented_token cnf does not match agent_jkt');
    const mismatched = [['presented_jti', resourceToken.presented_jti, presented.payload.jti], ['ps', resourceToken.ps, presented.ps], ['ps', resourceToken.ps, this.id],
      ['sub', resourceToken.sub, presented.payload.sub], ['mission_s256', resourceToken.mission_s256, presented.payload.mission_s256],
      ['tenant', resourceToken.tenant, presented.payload.tenant]].filter(([, a, b]) => a !== b).map(([name]) => name);
    if (mismatched.length) throw new Refusal('invalid_resource_token', `Resource token does not match the presented token: ${[...new Set(mismatched)].join(', ')}`);
    const mission = resourceToken.mission_s256 ? this.activeMission(resourceToken.mission_s256) : null;
    if (!mission) throw new Refusal('denied', 'This PS issues auth tokens only under a mission', 403);
    const person = this.directed.get(`${presented.payload.aud}|${presented.payload.sub}`);
    if (!person) throw new Refusal('invalid_presented_token', 'No record of this person at the resource');
    let upstream = null;
    if (body.upstream_token) {
      upstream = (await this.upstream(caller, body.upstream_token)).payload;
      entry.checks.push(row(`upstream_token: issued by this PS, aud == signing intermediary (${PARTIES[this.demo.partyById(upstream.aud)] ?? upstream.aud})`, true, 'call chaining'));
    }
    // Supervision policy (§9.4.5 step 5). approved_tools and approved_resources are
    // records, not limits (§C.1.10, §8.2); this PS enforces its own lab extension.
    const checks = entry.checks;
    checks.push(row(`mission ${mission.s256.slice(0, 10)}… is active and unexpired`, true, 'mission'));
    checks.push(row(`mission was approved by ${PEOPLE[person].email}`, mission.person === person, 'mission'));
    const label = PARTIES[this.demo.partyById(resourceToken.iss)] ?? resourceToken.iss;
    const allowed = mission.blob.relay.scopes?.[resourceToken.iss] ?? [];
    for (const scope of (resourceToken.scope ?? '').split(' ').filter(value => value && !IDENTITY_SCOPES.has(value))) {
      checks.push(row(`relay.scopes[${label}] ∋ "${scope}"`, allowed.includes(scope), 'PS policy · lab extension', allowed));
    }
    if (resourceToken.account !== undefined) checks.push(row(`account "${resourceToken.account}" == relay.payer "${mission.blob.relay.payer}"`, resourceToken.account === mission.blob.relay.payer, 'PS policy · lab extension', [mission.blob.relay.payer]));
    const failed = checks.filter(check => !check.present);
    if (failed.length) throw new Refusal('denied', `Mission evaluation failed: ${failed.map(check => check.logic).join('; ')}`, 403);
    const exp = Math.min(now() + 3600, caller.agent.exp, presented.payload.exp, upstream?.exp ?? Infinity, this.missionExp(mission));
    const scope = resourceToken.scope.split(' ');
    const jti = id('at');
    const authToken = await this.sign({ iss: this.id, dwk: DWK.person, aud: resourceToken.iss, ps: this.id, sub: resourceToken.sub, jti,
      iat: now(), exp, cnf: { jwk: caller.jwk }, scope: resourceToken.scope, ...(resourceToken.account !== undefined ? { account: resourceToken.account } : {}),
      mission_s256: mission.s256, ...(scope.includes('email') ? { email: PEOPLE[person].email } : {}), ...(scope.includes('profile') ? { name: PEOPLE[person].name } : {}) }, TOKEN_TYP.auth);
    this.issued.set(jti, { agent: caller.agent.sub, kind: 'auth', aud: resourceToken.iss, exp });
    Object.assign(entry, { decision: 'issued', person: PEOPLE[person].email });
    return json({ auth_token: authToken, expires_in: exp - now() });
  }
}

// ── Resources ───────────────────────────────────────────────────────────────
// Shared resource gate. One endpoint answers all three AAuth stages:
//   agent token  → identity-based access control (§4.2.1), then ask for a person token
//   person token → issue a resource token naming the scope and billing account
//   auth token   → hand the verified token to the endpoint's policy
// No token in the three-party flow names the agent (§C.1.6), so caller trust
// can only be decided on a request that carries the agent token.
class Resource extends Agent {
  metadata() {
    return { ...super.metadata(), 'aauth-resource.json': { issuer: this.id, jwks_uri: `${this.id}/jwks.json`, name: this.label, access_mode: 'auth-token' } };
  }
  trusts() { return false; }
  trustedCallers() { return []; }
  async gate(request, text, { scope, account, decision }) {
    const url = new URL(request.url);
    const signature = await verifySignature({ method: request.method, authority: url.host, path: url.pathname, headers: request.headers, body: text });
    if (!signature.verified) {
      Object.assign(decision, { phase: 'verification', permitted: false, summary: `HTTP signature rejected: ${signature.error}` });
      const code = signature.signatureError?.error ?? 'invalid_signature';
      return { response: problem(code, signature.error, 401, { 'signature-error': `error=${code}` }) };
    }
    let token;
    try { token = await verifyToken({ jwt: signature.jwt.raw, httpSignatureThumbprint: signature.thumbprint, resource: this.id, accept: ['agent', 'person', 'auth'] }); }
    catch (error) {
      const issuer = claims(signature.jwt.raw)?.payload.iss;
      Object.assign(decision, { phase: 'verification', permitted: false, error: error.message,
        summary: `${this.label} rejected the presented token: ${error.message}` });
      decision.rows = [row('RFC 9421 HTTP signature verifies', true, 'HTTP signature'),
        row(`token signature verifies against ${PARTIES[this.demo.partyById(issuer)] ?? issuer} JWKS`, false, 'token issuer')];
      const code = error.code ?? 'invalid_jwt';
      return { response: problem(code, error.message, 401, { 'signature-error': `error=${code}` }) };
    }
    if (token.type === 'agent') {
      const caller = this.demo.partyBySub(token.sub);
      const rows = [row('RFC 9421 HTTP signature verifies', true, 'HTTP signature'), row(`agent token: ${token.sub}`, true, 'agent provider'),
        row(`trusts_caller(${PARTIES[caller] ?? token.sub}, ${this.label})`, this.trusts(caller), `${this.label} policy`, this.trustedCallers())];
      decision.identity_rows = rows;
      if (!this.trusts(caller)) {
        Object.assign(decision, { phase: 'identity', permitted: false, rows, summary: `${this.label} does not trust ${PARTIES[caller] ?? token.sub} as a caller; no person server was contacted.` });
        return { response: problem('denied', `${this.label} does not accept calls from ${token.sub}`, 403) };
      }
      return { response: problem('person_token_required', 'Present a person token', 401, { 'aauth-requirement': buildAAuthHeader('person-token') }) };
    }
    if (token.type === 'person') {
      const resourceToken = await createResourceToken({ resource: this.id, audience: token.iss, presentedToken: token, agentJkt: signature.thumbprint,
        scope, ...(account ? { account } : {}), kid: this.kid }, (payload, header) => new SignJWT(payload).setProtectedHeader(header).sign(this.issuerKey));
      return { response: problem('auth_token_required', 'Present an auth token', 401, { 'aauth-requirement': buildAAuthHeader('auth-token', { resourceToken }) }) };
    }
    return { token, raw: signature.jwt.raw, thumbprint: signature.thumbprint };
  }
}

class Operator extends Resource {
  trusts(caller) { return this.name === 'planner' ? caller === 'assistant' : this.demo.edges.some(([from, to]) => from === caller && to === this.name); }
  trustedCallers() { return this.name === 'planner' ? ['Assistant'] : this.demo.edges.filter(([, to]) => to === this.name).map(([from]) => OPERATORS[from]); }
  accepts() { return this.demo.accepts[this.name].map(who => PEOPLE[who].email); }
  async handle(request) {
    const action = new URL(request.url).pathname.match(/^\/tasks\/(\w+)$/)?.[1];
    if (!action) return problem('not_found', 'Unknown task', 404);
    const text = await request.text();
    const body = JSON.parse(text || '{}');
    const task = body.lab_task === null ? null : this.demo.tasks[body.lab_task];
    const decision = task ? (task.decision = task.decision ?? { phase: 'pending', rows: [] }) : this.demo.rootDecision;
    const gate = await this.gate(request, text, { scope: `${action} email`, account: body.payer, decision });
    if (gate.response) {
      if (decision.permitted === false && task) this.deny(task, decision.summary);
      return gate.response;
    }
    const { token, raw, thumbprint } = gate;
    const email = token.claims.email;
    const rows = [
      row(`RFC 9421 signature · key ${thumbprint.slice(0, 10)}…`, true, 'HTTP signature'),
      row(`auth token iss == ${this.demo.ps.label}, aud == ${this.label}, cnf == signing key`, true, 'PS-signed auth token'),
      row(`accepts_requester("${email}")`, this.accepts().includes(email), `${this.label} policy`, this.accepts()),
    ];
    if (task) rows.push(
      row(`scope ∋ "${action}"`, token.scope?.split(' ').includes(action) ?? false, 'PS-signed auth token', [token.scope]),
      row(`offers("${action}")`, OFFERS[this.name].includes(action), `${this.label} policy`, OFFERS[this.name]),
      row(`account "${token.account}" == requested payer "${body.payer}"`, token.account === body.payer, 'PS-signed auth token', [token.account]));
    Object.assign(decision, { phase: task ? 'policy' : 'ingress', rows, token_claims: token.claims,
      call_values: { service: this.label, action, payer: body.payer, amount: body.amount } });
    if (rows.some(check => !check.present)) {
      Object.assign(decision, { permitted: false, summary: `${this.label}'s local policy denied this call. Red rows show the failed checks.` });
      if (task) this.deny(task, decision.summary);
      return problem('denied', decision.summary, 403);
    }
    decision.permitted = true;
    if (!task) return this.plan(raw);
    decision.summary = 'The PS-issued auth token verified and every local policy check passed.';
    this.demo.event('authorized', this.name, `HTTP signature, PS auth token and ${this.label} policy verified`, task);
    return this.work(task, token, raw, body);
  }
  deny(task, message) { task.status = 'denied'; task.error = message; this.demo.event('denied', this.name, message, task); }

  // The clearinghouse needs to know which provider bills, and AAuth tokens do not
  // name agents (§C.1.6). The provider says so in a JWT signed with its agent
  // provider key and bound to the key signing the request. Lab-defined.
  async billing(path, task, upstream, payload) {
    const assertion = await this.sign({ iss: this.id, operation_id: payload.operation_id, path, jkt: await calculateJwkThumbprint(this.signingPublic),
      iat: now(), exp: now() + 300 }, 'relay-billing+jwt');
    return this.authorizedCall('clearinghouse', path, { ...payload, provider_assertion: assertion, lab_task: task.index },
      { upstream, taskIndex: task.index, cacheKey: `clearinghouse|${task.operation_id}|${task.index}` });
  }
  async work(task, token, upstream, body) {
    const reserve = await this.billing('/reserve', task, upstream, { operation_id: body.operation_id, action: body.action, amount: body.amount, payer: token.account });
    if (reserve.status >= 400 || reserve.status === 0) {
      task.status = 'denied'; task.error = reserve.data?.detail ?? reserve.data?.error;
      if (!task.decision.billing) task.decision.billing = { passed: false, reason: task.error };
      if (reserve.boundary === 'ps') Object.assign(task.decision, { phase: 'ps', permitted: false, summary: `The person server refused a billing token: ${task.error}` });
      this.demo.event('denied', this.name, task.error, task);
      return problem(reserve.data?.error ?? 'denied', task.error, reserve.status || 403);
    }
    if (reserve.data.duplicate && reserve.data.status === 'settled') {
      task.status = 'reused'; task.decision.summary = 'Authorized; the clearinghouse returned the existing settlement for this operation ID.';
      this.demo.event('reused', this.name, 'Retry returned the existing settlement; no additional work or charge', task);
      return json({ status: 'reused', operation_id: body.operation_id });
    }
    task.grant = reserve.data.grant;
    this.demo.event('reserved', this.name, `${body.amount} credits reserved against ${token.account}`, task);
    this.demo.event('executing', this.name, 'Provider starts the simulated operation', task);
    if (body.simulate_failure) {
      await this.billing('/release', task, upstream, { operation_id: body.operation_id });
      task.status = 'released'; task.decision.summary = 'Authorized; simulated execution failed and the clearinghouse released the reservation.';
      this.demo.event('released', this.name, `Simulated operation failed; ${body.amount} credits released`, task);
      return problem('operation_failed', 'Simulated operation failed; reservation released', 502);
    }
    task.receipt = await this.sign({ iss: this.id, operation_id: body.operation_id, provider: this.name, grant_hash: await digest(task.grant),
      result: 'completed', iat: now() }, 'relay-receipt+jwt');
    const settle = await this.billing('/settle', task, upstream, { operation_id: body.operation_id, receipt: task.receipt });
    if (settle.status !== 200) { this.deny(task, settle.data?.detail ?? 'Settlement failed'); return problem('server_error', 'Settlement failed', 500); }
    task.status = 'settled';
    this.demo.event('settled', this.name, `${body.amount} credits charged to ${token.account}; signed receipt verified`, task);
    if (this.name === 'research') await this.demo.researchDelegates(this, upstream);
    return json({ status: 'settled', operation_id: body.operation_id });
  }
  plan(upstream) {
    this.demo.rootDecision.summary = 'PlannerCo accepted the original requester and started delegation.';
    this.demo.event('accepted', 'planner', 'PlannerCo accepted the original requester and can delegate work');
    return this.demo.plannerDelegates(this, upstream).then(() => json({ status: 'planned' }));
  }
}

class Clearinghouse extends Resource {
  async init() {
    await super.init();
    this.operations = new Map(); this.queue = Promise.resolve(); this.budget = null; this.payer = null; this.mission = null;
    return this;
  }
  trusts(caller) { return Object.hasOwn(OPERATORS, caller); }
  trustedCallers() { return Object.values(OPERATORS); }
  async provider(assertion, thumbprint, path, operationId) {
    const issuer = decodeJwt(assertion).iss;
    const keys = createLocalJWKSet(await discoverJwks({ iss: issuer, dwk: DWK.agent }));
    const { payload } = await jwtVerify(assertion, keys, { issuer, typ: 'relay-billing+jwt' });
    if (payload.jkt !== thumbprint || payload.path !== path || payload.operation_id !== operationId) throw new Error('Provider assertion is not bound to this request');
    const provider = this.demo.partyById(issuer);
    if (!Object.hasOwn(OPERATORS, provider)) throw new Error('Provider assertion is not from a registered operator');
    return provider;
  }
  async handle(request) {
    const path = new URL(request.url).pathname;
    const text = await request.text();
    const body = JSON.parse(text || '{}');
    const task = this.demo.tasks[body.lab_task];
    const gate = await this.gate(request, text, { scope: 'billing', account: body.payer, decision: {} });
    if (gate.response) return gate.response;
    const { token, thumbprint } = gate;
    if (token.ps !== this.demo.ps.id || token.mission_s256 !== this.mission) return problem('denied', 'Clearinghouse: token is not bound to the funded mission', 403);
    let provider;
    try { provider = await this.provider(body.provider_assertion, thumbprint, path, body.operation_id); }
    catch (error) { return problem('invalid_request', error.message, 400); }
    if (path === '/reserve') return this.serialize(() => this.reserve(task, provider, token, body));
    if (path === '/settle') return this.settle(provider, body);
    if (path === '/release') { const entry = this.operations.get(body.operation_id); if (entry?.provider === provider && entry.status === 'reserved') entry.status = 'released'; return json({ status: 'released' }); }
    return problem('not_found', 'Unknown endpoint', 404);
  }
  serialize(work) { const pending = this.queue.then(work); this.queue = pending.catch(() => {}); return pending; }
  async reserve(task, provider, token, body) {
    if (!Number.isInteger(body.amount) || body.amount <= 0) return problem('invalid_request', 'Price must be a positive integer number of credits', 400);
    const fingerprint = await digest({ operation_id: body.operation_id, provider, action: body.action, amount: body.amount, payer: token.account, mission: token.mission_s256 });
    const previous = this.operations.get(body.operation_id);
    if (previous) {
      if (previous.fingerprint !== fingerprint) return problem('idempotency_conflict', 'Operation ID reused with different billing details', 409);
      if (previous.status === 'released') return problem('released', 'This operation was released; create a new operation ID', 409);
      if (task) task.decision.billing = { requested: body.amount, available_before: previous.available_before, passed: true, reason: 'Existing reservation reused' };
      return json({ grant: previous.grant, duplicate: true, status: previous.status });
    }
    const used = [...this.operations.values()].filter(entry => entry.status !== 'released').reduce((sum, entry) => sum + entry.amount, 0);
    const available = this.budget - used;
    if (body.amount > available) {
      if (task) task.decision.billing = { requested: body.amount, available_before: available, passed: false, reason: `${body.amount} > ${available} available credits` };
      if (task) Object.assign(task.decision, { phase: 'billing', summary: 'AAuth allowed the call; the clearinghouse denied its credit reservation.' });
      return problem('insufficient_credits', `Insufficient credits: ${body.amount} requested, ${available} available`, 402, {}, { requested: body.amount, available });
    }
    const grant = await this.sign({ iss: this.id, operation_id: body.operation_id, mission_s256: token.mission_s256, payer: token.account, provider,
      amount: body.amount, fingerprint, available_before: available, iat: now() }, 'relay-grant+jwt');
    this.operations.set(body.operation_id, { id: body.operation_id, fingerprint, provider, amount: body.amount, status: 'reserved', grant, receipt: null, available_before: available });
    if (task) task.decision.billing = { requested: body.amount, available_before: available, passed: true, reason: `${body.amount} ≤ ${available} available credits` };
    return json({ grant, duplicate: false, status: 'reserved' });
  }
  async settle(provider, body) {
    const entry = this.operations.get(body.operation_id);
    try {
      const keys = createLocalJWKSet(await discoverJwks({ iss: this.demo.parties[provider].id, dwk: DWK.agent }));
      const { payload } = await jwtVerify(body.receipt, keys, { issuer: this.demo.parties[provider].id, typ: 'relay-receipt+jwt' });
      if (payload.result !== 'completed') throw new Error('Receipt does not prove completion');
      if (!entry || entry.provider !== provider || payload.grant_hash !== await digest(entry.grant)) throw new Error('Receipt is not bound to this provider and reservation');
      if (entry.status === 'released') throw new Error('Cannot settle a released reservation');
    } catch (error) { return problem('invalid_receipt', error.message, 400); }
    entry.status = 'settled'; entry.receipt = body.receipt;
    return json({ status: 'settled', operation_id: body.operation_id, amount: entry.amount });
  }
  // The clearinghouse funds a mission by reading it from the PS and checking its hash.
  async fund(s256) {
    const response = await fetch(`${this.demo.ps.id}/missions/${s256}`);
    const bytes = await response.text();
    if (await digest(bytes) !== s256) throw new Error('Mission bytes do not match mission_s256');
    const { relay } = JSON.parse(bytes);
    Object.assign(this, { mission: s256, budget: relay.budget, payer: relay.payer });
  }
  snapshot() {
    const operations = [...this.operations.values()];
    const sum = status => operations.filter(entry => entry.status === status).reduce((total, entry) => total + entry.amount, 0);
    const settled = sum('settled'), reserved = sum('reserved');
    const budget = this.budget ?? this.demo.budget;
    return { budget, settled, reserved, available: budget - settled - reserved, operations: operations.map(({ available_before, ...entry }) => entry),
      balances: Object.fromEntries(Object.keys(OPERATORS).map(name => [name, operations.filter(entry => entry.provider === name && entry.status === 'settled').reduce((total, entry) => total + entry.amount, 0)])) };
  }
}

// ── Demo run ────────────────────────────────────────────────────────────────
class Demo {
  static async create(config = {}, hooks = {}) {
    if (!config || typeof config !== 'object' || Array.isArray(config)) throw new ValidationError('Settings must be an object');
    const demo = new Demo(config);
    demo.hooks = hooks;
    demo.ps = await new PersonServer(demo, 'ps').init();
    demo.parties = { ps: demo.ps };
    demo.parties.clearinghouse = await new Clearinghouse(demo, 'clearinghouse').init();
    demo.parties.assistant = await new Agent(demo, 'assistant').init();
    for (const name of Object.keys(OPERATORS)) demo.parties[name] = await new Operator(demo, name).init();
    return demo;
  }
  constructor(config) {
    this.scenario = config.scenario ?? 'happy';
    if (!SCENARIOS.has(this.scenario)) throw new ValidationError('Unknown scenario');
    this.budget = config.budget ?? 100;
    if (!Number.isInteger(this.budget) || this.budget < 1 || this.budget > 10000) throw new ValidationError('Budget must be an integer from 1 to 10000');
    this.requester = config.requester ?? 'alice';
    if (!Object.hasOwn(PEOPLE, this.requester)) throw new ValidationError('Choose Alice or Bob');
    this.payer = PEOPLE[this.requester].payer;
    // What the simulated person does at the PS consent screen.
    this.consent = config.consent ?? 'approve';
    if (!['approve', 'decline'].includes(this.consent)) throw new ValidationError('Consent must be approve or decline');
    this.edges = config.edges ?? DEFAULT_EDGES;
    if (!Array.isArray(this.edges) || this.edges.length > 16 || this.edges.some(edge => !Array.isArray(edge) || edge.length !== 2 || edge.some(value => !Object.hasOwn(OPERATORS, value)) || edge[0] === edge[1])) throw new ValidationError('Trust edges must connect two different known operators');
    this.accepts = config.accepts ?? Object.fromEntries(Object.keys(OPERATORS).map(name => [name, ['alice', 'bob']]));
    if (!this.accepts || typeof this.accepts !== 'object' || Object.keys(OPERATORS).some(name => !Array.isArray(this.accepts[name]) || this.accepts[name].some(value => !Object.hasOwn(PEOPLE, value)))) throw new ValidationError('Each operator must list its accepted requesters');
    this.tag = crypto.randomUUID().replaceAll('-', '').slice(0, 8);
    this.events = []; this.tasks = []; this.debug = []; this.seq = 0;
    this.rootDecision = { phase: 'ingress', permitted: false, rows: [], summary: '' };
  }
  partyById(value) { return Object.values(this.parties).find(party => party.id === value)?.name; }
  partyBySub(sub) { return Object.values(this.parties).find(party => party.sub === sub)?.name; }
  event(kind, operator, message, task = null) {
    const ledger = this.parties.clearinghouse.snapshot();
    const states = { ...Object.fromEntries(Object.keys(OPERATORS).map(name => [name, 'waiting'])), ...this.events.at(-1)?.snapshot.operator_states };
    if (Object.hasOwn(states, operator)) states[operator] = kind;
    this.events.push({ index: this.events.length + 1, kind, operator, message, task_index: task?.index ?? -1,
      snapshot: { operator_states: states, ledger: { budget: ledger.budget, settled: ledger.settled, reserved: ledger.reserved, available: ledger.available } } });
  }
  trace(entry) {
    const { started, requirement, presented, ...rest } = entry;
    const outcome = entry.status === 202 ? 'pending' : entry.status >= 200 && entry.status < 300 ? 'allowed' : requirement ? 'challenge' : 'denied';
    this.debug.push({ transport: 'virtual-http', stage: entry.step, operator: entry.to, ...rest,
      outcome, duration_ms: Math.max(0, Math.round((performance.now() - started) * 100) / 100), presented_token: presented, requirement,
      ...narrate(this, entry, requirement) });
  }
  async discovery(party, request, response) {
    const text = await response.clone().text();
    this.debug.push({ seq: this.seq++, transport: 'virtual-http', stage: 'discovery', step: 'discovery', from: null, to: party.name,
      operator: party.name, task_index: null, started_at: new Date().toISOString(), duration_ms: 0, outcome: response.ok ? 'allowed' : 'denied',
      request: { method: request.method, url: request.url, headers: {}, body: null }, status: response.status, response_headers: Object.fromEntries(response.headers), response_text: text,
      summary: `Key discovery: GET ${new URL(request.url).pathname} on ${party.label}`,
      description: 'Verifiers resolve signing keys online: {iss}/.well-known/{dwk} names a jwks_uri, and the JWT kid selects the key. Unsigned and public.' });
    return response;
  }
  // What the person does in their browser at the PS. Not an agent request, so it is not signed.
  personStep(ps, url, summary, description) {
    this.debug.push({ seq: this.seq++, transport: 'person', stage: 'consent', step: 'consent', from: 'person', to: ps.name, operator: ps.name,
      task_index: null, started_at: new Date().toISOString(), duration_ms: 0, outcome: 'allowed',
      request: { method: 'GET', url, headers: {}, body: null }, status: 200, response_headers: {}, response_text: '', summary, description });
  }
  // §8.1–8.2 plus §11.8: propose, wait for the person, verify s256 against the bytes.
  async proposeMission(agent, body, { person = this.requester, approve = this.consent === 'approve' } = {}) {
    let code;
    const proposal = await agent.send('ps', '/missions', { ps: true, token: agent.agentToken, step: 'mission_proposal', body });
    const answer = await agent.deferred(proposal, { to: 'ps', step: 'consent_poll', onPending: response => {
      if (response.requirement?.requirement === 'interaction') { code = response.requirement.code; this.ps.interact(code, person); }
      else if (response.data?.status === 'interacting') this.ps.decide(code, person, approve);
    } });
    if (answer.status !== 200) return { ...answer, approved: false };
    // §8.2: the agent verifies s256 against the decoded bytes before first use.
    if (await digest(new TextDecoder().decode(base64url.decode(answer.data.mission))) !== answer.data.s256) throw new Error('Mission bytes do not match s256');
    return { ...answer, approved: true };
  }
  async delegate(caller, provider, action, amount, upstream, options = {}) {
    const task = { index: this.tasks.length, caller: caller.name, provider, action, amount, payer: options.payer ?? this.payer,
      operation_id: options.operationId ?? id('op'), task_id: id('task'), status: 'pending', decision: null };
    this.tasks.push(task);
    this.event('delegated', provider, `${OPERATORS[caller.name]} → ${OPERATORS[provider]}: ${action}`, task);
    const body = { operation_id: task.operation_id, action, amount, payer: task.payer, lab_task: task.index, ...(options.fail ? { simulate_failure: true } : {}) };
    const result = await caller.authorizedCall(provider, `/tasks/${action}`, body, { upstream, taskIndex: task.index, forge: options.forge });
    task.tokens = Object.fromEntries(Object.entries(result.record).filter(([, value]) => typeof value === 'string').map(([key, value]) => [key, { raw: value, ...claims(value) }]));
    task.http_status = result.status;
    if (task.status === 'pending') {
      task.status = result.status === 200 ? 'settled' : 'denied';
      if (task.status === 'denied') {
        task.error = result.data?.detail ?? result.data?.error ?? `HTTP ${result.status}`;
        const checks = this.ps.log.findLast(entry => entry.type === 'auth_token' && entry.decision === 'denied')?.checks ?? [];
        task.decision = { ...(task.decision ?? {}), phase: result.boundary === 'ps' ? 'ps' : task.decision?.phase ?? 'verification', permitted: false,
          summary: result.boundary === 'ps' ? `The person server refused to issue a token: ${task.error}` : task.decision?.summary ?? task.error,
          ps_checks: result.boundary === 'ps' ? result.data?.mission_checks ?? checks : undefined, rows: task.decision?.rows ?? [] };
        this.event('denied', provider, task.error, task);
      }
    }
    return task;
  }
  async plannerDelegates(planner, upstream) {
    const research = () => this.delegate(planner, 'research', 'research', 5, upstream);
    if (this.scenario === 'overspend') {
      await Promise.all([research(), this.delegate(planner, 'compute', 'compute', 60, upstream)]);
    } else {
      await research();
      await this.delegate(planner, 'compute', 'compute', 25, upstream);
    }
    if (!this.tasks.some(task => task.provider === 'search')) this.event('skipped', 'search', 'Search task skipped because its parent research task did not settle');
  }
  async researchDelegates(research, upstream) {
    const scenario = this.scenario;
    let forge;
    if (scenario === 'untrusted') {
      // A rogue key mints an auth token that claims to come from the trusted PS.
      const rogue = await generateKeyPair(SIGNING_ALG, { extractable: true });
      forge = async (resourceToken, personToken) => new SignJWT({ iss: this.ps.id, dwk: DWK.person, aud: resourceToken.iss, ps: this.ps.id,
        sub: resourceToken.sub, jti: id('at'), iat: now(), exp: now() + 600, cnf: decodeJwt(personToken).cnf, scope: resourceToken.scope,
        account: this.payer, mission_s256: resourceToken.mission_s256, email: PEOPLE[this.requester].email })
        .setProtectedHeader({ alg: SIGNING_ALG, typ: TOKEN_TYP.auth, kid: this.ps.kid }).sign(rogue.privateKey);
    }
    const options = { payer: scenario === 'payer_swap' ? 'mallory-org' : undefined, fail: scenario === 'failure', forge };
    const action = scenario === 'forbidden' ? 'delete' : 'search';
    const amount = scenario === 'overspend' ? 60 : 10;
    const first = await this.delegate(research, 'search', action, amount, upstream, options);
    if (scenario === 'retry' && first.status === 'settled') await this.delegate(research, 'search', action, amount, upstream, { operationId: first.operation_id });
  }
  async run() {
    const assistant = this.parties.assistant;
    const person = PEOPLE[this.requester];
    try {
      this.ps.bind(assistant.sub, this.requester);
      const proposal = await this.proposeMission(assistant, {
        description: '# Research a topic\n\nPlan the work, research, search sources and run compute, billed to my organization.',
        tools: AGENT_TOOLS, resources: [this.parties.planner.id],
        relay: { payer: this.payer, budget: this.budget, scopes: Object.fromEntries(Object.entries(SCOPES).map(([name, scopes]) => [this.parties[name].id, scopes])) } });
      if (!proposal.approved) {
        this.rootDecision.summary = `The person server did not approve the mission: ${proposal.data?.detail ?? proposal.data?.error ?? proposal.status}`;
        this.event('denied', 'planner', `${person.name} did not approve the mission; no tasks were created`);
        return await this.result();
      }
      this.mission = proposal.data.s256;
      for (const [resource, token] of Object.entries(proposal.data.person_tokens ?? {})) assistant.personTokens.set(resource, token);
      await this.parties.clearinghouse.fund(this.mission);
      this.event('issued', 'clearinghouse', `${person.name} approved a mission at the PS: ${this.budget} credits from ${this.payer}`);
      const root = await assistant.authorizedCall('planner', '/tasks/plan', { topic: 'agent authorization', lab_task: null, payer: this.payer },
        { mission: this.mission, loginHint: person.email });
      this.rootTokens = root.record;
      if (root.status !== 200) {
        this.rootDecision.permitted = false;
        this.rootDecision.summary = this.rootDecision.summary || `PlannerCo denied the original request: ${root.data?.detail ?? root.status}`;
        this.event('denied', 'planner', 'PlannerCo does not accept this original requester; no downstream tasks were created');
      }
      return await this.result();
    } finally { this.close(); }
  }
  close() {
    for (const party of Object.values(this.parties)) routes.delete(party.host);
    clearMetadataCache();
  }
  async result() {
    const clearing = this.parties.clearinghouse;
    const mission = this.ps.missions.get(this.mission);
    // Entries are recorded when responses arrive; order them by when each request started.
    this.debug.sort((a, b) => a.seq - b.seq).forEach((entry, index) => { entry.id = `${this.tag}-${index + 1}`; delete entry.seq; });
    const http = this.debug.filter(entry => entry.transport === 'virtual-http' && entry.stage !== 'discovery');
    return { request_id: this.mission ?? this.tag, requester: this.requester, payer: this.payer, scenario: this.scenario, consent: this.consent,
      grant: { requester: PEOPLE[this.requester].email, payer: this.payer, request_id: this.mission, rights: [...new Set(Object.values(mission?.blob.relay.scopes ?? {}).flat())].sort(),
        expires: mission?.blob.expires_at, budget: this.budget, resources: mission?.blob.approved_resources ?? [] },
      mission: mission ? { s256: mission.s256, blob: mission.blob, log: this.ps.log } : null,
      parties: Object.fromEntries(Object.values(this.parties).map(party => [party.name, { id: party.id, label: party.label, agent: party.sub ?? null, jwks: party.jwks }])),
      root_decision: this.rootDecision, root_tokens: Object.fromEntries(Object.entries(this.rootTokens ?? {}).map(([key, value]) => [key, { raw: value, ...claims(value) }])),
      events: this.events, tasks: this.tasks, ledger: clearing.snapshot(), edges: this.edges, accepts: this.accepts, debug: this.debug,
      stats: { signed_requests: http.length, person_server_requests: http.filter(entry => entry.to === 'ps').length,
        key_discovery_requests: this.debug.filter(entry => entry.stage === 'discovery').length, challenges: http.filter(entry => entry.outcome === 'challenge').length,
        consent_polls: http.filter(entry => entry.stage === 'consent_poll').length } };
  }
}

// Narration in the style of `@aauth/fetch --explain`: a one-line summary and a
// teaching description for every exchange.
function narrate(demo, entry, requirement) {
  const from = PARTIES[entry.from], to = PARTIES[entry.to], status = entry.status;
  const body = (() => { try { return JSON.parse(entry.response_text); } catch { return {}; } })();
  switch (entry.step) {
    case 'mission_proposal': return { summary: `${from} → PS: mission proposal → ${status === 202 ? `202 pending (${requirement?.requirement ?? 'pending'})` : `${status} ${body.error ?? ''}`.trim()}`,
      description: status === 202
        ? `The agent proposes a mission: a description, its own tools and the resources it will call, plus a lab extension (payer, budget and the scopes the PS may issue per resource). Only the person can approve it, so the PS answers 202 with AAuth-Requirement requirement=interaction, an interaction URL and code ${requirement?.code ?? ''}, and a Location to poll. The agent shows the person the URL and code.`
        : `The PS refused the proposal before asking the person: ${body.detail ?? body.error}.` };
    case 'consent_poll': return { summary: `${from} → PS: poll pending URL → ${status === 202 ? `202 ${body.status}` : status === 200 ? '200 mission approved' : `${status} ${body.error ?? ''}`.trim()}`,
      description: status === 202
        ? (body.status === 'interacting' ? 'Signed GET of the pending URL. The person has reached the interaction page, so the agent stops prompting and keeps polling.' : 'Signed GET of the pending URL (§11.8.3). The PS checks the poll comes from the agent that made the request; the person has not acted yet.')
        : status === 200 ? 'The person approved. The body carries the mission blob (base64url), its s256 (SHA-256 of the exact bytes; every later token carries it) and a person token for each resource the mission named. The agent checks s256 against the bytes before using it.'
          : `Polling ends: ${body.detail ?? body.error}.` };
    case 'agent_token_call': return { summary: `${from} → ${to}: signed request with agent token → ${status}${requirement ? ` (${requirement.requirement})` : ''}`,
      description: status === 403 ? `${to} identified the caller from the signature alone (agent token in Signature-Key, cnf = signing key) and refused it by local policy. No person server or person was involved.`
        : `Identity-based flow. The request is signed per RFC 9421; Signature-Key carries a self-issued aa-agent+jwt whose cnf is the signing key. ${to} now knows WHO is calling, but needs to know on whose behalf, so it answers 401 requirement=person-token.` };
    case 'person_token_request': return { summary: `${from} → PS: person token for ${PARTIES[demo.partyById(JSON.parse(entry.request.body ?? '{}').resource)] ?? 'resource'} → ${status}`,
      description: JSON.parse(entry.request.body ?? '{}').upstream_token
        ? `Call chaining. ${from} is an intermediary: it signs with its own agent token and passes the token it received as upstream_token. The PS checks upstream_token.aud is this agent, resolves the person from its own records, and issues a person token with a new directed sub. The mission travels inside the upstream token.`
        : 'The agent asks the PS for a person token (aa-person+jwt): an identity assertion for one resource (aud), bound to the agent key (cnf), carrying mission_s256. It authorizes nothing by itself.' };
    case 'person_token_call': return { summary: `${from} → ${to}: signed request with person token → ${status}${requirement ? ` (${requirement.requirement})` : ''}`,
      description: `${to} verified the person token and minted a resource token (aa-resource+jwt) naming the scope it needs, the billing account, agent_jkt and presented_jti. Only the PS can redeem it.` };
    case 'auth_token_request': return { summary: `${from} → PS: resource token → ${status === 200 ? '200 auth token issued' : `${status} ${body.error ?? ''}`}`,
      description: status === 200 ? 'The PS verified the resource token against the resource\'s JWKS, matched presented_jti and agent_jkt, evaluated the request against the approved mission, and minted an aa-auth+jwt for this resource. This is where authorization is decided.'
        : `The PS evaluated the request against the mission and refused: ${body.detail ?? body.error}. Nothing reaches the resource.` };
    case 'auth_token_call': return { summary: `${from} → ${to}: signed request with auth token → ${status}`,
      description: status === 200 ? `${to} verified the auth token (issuer JWKS, aud, exp, cnf == signing key), then applied its own policy. It sees who is calling, on whose behalf and under which mission.`
        : `${to} refused the call: ${body.detail ?? body.error ?? status}.` };
    default: return { summary: `${from} → ${to}: ${status}`, description: '' };
  }
}

export async function runDemo(config, hooks) { return (await Demo.create(config, hooks)).run(); }
// For protocol tests that drive the parties directly. Call close() when done.
export function createLab(config = {}) { return Demo.create(config, {}); }
