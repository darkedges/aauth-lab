// Live hop: the Assistant's first hop, run once in the simulated lab and once
// against real services with the agent identity set up by @aauth/bootstrap.
//
//   pnpm live [--prompt-consent] [--resource <url>]
//
// The live side signs as your agent (~/.aauth/config.json, key in the OS
// keychain), asks your person server for tokens and calls a real resource. The
// lab's operators exist only in-process, so a real PS cannot address them: the
// live hop goes to whoami.aauth.dev instead of PlannerCo.
import { mkdir, writeFile } from 'node:fs/promises';
import { createAAuthFetch } from '@aauth/agent';
import { createAgentToken, readConfig } from '@aauth/local-keys';
import { decodeJwt, decodeProtectedHeader } from 'jose';
import { runDemo } from '../lib/relay.js';

const args = process.argv.slice(2);
const flag = name => args.includes(name);
const option = (name, fallback) => (args.includes(name) ? args[args.indexOf(name) + 1] : fallback);
const resource = option('--resource', 'https://whoami.aauth.dev?scope=openid+profile');

const [agentUrl, agent] = Object.entries(readConfig().agents ?? {})[0] ?? [];
if (!agent) {
  console.error('No agent identity found. Run `npx @aauth/bootstrap skill setup` first (see AGENTS.md).');
  process.exit(1);
}

// ── Simulated: the Assistant → PlannerCo hop of the happy path ────────────────
const lab = await runDemo({ scenario: 'happy' });
const labHop = lab.debug.filter(entry => entry.task_index === null && (entry.from === 'assistant' || entry.transport === 'person'))
  .map(entry => ({ stage: entry.stage, method: entry.request.method, status: entry.status, signed: entry.transport === 'virtual-http',
    to: entry.to, requirement: entry.requirement?.requirement ?? null, summary: entry.summary }));
const labAuth = lab.root_tokens.auth_token?.payload ?? {};

// ── Live: record every request the reference client sends ─────────────────────
const exchanges = [];
const network = globalThis.fetch;
const text = body => (body == null ? null : typeof body === 'string' ? body : new TextDecoder().decode(body));
globalThis.fetch = async (input, init = {}) => {
  const request = new Request(input, init), started = Date.now();
  const response = await network(input, init);
  exchanges.push({ method: request.method, url: request.url, headers: Object.fromEntries(request.headers), body: text(init.body),
    status: response.status, response_headers: Object.fromEntries(response.headers), response_text: await response.clone().text(), ms: Date.now() - started });
  return response;
};

const psMetadata = await (await network(`${agent.personServerUrl}/.well-known/aauth-person.json`)).json();
const aauthFetch = createAAuthFetch({
  getKeyMaterial: () => createAgentToken({ agentUrl, personServerUrl: agent.personServerUrl }),
  personServerUrl: agent.personServerUrl,
  personServerMetadata: psMetadata,
  // AAuth-Capabilities: this agent can send the person to an interaction URL (§11.7).
  capabilities: ['interaction'],
  ...(flag('--prompt-consent') ? { prompt: 'consent' } : {}),
  onInteraction: (url, code) => console.log(`\nApprove in your browser: ${url}?code=${code}\nCode: ${code}\nWaiting for the person server…\n`),
});
const response = await aauthFetch(resource);
const result = await response.text();
globalThis.fetch = network;

const typOf = headers => {
  const jwt = /jwt="([^"]+)"/.exec(headers['signature-key'] ?? '')?.[1];
  return jwt ? decodeProtectedHeader(jwt).typ : null;
};
// Name each live exchange with the lab's stage vocabulary.
const stageOf = exchange => {
  const url = new URL(exchange.url);
  if (exchange.url.startsWith(psMetadata.person_token_endpoint)) return 'person_token_request';
  if (exchange.url.startsWith(psMetadata.auth_token_endpoint)) return 'auth_token_request';
  if (url.origin === agent.personServerUrl && exchange.method === 'GET' && url.pathname.includes('/pending/')) return 'consent_poll';
  if (url.pathname.startsWith('/.well-known/') || url.pathname.endsWith('jwks.json')) return 'discovery';
  return { 'aa-agent+jwt': 'agent_token_call', 'aa-person+jwt': 'person_token_call', 'aa-auth+jwt': 'auth_token_call' }[typOf(exchange.headers)] ?? 'other';
};
const liveHop = exchanges.map(exchange => ({ stage: stageOf(exchange), method: exchange.method, status: exchange.status,
  signed: Boolean(exchange.headers['signature-input']), to: new URL(exchange.url).host,
  requirement: /requirement=([\w-]+)/.exec(exchange.response_headers['aauth-requirement'] ?? '')?.[1] ?? null }));
const authToken = (() => {
  const call = exchanges.findLast(exchange => typOf(exchange.headers) === 'aa-auth+jwt');
  return call ? decodeJwt(/jwt="([^"]+)"/.exec(call.headers['signature-key'])[1]) : {};
})();

// ── Report ────────────────────────────────────────────────────────────────────
const line = hop => `${hop.signed ? 'signed' : 'person'} ${hop.method.padEnd(4)} ${hop.stage.padEnd(21)} → ${String(hop.status).padEnd(3)} ${hop.requirement ?? ''}`.trimEnd();
const count = (hop, test) => hop.filter(test).length;
const stats = (hop, psHost) => ({
  'signed requests': count(hop, entry => entry.signed && entry.stage !== 'discovery'),
  'to the person server': count(hop, entry => entry.signed && entry.to === psHost),
  'consent polls': count(hop, entry => entry.stage === 'consent_poll'),
  '401 challenges': count(hop, entry => entry.status === 401),
});
const labStats = stats(labHop, 'ps'), liveStats = stats(liveHop, new URL(agent.personServerUrl).host);
const keys = payload => Object.keys(payload).sort().join(', ');

console.log(`\nLab · Assistant → PlannerCo (simulated PS, mission ${lab.mission.s256.slice(0, 10)}…)`);
for (const hop of labHop) console.log(`  ${line(hop)}`);
console.log(`\nLive · ${agent.agentId} → ${new URL(resource).host} (PS ${agent.personServerUrl}, no mission: the PS publishes no mission endpoint)`);
for (const hop of liveHop.filter(entry => entry.stage !== 'discovery')) console.log(`  ${line(hop)}`);
console.log('\n                         lab   live');
for (const name of Object.keys(labStats)) console.log(`  ${name.padEnd(22)} ${String(labStats[name]).padStart(4)} ${String(liveStats[name]).padStart(6)}`);
console.log(`\nAuth token claims\n  lab:  ${keys(labAuth)}\n  live: ${keys(authToken)}`);
console.log(`\nLive response: HTTP ${response.status}${response.ok ? '' : ` ${result}`}`);

await mkdir(new URL('../live/', import.meta.url), { recursive: true });
const file = new URL(`../live/live-${new Date().toISOString().replaceAll(':', '-')}.json`, import.meta.url);
await writeFile(file, JSON.stringify({ resource, agent: agent.agentId, person_server: agent.personServerUrl, lab: { hop: labHop, stats: labStats, auth_token_claims: Object.keys(labAuth) },
  live: { hop: liveHop, stats: liveStats, exchanges, response: { status: response.status, body: result } } }, null, 2));
console.log(`Full live trace (contains your tokens and profile; keep it local): ${decodeURIComponent(file.pathname.replace(/^\/(\w:)/, '$1'))}`);
