import { initDebug } from './debug.js';
import { initPlayback, renderComparison, lessons } from './playground.js';
const $ = (selector) => document.querySelector(selector);
const names = { planner: 'PlannerCo', research: 'ResearchCo', search: 'SearchCo', compute: 'ComputeCo' };
const descriptions = {
  happy: 'Every hop gets its own PS-issued auth token through call chaining. Three operations settle for 40 credits.',
  payer_swap: 'ResearchCo asks SearchCo to bill mallory-org. SearchCo names that account in its resource token; the person server must refuse it.',
  forbidden: 'ResearchCo asks SearchCo to delete. SearchCo offers delete, but Alice’s mission never approved that tool.',
  untrusted: 'ResearchCo skips the person server and presents an auth token signed by a rogue key that claims the PS as issuer.',
  overspend: 'After 5 credits for research, search and compute both request 60 credits. Only one reservation can fit in a 100-credit budget.',
  retry: 'The search call is sent twice with the same operation ID, reusing the cached auth token. The ledger must charge it only once.',
  failure: 'Search reserves 10 credits, then fails. Its reservation is released without a charge.'
};
let edges = [['planner', 'research'], ['research', 'search'], ['planner', 'compute']];
let latest = null;
let runHistory = [];
const debuggerView = initDebug($('#debug'), (result, taskIndex) => {
  render(result); $('#task-select').value = taskIndex === null || taskIndex === undefined ? 'root' : String(taskIndex); showTask(); switchTab('decision');
});
const playback = initPlayback($('.network-panel'), ledger => {
  for (const metric of ['budget', 'settled', 'reserved', 'available']) $(`#metric-${metric}`).replaceChildren(document.createTextNode(String(ledger[metric])), el('small', 'cr'));
});
$('.network-panel .playback').before($('.ledger-strip'));
const lessonBox = el('div', undefined, 'lesson-box');
const lessonLabel = el('label', 'Guided exercise'); lessonLabel.htmlFor = 'lesson';
const lessonSelect = el('select'); lessonSelect.id = 'lesson';
for (const [key, lesson] of Object.entries(lessons)) { const option = el('option', lesson.label); option.value = key; lessonSelect.append(option); }
const lessonText = el('p', lessons.free.text);
lessonBox.append(lessonLabel, lessonSelect, lessonText); $('.controls .panel-heading').after(lessonBox);
lessonSelect.onchange = () => {
  const lesson = lessons[lessonSelect.value]; lessonText.textContent = lesson.text;
  if (lessonSelect.value === 'free') return;
  $('#scenario').value = lesson.scenario; $('#budget').value = '100'; $('#requester').value = 'alice';
  edges = [['planner', 'research'], ['research', 'search'], ['planner', 'compute']];
  document.querySelectorAll('#accepts input').forEach(input => { input.checked = true; });
  if (lessonSelect.value === 'trust') edges = edges.filter(edge => edge[1] !== 'search');
  if (lessonSelect.value === 'requester') $('#accepts input[data-operator="search"][data-requester="alice"]').checked = false;
  renderEdges(); scenarioChanged();
};
function el(tag, text, className) { const item = document.createElement(tag); if (text !== undefined) item.textContent = text; if (className) item.className = className; return item; }
function renderEdges() {
  $('#edges').replaceChildren(...edges.map(([from, to], index) => {
    const row = el('div', undefined, 'edge');
    const remove = el('button', '×'); remove.type = 'button'; remove.setAttribute('aria-label', `Remove trust from ${names[from]} to ${names[to]}`);
    remove.onclick = () => { edges.splice(index, 1); renderEdges(); markChanged(); };
    row.append(el('span', names[from]), el('span', '→', 'arrow'), el('span', names[to]), remove); return row;
  }));
  playback.updateTrust(edges);
}
for (const [id, name] of Object.entries(names)) {
  for (const select of ['#edge-from', '#edge-to']) { const option = el('option', name); option.value = id; $(select).append(option); }
  const row = el('div', undefined, 'requester-row'); row.append(el('span', name));
  for (const requester of ['alice', 'bob']) { const label = el('label'); const check = el('input'); check.type = 'checkbox'; check.checked = true; check.dataset.operator = id; check.dataset.requester = requester; check.setAttribute('aria-label', `${name} accepts ${requester}`); check.onchange = markChanged; label.append(check); row.append(label); }
  $('#accepts').append(row);
}
$('#edge-to').value = 'research';
$('#add-edge').onclick = () => { const from = $('#edge-from').value, to = $('#edge-to').value; if (from !== to && !edges.some(e => e[0] === from && e[1] === to)) { edges.push([from, to]); renderEdges(); markChanged(); } };
function markChanged() { if (latest) { $('#run-status').textContent = 'Settings changed · run again'; $('#run-status').className = 'status-chip'; } }
function scenarioChanged() { $('#scenario-description').textContent = descriptions[$('#scenario').value]; markChanged(); }
$('#scenario').onchange = scenarioChanged; $('#budget').oninput = markChanged; $('#requester').onchange = markChanged;
function switchTab(id) {
  if (id !== 'debug') debuggerView.collapse();
  document.querySelectorAll('[data-tab]').forEach(button => button.setAttribute('aria-selected', String(button.dataset.tab === id)));
  document.querySelectorAll('.tab-panel').forEach(panel => panel.hidden = panel.id !== id);
  history.replaceState(null, '', `#${id}`);
}
const evidenceTabs = [...document.querySelectorAll('[data-tab]')];
evidenceTabs.forEach((button, index) => {
  button.id = `tab-${button.dataset.tab}`; button.setAttribute('aria-controls', button.dataset.tab);
  $(`#${button.dataset.tab}`).setAttribute('aria-labelledby', button.id);
  button.onclick = () => switchTab(button.dataset.tab);
  button.onkeydown = event => {
    const target = event.key === 'ArrowRight' ? (index + 1) % evidenceTabs.length : event.key === 'ArrowLeft' ? (index + evidenceTabs.length - 1) % evidenceTabs.length : event.key === 'Home' ? 0 : event.key === 'End' ? evidenceTabs.length - 1 : null;
    if (target !== null) { event.preventDefault(); evidenceTabs[target].focus(); switchTab(evidenceTabs[target].dataset.tab); }
  };
});
function details(target, title, value) { const disclosure = el('details'); disclosure.append(el('summary', title), el('pre', typeof value === 'string' ? value : JSON.stringify(value, null, 2))); target.append(disclosure); }
function origin(source) {
  if (source === 'mission' || source === 'call chaining' || source.startsWith('PS policy')) return 'delegation';
  if (source.includes('policy')) return 'receiver';
  if (source.startsWith('PS-signed')) return 'issuer';
  return 'call';
}
function checkList(target, title, caption, checks) {
  target.append(el('h3', title)); if (caption) target.append(el('p', caption, 'code-caption'));
  const list = el('div', undefined, 'grounded-rule');
  for (const check of checks) {
    const item = el('div', undefined, `rule-row ${check.present ? 'rule-pass' : 'rule-fail'}`);
    const source = el('span', check.source, 'rule-source'); source.dataset.origin = origin(check.source);
    item.append(el('span', check.present ? '✓' : '×', 'rule-mark'), el('code', check.logic), source);
    if (!check.present) item.append(el('span', check.available?.length ? `Available: ${check.available.join(', ')}` : 'No matching value', 'rule-available'));
    list.append(item);
  }
  target.append(list);
}
const headlines = { verification: 'Verification denied', identity: 'Caller refused on identity', ps: 'Person server refused', billing: 'Credit reservation denied', policy: 'Receiver policy denied' };
function showDecision(target, task) {
  const decision = task.decision;
  if (!decision) return;
  const headline = decision.phase === 'ingress' ? (decision.permitted ? 'Root request accepted' : 'Root request denied')
    : task.status === 'denied' ? headlines[decision.phase] ?? 'Denied'
    : task.status === 'released' ? 'Authorized · credits released' : task.status === 'reused' ? 'Authorized · original charge reused' : 'Authorized and settled';
  const banner = el('div', undefined, `decision-banner ${task.status === 'denied' ? 'decision-fail' : 'decision-pass'}`);
  banner.append(el('strong', headline), el('span', decision.summary ?? '')); target.append(banner);
  const call = decision.call_values;
  if (call) target.append(el('p', `Signed call to ${call.service}: action ${call.action}, payer ${call.payer}${call.amount !== undefined ? `, ${call.amount} credits` : ''}. The auth token does not name the calling agent (§C.1.6).`, 'decision-values'));
  const provenance = el('div', undefined, 'provenance-legend');
  for (const [key, label] of [['issuer', 'PS-signed auth token'], ['receiver', 'Receiver · local policy'], ['call', 'HTTP signature · agent identity'], ['delegation', 'Mission · person server']]) {
    const badge = el('span', label); badge.dataset.origin = key; provenance.append(badge);
  }
  target.append(provenance);
  if (decision.identity_rows?.length && decision.phase !== 'identity') checkList(target, 'Identity-based request · agent token (§4.2.1)', 'Caller trust is decided here, on the one request that carries the agent token. No later token names the agent.', decision.identity_rows);
  if (decision.ps_checks?.length) checkList(target, 'Person server · mission evaluation', 'The PS verified the resource token against the presented token, then applied its supervision policy to the mission. relay.* is a lab extension of the mission blob; approved_tools is a record, not a limit (§C.1.10). The receiver never saw an auth token.', decision.ps_checks);
  if (decision.rows?.length) checkList(target, decision.phase === 'ingress' ? 'PlannerCo · ingress checks' : `${names[task.provider] ?? 'Receiver'} · checks on the presented request`,
    decision.phase === 'verification' ? 'Token verification failed, so local policy was never evaluated.' : 'Each row was evaluated by the receiving operator on its own origin.', decision.rows);
  if (decision.billing) {
    const billing = decision.billing; target.append(el('h3', 'Clearinghouse budget decision'));
    const card = el('div', undefined, `billing-decision ${billing.passed ? 'rule-pass' : 'rule-fail'}`);
    card.append(el('strong', `${billing.passed ? '✓' : '×'} ${billing.requested ?? '?'} credits requested · ${billing.available_before ?? '?'} available`), el('span', billing.reason)); target.append(card);
  } else if (task.status === 'denied') target.append(el('p', 'No reservation was attempted because authorization failed.', 'code-caption'));
}
function tokenDetails(target, tokens = {}) {
  const labels = { person_token: 'Person token · aa-person+jwt', resource_token: 'Resource token · aa-resource+jwt', auth_token: 'Auth token · aa-auth+jwt' };
  for (const [key, label] of Object.entries(labels)) if (tokens[key]) details(target, label, { header: tokens[key].header, payload: tokens[key].payload });
}
function showTask() {
  if (!latest) return;
  const content = $('#decision-content'); content.replaceChildren();
  if ($('#task-select').value === 'root') {
    showDecision(content, { status: latest.root_decision.permitted ? 'settled' : 'denied', decision: latest.root_decision });
    if (latest.mission) {
      details(content, `Mission blob · mission_s256 ${latest.mission.s256}`, latest.mission.blob);
      details(content, `Person server mission log · ${latest.mission.log.length} entries`, latest.mission.log);
    }
    tokenDetails(content, latest.root_tokens);
    details(content, 'Party identifiers and public JWKS', latest.parties); return;
  }
  const task = latest.tasks[Number($('#task-select').value)];
  content.append(el('p', `${names[task.caller]} → ${names[task.provider]} · ${task.operation_id} · ${task.status}`, 'code-caption'));
  showDecision(content, task);
  if (task.error) details(content, 'Detailed denial', task.error);
  tokenDetails(content, task.tokens);
  if (task.grant) details(content, 'Clearinghouse reservation grant (JWT)', task.grant);
  if (task.receipt) details(content, 'Provider-signed completion receipt (JWT)', task.receipt);
  const exchanges = latest.debug.filter(entry => entry.task_index === task.index && entry.stage !== 'discovery').map(entry => entry.summary);
  details(content, `HTTP exchanges for this task · ${exchanges.length}`, exchanges.join('\n'));
}
$('#task-select').onchange = showTask;
function renderGrant(result) {
  const grant = result.grant;
  const values = $('#grant-values'); values.replaceChildren();
  for (const [label, value] of [['Person', grant.requester], ['Payer', grant.payer], ['Budget', `${grant.budget} credits`], ['mission_s256', grant.request_id ?? '—'], ['Expires', grant.expires ?? '—']]) {
    const row = el('div', undefined, 'grant-fact'); row.append(el('span', label), el('code', String(value))); values.append(row);
  }
  values.append(el('div', 'SCOPES THE PS WILL ISSUE · relay.scopes (LAB EXTENSION)', 'grant-rights-label'));
  const rights = el('div', undefined, 'grant-rights'); grant.rights.forEach(right => rights.append(el('code', right, 'grant-chip'))); values.append(rights);
  const list = $('#delegation-values'); list.replaceChildren();
  for (const task of result.tasks) {
    const group = el('div', undefined, 'grant-delegation');
    group.append(el('strong', `${names[task.caller]} → ${names[task.provider]} · ${task.action}`));
    const auth = task.tokens?.auth_token?.payload;
    if (auth) {
      group.append(el('div', `${task.decision?.phase === 'verification' ? 'Presented auth token · verification failed' : 'Auth token issued by the person server'}`, 'grant-effective'));
      for (const claim of ['scope', 'account', 'sub', 'email']) if (auth[claim]) group.append(el('code', `${claim}: ${auth[claim]}`, 'grant-check'));
    } else group.append(el('div', task.decision?.phase === 'ps' ? 'No auth token: the person server refused' : task.decision?.phase === 'identity' ? 'No token requested: caller refused on identity' : 'Cached auth token reused', 'grant-effective'));
    list.append(group);
  }
  if (!result.tasks.length) list.append(el('p', 'No tasks were delegated in this run.', 'muted'));
}
function render(result) {
  latest = result; $('#export').disabled = false;
  const denied = result.tasks.filter(t => t.status === 'denied').length + (result.root_decision.permitted ? 0 : 1);
  $('#run-status').textContent = denied ? `Complete · ${denied} denied` : 'Run complete'; $('#run-status').className = 'status-chip done';
  $('#requester-name').textContent = result.requester === 'alice' ? 'Alice' : 'Bob'; $('.requester-node .node-icon').textContent = result.requester[0].toUpperCase();
  const stats = $('#exchange-stats'); stats.replaceChildren();
  for (const [value, label] of [[result.stats.signed_requests, 'signed HTTP requests'], [result.stats.person_server_requests, 'to the person server'], [result.stats.challenges, '401 challenges'], [result.stats.key_discovery_requests, 'key discovery fetches']]) {
    const item = el('span'); item.append(el('strong', String(value)), document.createTextNode(label)); stats.append(item);
  }
  renderGrant(result);
  for (const metric of ['budget', 'settled', 'reserved', 'available']) $(`#metric-${metric}`).replaceChildren(document.createTextNode(String(result.ledger[metric])), el('small', 'cr'));
  for (const [operator] of Object.entries(names)) {
    const node = $(`.node[data-operator="${operator}"]`); const task = result.tasks.findLast(t => t.provider === operator);
    node.classList.remove('settled', 'denied', 'released', 'reused');
    if (task) { node.classList.add(task.status); node.querySelector('.node-state').textContent = task.status[0].toUpperCase() + task.status.slice(1); }
    else { node.querySelector('.node-state').textContent = operator === 'planner' ? (result.root_decision.permitted ? 'Root task' : 'Denied') : 'Skipped'; }
  }
  $('#search-price').textContent = `Search · ${result.scenario === 'overspend' ? 60 : 10} cr`;
  $('#compute-price').textContent = `Compute · ${result.scenario === 'overspend' ? 60 : 25} cr`;
  const activity = el('div', undefined, 'activity-list');
  result.events.forEach(event => { const row = el('div', undefined, 'event'); const message = el('div', event.message, 'event-message'); message.append(el('small', names[event.operator] || 'Person server / clearinghouse')); row.append(el('span', String(event.index).padStart(2, '0'), 'event-index'), el('span', event.kind, `event-type ${event.kind}`), message); activity.append(row); });
  $('#activity').replaceChildren(activity);
  const select = $('#task-select'); select.replaceChildren(); const root = el('option', 'Mission / original request'); root.value = 'root'; select.append(root);
  result.tasks.forEach((task, i) => { const option = el('option', `${names[task.provider]} · ${task.action} · ${task.status}`); option.value = i; select.append(option); });
  const firstDenial = result.tasks.findIndex(t => t.status === 'denied');
  const searchTask = result.tasks.findIndex(t => t.provider === 'search');
  select.value = result.tasks.length ? String(firstDenial >= 0 ? firstDenial : searchTask >= 0 ? searchTask : 0) : 'root';
  showTask(); renderLedger(); playback.render(result);
  const historyIndex = runHistory.findIndex(run => run.request_id === result.request_id);
  renderComparison($('#compare'), result, runHistory[historyIndex + 1]);
  if ($('#debug').hidden && $('#compare').hidden) switchTab('decision');
}
function renderLedger() {
  const content = $('#ledger-content'); content.replaceChildren();
  content.append(el('p', `Payer: ${latest.payer} · Mission: ${latest.request_id}`, 'code-caption'));
  const table = el('table', undefined, 'ledger-table'); const head = el('thead'); const header = el('tr'); ['Operation', 'Operator', 'Credits', 'State'].forEach(text => header.append(el('th', text))); head.append(header); table.append(head);
  const body = el('tbody'); latest.ledger.operations.forEach(operation => { const row = el('tr'); [operation.id, names[operation.provider], String(operation.amount), operation.status].forEach(text => row.append(el('td', text))); body.append(row); }); table.append(body); content.append(table);
  const balances = el('div', undefined, 'balance-pills'); Object.entries(latest.ledger.balances).forEach(([operator, amount]) => balances.append(el('span', `${names[operator]} +${amount} cr`))); content.append(balances);
  if (!latest.ledger.operations.length) content.append(el('p', 'No reservations or charges were made.', 'code-caption'));
  latest.ledger.operations.forEach(operation => details(content, `${names[operation.provider]} · reservation and receipt · ${operation.id}`, operation));
}
document.querySelectorAll('.node[data-operator]').forEach(node => node.onclick = () => { switchTab('decision'); if (latest) { const index = latest.tasks.findLastIndex(t => t.provider === node.dataset.operator); $('#task-select').value = index === -1 ? 'root' : String(index); showTask(); } });
$('#run').onclick = async () => {
  if (!$('#budget').reportValidity()) return;
  const accepts = {}; for (const operator of Object.keys(names)) accepts[operator] = [...document.querySelectorAll(`#accepts input[data-operator="${operator}"]:checked`)].map(input => input.dataset.requester);
  const config = { scenario: $('#scenario').value, budget: Number($('#budget').value), requester: $('#requester').value, edges, accepts };
  $('#run').disabled = true; $('#run').textContent = 'Signing & settling…'; $('#error').hidden = true;
  try { const result = await debuggerView.run(config); runHistory.unshift(result); runHistory = runHistory.slice(0, 10); render(result); }
  catch (error) { $('#error').textContent = error.message; $('#error').hidden = false; }
  finally { $('#run').disabled = false; $('#run').replaceChildren(document.createTextNode('Run network'), el('span', '↗')); }
};
$('#export').onclick = () => { const url = URL.createObjectURL(new Blob([JSON.stringify(latest, null, 2)], { type: 'application/json' })); const a = el('a'); a.href = url; a.download = `relay-aauth-${latest.request_id}.json`; a.click(); setTimeout(() => URL.revokeObjectURL(url), 1000); };
renderEdges(); scenarioChanged();
if (['debug', 'compare'].includes(location.hash.slice(1))) switchTab(location.hash.slice(1));
$('#run').click();
