# Biscuit vs AAuth on the same use cases

Both labs run the same network:

- **Operators:** Alice → PlannerCo → ResearchCo → SearchCo, and PlannerCo → ComputeCo.
- **Shared rules:** the same clearinghouse, the same seven scenarios and the same trust/requester editor.
- **Outcomes:** every scenario settles the same credits in both (40 / 30 / 30 / 30 / 65 / 40 / 30).

What differs is *where* each decision is made and *what it costs*.

## The one-line difference

- **Biscuit** puts authority **in the token**. The clearinghouse mints a root token once. Each intermediary narrows it offline by appending blocks, and each receiver decides locally with Datalog.
- **AAuth** puts authority **in the person server**. Every hop asks Alice's PS for a fresh, key-bound auth token. The PS decides against the approved mission, and receivers verify the token and apply local policy.

## Scenario by scenario: where the denial happens

| Scenario | Biscuit lab | AAuth lab |
| --- | --- | --- |
| Change payer | SearchCo's Datalog: `payer("alice-org")` vs `billing_payer("mallory-org")` | **PS refuses to issue**: resource token `account` ≠ mission `payer`. SearchCo never sees an auth token. |
| Forbidden operation (`delete`) | SearchCo's Datalog: no `right("delete")`, and the delegation block `check if action("search")` fails | **PS refuses** under its own supervision policy: `delete` ∉ the mission's `relay.scopes` for SearchCo, even though SearchCo offers it. AAuth's own `approved_tools` is explicitly not enforced (§C.1.10), so this rule is a lab extension. |
| Untrusted issuer | Token signature fails against the pinned root public key (offline) | Auth token signature fails against the PS JWKS fetched from `{iss}/.well-known/aauth-person.json` (online) |
| Remove caller trust | SearchCo's Datalog: `trusts_caller` row missing, evaluated **after** token checks, and binding on every call | SearchCo returns `403` on the **first, identity-only** request. But only that request names the agent (§C.1.6): an agent that goes straight to a person token is never identified and is served (see `tests/conformance.test.mjs`). |
| Requester not accepted | Datalog `accepts_requester("alice")`, using the requester string from the token | Local check on the PS-vouched `email` claim, released because the resource asked for scope `email` |
| Budget race / retry / failure | Clearinghouse: identical in both | Clearinghouse: identical. The retry also reuses the cached auth token, so the second hop needs no PS round trip. |

## Measured on one happy-path run

| | Biscuit lab | AAuth lab |
| --- | ---: | ---: |
| Network calls to the issuer after minting | 0 | 16 (PS), including 2 consent polls |
| Recorded exchanges / evaluations | 13 internal evaluations | 40 signed HTTP requests, including 14 `401` challenges |
| Key-discovery fetches | 0 (root key pinned) | 23 (`.well-known` + JWKS) |
| Credential the SearchCo call carries | 1,008-char Biscuit (3 blocks), plus ~3 KB of signed call and delegation envelopes the lab had to invent | 810-char auth token in `Signature-Key`, plus 94/103-char `Signature`/`Signature-Input` |
| Mean run time (Node, in-process) | ~35 ms | ~130 ms |

Both labs run every party in one process, so these numbers count messages, not network latency. In a real deployment, every AAuth PS call and discovery fetch is a network round trip, and caching mitigates the discovery fetches.

## Analysis

### 1. Delegation narrowing: offline attenuation vs a central decision

Biscuit's defining feature is that ResearchCo can narrow PlannerCo's grant to `action("search")` **without asking anyone**, and SearchCo can check the result offline. AAuth has no equivalent. Draft -11 states that downstream scope "is not required to be a subset of upstream scope". The PS governs each hop through the mission, and the auth token carries "no agent identifier and no delegation chain". An intermediary therefore cannot constrain what its sub-delegate may do; only the PS (the mission) and the receiver (local policy) can.

- **Biscuit is better when** intermediaries need to restrict authority for their own sub-delegates, when the issuer must not be on the hot path, or when work must proceed offline or across partitions.
- **AAuth is better when** you want one place, accountable to the person, that sees and decides every hop.

### 2. Who is calling: bolted on vs built in

Biscuit blocks do not identify their author, and Biscuit tokens are bearer tokens. The Biscuit lab therefore had to invent two things:

- a separate Ed25519 signature over every call;
- signed delegation envelopes chained by hash.

The receiver and the clearinghouse re-verify both. AAuth provides proof of possession natively:

- Every request is RFC 9421-signed.
- Every token is `cnf`-bound to the signing key, so a stolen token is useless without the key.
- An intermediary signs with its own agent token.

That is AAuth's clearest advantage over the Biscuit lab. **Caller identity is a different matter.** AAuth deliberately keeps the agent's identity away from resources in three-party mode: no person, resource or auth token names it, so that a person's relationship with a resource survives a change of agent (§C.1.6). A resource can refuse an agent on the identity-only request, but nothing forces an agent to make that request first. The Biscuit lab's per-receiver `trusts_caller` rule has no binding equivalent; in AAuth that policy belongs to the person server, which sees every hop. The lab's clearinghouse needs to know which operator bills, so it uses a lab-defined, key-bound provider assertion.

### 3. The person in the loop

Biscuit has no notion of a person or consent. The root token appears with `requester("alice")` already asserted. AAuth makes Alice's approval of a mission a protocol step. Interactive consent uses `202` plus an interaction URL, which this lab simulates. Every later token is bound to that mission by `mission_s256`, and the PS keeps a **mission log** of every token request and denial, an audit trail the Biscuit lab spreads across tokens and envelopes. AAuth also issues a **directed `sub` per resource**, so SearchCo and ComputeCo cannot correlate Alice by identifier. Every Biscuit receiver sees the same `requester("alice")` fact.

### 4. Policy expressiveness

Biscuit gives every party the same language (Datalog) for token checks and receiver policy, and the decision is explainable fact by fact. AAuth defines no policy language:

- The PS's mission evaluation is implementation-defined. Here it is a handful of set-membership checks.
- Receiver policy is application code.

The UI shows the same kind of pass/fail rows for both labs, but in AAuth those rows are the lab's own presentation, not a protocol artifact.

### 5. Availability, latency and revocation

AAuth puts the PS online at every hop:

- 16 PS calls and 23 discovery fetches for a three-operation job;
- the PS is a dependency for liveness;
- revocation is simple: the PS stops issuing, and tokens live at most an hour (here, no longer than the mission).

Biscuit makes the reverse trade:

- no issuer on the hot path;
- revocation needs revocation IDs distributed to every verifier;
- a leaked token is replayable until it expires, unless you add PoP as this lab did.

### 6. Payer protection specifically

In Biscuit the payer is an immutable fact in the root block, and every receiver must remember to compare it with the call. In this AAuth lab the payer lives in the mission at the PS, as a lab extension member (`relay.payer`); AAuth defines `account` but not payers or budgets:

- The PS refuses any token whose `account` differs from the mission payer.
- The clearinghouse takes the payer from the PS-signed `account` claim rather than from the request.

A receiver that forgets the check cannot redirect billing. The trade-off is that the payer rule is enforced by PS implementation, not by a standard.

## Checked against a live person server

The `AGENTS.md` walkthrough ran on 2026-10-24 with a real agent (`aauth:local@agent.demos.darkedges.com`), a real PS (`person.hello.coop`) and a real resource (`whoami.aauth.dev`), using `@aauth/fetch` 4.0.0. What it confirmed and what it added:

| | Live run | This lab |
| --- | --- | --- |
| Order of challenges | Agent token → `401 requirement=person-token` → person token → `401 requirement=auth-token` with resource token → auth token | Same order at every hop |
| Where the person consents | At the **person token** request: `202` + `requirement=interaction`, then polling the pending URL until `200` | Once, at mission approval: `202` + `requirement=interaction`, then polling until `200` (the person's browser session is simulated) |
| Auth token request after consent | `202 requirement=approval` (the PS decides without the person), then `200` after one poll | `200` immediately, or `403 denied` from the PS's policy |
| Agent identity at the resource | Seen only on the agent-token call. The final response names the person, not the agent. | Same (§C.1.6) |
| Agent identity at the PS | The person token carries `agent_id`, a Hello claim not defined in draft -11 | The PS records which agent each token was issued to |
| Token lifetimes | Person token and auth token both end at the agent token's `exp` | Same clamping (agent token, upstream token, mission) |
| Scope versus claims | Resource token asked for `whoami openid profile`; the auth token carries `scope: "whoami"` plus `name`, `email` and `email_verified` claims | Scope names the operation (`search`); the PS releases `email` when the resource asks for it |
| Resource token extras | `person_token_jti` beside `presented_jti`, which is not in draft -11 | `presented_jti` only |

Two conclusions for the comparison:

- **Caller identity.** The live run is direct evidence for §2 above. The PS knows the agent, but the resource that served the person never learns which agent called. A Biscuit-style "receiver trusts this caller" rule has to live at the PS or on the identity-only request.
- **Cost.** The lab now includes the consent round trip and its polls, but it answers each poll at once. A live PS holds polls open (`Prefer: wait=45`) while the person decides, and may defer later requests with `requirement=approval`. The 16 PS calls per run measured above are a lower bound for a deployment.

`pnpm live` repeats this check on demand: it runs the Assistant's first hop in the lab and against `whoami.aauth.dev` with your own agent, and prints both sequences side by side. On 2026-10-24, with consent already on file at Hello, the live hop took 5 signed requests (2 to the PS, no polls), against the lab's 7 (4 to the PS, 2 of them polls). The difference is the mission: Hello has no mission endpoint, so the live hop asks for a person token directly, and the lab's hop gets its person token from the mission approval.

## When to pick which

| Need | Better fit |
| --- | --- |
| Offline or partition-tolerant verification, issuer off the hot path | Biscuit |
| Intermediaries narrowing authority for their own sub-delegates | Biscuit |
| Rich, uniform, explainable policy in tokens and at receivers | Biscuit |
| Proof of possession on every request and token, out of the box | AAuth |
| Receivers enforcing which agent may call them, on every call | Biscuit (AAuth keeps agent identity from resources by design, §C.1.6) |
| Person consent, mission scoping and a central audit log | AAuth |
| Per-resource pseudonymous user identifiers | AAuth |
| Fewest round trips | Biscuit |

They also combine well. AAuth can carry *who* (signed agent, person, mission) and Biscuit can carry *what* (offline-attenuable rights), for example as an AAuth resource that accepts a Biscuit as its scoped grant. These labs keep the two separate so the differences stay visible.
