---
title: 'Missions, consent and three tokens: how the AAuth person server decides'
published: false
devto: true
description: >-
  How Alice approves the work once at her person server, and how person tokens,
  resource tokens and auth tokens let that person server decide every hop
  against what she approved.
tags: 'security, authorization, oauth, javascript'
series: AAuth Network Lab
cover_image: >-
  https://raw.githubusercontent.com/darkedges/aauth-lab/main/docs/playground-screenshot.png
---

Part 2 ended with SearchCo answering `401 requirement=person-token`: it knows which agent is calling, and now wants to know who for. This part covers the rest of a hop, and the mission that every decision is checked against.

{% embed https://github.com/darkedges/aauth-lab %}

## The mission

Before any work starts, Alice's assistant proposes a **mission** to her person server (PS). It is a short, signed POST:

```json
{
  "description": "# Research a topic\n\nPlan the work, research, search sources and run compute, billed to my organization.",
  "tools": [{ "name": "Delegate", "description": "Hand research tasks to Relay operators" }],
  "resources": ["https://planner.example"],
  "relay": { "payer": "alice-org", "budget": 100, "scopes": { "https://search.example": ["search"], "…": [] } }
}
```

`description`, `tools` and `resources` come from the draft. `relay` is the lab's extension: who pays, how much, and which scopes the PS may issue to each company. The draft allows extra members, and section C.1.10 is explicit that `tools` and `resources` are a record of what the agent said it would do, not limits the PS has to enforce. The lab's PS enforces `relay` instead.

## Consent is a deferred response

Only Alice can approve a mission, and she isn't sitting inside the HTTP request. So the PS answers straight away with `202 Accepted`:

```http
HTTP/1.1 202 Accepted
AAuth-Requirement: requirement=interaction; url="https://ps.example/interact"; code="NTAY-S7A3"
Location: https://ps.example/pending/UAoyqZ00s8O-skbMstbB7w
Retry-After: 0
Cache-Control: no-store

{"status":"pending","requirement":"interaction","code":"NTAY-S7A3","timeout":600}
```

The assistant shows Alice the URL and the code. The code is eight Crockford base32 characters, so it is easy to read aloud and compare on screen. Meanwhile the assistant polls the `Location` with signed `GET` requests:

```text
GET /pending/…  → 202 {"status":"interacting"}   Alice has opened the page
GET /pending/…  → 200 { s256, mission, person_tokens }
```

The PS checks every poll is signed by the agent that made the original request, and answers `410 Gone` once the result has been collected. If Alice declines, the poll returns `403 denied` and the assistant stops.

The `200` carries the approved mission as base64url bytes, its `s256` (the SHA-256 of those exact bytes), and a person token for each resource the mission named. The assistant checks the hash against the bytes before using it:

```js
if (await digest(new TextDecoder().decode(base64url.decode(answer.data.mission))) !== answer.data.s256) throw new Error('Mission bytes do not match s256');
```

From here on, every token in the run carries `mission_s256`. That hash is how the PS, and anyone else who fetches the mission, knows which approval a request belongs to.

In the lab, Alice's browser session is simulated: she opens the URL and approves (or declines, if you pick that option). The `202`, the code and the signed polls are real.

## Token one: the person token

The person token says who the agent is acting for, at one specific resource. Here is the one ResearchCo presents to SearchCo:

```json
{ "alg": "Ed25519", "typ": "aa-person+jwt", "kid": "ps-1" }
{
  "iss": "https://ps.example",
  "dwk": "aauth-person.json",
  "aud": "https://search.example",
  "sub": "0_I1miUFWgU1z6VmwgCDnI",
  "cnf": { "jwk": { "…": "ResearchCo's signing key" } },
  "mission_s256": "UBwsblTo4WYic7rJjRutN63H4ftxVCWS-ll8eehE6jE",
  "jti": "pt-4c1eb61e",
  "exp": 1792880414
}
```

Two details matter:

- **`sub` is directed.** The PS gives Alice a different identifier at each resource, so SearchCo and ComputeCo can't match her up between them.
- **It authorizes nothing.** A person token has no scope. It only identifies the person, so the resource can say what it needs.

## Token two: the resource token

ResearchCo repeats its call with the person token. SearchCo verifies it, then answers with a second challenge:

```http
HTTP/1.1 401 Unauthorized
AAuth-Requirement: requirement=auth-token; resource-token="eyJhbGciOiJFZDI1NTE5IiwidHlwIjoiYWEtcmVzb3…"
```

The resource token is SearchCo's request to the PS, addressed to it (`aud`):

```json
{
  "iss": "https://search.example",
  "aud": "https://ps.example",
  "sub": "0_I1miUFWgU1z6VmwgCDnI",
  "scope": "search email",
  "account": "alice-org",
  "agent_jkt": "z6mEDnxVP4k0Op6Yn9LN7-DS8ucrLW0m3MXBj5eqnE4",
  "presented_jti": "pt-4c1eb61e",
  "mission_s256": "UBwsblTo4WYic7rJjRutN63H4ftxVCWS-ll8eehE6jE",
  "exp": 1792879815
}
```

It names the scope SearchCo needs, the billing account the caller asked for, the thumbprint of the caller's key (`agent_jkt`) and the person token it was issued against (`presented_jti`). It lives for five minutes. The lab builds it with one library call:

```js
const resourceToken = await createResourceToken({ resource: this.id, audience: token.iss, presentedToken: token,
  agentJkt: signature.thumbprint, scope, account, kid: this.kid }, sign);
```

## Token three: the auth token

ResearchCo sends the resource token and the person token to the PS. This is where authorization is decided. The PS first checks the resource token is genuine and matches what was presented (section 6.7.2 of the draft):

- the resource token is signed by the resource named in its `iss`, and addressed to this PS;
- `agent_jkt` is the key signing this request;
- the person token was issued by this PS, to the resource that issued the resource token, bound to the same key;
- `presented_jti`, `sub`, `mission_s256` and `tenant` all match.

The `mission_s256` check matters more than it looks. Without it, an agent could ask a resource for a token, strip the mission hash, and get an auth token that isn't bound to any approval. The lab has a test for exactly that.

Then the PS applies its own policy to the mission. In the lab, that means two checks from the `relay` extension:

```js
for (const scope of resourceToken.scope.split(' ').filter(value => !IDENTITY_SCOPES.has(value))) {
  checks.push(row(`relay.scopes[${label}] ∋ "${scope}"`, allowed.includes(scope), 'PS policy · lab extension', allowed));
}
checks.push(row(`account "${resourceToken.account}" == relay.payer "${mission.blob.relay.payer}"`,
  resourceToken.account === mission.blob.relay.payer, 'PS policy · lab extension'));
```

If both pass, the PS mints the auth token:

```json
{ "typ": "aa-auth+jwt" }
{
  "iss": "https://ps.example",
  "aud": "https://search.example",
  "sub": "0_I1miUFWgU1z6VmwgCDnI",
  "scope": "search email",
  "account": "alice-org",
  "email": "alice@alice-org.example",
  "mission_s256": "UBwsblTo4WYic7rJjRutN63H4ftxVCWS-ll8eehE6jE",
  "cnf": { "jwk": { "…": "ResearchCo's signing key" } },
  "exp": 1792880414
}
```

The PS released `email` because SearchCo asked for the `email` scope. The token can't outlive the agent token, the person token or the mission.

ResearchCo presents it on the third call, and SearchCo checks it against its own policy: does it accept work for this person, does the scope include the action, does it offer that action, and does the account match the payer in the request.

## Three scenarios, three places they fail

**Change payer.** ResearchCo asks SearchCo to bill `mallory-org`. SearchCo dutifully puts `account: mallory-org` in the resource token, and the PS refuses:

```json
{"error":"denied","detail":"Mission evaluation failed: account \"mallory-org\" == relay.payer \"alice-org\"","mission_checks":[…]}
```

SearchCo never receives an auth token, so it can't be talked into billing anyone.

**Forbidden operation.** ResearchCo asks for `delete`. SearchCo really does offer delete, but the mission only allows `search` there, so the PS refuses with `relay.scopes[SearchCo] ∋ "delete"` failing.

**Untrusted issuer.** ResearchCo skips the PS and presents an auth token signed by a rogue key, claiming to come from Alice's PS. SearchCo fetches the PS's real keys, the signature fails, and the call is rejected. This is the one scenario the receiver catches rather than the PS.

All errors use the draft's format: `application/problem+json` with an AAuth `error` code, and `denied` for policy refusals.

## Next

So far every hop looks like the Assistant calling PlannerCo. Part 4 covers what changes when PlannerCo passes work on to ResearchCo, and ResearchCo to SearchCo: call chaining with `upstream_token`.
