---
title: 'Call chaining in AAuth: passing authority on with upstream tokens'
published: false
devto: true
description: >-
  How an AAuth intermediary hands work to the next company: upstream_token,
  what the person server verifies, why every hop gets a new identifier for the
  person, and what an intermediary can't do.
tags: 'security, authorization, oauth, distributedsystems'
series: AAuth Network Lab
cover_image: >-
  https://raw.githubusercontent.com/darkedges/aauth-lab/main/docs/playground-screenshot.png
---

Part 3 followed one hop: the Assistant calling PlannerCo with tokens from Alice's person server. But PlannerCo doesn't do the research itself. It hands it to ResearchCo, which hands the search to SearchCo. This part covers how authority travels down that chain.

{% embed https://github.com/darkedges/aauth-lab %}

## The problem

When ResearchCo calls SearchCo, it needs a person token and an auth token for SearchCo. But ResearchCo has never met Alice. No one connected ResearchCo to her person server, and Alice didn't approve anything with ResearchCo directly.

What ResearchCo does have is the auth token PlannerCo presented to it. That token proves Alice's PS authorized PlannerCo to call ResearchCo, under Alice's mission. AAuth's answer is to show that token to the PS as evidence.

## upstream_token

When an intermediary needs a token for the next resource, it passes the token it received as `upstream_token`. It signs the request with its own agent token, as always:

```json
POST /person-token
Signature-Key: sig=jwt;jwt="<ResearchCo's agent token>"

{ "resource": "https://search.example", "upstream_token": "<the auth token PlannerCo presented>" }
```

There is no `mission_s256` in this request. The upstream token already carries it.

It sends the same `upstream_token` again when it exchanges SearchCo's resource token for an auth token, alongside the resource token and the person token it presented:

```json
{ "resource_token": "…", "presented_token": "…", "upstream_token": "…" }
```

## What the person server checks

Section 9.4.5 of the draft lists what the PS must verify before it trusts an upstream token. In the lab:

```js
async upstream(caller, raw) {
  const { payload, ps } = await this.ownToken(raw, 'upstream_token');
  if (ps !== this.id) throw new Refusal('invalid_upstream_token', 'upstream_token does not name this PS');
  if (payload.aud !== caller.agent.iss) throw new Refusal('invalid_upstream_token', `upstream_token aud ${payload.aud} is not the signing intermediary`);
  const record = this.issued.get(payload.jti);
  if (!record) throw new Refusal('invalid_upstream_token', 'This PS cannot identify the calling agent the upstream token was issued to');
  const person = this.directed.get(`${payload.aud}|${payload.sub}`);
  if (!person) throw new Refusal('invalid_upstream_token', 'This PS holds no record of the person at the upstream resource');
  return { payload, person, callingAgent: record.agent };
}
```

In words:

1. **It is one of this PS's own tokens,** a person token or an auth token, correctly signed and not expired.
2. **It was addressed to the intermediary that is now signing.** PlannerCo's token to ResearchCo has `aud` set to ResearchCo. If SearchCo got hold of it and tried to use it, the `aud` wouldn't match SearchCo's signing identity and the PS would refuse.
3. **The PS knows which agent it issued that token to.** That's how it identifies the calling agent one step up, even though the token itself doesn't name it.
4. **The PS knows which person the token's `sub` refers to** at the upstream resource.

Then it evaluates the new request against the same mission, exactly as in part 3.

The lab has conformance tests for the two interesting failures: an upstream token addressed to someone else, and a correctly signed upstream token the PS has no record of issuing. Both come back `400 invalid_upstream_token`.

## Lifetimes only shrink

A token issued with an upstream token can't outlive it:

```js
const exp = Math.min(now() + 3600, caller.agent.exp, presented.payload.exp, upstream?.exp ?? Infinity, this.missionExp(mission));
```

So the whole chain expires no later than the first token, and no later than the mission. If Alice's mission ends, every token in the chain ends with it.

## A new identifier at every hop

The person token PlannerCo got for ResearchCo has a `sub` that means Alice at ResearchCo. The one ResearchCo gets for SearchCo has a different `sub`, meaning Alice at SearchCo. The draft is strict about this: an issuer must not copy a directed `sub` from an upstream token into a token it issues.

The effect is that no two companies in the chain see the same identifier for Alice, so they can't use it to compare notes about her.

## What an intermediary can't do

If you've used Biscuit, the obvious question is: can ResearchCo restrict what SearchCo may do?

No. The draft says downstream authorization "is not required to be a subset of the upstream scopes". A flight-booking service that calls a payment processor needs payment scopes it never had itself. So scopes don't narrow down the chain, and ResearchCo has no way to add restrictions of its own.

Every decision about what SearchCo may do is made by two parties:

- **The person server,** against Alice's mission. In the lab, the mission's `relay.scopes` says SearchCo may be asked for `search` and nothing else.
- **SearchCo itself,** with its local policy.

Section C.1.11 explains why there isn't even a record of the chain in the token: the immediate caller already identifies itself by signing, the parties further up are none of the downstream's business, and "the resource enforces, the person server attributes".

## Caller trust, revisited

Part 2 showed that SearchCo can refuse ResearchCo on the identity request, and that nothing forces ResearchCo to make that request. Call chaining makes the gap concrete. Here is the lab's test, condensed:

```js
// ResearchCo goes straight to a person token at SearchCo, which does not trust it.
if (to !== 'search') { /* normal identity call */ }
const person = await agent.send('ps', '/person-token', { body: { resource: target.id, upstream_token: upstream }, … });
const challenge = await agent.send(to, path, { token: person.data.person_token, … });
// …exchange the resource token, present the auth token…
assert.equal(run.tasks.find(task => task.provider === 'search').status, 'settled');
```

The run removes the ResearchCo to SearchCo trust edge, and the search still settles. SearchCo never saw anything naming ResearchCo.

The PS, however, knows exactly who asked. Every token request it handles is signed by an agent token, and its upstream check identifies the agent one step up. So "SearchCo only accepts work passed on by ResearchCo" is enforceable, but as a rule at the person server, not at SearchCo. That's the AAuth way of thinking: the resource enforces the request in front of it, and the person server owns the chain.

The lab keeps SearchCo's identity check, because it works whenever an agent behaves, and labels its limits clearly in the UI.

## The library gap

The reference client, `@aauth/agent`, supports `upstream_token` on the person-token request but not on the auth-token request. `exchangeToken` has no option for it, and the high-level `createAAuthFetch` has no upstream option at all.

The lab's interop tests, which use the reference client as every agent, therefore call `exchangeToken` without `upstream_token`. The lab's PS accepts that, since the parameter is optional. But it then can't run the upstream checks at that step, or cap the auth token's lifetime at the upstream token's. I've reported it as [aauth-dev/packages-js#37](https://github.com/aauth-dev/packages-js/issues/37).

## Next

Part 5 covers the last company in every chain, the one that gets paid: how the clearinghouse bills Alice's organisation when no token names the company doing the work, and what changed when I ran the flow against a real person server.
