---
title: 'Paying for it, and checking AAuth against a real person server'
published: false
devto: true
description: >-
  How the lab's clearinghouse bills the right company when AAuth tokens don't
  name agents, what a live run against Hellō's person server confirmed and
  changed, and what a production version would need.
tags: 'security, authorization, javascript, cloudflare'
series: AAuth Network Lab
cover_image: >-
  https://raw.githubusercontent.com/darkedges/aauth-lab/main/docs/playground-screenshot.png
---

The first four parts covered authority: who is calling, on whose behalf, and who decides. This last part covers money, and then checks the whole thing against the real world.

{% embed https://github.com/darkedges/aauth-lab %}

## The clearinghouse is just another resource

Every billable call goes to a shared clearinghouse: reserve credits before the work, settle after it, release them if the work fails. In the lab the clearinghouse is an ordinary AAuth resource. Each operator reaches it with the same five-step hop as any other call, passing its upstream token, so the PS authorizes every billing call against Alice's mission too. The scope is `billing`.

Before the first call, the clearinghouse funds the mission. It fetches the mission from the PS and checks the bytes against the hash:

```js
async fund(s256) {
  const bytes = await (await fetch(`${this.demo.ps.id}/missions/${s256}`)).text();
  if (await digest(bytes) !== s256) throw new Error('Mission bytes do not match mission_s256');
  const { relay } = JSON.parse(bytes);
  Object.assign(this, { mission: s256, budget: relay.budget, payer: relay.payer });
}
```

On each call it takes the payer from the auth token's `account` claim, which the PS signed after checking it against the mission. Nothing in the request body can change who pays.

## Who gets paid?

Here AAuth's privacy design gets in the way. The clearinghouse has to credit the company that did the work, but as part 2 explained, no token in the three-party flow names the calling agent.

The lab fills the gap with a small, clearly labelled extension: a **provider assertion**. The operator signs a short JWT with its agent-provider key, bound to the key that signs the request and to this one operation:

```js
const assertion = await this.sign({ iss: this.id, operation_id: payload.operation_id, path,
  jkt: await calculateJwkThumbprint(this.signingPublic), iat: now(), exp: now() + 300 }, 'relay-billing+jwt');
```

The clearinghouse verifies it against the operator's published keys and checks the binding:

```js
if (payload.jkt !== thumbprint || payload.path !== path || payload.operation_id !== operationId) throw new Error('Provider assertion is not bound to this request');
```

Because `jkt` must match the key that signed the HTTP request, an assertion can't be lifted from one request and replayed on another. This isn't part of AAuth. It's what a real billing service would need to add, and it's the clearest example in the lab of AAuth leaving agent identity to the application.

## Reserve, execute, settle

The accounting is the same as in the Biscuit version of the lab, because none of it depends on the authorization protocol:

- **Reservations are serialised.** JavaScript is single-threaded, but `await` points interleave requests. A promise queue makes each reservation's read-then-write atomic, so two 60-credit calls against 100 credits can't both succeed. The loser gets `402 insufficient_credits`.
- **Retries are idempotent.** A reservation is keyed by operation ID and fingerprinted. Repeating the same operation returns the existing result with `duplicate: true`. Reusing the ID with different details is a `409`.
- **Failures release.** If the work fails after reserving, the operator releases the reservation and the credits return to available.
- **Settlement needs a receipt.** The operator signs a receipt bound to the reservation grant, and the clearinghouse only settles against it.

The retry scenario shows one AAuth-specific benefit: the second attempt reuses the cached auth token, so it needs no PS round trip at all.

## Checking it against the real thing

A simulation can be wrong in ways its own tests won't catch. Everything so far runs against a person server I wrote. So I set up a real agent identity (part 2), and ran the AAuth walkthrough against Hellō's person server, `person.hello.coop`, and the public test resource `whoami.aauth.dev`.

The first call, signed with just the agent token, came back `200` with my agent's identifier. The second asked for my profile and walked the full three-party flow, pausing for me to approve in a browser. It ended with:

```json
{
  "iss": "https://person.hello.coop",
  "sub": "sub_…",
  "name": "…",
  "email": "…",
  "email_verified": true
}
```

The live run **confirmed** the lab's model:

- The challenge order is the same: agent token, then `401 requirement=person-token`, then person token, then `401 requirement=auth-token` with a resource token, then the auth token.
- Token lifetimes are capped the same way. The person token and auth token both ended exactly when the agent token did.
- The final response named me, but not my agent. The person token did carry my agent's identifier, in a Hellō-specific claim. The PS knows the agent; the resource doesn't.

It also **differed** in useful ways:

- Hellō asked for consent at the person-token request, not at a mission. It doesn't publish a mission endpoint at all.
- The later auth-token request came back `202 requirement=approval`: the PS was deciding without needing me in a browser. The lab's PS decides those at once.
- The profile came back as claims in the auth token, with a `whoami` scope, rather than as `openid profile` scopes.

The lab now copies the consent `202` and polling, and `pnpm live` runs the assistant's first hop both ways, in the lab and against the real services, and prints them side by side:

```text
                         lab   live
  signed requests           7      5
  to the person server      4      2
  consent polls             2      0
  401 challenges            2      2
```

The difference is the mission. The live hop asks for a person token directly; the lab's hop gets one from the mission approval.

The live run also turned up two gaps in the reference libraries, both reported: `exchangeToken` can't send `upstream_token` ([#37](https://github.com/aauth-dev/packages-js/issues/37)), and the `--explain` narration in `@aauth/fetch` sometimes describes a different message from the one on the wire ([#38](https://github.com/aauth-dev/packages-js/issues/38)).

## What a production version would need

The lab deliberately stops short of being a real system. To make it one you would need:

- **A real person server**, with persistent missions, real consent screens, revocation and a mission log the person can read.
- **Persistent agent keys**, published at stable agent-provider URLs and rotated, instead of fresh keys on every run.
- **Network transport** between companies, where every PS call and key-discovery fetch is a round trip. The happy path makes 16 PS calls and 23 discovery fetches; caching helps the second number, not the first.
- **A decision about caller trust.** If a company must only accept work from particular callers, enforce that at the person server, which sees every hop.
- **Durable accounting**, with transactional reservations, reservation expiry and reconciliation.

## Wrapping up

Across the five parts, we covered:

1. **Agents that sign every request**, with keys bound to self-published identities, and no bearer tokens anywhere.
2. **A mission** that the person approves once, with deferred consent, and whose hash every later token carries.
3. **Three tokens per hop:** a person token that says who for, a resource token that says what's needed, and an auth token the person server mints after checking both against the mission.
4. **Call chaining**, where intermediaries present upstream tokens and the person server, not the token, holds the chain.
5. **A clearinghouse** that bills the right payer and the right company, with the gaps AAuth leaves to the application filled in and labelled.

The most important lesson for me was where the decisions end up. Almost everything that matters, who pays, what's allowed, and even who may call whom, is decided by the person server. That gives you one accountable place, at the cost of putting it on every hop.

If you want the side-by-side with Biscuit, which makes the opposite trade, it's in [COMPARISON.md](https://github.com/darkedges/aauth-lab/blob/main/COMPARISON.md).

Try to break it. Remove trust, swap payers, squeeze the budget, have Alice decline, and watch the Debug tab. If you find a way to get SearchCo to do work it shouldn't, please open an issue.

Code: **[github.com/darkedges/aauth-lab](https://github.com/darkedges/aauth-lab)** · Demo: **[aauth.demos.darkedges.com](https://aauth.demos.darkedges.com)**
