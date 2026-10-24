---
title: Delegating work across companies with AAuth
published: false
devto: true
description: >-
  Agents that call other agents need to answer who is calling, on whose behalf,
  and who pays. This series builds a four-company delegation network on AAuth,
  an HTTP authorization protocol where every request is signed and a person
  server issues the tokens.
tags: 'security, authorization, javascript, cloudflare'
series: AAuth Network Lab
cover_image: >-
  https://raw.githubusercontent.com/darkedges/aauth-lab/main/docs/playground-screenshot.png
---

Alice wants a piece of work done, and her organisation pays for it. She gives the job to her assistant, an AI agent. The assistant hands it to a coordinator, and the coordinator splits it between other companies. Some of those companies pass part of the job on again.

Every company in that chain has to answer the same questions before it does any work:

- Who is calling me, and do I accept work from them?
- On whose behalf is this request, and did that person actually approve it?
- Who pays, and is that the payer the person agreed to?
- Is this action within what the person approved?
- Is there still money left?

A bearer token or API key answers almost none of these. It says "the holder may do X", and anyone who copies it becomes the holder.

**[AAuth](https://datatracker.ietf.org/doc/html/draft-hardt-oauth-aauth-protocol)** is an HTTP authorization protocol designed for agents. It is an IETF draft (this series uses draft 11) by Dick Hardt. I built **[AAuth Network Lab](https://github.com/darkedges/aauth-lab)** to see how far it gets on this problem, with real signatures and tokens and simulated companies. This series walks through how it works.

{% embed https://github.com/darkedges/aauth-lab %}

**Live demo:** [aauth.demos.darkedges.com](https://aauth.demos.darkedges.com)

If you read my earlier Biscuit Trust Lab series ([code](https://github.com/darkedges/biscuit-trust-lab)), this is the same network, the same seven scenarios and the same clearinghouse, rebuilt on a different protocol. You don't need to have read it.

## The network

```text
Alice (person) / alice-org (payer)
  └─ Assistant (Alice's agent)
       └─ PlannerCo (coordinator)
            ├─ ResearchCo [5 credits]
            │    └─ SearchCo [10 credits]
            └─ ComputeCo [25 credits]

All billable calls → shared clearinghouse
Alice's person server issues every token
```

Alice approves a budget of 100 credits. The happy path costs 40: research 5, search 10, compute 25.

Seven scenarios try to break it:

| Scenario | What goes wrong |
| --- | --- |
| Authorized delegation | Nothing. Three operations settle for 40 credits. |
| Change payer | ResearchCo asks SearchCo to bill `mallory-org` |
| Forbidden operation | ResearchCo asks SearchCo to `delete`, which SearchCo offers but Alice never approved |
| Untrusted issuer | ResearchCo presents a token signed by a rogue key claiming to be Alice's person server |
| Competing reservations | Two 60-credit calls race for a 100-credit budget |
| Retry | ResearchCo repeats a search with the same operation ID |
| Operation failure | SearchCo reserves credits, then fails |

A trust editor lets you remove a "this company accepts calls from that company" relationship, or stop a company accepting Alice as a requester, and run again.

## Four roles

AAuth gives every participant one of a few roles. In the lab:

- **Agents** make requests. The Assistant, PlannerCo, ResearchCo and ComputeCo are all agents, because each calls someone else. An agent has a signing key and an **agent token** that binds that key to an identifier such as `aauth:research@research.example`.
- **Agent providers** vouch for agents. An agent provider publishes `/.well-known/aauth-agent.json` and a JWKS, and signs agent tokens. In the lab each company is its own agent provider.
- **Resources** receive requests. PlannerCo, ResearchCo, SearchCo, ComputeCo and the clearinghouse are resources. Intermediaries are both: a resource to their caller, an agent to the next company.
- **The person server (PS)** represents Alice. It knows who she is, records what she approved, and issues the tokens that let agents act for her.

The important design choice is the last one. Authority doesn't live in a token that gets passed down the chain. It lives at the person server, and every hop asks it again.

## One hop, five steps

Every call between two companies follows the same pattern. Here is ResearchCo calling SearchCo:

1. **Identity call.** ResearchCo signs the HTTP request with its own key (RFC 9421 HTTP Message Signatures) and puts its agent token in a `Signature-Key` header. SearchCo now knows who is calling. It answers `401` with `AAuth-Requirement: requirement=person-token`.
2. **Person token.** ResearchCo asks Alice's PS for a person token addressed to SearchCo. Because ResearchCo is an intermediary, it includes the token it was given by PlannerCo as `upstream_token`.
3. **Resource token.** ResearchCo repeats the call, presenting the person token. SearchCo answers `401` again with `requirement=auth-token` and a **resource token** saying what it needs: scope `search email`, billing account `alice-org`.
4. **Auth token.** ResearchCo takes the resource token to the PS. The PS checks it against what Alice approved, and either mints an **auth token** or refuses.
5. **Authorized call.** ResearchCo calls SearchCo a third time, presenting the auth token. SearchCo verifies it, applies its own policy, and does the work.

Every request in that list is signed by ResearchCo's key, and every token is bound to that key. A token copied off the wire is useless without the private key.

Before any of this, Alice approves a **mission** at her PS: what the assistant is trying to do, which tools it will use, and which services it will call. Every token in the run carries the mission's hash.

On the happy path that adds up to 40 signed HTTP requests, 16 of them to the person server.

## What the lab adds on top of AAuth

AAuth defines the signatures, tokens and person server. It deliberately doesn't define payers, budgets or billing. The lab adds three things and labels each one as a lab extension in the UI:

1. **A `relay` member in the mission** that records the payer, the budget and the scopes the PS may issue for each company. The draft allows extra members in the mission.
2. **A clearinghouse** that reserves, settles and releases credits, the same as in the Biscuit lab.
3. **A signed provider assertion** on billing calls, because AAuth tokens don't name the calling agent and the clearinghouse needs to know who to pay. Part 5 explains why.

## Try it

Open the demo and leave the defaults. Run the network.

The **Debug** tab lists every signed request in order, with the real `Signature`, `Signature-Input` and `Signature-Key` headers, the decoded token, the `AAuth-Requirement` challenge and a short narration of what happened. The **Decision logic** tab shows, for each company, which checks passed and where each fact came from: the HTTP signature, a token the PS signed, the company's own policy, or the mission.

Then try the guided exercises:

- **Protect the original payer.** The PS refuses to mint the auth token. SearchCo never sees a request it could act on.
- **Remove a trust relationship.** SearchCo refuses ResearchCo on the very first request, before anyone contacts the PS.
- **The person declines the mission.** Alice says no at her PS, and nothing runs.

## Run it locally

You need Node.js 22 and pnpm 11.

```sh
git clone https://github.com/darkedges/aauth-lab
cd aauth-lab
pnpm install
pnpm dev     # http://127.0.0.1:8796
pnpm check   # 33 tests: behaviour, spec conformance, reference-client interop
```

All parties run inside one Cloudflare Pages function. Each run creates fresh keys and fresh origins such as `https://search.<tag>.relay.example`, and requests between them are real `Request` and `Response` objects routed in process.

Signing and verification use the official libraries: `@aauth/agent` signs, `@hellocoop/httpsig` verifies, `@aauth/resource` verifies tokens and builds the challenges, and `jose` signs the tokens the PS mints.

## Coming up in this series

1. **This post:** the problem, the network and the shape of a hop.
2. **Signed requests and agent identity:** RFC 9421 signatures, the `Signature-Key` header, agent tokens and key discovery.
3. **Missions, consent and three tokens:** how Alice approves the work, and how the PS decides each hop.
4. **Call chaining:** how intermediaries pass authority on with `upstream_token`, and what they can't do.
5. **Paying for it, and checking against a real person server:** billing without agent identity, and what a live run against Hellō's person server showed.

