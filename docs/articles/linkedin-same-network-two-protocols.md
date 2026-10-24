# Who decides when AI agents hand work to each other? I built the same system twice to find out

Agents are starting to call other agents. A planning agent hands research to a research agent, which hands a search to a search service, and somebody pays for all of it. The hard question is not whether each call is authenticated. It's who decides what each agent may do, on whose behalf, and who gets billed.

To make that concrete, I built a small delegation network and implemented it twice, once on Biscuit and once on AAuth, and compared them scenario by scenario.

## The network

Alice asks PlannerCo for research. PlannerCo hands work to ResearchCo and ComputeCo. ResearchCo hands a search to SearchCo. A shared clearinghouse reserves and settles credits against Alice's organisation.

Seven scenarios try to break it: changing who pays, asking for an operation that was never approved, presenting a token from an untrusted issuer, two operations competing for the last of the budget, a retry, a failure after credits are reserved, and removing trust between two companies.

Both versions stop every one of those and settle exactly the same credits. The interesting part is where each one stops them.

## Two different answers to "who decides"

**Biscuit puts authority in the token.** One root token is minted at the start. Each company narrows it before passing it on, with no call back to the issuer, and each receiver checks it locally with a small Datalog policy. Decisions happen at the edges.

**AAuth puts authority in the person server.** Every agent signs every HTTP request with its own key. At each hop the caller asks Alice's person server for a fresh token bound to that key, and the person server checks the request against the mission Alice approved. Decisions happen in the middle.

So when ResearchCo tries to bill a different organisation, Biscuit stops it at SearchCo's policy check. AAuth stops it earlier: the person server refuses to issue the token, so SearchCo never sees the request at all.

## What AAuth gets right

**Proof of possession everywhere.** Every request is signed and every token is bound to the signing key, so a stolen token is useless on its own. In the Biscuit version I had to add request signatures and a signed delegation chain myself to get the same guarantee.

**The person is part of the protocol.** Alice approves a mission once, in her browser, and every later token traces back to it. The person server keeps an audit log of every token it issues or refuses. Each service sees a different pseudonymous identifier for her, so the companies can't correlate her across services.

**Revocation is simple.** The person server stops issuing, and tokens expire within the hour.

## What it costs

**The person server is on every hop.** In my happy-path run, AAuth made 40 signed HTTP requests, 16 of them to the person server, plus 23 key-discovery fetches. Biscuit needed no calls to the issuer after the first token. In production each of those is a network round trip, and the person server has to be available for any work to happen.

**Intermediaries can't narrow authority themselves.** With Biscuit, ResearchCo can restrict what SearchCo may do without asking anyone. AAuth has no equivalent. Only the person server and the receiving service decide.

## The finding I didn't expect

In AAuth's three-party flow, no token names the calling agent. That is deliberate: the specification wants a person's relationship with a service to survive a change of agent.

The consequence is that a service can refuse an agent only on the first, identity-only request, and nothing forces an agent to make that request. I wrote a test where ResearchCo skips it, goes straight to the person server, and is served by SearchCo even after SearchCo stopped trusting ResearchCo.

In Biscuit, "I only accept work from callers I trust" is enforced by every receiver on every call. In AAuth that rule has to live at the person server. If you are designing agent-to-agent systems, that is a design decision to make on purpose, not one to discover later.

## Checked against the real thing

A simulation can be wrong in ways its own tests won't catch. So I also set up a real agent identity and ran the flow against Hellō's live person server and a public test service. The live run confirmed the ordering, the token lifetimes and the caller-identity behaviour above. It also turned up two gaps in the reference JavaScript libraries, which I've reported to the maintainers.

## Which one should you use?

Choose Biscuit when verification has to work offline, when intermediaries need to restrict what their own sub-contractors can do, or when you want one policy language everywhere.

Choose AAuth when you want every request signed and every token bound to a key, a person who approves and can audit what agents do, and identifiers that services can't correlate.

They also combine well: AAuth can carry who is acting and for whom, and a Biscuit can carry the narrowed rights.

Both labs are open source and run in the browser. Try the same scenario in each and compare what happens.

AAuth lab: https://aauth.demos.darkedges.com (code: https://github.com/darkedges/aauth-lab)

Biscuit lab: https://biscuits.demos.darkedges.com (code: https://github.com/darkedges/biscuit-trust-lab)

Full comparison: https://github.com/darkedges/aauth-lab/blob/main/COMPARISON.md

I'd like to hear how others are handling authorization between agents, especially across company boundaries.
