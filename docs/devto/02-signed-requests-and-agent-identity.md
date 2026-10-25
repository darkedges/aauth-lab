---
title: Signed requests and agent identity in AAuth
published: true
devto: true
description: >-
  How an AAuth agent proves who it is on every HTTP request: RFC 9421
  signatures, the Signature-Key header, self-issued agent tokens, key discovery,
  and what a receiver can and can't decide from them.
tags: 'security, authorization, javascript, http'
series: AAuth Network Lab
cover_image: >-
  https://raw.githubusercontent.com/darkedges/aauth-lab/main/docs/playground-screenshot.png
devto_id: 4914508
---

Part 1 introduced the network and the five steps of a hop. This part covers the first step and the thing every later step depends on: how an agent proves who it is.

{% embed https://github.com/darkedges/aauth-lab %}

## No bearer tokens

In OAuth as most people use it, a request carries `Authorization: Bearer <token>`, and whoever holds the token can use it. AAuth never sends a credential that works on its own. Every request is signed with the agent's private key, and every token the agent presents is bound to the matching public key.

That gives two properties at once:

- **A copied token is useless.** It only works on requests signed by the key named inside it.
- **The receiver knows which key made the request,** so it can tie the request to an identity without a separate login.

## The three headers

Here is ResearchCo's first request to SearchCo, as recorded by the lab:

```http
POST /tasks/search HTTP/1.1
Host: search.49ba54c6.relay.example
Content-Type: application/json
Content-Digest: sha-256=:…:
Signature-Input: sig=("@method" "@authority" "@path" "content-type" "signature-key" "content-digest");created=1792879515
Signature: sig=:LwNGjQhr2M7YekfJkCNS0OLxz4GZAe2xBVb…:
Signature-Key: sig=jwt;jwt="eyJhbGciOiJFZDI1NTE5IiwidHl…"
```

- **`Signature-Input`** lists what the signature covers: the method, host and path, the content type, the body digest, and the `Signature-Key` header itself. Covering `Signature-Key` stops someone swapping in a different token.
- **`Signature`** is the Ed25519 signature over those components (RFC 9421).
- **`Signature-Key`** says where to find the key that verifies it. Here `sig=jwt` means the key is inside a JWT: the agent token.

POST requests to the person server always include `content-digest`, so the body can't be changed in transit. A signed `GET` with no body covers only the method, authority, path and `signature-key`.

## The agent token

Decoded, ResearchCo's agent token looks like this:

```json
{ "alg": "Ed25519", "typ": "aa-agent+jwt", "kid": "research-1" }
{
  "iss": "https://research.49ba54c6.relay.example",
  "dwk": "aauth-agent.json",
  "sub": "aauth:research@research.49ba54c6.relay.example",
  "ps": "https://ps.49ba54c6.relay.example",
  "cnf": { "jwk": { "kty": "OKP", "crv": "Ed25519", "x": "…" } },
  "jti": "agt-99716a01",
  "iat": 1792879514,
  "exp": 1792883114
}
```

- `iss` is the agent provider, and `dwk` names its well-known document, so a verifier knows to fetch `{iss}/.well-known/aauth-agent.json`.
- `sub` is the agent's identifier, in the form `aauth:local@domain`.
- `cnf.jwk` is the public key the request must be signed with.
- `ps` names the person server this agent works with.

In the lab each company is its own agent provider. It generates a provider key and a separate signing key, and signs its own agent token:

```js
this.agentToken = await this.sign({ iss: this.id, dwk: DWK.agent, sub: this.sub, ps: this.demo.ps.id,
  cnf: { jwk: this.signingPublic }, jti: id('agt'), iat: now(), exp: now() + 3600 }, TOKEN_TYP.agent);
```

Signing a request is one call to the reference library:

```js
const signedFetch = createSignedFetch(async () => ({ signingKey: this.signingPrivate, signatureKey: { type: 'jwt', jwt: token } }),
  { signBody: ps, onSigned: value => { sent = value; } });
const response = await signedFetch(`${target.id}${path}`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) });
```

The same function signs every request in the run. Only the token in `Signature-Key` changes from step to step: the agent token, then a person token, then an auth token.

## Verifying on the receiving side

SearchCo checks two things, in order. First the HTTP signature, then the token:

```js
const signature = await verifySignature({ method: request.method, authority: url.host, path: url.pathname, headers: request.headers, body: text });
if (!signature.verified) return problem(code, signature.error, 401, { 'signature-error': `error=${code}` });

const token = await verifyToken({ jwt: signature.jwt.raw, httpSignatureThumbprint: signature.thumbprint,
  resource: this.id, accept: ['agent', 'person', 'auth'] });
```

`verifyToken` fetches the issuer's well-known document, follows its `jwks_uri`, picks the key by `kid`, checks the JWT signature and expiry, and checks that the token's `cnf` key is the key that signed the request (by comparing thumbprints). Those fetches are the 23 "key discovery" entries in the lab's Debug tab. They are public and unsigned, and a real deployment caches them.

## Identity-based access

With just the agent token, SearchCo knows who is calling. That is enough for some decisions, and the draft calls this identity-based access. In the lab, SearchCo uses it for caller trust:

```js
if (token.type === 'agent') {
  const caller = this.demo.partyBySub(token.sub);
  if (!this.trusts(caller)) return { response: problem('denied', `${this.label} does not accept calls from ${token.sub}`, 403) };
  return { response: problem('person_token_required', 'Present a person token', 401, { 'aauth-requirement': buildAAuthHeader('person-token') }) };
}
```

Remove the ResearchCo to SearchCo trust edge in the demo and SearchCo answers `403 denied` on this first request. No person server is contacted and no token is minted.

If SearchCo does trust the caller, it answers:

```http
HTTP/1.1 401 Unauthorized
AAuth-Requirement: requirement=person-token
Content-Type: application/problem+json

{"error":"person_token_required","detail":"Present a person token"}
```

The caller now has to show who it is acting for.

## A real agent identity

The lab's agents only exist inside one run. To check the lab against the real world, I also set up a real agent with the `@aauth/bootstrap` tool. It generated an Ed25519 key in the Windows keychain and printed the public key. I published that key and the agent metadata as two static files on Cloudflare Pages:

```text
https://agent.demos.darkedges.com/.well-known/aauth-agent.json
https://agent.demos.darkedges.com/.well-known/jwks.json
```

That's all an agent provider needs. A signed request to the public test resource `whoami.aauth.dev` then came back with:

```json
{
  "iss": "https://agent.demos.darkedges.com",
  "sub": "aauth:local@agent.demos.darkedges.com",
  "ps": "https://person.hello.coop"
}
```

The resource fetched my published key, checked the signature, and knew which agent was calling. There was no account to register and no client secret to exchange.

## The catch: identity stops at the first request

Here is the part that surprised me. In AAuth's three-party flow, the agent identifier appears only on this first request. The person token, resource token and auth token that follow don't name the agent at all.

That is deliberate. Appendix C.1.6 of the draft explains that a person's relationship with a resource should survive a change of agent. If Alice switches assistants, SearchCo should still recognise her, not the assistant.

The consequence is that caller trust can only be enforced on the identity request, and nothing forces an agent to make it. The lab has a test where ResearchCo skips the identity call, goes straight to the person server for a person token, and is served by SearchCo even after SearchCo has stopped trusting it.

So "SearchCo only accepts work from ResearchCo" isn't a rule SearchCo can enforce on its own in AAuth. If you need it, it belongs at the person server, which sees every hop and knows which agent asked for each token. I'll come back to this in part 4.

## Next

Part 3 follows the request past the `401`: how Alice approves a mission, and how the person, resource and auth tokens let her person server decide each hop.
