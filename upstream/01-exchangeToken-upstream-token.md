# @aauth/agent: `exchangeToken` cannot send `upstream_token` (call chaining, draft -11 §7.2.1 / §10.1.1)

**Repo:** https://github.com/aauth-dev/packages-js/issues
**Package:** `@aauth/agent` 4.1.1

## Summary

`requestPersonToken` accepts `upstreamToken` and sends `upstream_token` in place of `mission_s256`, but `exchangeToken` has no matching option. An intermediary agent can therefore get the downstream person token through the library, but cannot complete the auth-token step of call chaining with it.

## Spec

Draft -11 §7.2.1 (auth token request) lists `upstream_token` (OPTIONAL) as "the person token or auth token the calling agent presented to the requester, used in call chaining". §10.1.1 describes the full sequence:

> The intermediary first obtains a person token for the downstream resource, presenting the upstream token as upstream_token. It then presents that person token at the downstream resource, … along with the person token as presented_token and the upstream token as upstream_token.

The PS needs it on the auth token request to verify the chain (§9.4.5) and to cap the auth token's `exp` at the upstream token's (§9.4.1: "When the token request carried upstream_token, the auth token MUST NOT expire later than that").

## Current behaviour

`dist/token-exchange.js`, `exchangeToken(options)` destructures:

```js
const { signedFetch, authServerUrl, resourceToken, justification, localhostCallback,
        loginHint, tenant, domainHint, onInteraction, onClarification, onEvent,
        getKeyMaterial, sentTracker } = options;
```

There is no `upstreamToken`, and the request body never carries `upstream_token`. By contrast, `dist/person-token.js` handles `upstreamToken` ("With `upstreamToken` the body carries `upstream_token` instead of `mission_s256` (call chaining)").

## Expected

`exchangeToken({ …, presentedToken, upstreamToken })` sends `upstream_token` in the body alongside `resource_token` and `presented_token`, and `createAAuthFetch` passes it through when the caller is an intermediary.

## How we found it

We built a multi-hop lab (agent → PlannerCo → ResearchCo → SearchCo) where every hop uses call chaining. Using the reference client for every agent, the person-token step works through `requestPersonToken({ upstreamToken })`, but the auth-token step can only call `exchangeToken` without `upstream_token`. The lab's person server accepts that (the parameter is OPTIONAL), but it then cannot run the §9.4.5 upstream checks at that step or cap the auth token's `exp` at the upstream token's (§9.4.1). `createAAuthFetch` has no upstream option either, so an intermediary has to compose the lower-level functions.

_Corrected after filing: the original text said the test hand-built the auth-token request. See the follow-up comment on #37._
