# @aauth/fetch: `--explain` narration doesn't match the wire in the three-party flow

**Repo:** https://github.com/aauth-dev/packages-js/issues
**Package:** `@aauth/fetch` 4.0.0, with `person.hello.coop` and `whoami.aauth.dev`

## Reproduce

```sh
npx @aauth/fetch --explain --explain-log walkthrough.jsonl --prompt-consent "https://whoami.aauth.dev?scope=openid+profile"
```

Approve in the browser, then compare each event's `summary`/`description` with its `request`/`response`. The `AGENTS.md` walkthrough tells agents to render that narration verbatim and not paraphrase it, so a mismatch reaches the learner unchanged.

## Mismatches (one run, 2026-10-24)

1. **First 401.** `agent_token_request` has the summary `agent → resource · agent-token → 401 + resource-token`, and the response description says the `AAuth-Requirement` header "carries a resource token". The actual header was `requirement=person-token`, with body `{"error":"person_token_required"}`. Under -11 the resource token comes only after a person token is presented.
2. **First consent poll result.** The `consent_poll` summary says `poll → 200 + auth-token (person approved)`, and the description says the body "carries the freshly issued auth token". The body was `{"person_token": "…", "expires_in": 3533}`, an `aa-person+jwt` from the person-token endpoint's pending URL.
3. **Auth token endpoint 202.** The `auth_token_endpoint` response description says "User interaction required … (`AAuth-Requirement: requirement=interaction`) — the person must approve in a browser". The header was `requirement=approval`, which §11.6.4 uses when a server is getting approval "without requiring the agent to direct a user". No browser step followed.
4. **Final call.** The `auth_token_request` response description says the resource "now knows who is calling (`agent`)". The body has no `agent` field, and §C.1.6 says auth tokens carry no agent identifier.
5. **Generic events.** `ps_person_token_request` has no summary, and its descriptions are only `Request: ps_person_token_request.` / `Response: 202.`. `person_token_received` and `retry_with_person_token` are the same. These step names are also missing from the step vocabulary in `npx @aauth/fetch skill`, which lists `person_token_endpoint`.

## Suggested fixes

- Make the narration depend on the parsed requirement and the response body (`person-token` vs `auth-token`, `interaction` vs `approval`, `person_token` vs `auth_token`), not on the step name alone.
- Give the person-token steps real summaries and descriptions, and add them to the skill's step vocabulary.
- Drop the "who is calling (`agent`)" wording from the final description, or say that the PS (not the resource) knows the agent.
