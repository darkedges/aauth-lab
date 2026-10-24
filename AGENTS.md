AAuth is an HTTP authorization protocol that lets agents call protected resources on your behalf using signed requests instead of bearer tokens. The spec is at https://datatracker.ietf.org/doc/html/draft-hardt-oauth-aauth-protocol — consult it for any protocol detail.



This walkthrough teaches the protocol live, in front of a user who wants to learn it. Two goals:



\- a keypair generated and the public key published, with agent metadata, at a URL the user controls

\- signed calls to `whoami.aauth.dev` with each protocol step clearly explained — first the \*\*identity-based flow\*\*, then the \*\*three-party flow\*\* (agent ↔ person server ↔ resource)



This prompt is glue only. The bootstrap skills know how to set up and tear down; the fetch skill knows how to read and render `--explain` events. Before step 3, run `npx @aauth/fetch skill` and follow its "Inspecting requests" section — the events carry their own `summary` and `description` narration; render them, don't paraphrase or augment them.



\## Pacing — one section per turn



The user reads in chat; pace the output so each piece lands alone.



\- \*\*One section per turn.\*\* Each protocol exchange (or tight group, like the consent polls) is its own turn-ending message: the event's `summary` line on top, then the rendered events per the fetch skill. End the turn; the user's reply advances to the next section. Never bundle two sections into one message.

\- \*\*Front-load each phase.\*\* Before Setup, the calls, and Uninstall, say in one or two sentences what's coming. The second call's front-loader must warn that it pauses for a browser approval.

\- \*\*Tell the user how to advance.\*\* The front-loader before the first call must say the walkthrough pauses after each section and that replying with anything ("ok") advances it. Don't use a question prompt as the advance mechanism — a tool call after section text can swallow the text above it, so sections must end as plain text.

\- \*\*The CTA turn contains ONLY the CTA.\*\* The moment `interaction\_required` arrives, emit its `approval\_url` (clickable), `code`, and `qr` (fenced code block, no language tag) plus one line saying you're waiting — nothing else in that turn. Latency here is the user staring at a spinner.

\- \*\*Deliverables end the turn.\*\* Text emitted before a tool call in the same turn may never be displayed. The punchline must be the final text of its turn — no tool calls and no question tools after it.

\- \*\*No recap table, no closing invitation.\*\* The per-section `summary` lines are the recap. After the punchline's explanation, stop — with one exception: if we installed this run, the punchline's final line tells the user one more reply brings the keep-or-uninstall question (see step 4). Without that line the user doesn't know the walkthrough has one turn left.

\- \*\*Don't leave background work running between turns.\*\* The task notification fires when the background fetch exits — no polling loops, no `tail -f`.



\## 1. Check for existing setup



```

npx @aauth/bootstrap list

```



If `agentProviders` is non-empty, the user already has an identity — name what's there in one line (agent URL, keystore, person server) and skip to step 3. Skip step 4 entirely: we didn't install it this run, so never offer to uninstall it.



\## 2. Set up (if nothing exists)



```

npx @aauth/bootstrap skill setup

```



The skill is self-contained — follow it. Don't continue to step 3 until its `npx @aauth/fetch https://whoami.aauth.dev` verify step returns your `sub`.



\## 3. Two signed calls



Both calls hit `whoami`, which echoes who is calling. Pass `--explain-log` with a path you choose under `\~/.aauth/fetch/logs/` so you know exactly where the JSONL stream lands (a captured stderr stream is also JSONL when piped — either source works; pick one and stick with it).



\### First call — identity-based flow (foreground; sub-second)



```

npx @aauth/fetch --explain --explain-log \~/.aauth/fetch/logs/walkthrough-1.jsonl https://whoami.aauth.dev

```



Render its one exchange as one section and end the turn. The response body is the point: the resource saw the agent's `sub` from the signature alone — no person server, no consent, no bearer token.



\### Second call — three-party flow (background; pauses for consent)



```

npx @aauth/fetch --explain --explain-log \~/.aauth/fetch/logs/walkthrough-2.jsonl --prompt-consent "https://whoami.aauth.dev?scope=openid+profile"

```



`--prompt-consent` forces the consent prompt so the user sees the full interactive flow. Run it in the background with a `600000` ms timeout — the consent window is 600 s and humans take minutes to approve.



Then, one section per turn, the user advancing between them:



1\. \*\*The 401 exchange\*\* — agent-token call → 401 + resource-token.

2\. \*\*The person-server exchange\*\* — resource-token POSTed → 202 pending + approval code — immediately followed by \*\*the CTA turn\*\* (only the CTA; see Pacing).

3\. \*\*After the task notification: the consent polls\*\* — 202s while the person decided, then the 200 whose body carries the freshly issued `auth\_token`. That 200 is where the person server mints the token — don't bury it.

4\. \*\*The punchline\*\* — the `auth\_token\_request` pair. The response body (`sub`, `agent`, `name`, `email`) shows the resource now sees both who is calling and on whose behalf, with claims the person server vouched for. This ends the turn. If we installed this run, close with one line saying a reply brings the keep-or-uninstall question; otherwise nothing follows the explanation.



\## 4. Keep or uninstall (only if we installed in step 2)



If step 1 found an existing provider: the walkthrough is done — say so and stop.



If we ran setup this session: ask proactively in the turn \*\*after\*\* the punchline (never in the same turn — a question tool swallows any text above it). One question, keep first and default:



\- \*\*Keep installed\*\* — they just proved it works; the keys are useful next time.

\- \*\*Uninstall\*\* — return to a clean state.



If they choose uninstall:



```

npx @aauth/bootstrap skill uninstall

```



The skill is self-contained; the Keep/Uninstall answer counts as its confirmation — don't re-ask. Verify world state, not exit codes: the JWKS URL returns 404, and `list` shows `agentProviders: \[]`.

