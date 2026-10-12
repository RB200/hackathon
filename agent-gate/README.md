# Agent Gate

A local hackathon demo of layered defenses for a document-reading agent. An isolated LLM reviewer flags suspicious source text; a deterministic server gate enforces tool permissions; outbound checks detect selected secret patterns; humans approve exact email payloads. The browser shows the evidence and every decision.

## Run

Requires Python 3.10+; no packages to install.

```sh
python3 -B server.py
```

Open **http://127.0.0.1:8000**. With no API key, the app runs in **offline replay** mode: heuristic screening plus scripted tool proposals. This is a repeatable demonstration of the gate, not evidence of an actual LLM being exploited.

For live LLM review and agent inference:

```sh
cp .env.example .env
```

Set `OPENAI_API_KEY` in `.env`, then restart the server and select **Live OpenAI agent**. Documents and tasks are sent to OpenAI after local secret checks/redaction. The key remains on the server. Live failures are reported; the app never silently substitutes scripted results.

### Change the model

```dotenv
OPENAI_API_KEY=your-key
OPENAI_MODEL=gpt-4.1-mini
REVIEWER_MODEL=gpt-4.1-mini
PORT=8000
ALLOWED_RECIPIENTS=team@example.com
```

`OPENAI_MODEL` controls the agent and, by default, the reviewer. `REVIEWER_MODEL` optionally overrides the reviewer. Restart after changes. Models must support the Responses API, function calling and structured JSON schema output. To use another provider, replace the adapter in `defense/provider.py`; the policy gate is independent of the model.

`.env` parsing supports plain `KEY=value` assignments and matching surrounding quotes. Shell exports take precedence. It does not evaluate shell commands or interpolate variables.

## Demo flow

Start in offline replay for predictable policy outcomes; then switch to live mode to show real review and agent behavior.

| Scenario | What happens in offline replay |
| --- | --- |
| Normal document | Public handbook read succeeds; launch facts are summarized. |
| Prompt injection | Source impersonates a system instruction; screening quarantines it. Protected reads and sends are blocked. |
| Detector misses | Both detector signals are deliberately suppressed **only in this fixed offline scenario**. A protected read and external recipient are still denied. |
| Tool misuse | A destructive request against a clean source is denied by the tool allowlist. |
| Encoded secret | A compromised agent's scripted send to an allowed address contains a base64 fake key. DLP blocks it before approval. |
| Human approval | Draft succeeds. Send pauses for exact-payload approval and then enters a **local mock outbox**, or is declined. |

In live mode, none of the scripted proposals or forced verdicts apply. A real model may reject an attack before proposing a tool call. The gate still checks every proposed action. The destructive tool is deliberately absent from the model's tool definitions; the offline scenario tests what happens if a compromised caller requests it anyway.

Try your own text by editing the document or uploading a plain-text file. Edits select **Custom document**. Custom offline mode performs heuristic screening, a public handbook read, and a labeled text preview; use live mode for an AI-generated summary and AI tool proposals. Document limit: 20,000 characters. Task limit: 2,000 characters.

Decision log headings and finding categories use plain language. The decision log sits in the defense result where the finding cards were, with screening findings available by expanding the document review entry. Hover over or keyboard-focus the **Quarantined** count to see which source was quarantined and why. Click any decision log entry to inspect recorded findings, tool arguments, policy rules, and outcomes; entries open on demand and stay in chronological order. These are recorded checks and evidence, not hidden model reasoning. Review evidence shows likely requested tools inferred from each suspicious instruction; that does not mean a tool was invoked. **Tool actions stopped** counts rejected tool calls plus literal or inferred tool requests detected in a quarantined source before invocation; the note says how many calls reached the gate. In offline replay, scripted tool proposals demonstrate gate blocks. **Export JSON** downloads the redacted run snapshot, including screening evidence, policy, decisions, drafts, approvals and mock outbox.

## Defense layers

1. **Trust boundaries:** user task and run permissions are separate from untrusted reference text. Document instructions never modify server policy. Tool results are labeled untrusted too.
2. **Document screening:** a reviewer with no tools returns a strict risk/evidence JSON schema. Evidence must be exact document substrings. Heuristic matches cannot be overruled by a benign LLM verdict. A suspicious, malicious, refused, invalid or unavailable review quarantines the source. Quarantined runs can read public knowledge and summarize, but cannot draft or send.
3. **Mandatory gate:** tool allowlist, strict runtime argument validation, exact public document IDs, exact recipient addresses, independent user-granted draft/send capabilities, and an eight-attempt budget. Blocked calls also count. The agent has no filesystem, shell, arbitrary network, or deletion tool.
4. **Data checks:** redact recognized sensitive input before any model request; block sensitive tool arguments/results and final answers. Recognizes the synthetic protected key, configured API key, their exact base64/URL-safe base64/hex/percent-encoded forms, whitespace/zero-width splits, and selected API/AWS/private-key patterns. Audit and API snapshots redact sensitive strings too.
5. **Human approval:** allowed sends generate a server-held copy of the exact recipient, subject and body. A random action ID is scoped to its run, expires in five minutes and is single use. The approval endpoint accepts only that ID and a boolean decision. All policy rules are rechecked before execution. Approval cannot authorize a denied action.
6. **Audit:** record source trust, screening findings, proposed action, decision, rule and outcome. Final answers are checked separately. No raw prompts or provider error bodies are printed.

Approvals resolve after the agent finishes reporting a pending send; approval does not restart model inference. The UI records a separate approval update and displays actual mock outbox contents.

## Architecture

```text
Browser → Local server → Input redaction → Isolated reviewer
                              ↓                 ↓
                          Agent ← Trusted policy / source risk
                              ↓
                      Mandatory tool gate
                      ↓              ↓
                 Public reads    Draft / approval → Mock outbox
                      ↓
                 Tool-result check → Agent → Final-answer check

Every decision → redacted in-memory event log → Browser / JSON export
```

| File | Responsibility |
| --- | --- |
| `server.py` | Local HTTP API, `.env` configuration, concurrency limits, run storage and approval lifecycle. |
| `defense/provider.py` | OpenAI Responses API adapter, request redaction, timeouts and sanitized errors. |
| `defense/engine.py` | Isolated review, evidence validation, quarantine, live tool loop and labeled offline replay. |
| `defense/security.py` | Deterministic tool gate, permission rules, approvals, secret recognition and redaction. |
| `defense/fixtures.py` | Synthetic public knowledge, fake protected key and demo scenarios. |
| `static/` | Browser UI; untrusted values are rendered with `textContent`, never HTML. |
| `tests/test_defenses.py` | Boundary regression tests, stubbed model loops and local HTTP integration tests. |

## HTTP API

- `GET /api/config` — model configuration, live availability, scenarios and local CSRF token; never the API key.
- `POST /api/runs` — `{mode, task, document, allow_draft, allow_send, scenario_id}`. Returns a snapshot and starts a background run.
- `GET /api/runs/{id}` — polling snapshot; also expires stale approvals.
- `POST /api/runs/{id}/approval` — `{action_id, approve}`; returns updated snapshot.

POST requests require `Content-Type: application/json` and `X-CSRF-Token` from `/api/config`. The server binds to `127.0.0.1`, verifies Host and supplied Origin, serves only three fixed static paths, and applies a Content Security Policy. Up to two runs execute concurrently. At most 50 runs are retained; completed runs are evicted first. Pending runs remain until approved, declined, expired on polling, or server restart. All state is in memory.

## Verification

```sh
python3 -B -m unittest discover -s tests -v
node --check static/app.js
```

Tests cover detector misses, unavailable/invalid reviews, quarantine, unknown tools, malformed arguments, path tricks, recipient tricks, encoded secrets, final-answer leaks, API-request redaction, budget exhaustion, immutable/single-use/expired approvals, policy rechecks, forged approval payloads, CSRF/origin checks and hidden-file access. OpenAI calls are stubbed in tests, so they need no API key and incur no inference cost.

Use `-B` for Python commands to avoid bytecode artifacts. `server.py` also disables bytecode before importing project modules.

## Scope and limitations

This is an eight-hour demo with fixed public knowledge and mock email tools. There is no real mail delivery, filesystem access, or protected-data retrieval; `secrets.env` is a denied mock document ID. The encoded-secret scenario injects a synthetic key into a scripted proposal to exercise DLP.

The reviewer and heuristics can miss attacks or flag legitimate security discussion. DLP uses a bounded set of known values/encodings and credential patterns; it does not comprehensively detect arbitrary encodings, transformed secrets, personal data, or fragments distributed across messages. Exact matching and enforced data-access scope are independent of detector limitations.

The app is a local single-user demo without login, durable audit storage, or production isolation. Future retrieval sources need review/taint handling before their content enters a run. Real tool adapters need least-privilege credentials, authentication, durable approval storage and execution-side validation.

The integration follows the official OpenAI documentation for [GPT-4.1 mini](https://developers.openai.com/api/docs/models/gpt-4.1-mini), [function calling](https://developers.openai.com/api/docs/guides/function-calling), and [structured outputs](https://developers.openai.com/api/docs/guides/structured-outputs).
