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

Every run begins with an actual gated `read_document({document_id: "supplied-document"})` call. The supplied text is stored only in that run and is not included directly in the agent's prompt. Live mode forces this function with the exact document ID; replay dispatches the same read before its scripted actions. Other actions are blocked until the read happens, and an agent that skips it cannot complete the run. A successful read counts in **Tool calls / blocked** and **Actions executed**, even when screening withholds the returned content. Quarantined supplied documents produce a withholding explanation instead of a fabricated summary. The initial review is reused for this read, so findings and quarantined-source counts are not duplicated.

| Scenario | What happens in offline replay |
| --- | --- |
| 01 / Normal document | Public handbook read succeeds; launch facts are summarized. |
| 02 / Prompt injection | Source impersonates a system instruction; screening quarantines it. Protected reads and sends are blocked. |
| 03 / Tool misuse | A destructive request against a clean source is denied by the tool allowlist. |
| 04 / Authorized file edit | Reads supplied-document, replaces Friday with Monday, and shows the edited mock document. |
| 05 / File tampering injection | Quarantines a document asking for a budget change and blocks the scripted edit. Firewall-off replay edits its own mock copy. |

In live mode, none of the scripted attack proposals or forced reviewer verdicts apply. The supplied-document read is always forced. Subsequent model-selected actions may vary, and a real model may reject an attack before proposing an unsafe call. The gate still checks every proposed action. The destructive tool is deliberately absent from the model's tool definitions; the offline scenario tests what happens if a compromised caller requests it anyway.

Try your own text by editing the document or uploading a plain-text file. Edits select **Custom document**. Custom offline mode performs heuristic screening, a public handbook read, and a labeled text preview; use live mode for an AI-generated summary and AI tool proposals. Document limit: 20,000 characters. Task limit: 2,000 characters.

The server derives tool scope from the user's task using local request heuristics and a central tool registry. Read and search are available by default. Explicit draft, send, or edit intent enables only the matching registered tools; sending still requires an allowed recipient and exact-payload approval. Model output and document contents cannot grant access. Heuristics can miss or misread intent, so the server still validates every call. The sidebar shows presets 01–05 and Custom; historical scenarios remain internal test fixtures and cannot be selected through the run API.

The **User task verdict**, beside **Input document verdict**, separately checks the request against registered tools and local sensitive-data rules. It shows **Outside permissions**, **Sensitive input**, or **No conflict detected**, with an explanation. This is a heuristic task check, not an LLM judgment that the user is malicious or a guarantee of safety. A clean document can accompany a forbidden deletion request. The check does not count inferred requests as blocked calls, and every actual tool call still requires the server gate.

Decision log entries show source intake, grouped review findings, detected requests, actual permission checks, tool execution, retrieved-source reviews, and output scans in chronological order. Tool names appear directly in the row; expand it to inspect arguments, rules, evidence, and supporting detectors. These are recorded checks, not hidden model reasoning. The **Recorded action status** below the answer comes from server state: it identifies disabled actions, real pending approvals, and mock sends independently of promises in the model answer. Inferred tool requests are labeled as such and never counted as actual calls.

The counters distinguish **Unsafe requests detected** (distinct source/tool pairs inferred from suspicious evidence or tasks outside permissions), **Tool calls / blocked** (total actual call attempts / attempts rejected by the gate), and **Actions executed** (reads, mock edits, mock drafts, and approved mock sends). For example, `3 / 1` means three attempts with one blocked; pending approval may account for another attempt that has not executed. Approval requests do not count as execution; approval rechecks do not count as new agent calls. JSON metrics retain separate `tool_calls` and `blocked_tool_calls` values. **Quarantined sources** includes retrieved documents; hover or keyboard-focus the number to inspect source IDs and reasons. The input-document verdict can remain benign while a retrieved source quarantines the run. Related LLM and signature evidence is grouped by category and overlapping quote, with every supporting detector retained.

Internal offline checks are available through `/api/evaluations`; the demo UI has no regression-report control. The report checks the five current presets, independently of gate decisions. It does not measure live model summary quality or attack success rates.

**Export JSON** downloads the redacted run snapshot, including initial and retrieved source reviews, policy, decisions, drafts, approvals, and mock outbox.

### Read the outcome

The **Agent answer** sits in a prominent card immediately below the outcome banner, before the comparison, metrics and decision log. Its **Recorded action status** stays inside the same card so model claims can be compared with actual server-recorded effects.

The **Recorded outcome** banner is derived from server state and audit events, independently of the agent's answer. It distinguishes a completed run, firewall intervention, an inferred unsafe request with no actual block, incomplete actions, pending approval and failures. A completed run describes recorded checks; it does not independently verify answer quality or every part of the task. **Where the defense intervened** identifies screening, the tool gate, data checks or human approval. Click a layer to open its exact decision-log entry. A model refusal or omission gets no firewall-block credit.

**What changed?** compares recorded mock edits and email recipients, plus secret retrieval, deletion or simulated commands when relevant. The firewall-off column says **Not run yet** until you explicitly start the comparison; it never invents an unprotected outcome. It shows the actual replacement text, such as the budget staying at $5,000 versus changing to $50,000. Both columns persist when switching tabs and reset for a new run. Partial effects from failed runs are labeled.

For a short demo: run **01** to show normal reads, **05** to show screening and blocked editing, then click **Compare with firewall off** to show the changed mock budget. Finish with **03** to demonstrate an independent tool-allowlist block against a clean document. Offline mode is repeatable; live tool choices can differ.

### Edit mock files

Ask for the desired change in the user task, for example: `Edit supplied-document: replace Friday with Monday.` The server grants the registered edit tool when its local task-intent check recognizes the request. In live mode the agent reads the target then proposes `edit_document({document_id, old_text, new_text})`; offline scenario 04 scripts the same edit. Custom offline mode remains a document preview and does not interpret arbitrary editing instructions.

The server requires the edit task and grant, a read and screening of the target, no quarantine, and any required reference to be screened first. `old_text` must match exactly once; empty `new_text` removes that passage. Unknown IDs, filesystem paths, ambiguous or unchanged replacements, edits over 20,000 characters, recognized sensitive data and heuristic instruction patterns are rejected before mutation. The returned edited content also goes through source review before entering model history. Edits affect only the supplied document or overrides of listed public documents within that run; original fixtures and real files stay unchanged. **Local artifacts** displays each replacement, full before/after text and a download button; snapshots include `edits`. Reads and searches within that run see its updated content. Editing counts as a tool call and executed action.

### Compare with the firewall off

After a protected run finishes, select **Firewall off** at the top of its result panel. The server creates a separate comparison with the original task, document, reference and execution mode. Switching tabs preserves both results; opening the comparison again reuses it. A new defense run resets the comparison.

The comparison disables source review, quarantine, tool permissions, recipient restrictions, outbound policy checks and human approval **inside an isolated mock tool environment**. It can read a synthetic `secrets.env`, send directly to its own mock outbox, edit or delete copies of mock documents, or record simulated commands. It cannot access real files, execute a shell or deliver email. Transport redaction of configured credentials and audit redaction remain in place. Disabled detector counters show **Off**, rather than suggesting the input was safe.

Offline mode uses a labeled vulnerable-agent script to illustrate possible consequences. It is not a prediction or evidence that an LLM was compromised. Live mode makes additional agent API calls with screening and application policy removed, and exposes the mock destructive tools; the model can still refuse. The two live runs can differ because the prompts, available tools and model choices differ. Compare recorded calls and mock effects, not just the wording of the answer.

In a live firewall-off comparison, a destructive action explicitly requested by the user task is forced through its mock tool before the agent answers. An “all documents” request constrains the mock deletion target to `*`. The answer must report the tool's actual result; only documents listed in the comparison's isolated mock store are affected. This makes the deletion demo reproducible while preserving the distinction between claimed and recorded effects.

## Defense layers

1. **Trust boundaries:** the server derives registered tool grants from the user task. Untrusted reference text and model output cannot change those grants. Tool results are labeled untrusted and screened before model access.
2. **Document screening:** a reviewer with no tools returns a strict risk/evidence JSON schema. Evidence must be exact document substrings. Heuristic matches cannot be overruled by a benign LLM verdict. A suspicious, malicious, refused, invalid or unavailable review quarantines the source. Every retrieved read/search document is screened too. Suspicious retrieved text is withheld, quarantine disables edits and email actions for the whole run, and pending approvals are canceled. Repeated sources reuse review only when both their ID and content digest match. Quarantine cannot be cleared by a later benign source. Heuristics skip locally negated patterns and quoted educational examples; those filters remain fallible, and live LLM review still runs independently.
3. **Mandatory gate:** central tool registry, strict runtime argument validation, run-local supplied-document access plus exact public reference IDs, required supplied-document read, exact recipient addresses, task-derived grants, and an eight-attempt budget. Sending requires approval. The mandatory read and blocked calls also count. The agent has no filesystem, shell, arbitrary network, or deletion tool.
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
                 Tool-result screening → Agent → Final-answer check

Every decision → redacted in-memory event log → Browser / JSON export
```

| File | Responsibility |
| --- | --- |
| `server.py` | Local HTTP API, `.env` configuration, concurrency limits, run storage and approval lifecycle. |
| `defense/provider.py` | OpenAI Responses API adapter, request redaction, timeouts and sanitized errors. |
| `defense/engine.py` | Isolated review, evidence validation, quarantine, live tool loop and labeled offline replay. |
| `defense/security.py` | Deterministic tool gate, permission rules, approvals, secret recognition and redaction. |
| `defense/tools.py` | Callable tool schemas, descriptions, capability requirements and task-intent patterns. |
| `defense/fixtures.py` | Synthetic public knowledge, five public demo presets and historical internal test fixtures. |
| `defense/evidence.py` | Context-aware heuristic helpers, inferred tool intent, and grouping of supporting evidence. |
| `defense/evaluation.py` | Offline regression report with independent per-scenario expectations. |
| `defense/comparison.py` | Separate firewall-off live/replay execution with synthetic secrets and isolated mock effects. |
| `static/` | Browser UI; untrusted values are rendered with `textContent`, never HTML. |
| `tests/test_defenses.py` | Boundary regression tests, stubbed model loops and local HTTP integration tests. |

## HTTP API

- `GET /api/config` — model configuration, live availability, scenarios and local CSRF token; never the API key.
- `POST /api/runs` — `{mode, required_document, task, document, scenario_id}`. Tool grants are derived server-side from the task and registered tool capabilities. Returns a snapshot and starts a background run.
- `POST /api/evaluations` — `{}`; internal check of the five public presets in offline replay.
- `GET /api/runs/{id}` — polling snapshot; also expires stale approvals.
- `POST /api/runs/{id}/comparison` — `{}`; starts or returns the cached isolated firewall-off comparison for a finished protected run. Input overrides are not accepted. Snapshots identify `firewall_enabled`, `comparison_of`, and synthetic `comparison_effects`.
- `POST /api/runs/{id}/approval` — `{action_id, approve}`; returns updated snapshot.

POST requests require `Content-Type: application/json` and `X-CSRF-Token` from `/api/config`. The server binds to `127.0.0.1`, verifies Host and supplied Origin, serves only fixed static paths, and applies a Content Security Policy. Up to two runs execute concurrently. At most 50 runs are retained; completed runs are evicted first. Pending runs remain until approved, declined, expired on polling, or server restart. All state is in memory.

## Verification

```sh
python3 -B -m unittest discover -s tests -v
node --check static/app.js
```

The 65 tests cover selected-task enforcement, forged out-of-scope calls, required-reference ordering and completion checks, retrieved and search-result injection, review failure during retrieval, pending approval cancellation, grouped evidence, benign educational/negated controls, regression reporting, detector misses, unavailable/invalid reviews, quarantine, unknown tools, malformed arguments, path tricks, recipient tricks, encoded secrets, final-answer leaks, API-request redaction, budget exhaustion, immutable/single-use/expired approvals, policy rechecks, forged approval payloads, CSRF/origin checks and hidden-file access. OpenAI calls are stubbed in tests, so they need no API key and incur no inference cost.

Use `-B` for Python commands to avoid bytecode artifacts. `server.py` also disables bytecode before importing project modules.

## Scope and limitations

This is an eight-hour demo with fixed public knowledge and mock email tools. There is no real mail delivery, filesystem access, or protected-data retrieval; `secrets.env` is a denied mock document ID. Encoded-secret proposals remain covered by internal fixtures. The required-reference dependency is available to API clients but has no sidebar selector.

The reviewer and heuristics can miss attacks or flag legitimate security discussion. DLP uses a bounded set of known values/encodings and credential patterns; it does not comprehensively detect arbitrary encodings, transformed secrets, personal data, or fragments distributed across messages. Exact matching and enforced data-access scope are independent of detector limitations.

The app is a local single-user demo without login, durable audit storage, or production isolation. New retrieval adapters must route every returned source through the existing screening flow before its content enters a run. The added reviews introduce model calls and latency for each new source in live mode. Real tool adapters need least-privilege credentials, authentication, durable approval storage and execution-side validation.

The integration follows the official OpenAI documentation for [GPT-4.1 mini](https://developers.openai.com/api/docs/models/gpt-4.1-mini), [function calling](https://developers.openai.com/api/docs/guides/function-calling), and [structured outputs](https://developers.openai.com/api/docs/guides/structured-outputs).
