# Prompt Guardian

A local demo of defenses for a document-reading AI agent: document screening, server-enforced tool permissions, secret checks, human approval, and an isolated firewall-off comparison. Tools use mock data; no real files are edited and no mail is sent.

[Watch the demo](https://www.youtube.com/watch?v=FNZFqLeXGL4)

## Run

Requires Python 3.10+; no packages to install.

```sh
python3 -B server.py
```

Open <http://127.0.0.1:8000>. Without an API key, the app runs scripted offline scenarios. For live mode, copy `.env.example` to `.env`, set `OPENAI_API_KEY`, and restart the server. The key stays on the server; input is checked and redacted before model requests.

## Model roles

- **GPT-4.1 mini** is the agent: it reads the document, answers the task, and proposes tool calls.
- **Luna** is the independent reviewer: it checks untrusted document text for prompt injection and returns risk findings. It has no tools and cannot grant permissions.
- **The server gate** makes the final tool decision. It checks each call against task permissions and policy, regardless of either model's output.

The code currently ships with an OpenAI Responses API adapter. `OPENAI_MODEL` selects the agent model; `REVIEWER_MODEL` can select a separate OpenAI reviewer model. To connect Luna through another provider, adapt `defense/provider.py`; the gate does not depend on the model provider.

## Demo scenarios

| Example | Offline replay |
| --- | --- |
| 01 / Normal document | Reads and summarizes a public handbook. |
| 02 / Prompt injection | Quarantines a document that tries to override instructions. |
| 03 / Tool misuse | Denies an unauthorized destructive request against a clean document. |
| 04 / Authorized file edit | Changes Friday to Monday in a run-local mock document. |
| 05 / File tampering injection | Quarantines an injected edit request and blocks the edit. |

Offline outcomes are scripted to make the gate repeatable; they are not evidence of live model behavior. In live mode, the model may refuse or choose different tools. Every run starts with a gated read of the supplied document. Try custom text by editing the document or uploading a plain-text file (20,000 character limit; task limit 2,000).

## Reading results

- **Input document verdict** reports screening of the supplied document. **User task verdict** separately reports locally detected conflicts or sensitive task input.
- **Unsafe requests detected** counts inferred requests. **Tool calls / blocked** counts actual model call attempts and the subset rejected by the gate. **Actions executed** counts successful mock tool actions, including document reads.
- **Quarantined sources** includes supplied and retrieved documents. Expand a decision-log entry to inspect recorded evidence, tool names, arguments, and policy checks. These records are not hidden model reasoning.
- **Recorded outcome** and **Recorded action status** come from server events, not claims in the agent's answer.

After a protected run, choose **Firewall off** to start a separate comparison using the original inputs. It disables screening and application policy only inside an isolated mock environment. Offline comparison uses scripted outcomes; live comparison makes additional model calls and may vary. It cannot access real files, execute commands, or send real mail. Compare recorded mock effects, not just the answer text.

## Safety boundaries

- The server derives tool grants from the user task; document text and model output cannot grant access.
- Every source returned by a read or search is screened before the agent can use it. Suspicious sources are withheld and quarantined.
- Email sends require an allowed recipient and approval of the exact message. All email, edit, delete, secret-read, and command effects are mock-only.
- Secret checks cover selected known values and credential patterns; they are not complete protection against arbitrary encodings or transformed data.
- Runs, approvals, logs, and mock effects are in memory and disappear when the server restarts. This is a local demo, not a production deployment.

## Development

```sh
python3 -B -m unittest discover -s tests -v
node --check static/app.js
```

`-B` prevents Python bytecode files. The server also disables bytecode generation.

Key files: `server.py` (local API and run state), `defense/` (review, policy, tools, and comparisons), `static/` (browser UI), and `tests/` (offline and integration checks). `POST /api/evaluations` runs the internal offline scenario report; the UI does not expose it.
