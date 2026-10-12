# Agent Sentinel demo

A static, private-site prototype showing policy decisions in a simulated agent sandbox.

## Demo corpus

`dist/workspace/` contains ordinary task prompts and public sample data. `dist/quarantine/malicious-instructions.fixture.json` is the only hostile prompt fixture. It is inert test input and is never executed. `data/agents.json` defines two approved and two untrusted demo agents with distinct proposed actions; `data/policy.json` defines the checks applied to their proposed actions.

## Safety boundary

The browser demo reads the fixture as text and runs deterministic local checks. It does not run an LLM, connect tools, access customer records, or send data. Its “blocked” states are a visual simulation of where a server-side enforcement gateway must deny a real agent action. This prototype is not connected to real agents and does not provide production enforcement.
