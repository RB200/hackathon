#!/usr/bin/env python3
"""Run with python3 -B server.py; serves only on loopback."""

import sys
sys.dont_write_bytecode = True

import json
import os
import secrets
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

from defense.engine import Engine, Run
from defense.fixtures import PUBLIC_DOCUMENTS, DEMO_SCENARIOS, public_scenarios
from defense.provider import OpenAIProvider
from defense.security import DLP, Policy, grants_for_task, task_mode_for_grants
from defense.evaluation import evaluate
from defense.comparison import ComparisonEngine

ROOT = Path(__file__).resolve().parent


def load_env(path):
    """Read simple KEY=value assignments without running shell code."""
    if not path.exists():
        return
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        if key.strip() in {"OPENAI_API_KEY", "OPENAI_MODEL", "REVIEWER_MODEL", "PORT", "ALLOWED_RECIPIENTS"}:
            os.environ.setdefault(key.strip(), value.strip().strip("\"'"))


class App:
    def __init__(self, provider, dlp, recipients):
        self.engine = Engine(provider, dlp)
        self.provider = provider
        self.dlp = dlp
        self.recipients = frozenset(recipients)
        self.csrf = secrets.token_urlsafe(32)
        self.runs = {}
        self.lock = threading.RLock()
        self.slots = threading.BoundedSemaphore(2)
        self.comparisons = {}

    def config(self):
        return {"csrf_token": self.csrf, "live_available": bool(self.provider.api_key), "agent_model": self.provider.agent_model,
                "reviewer_model": self.provider.reviewer_model, "allowed_recipients": sorted(self.recipients), "public_document_ids": sorted(PUBLIC_DOCUMENTS), "scenarios": public_scenarios()}

    def create(self, data):
        if not isinstance(data, dict) or set(data) - {"mode", "task", "document", "scenario_id", "required_document"}:
            raise ValueError("Unexpected run fields.")
        for key, limit in (("task", 2000), ("document", 20000)):
            if not isinstance(data.get(key), str) or not data[key].strip() or len(data[key]) > limit:
                raise ValueError(f"{key} must be nonempty text, at most {limit} characters.")
        if data.get("mode") not in {"live", "replay"}:
            raise ValueError("Choose live or replay mode.")
        required_document = data.get("required_document", "")
        if not isinstance(required_document, str) or (required_document and required_document not in PUBLIC_DOCUMENTS):
            raise ValueError("The required reference must be a public document ID.")
        scenario_id = data.get("scenario_id", "custom")
        if not isinstance(scenario_id, str) or len(scenario_id) > 50:
            raise ValueError("Invalid scenario.")
        fixture = next((item for item in DEMO_SCENARIOS if item["id"] == scenario_id), None)
        if scenario_id != "custom" and not fixture:
            raise ValueError("Unknown scenario.")
        if data["mode"] == "replay" and fixture and (data["document"] != fixture["document"] or data["task"] != fixture["task"]):
            raise ValueError("Edited documents must use the custom scenario; preset replay actions are fixed.")
        if data["mode"] == "live" and not self.provider.api_key:
            raise ValueError("Set OPENAI_API_KEY in .env and restart the server for live mode.")
        if not self.slots.acquire(blocking=False):
            raise ValueError("Two runs are already active. Wait for a run to finish.")
        try:
            granted_tools = grants_for_task(data["task"])
            task_mode = task_mode_for_grants(granted_tools)
            policy = Policy("draft_email" in granted_tools, "send_email" in granted_tools, self.recipients,
                            task_mode=task_mode, required_document=required_document,
                            allow_edit="edit_document" in granted_tools, granted_tools=granted_tools)
            run = Run(data["mode"], data["task"], data["document"], policy, self.dlp, scenario_id)
            with self.lock:
                # Bound memory; do not remove active or pending runs.
                removable = [item for item in self.runs.values() if item.status in {"completed", "failed"}]
                for old in sorted(removable, key=lambda item: item.created_at):
                    if len(self.runs) < 50:
                        break
                    del self.runs[old.id]
                    self.comparisons = {parent: child for parent, child in self.comparisons.items() if old.id not in {parent, child}}
                if len(self.runs) >= 50:
                    raise ValueError("Run storage is full. Resolve pending approvals or restart the demo.")
                self.runs[run.id] = run
            threading.Thread(target=self.work, args=(run,), daemon=True).start()
            return run.snapshot()
        except Exception:
            self.slots.release()
            raise

    def work(self, run):
        try:
            if run.firewall_enabled:
                self.engine.execute(run)
            else:
                ComparisonEngine(self.provider, self.dlp).execute(run)
        finally:
            self.slots.release()

    def compare(self, run_id, data):
        if data != {}:
            raise ValueError("Comparison uses the original run inputs; overrides are not accepted.")
        original = self.get(run_id)
        with self.lock:
            if not original.firewall_enabled:
                raise ValueError("Select a protected run to compare.")
            if original.status not in {"completed", "failed", "awaiting_approval"}:
                raise ValueError("Wait for the protected run to finish.")
            previous_id = self.comparisons.get(run_id)
            if previous_id and previous_id in self.runs:
                return self.runs[previous_id].snapshot()
            if len(self.runs) >= 50:
                raise ValueError("Run storage is full. Restart the demo to clear it.")
            if not self.slots.acquire(blocking=False):
                raise ValueError("Two runs are already active. Wait for a run to finish.")
            try:
                comparison = Run(original.mode, original.task, original.document, original.policy, self.dlp, original.scenario_id, firewall_enabled=False, comparison_of=original.id)
                self.runs[comparison.id] = comparison
                self.comparisons[original.id] = comparison.id
                threading.Thread(target=self.work, args=(comparison,), daemon=True).start()
            except Exception:
                self.slots.release()
                raise
        return comparison.snapshot()

    def evaluate(self):
        if not self.slots.acquire(blocking=False):
            raise ValueError("Two runs are already active. Wait for a run to finish.")
        try:
            return evaluate(self.engine, self.recipients)
        finally:
            self.slots.release()

    def get(self, run_id):
        with self.lock:
            if run_id not in self.runs:
                raise KeyError("Run not found.")
            run = self.runs[run_id]
        with run.lock:
            if run.gate and run.status == "awaiting_approval":
                for action_id, action in list(run.gate.pending.items()):
                    if action["expires_at"] <= time.time():
                        run.gate.decide(action_id, False)
                        if not run.summary.startswith("Agent answer before approval:"):
                            run.summary = "Agent answer before approval:\n" + run.summary
                        run.summary += "\n\nApproval update: The approval expired. No email was sent."
                if not run.gate.pending:
                    run.status = "completed"
        return run

    def decide(self, run_id, data):
        if not isinstance(data, dict) or set(data) != {"action_id", "approve"} or not isinstance(data["action_id"], str) or type(data["approve"]) is not bool:
            raise ValueError("Provide action_id and a boolean approve; payload edits are forbidden.")
        run = self.get(run_id)
        with run.lock:
            if run.status != "awaiting_approval":
                raise ValueError("This run is not waiting for approval.")
            result = run.gate.decide(data["action_id"], data["approve"])
            run.log("completion", "info", "Approval resolved; the agent is not resumed.", {"result": result["status"]})
            if not run.summary.startswith("Agent answer before approval:"):
                run.summary = "Agent answer before approval:\n" + run.summary
            run.summary += "\n\nApproval update: " + {"sent_to_mock_outbox": "The approved email was added to the local mock outbox. No real email was sent.", "declined": "The send was declined. No email was sent.", "expired": "The approval expired. No email was sent.", "blocked": "The send was blocked by the policy recheck. No email was sent."}.get(result["status"], result["status"])
            if not run.gate.pending:
                run.status = "completed"
            return run.snapshot()


class Handler(BaseHTTPRequestHandler):
    server_version = "PromptGuardian/1.0"

    def log_message(self, format, *args):
        # Do not write document content, query strings or credentials to console.
        pass

    def trusted_host(self):
        return self.headers.get("Host") in {f"127.0.0.1:{self.server.server_port}", f"localhost:{self.server.server_port}"}

    def reply(self, status, payload, content_type="application/json; charset=utf-8"):
        body = json.dumps(payload).encode() if content_type.startswith("application/json") else payload
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'")
        self.send_header("Referrer-Policy", "no-referrer")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if not self.trusted_host():
            return self.reply(403, {"error": "Untrusted host."})
        path = urlparse(self.path).path
        app = self.server.app
        if path == "/api/config":
            return self.reply(200, app.config())
        if path.startswith("/api/runs/"):
            try:
                return self.reply(200, app.get(path.removeprefix("/api/runs/")).snapshot())
            except KeyError:
                return self.reply(404, {"error": "Run not found."})
        files = {"/": ("index.html", "text/html; charset=utf-8"), "/app.js": ("app.js", "text/javascript; charset=utf-8"), "/styles.css": ("styles.css", "text/css; charset=utf-8"), "/metrics.css": ("metrics.css", "text/css; charset=utf-8")}
        if path in files:
            filename, content_type = files[path]
            return self.reply(200, (ROOT / "static" / filename).read_bytes(), content_type)
        self.reply(404, {"error": "Not found."})

    def do_POST(self):
        app = self.server.app
        origin = self.headers.get("Origin")
        valid_origins = {f"http://127.0.0.1:{self.server.server_port}", f"http://localhost:{self.server.server_port}"}
        if not self.trusted_host() or (origin and origin not in valid_origins) or not secrets.compare_digest(self.headers.get("X-CSRF-Token", ""), app.csrf):
            return self.reply(403, {"error": "Request origin or CSRF token rejected."})
        if self.headers.get("Content-Type", "").split(";")[0] != "application/json":
            return self.reply(415, {"error": "Use application/json."})
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if not 0 < length <= 100000:
                return self.reply(413, {"error": "Request body is too large or empty."})
            data = json.loads(self.rfile.read(length))
            path = urlparse(self.path).path
            if path == "/api/runs":
                return self.reply(202, app.create(data))
            if path == "/api/evaluations":
                if data != {}:
                    raise ValueError("The offline regression report takes no parameters.")
                return self.reply(200, app.evaluate())
            parts = path.strip("/").split("/")
            if len(parts) == 4 and parts[:2] == ["api", "runs"] and parts[3] == "approval":
                return self.reply(200, app.decide(parts[2], data))
            if len(parts) == 4 and parts[:2] == ["api", "runs"] and parts[3] == "comparison":
                return self.reply(202, app.compare(parts[2], data))
            return self.reply(404, {"error": "Not found."})
        except (ValueError, TypeError, UnicodeDecodeError) as error:
            return self.reply(400, {"error": app.dlp.redact(str(error))[:200]})
        except KeyError:
            return self.reply(404, {"error": "Run not found."})


def build_app():
    load_env(ROOT / ".env")
    key = os.environ.get("OPENAI_API_KEY", "")
    model = os.environ.get("OPENAI_MODEL", "gpt-4.1-mini")
    reviewer = os.environ.get("REVIEWER_MODEL", model)
    dlp = DLP([key])
    provider = OpenAIProvider(key, model, reviewer, dlp)
    recipients = [item.strip() for item in os.environ.get("ALLOWED_RECIPIENTS", "team@example.com").split(",") if item.strip()]
    return App(provider, dlp, recipients)


def main():
    app = build_app()
    port = int(os.environ.get("PORT", "8000"))
    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    server.app = app
    print(f"Prompt Guardian: http://127.0.0.1:{server.server_port}", flush=True)
    print(f"Agent: {app.provider.agent_model} | Reviewer: {app.provider.reviewer_model} | Live API: {'configured' if app.provider.api_key else 'not configured; use offline replay'}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        server.server_close()


if __name__ == "__main__":
    main()
