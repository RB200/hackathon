"""Deterministic policy enforcement. Model output never grants permissions."""

import base64
import copy
import json
import re
import secrets
import time
import unicodedata
from dataclasses import dataclass, field
from urllib.parse import quote

from .fixtures import DEMO_SECRET, PUBLIC_DOCUMENTS


class DLP:
    """Known secret variants plus a few credential patterns, not general DLP."""

    PATTERNS = [
        ("api_key", re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}")),
        ("aws_key", re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b")),
        ("private_key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----[\s\S]*?(?:-----END [^-]*PRIVATE KEY-----|$)")),
    ]

    def __init__(self, values=()):
        self.variants = set()
        for value in (DEMO_SECRET, *values):
            if not value:
                continue
            raw = value.encode()
            self.variants.update({
                value, base64.b64encode(raw).decode(), base64.urlsafe_b64encode(raw).decode(),
                base64.b64encode(raw).decode().rstrip("="),
                base64.urlsafe_b64encode(raw).decode().rstrip("="),
                raw.hex(), raw.hex().upper(), quote(value, safe=""),
                "".join(f"%{byte:02X}" for byte in raw),
                "".join(f"%{byte:02x}" for byte in raw),
            })

    def inspect(self, text):
        normalized = unicodedata.normalize("NFKC", text)
        compact = re.sub(r"\s|[\u200b-\u200f\ufeff]", "", normalized)
        labels = set()
        if any(value in normalized or value in compact for value in self.variants):
            labels.add("known_secret_or_encoding")
        for label, pattern in self.PATTERNS:
            if pattern.search(normalized) or pattern.search(compact):
                labels.add(label)
        return sorted(labels)

    def redact(self, text):
        normalized = unicodedata.normalize("NFKC", text)
        for value in sorted(self.variants, key=len, reverse=True):
            normalized = normalized.replace(value, "[REDACTED]")
        for _, pattern in self.PATTERNS:
            normalized = pattern.sub("[REDACTED]", normalized)
        # Whitespace/zero-width splits cannot be safely mapped to exact offsets.
        if self.inspect(normalized):
            return "[REDACTED: sensitive content detected]"
        return normalized

    def safe(self, value):
        if isinstance(value, str):
            return self.redact(value)
        if isinstance(value, dict):
            return {self.redact(str(key)): self.safe(item) for key, item in value.items()}
        if isinstance(value, (list, tuple)):
            return [self.safe(item) for item in value]
        return value


SIGNATURES = [
    ("role_override", r"ignore\s+(?:all\s+)?(?:previous|prior|system)\s+instructions|system\s+override|you are now (?:the |a )?(?:security administrator|system)|(?:system|developer)\s*(?:message|prompt)\s*:"),
    ("secret_exfiltration", r"secrets?\.env|(?:send|reveal|exfiltrate|print|fetch|read)\b[^\n]{0,100}\b(?:api[ _-]?key|password|credential|secret)"),
    ("tool_instruction", r"\b(?:send_email|delete_document|execute_shell)\b|hide (?:this|these) instructions?"),
    ("obfuscation", r"(?:base64|hex)[ -]?(?:encode|decode)|decode.{0,40}(?:payload|instruction)"),
]


def signature_review(document):
    findings = []
    for category, pattern in SIGNATURES:
        for match in re.finditer(pattern, document, re.I):
            findings.append({"category": category, "quote": match.group(0), "reason": "Matched an injection heuristic; inspect the surrounding context.", "source": "signature"})
            if len(findings) >= 12:
                break
    return {"risk": "suspicious" if findings else "benign", "findings": findings, "source": "signatures"}


TOOL_FIELDS = {
    "search_knowledge": {"query": 200},
    "read_document": {"document_id": 100},
    "draft_email": {"to": 254, "subject": 200, "body": 8000},
    "send_email": {"to": 254, "subject": 200, "body": 8000},
}
TOOL_DESCRIPTIONS = {
    "search_knowledge": "Search mock public knowledge. Returns untrusted reference text.",
    "read_document": "Read a mock document by ID. Public IDs: launch-plan, team-handbook. Other IDs may be denied by the gate.",
    "draft_email": "Create a local draft. Requires user-granted draft permission; never sends anything.",
    "send_email": "Request sending to a permitted exact address. Always requires human approval. This demo uses a mock outbox.",
}


def tool_definitions():
    return [{"type": "function", "name": name, "description": TOOL_DESCRIPTIONS[name], "strict": True,
             "parameters": {"type": "object", "properties": {key: {"type": "string"} for key in fields},
                            "required": list(fields), "additionalProperties": False}}
            for name, fields in TOOL_FIELDS.items()]


@dataclass(frozen=True)
class Policy:
    allow_draft: bool = False
    allow_send: bool = False
    recipients: frozenset = frozenset({"team@example.com"})
    max_calls: int = 8


@dataclass
class Gate:
    policy: Policy
    dlp: DLP
    quarantine: bool
    log: object
    calls: int = 0
    drafts: list = field(default_factory=list)
    outbox: list = field(default_factory=list)
    pending: dict = field(default_factory=dict)

    def dispatch(self, name, args, *, approved=False):
        """Must be called under the run lock. Approval is only set by decide()."""
        if not approved:
            self.calls += 1
        decision, rule, reason = self.check(name, args, approved=approved)
        self.log("tool", decision, reason, {"tool": name, "arguments": args, "rule": rule, "attempt": self.calls})
        if decision == "blocked":
            return {"status": "blocked", "rule": rule, "reason": reason}
        if decision == "approval_required":
            action_id = secrets.token_urlsafe(24)
            self.pending[action_id] = {"id": action_id, "tool": name, "arguments": copy.deepcopy(args), "expires_at": time.time() + 300}
            return {"status": "approval_required", "reason": reason, "action_id": action_id}
        if name == "read_document":
            result = {"status": "ok", "document_id": args["document_id"], "trust": "untrusted", "text": PUBLIC_DOCUMENTS[args["document_id"]]}
        elif name == "search_knowledge":
            words = args["query"].lower().split()
            result = {"status": "ok", "trust": "untrusted", "documents": [{"id": key, "text": value} for key, value in PUBLIC_DOCUMENTS.items() if any(word in (key + value).lower() for word in words)]}
        elif name == "draft_email":
            self.drafts.append(copy.deepcopy(args))
            result = {"status": "drafted", "mock": True, **args}
        else:
            self.outbox.append(copy.deepcopy(args))
            result = {"status": "sent_to_mock_outbox", "mock": True, **args}
        # Enforce tool-result egress independently before the agent sees it.
        if self.dlp.inspect(json.dumps(result, ensure_ascii=False)):
            self.log("egress", "blocked", "Tool result contains sensitive data.", {"rule": "tool_result_dlp"})
            return {"status": "blocked", "rule": "tool_result_dlp"}
        return result

    def check(self, name, args, *, approved=False):
        if self.calls > self.policy.max_calls:
            return "blocked", "tool_budget", "This run exhausted its tool-call budget."
        if not isinstance(name, str) or name not in TOOL_FIELDS:
            return "blocked", "tool_allowlist", "This tool is not in the server allowlist."
        fields = TOOL_FIELDS[name]
        if not isinstance(args, dict) or set(args) != set(fields) or any(not isinstance(args[key], str) or not args[key].strip() or len(args[key]) > limit for key, limit in fields.items()):
            return "blocked", "argument_schema", "Tool arguments do not match the strict server schema."
        labels = self.dlp.inspect(json.dumps(args, ensure_ascii=False))
        if labels:
            return "blocked", "argument_dlp", "Sensitive data or a known encoded secret was found in tool arguments."
        if name == "read_document" and args["document_id"] not in PUBLIC_DOCUMENTS:
            return "blocked", "document_scope", "Only explicitly listed public document IDs can be read."
        if name in {"draft_email", "send_email"}:
            if self.quarantine:
                return "blocked", "document_quarantine", "Suspicious or unreviewed source content restricts this run to read and summarize."
            if not self.policy.allow_draft and name == "draft_email":
                return "blocked", "draft_capability", "The user did not grant drafting permission for this run."
            if not self.policy.allow_send and name == "send_email":
                return "blocked", "send_capability", "The user did not grant sending permission for this run."
            # Exact match rejects display names, extra recipients, whitespace and lookalike domains.
            if args["to"] not in self.policy.recipients:
                return "blocked", "recipient_allowlist", "The recipient is not an exact address in the server allowlist."
            if name == "send_email" and not approved:
                return "approval_required", "human_approval", "A human must approve this exact recipient, subject and body before sending."
        return "allowed", "policy_pass", "Tool, arguments, scope and data checks passed."

    def decide(self, action_id, approve):
        # Pop first: a decision is single use, including an expired/denied action.
        action = self.pending.pop(action_id, None)
        if not action:
            raise ValueError("Approval does not exist or was already consumed.")
        if action["expires_at"] <= time.time():
            self.log("approval", "blocked", "Approval expired; no action executed.", {"rule": "approval_expired"})
            return {"status": "expired"}
        if not approve:
            self.log("approval", "blocked", "Human declined the send; no action executed.", {"rule": "human_denied"})
            return {"status": "declined"}
        self.log("approval", "allowed", "Human approved the stored immutable payload.", {"action_id": action_id})
        # Recheck every policy condition; approval cannot bypass a deny.
        return self.dispatch(action["tool"], action["arguments"], approved=True)
