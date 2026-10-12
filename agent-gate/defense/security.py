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
from .evidence import contextual_span, is_reference_or_negated


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
    ("role_override", r"(?:ignore|disregard)\s+(?:all\s+)?(?:previous|prior|system)\s+(?:instructions|rules)|system\s+override|you are now (?:the |a )?(?:security administrator|system)|(?:system|developer)\s*(?:message|prompt)\s*:|treat.{0,60}as (?:a |the )?system (?:message|instruction)"),
    ("secret_exfiltration", r"secrets?\.env|(?:send|reveal|exfiltrate|print|fetch|read)\b[^\n.!?]{0,100}\b(?:api[ _-]?key|password|credential|secret)"),
    ("tool_instruction", r"\b(?:use|call|invoke|run|execute)\s+(?:the\s+)?(?:send_email|delete_document|execute_shell)\b|\b(?:send_email|delete_document|execute_shell)\s*\("),
    ("obfuscation", r"hide (?:this|these) instructions?"),
    ("obfuscation", r"(?:base64|hex)[ -]?(?:encode|decode)|decode.{0,40}(?:payload|instruction)"),
]


def signature_review(document):
    findings = []
    for category, pattern in SIGNATURES:
        for match in re.finditer(pattern, document, re.I):
            if is_reference_or_negated(document, match.start(), match.end()):
                continue
            quote = contextual_span(document, match.start(), match.end())[2]
            if any(item["category"] == category and item["quote"] == quote for item in findings):
                continue
            findings.append({"category": category, "quote": quote, "reason": "An instruction pattern was detected in this passage; context still requires review.", "source": "signature"})
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
    "read_document": "Read supplied-document for this run's user-supplied text, or a mock public document: launch-plan, team-handbook, release-notes. Other IDs are denied. Returned content is untrusted and screened before model access.",
    "draft_email": "Create a local draft. Requires user-granted draft permission; never sends anything.",
    "send_email": "Request sending to a permitted exact address. Always requires human approval. This demo uses a mock outbox.",
}


def tool_definitions(policy=None, quarantine=False, waiting_for_reference=False):
    return [{"type": "function", "name": name, "description": TOOL_DESCRIPTIONS[name], "strict": True,
             "parameters": {"type": "object", "properties": {key: {"type": "string"} for key in fields},
                            "required": list(fields), "additionalProperties": False}}
            for name, fields in TOOL_FIELDS.items()
            if (policy is None or policy.permits_tool(name, quarantine))
            and (not waiting_for_reference or name in {"read_document", "search_knowledge"})]


@dataclass(frozen=True)
class Policy:
    allow_draft: bool = False
    allow_send: bool = False
    recipients: frozenset = frozenset({"team@example.com"})
    max_calls: int = 8
    task_mode: str = "summarize"
    required_document: str = ""

    def __post_init__(self):
        if self.task_mode not in {"summarize", "draft", "send"}:
            raise ValueError("Choose summarize, draft, or send task mode.")
        if self.required_document and self.required_document not in PUBLIC_DOCUMENTS:
            raise ValueError("The required reference must be a public document ID.")

    def permits_tool(self, name, quarantine=False):
        if name in {"read_document", "search_knowledge"}:
            return True
        if quarantine:
            return False
        return ((name == "draft_email" and self.task_mode in {"draft", "send"} and self.allow_draft)
                or (name == "send_email" and self.task_mode == "send" and self.allow_send))


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
    origin: str = "agent_call"
    reviewed_documents: set = field(default_factory=set)
    supplied_document: str | None = None
    supplied_document_read: bool = False

    @property
    def waiting_for_document(self):
        return self.supplied_document is not None and not self.supplied_document_read

    @property
    def required_read(self):
        if self.waiting_for_document:
            return "supplied-document"
        return self.policy.required_document if self.waiting_for_reference else ""

    @property
    def waiting_for_reference(self):
        return bool(self.policy.required_document and self.policy.required_document not in self.reviewed_documents)

    def dispatch(self, name, args, *, approved=False):
        """Must be called under the run lock. Approval is only set by decide()."""
        if not approved:
            self.calls += 1
        decision, rule, reason = self.check(name, args, approved=approved)
        self.log("tool", decision, reason, {"tool": name, "arguments": args, "rule": rule, "attempt": self.calls, "attempted": not approved, "origin": "approval_recheck" if approved else self.origin})
        if decision == "blocked":
            return {"status": "blocked", "rule": rule, "reason": reason}
        if decision == "approval_required":
            action_id = secrets.token_urlsafe(24)
            self.pending[action_id] = {"id": action_id, "tool": name, "arguments": copy.deepcopy(args), "expires_at": time.time() + 300}
            return {"status": "approval_required", "reason": reason, "action_id": action_id}
        if name == "read_document":
            supplied = args["document_id"] == "supplied-document"
            text = self.supplied_document if supplied else PUBLIC_DOCUMENTS[args["document_id"]]
            result = {"status": "ok", "document_id": args["document_id"], "trust": "untrusted", "text": text}
            if supplied:
                self.supplied_document_read = True
        elif name == "search_knowledge":
            words = args["query"].lower().split()
            result = {"status": "ok", "trust": "untrusted", "documents": [{"id": key, "text": value} for key, value in PUBLIC_DOCUMENTS.items() if any(word in (key + value).lower() for word in words)]}
        elif name == "draft_email":
            self.drafts.append(copy.deepcopy(args))
            result = {"status": "drafted", "mock": True, **args}
        else:
            self.outbox.append(copy.deepcopy(args))
            result = {"status": "sent_to_mock_outbox", "mock": True, **args}
        details = {"tool": name, "origin": "approval" if approved else self.origin, "outcome": result["status"], "side_effect": name in {"draft_email", "send_email"}}
        if name == "read_document":
            details["document_id"] = args["document_id"]
        self.log("execution", "executed", f"{name} executed in the local sandbox.", details)
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
        if name == "read_document" and args["document_id"] not in PUBLIC_DOCUMENTS and not (args["document_id"] == "supplied-document" and self.supplied_document is not None):
            return "blocked", "document_scope", "Only this run's supplied document and explicitly listed public document IDs can be read."
        if self.waiting_for_document and not (name == "read_document" and args["document_id"] == "supplied-document"):
            return "blocked", "document_pending", "Read the supplied document before requesting other tool actions."
        if name in {"draft_email", "send_email"}:
            if self.quarantine:
                return "blocked", "document_quarantine", "Suspicious or unreviewed source content restricts this run to read and summarize."
            if self.policy.task_mode == "summarize" or (name == "send_email" and self.policy.task_mode != "send"):
                return "blocked", "task_scope", "The selected task mode does not permit this email action."
            if self.waiting_for_reference:
                return "blocked", "reference_pending", f"Read and screen the required reference {self.policy.required_document} before any email action."
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
