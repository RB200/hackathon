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
from .evidence import QUOTED, contextual_span, is_reference_or_negated
from .tools import TOOL_REGISTRY


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
    ("tool_instruction", r"\b(?:use|call|invoke|run|execute)\s+(?:the\s+)?(?:send_email|edit_document|delete_document|execute_shell)\b|\b(?:send_email|edit_document|delete_document|execute_shell)\s*\("),
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


TOOL_FIELDS = {name: spec["fields"] for name, spec in TOOL_REGISTRY.items()}
TOOL_DESCRIPTIONS = {name: spec["description"] for name, spec in TOOL_REGISTRY.items()}


def grants_for_task(task):
    """Resolve task intent to registered capabilities; model output is never consulted."""
    from .evidence import requested_tools

    grants = {"read_document", "search_knowledge"}
    # Quoted examples and copied text describe intent; they do not grant it.
    task_intent = QUOTED.sub(" ", task)
    for name in requested_tools(task_intent):
        spec = TOOL_REGISTRY.get(name)
        if not spec or spec["permission"] == "read":
            continue
        grants.add(name)
        grants.update(spec["implies"])
    return frozenset(grants)


def task_mode_for_grants(grants):
    if "send_email" in grants:
        return "send"
    if "edit_document" in grants:
        return "edit"
    if "draft_email" in grants:
        return "draft"
    return "summarize"


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
    allow_edit: bool = False
    granted_tools: frozenset | None = None

    def __post_init__(self):
        if self.task_mode not in {"summarize", "draft", "send", "edit"}:
            raise ValueError("Choose summarize, draft, send, or edit task mode.")
        if self.required_document and self.required_document not in PUBLIC_DOCUMENTS:
            raise ValueError("The required reference must be a public document ID.")

    def permits_tool(self, name, quarantine=False):
        if name in {"read_document", "search_knowledge"}:
            return True
        if quarantine:
            return False
        if self.granted_tools is not None:
            return name in self.granted_tools
        return ((name == "draft_email" and self.task_mode in {"draft", "send"} and self.allow_draft)
                or (name == "send_email" and self.task_mode == "send" and self.allow_send)
                or (name == "edit_document" and self.task_mode == "edit" and self.allow_edit))


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
    edited_documents: dict = field(default_factory=dict)
    edits: list = field(default_factory=list)

    def document_text(self, document_id):
        if document_id == "supplied-document":
            return self.supplied_document
        return self.edited_documents.get(document_id, PUBLIC_DOCUMENTS.get(document_id))

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
            text = self.document_text(args["document_id"])
            result = {"status": "ok", "document_id": args["document_id"], "trust": "untrusted", "text": text}
            if supplied:
                self.supplied_document_read = True
        elif name == "search_knowledge":
            words = args["query"].lower().split()
            documents = {**PUBLIC_DOCUMENTS, **self.edited_documents}
            result = {"status": "ok", "trust": "untrusted", "documents": [{"id": key, "text": value} for key, value in documents.items() if any(word in (key + value).lower() for word in words)]}
        elif name == "edit_document":
            document_id = args["document_id"]
            before = self.document_text(document_id)
            after = before.replace(args["old_text"], args["new_text"], 1)
            if document_id == "supplied-document":
                self.supplied_document = after
            else:
                self.edited_documents[document_id] = after
            self.edits.append({"document_id": document_id, "before": before, "after": after, "old_text": args["old_text"], "new_text": args["new_text"]})
            result = {"status": "edited", "mock": True, "trust": "untrusted", "document_id": document_id, "text": after}
        elif name == "draft_email":
            self.drafts.append(copy.deepcopy(args))
            result = {"status": "drafted", "mock": True, **args}
        else:
            self.outbox.append(copy.deepcopy(args))
            result = {"status": "sent_to_mock_outbox", "mock": True, **args}
        details = {"tool": name, "origin": "approval" if approved else self.origin, "outcome": result["status"], "side_effect": name in {"draft_email", "send_email", "edit_document"}}
        if name in {"read_document", "edit_document"}:
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
        if not isinstance(name, str) or name not in TOOL_REGISTRY:
            return "blocked", "tool_allowlist", "This tool is not in the server allowlist."
        fields = TOOL_FIELDS[name]
        if not isinstance(args, dict) or set(args) != set(fields) or any(not isinstance(args[key], str) or (not args[key].strip() and not (name == "edit_document" and key == "new_text")) or len(args[key]) > limit for key, limit in fields.items()):
            return "blocked", "argument_schema", "Tool arguments do not match the strict server schema."
        labels = self.dlp.inspect(json.dumps(args, ensure_ascii=False))
        if labels:
            return "blocked", "argument_dlp", "Sensitive data or a known encoded secret was found in tool arguments."
        if name in {"read_document", "edit_document"} and args["document_id"] not in PUBLIC_DOCUMENTS and not (args["document_id"] == "supplied-document" and self.supplied_document is not None):
            return "blocked", "document_scope", "Only this run's supplied document and explicitly listed public document IDs are accessible."
        if self.waiting_for_document and not (name == "read_document" and args["document_id"] == "supplied-document"):
            return "blocked", "document_pending", "Read the supplied document before requesting other tool actions."
        if name == "edit_document":
            if self.quarantine:
                return "blocked", "document_quarantine", "Quarantine disables document edits, drafting and sending."
            if not self.policy.permits_tool(name):
                return "blocked", "task_scope", "The task did not request a document edit."
            if self.waiting_for_reference:
                return "blocked", "reference_pending", "Read and screen the required reference before editing."
            if args["document_id"] not in self.reviewed_documents:
                return "blocked", "edit_read_required", "Read and screen the target document before editing it."
            before = self.document_text(args["document_id"])
            if before.count(args["old_text"]) != 1 or args["old_text"] == args["new_text"]:
                return "blocked", "edit_match", "old_text must match exactly once and the replacement must change it."
            after = before.replace(args["old_text"], args["new_text"], 1)
            if len(after) > 20000:
                return "blocked", "edit_size", "The edited document would exceed 20,000 characters."
            if self.dlp.inspect(after):
                return "blocked", "argument_dlp", "The edit would introduce sensitive data into the document."
            if signature_review(after)["findings"]:
                return "blocked", "edit_content", "The edit would leave suspicious instructions in the document."
        if name in {"draft_email", "send_email"}:
            if self.quarantine:
                return "blocked", "document_quarantine", "Suspicious or unreviewed source content restricts this run to read and summarize."
            if not self.policy.permits_tool(name):
                return "blocked", "task_scope", "The task did not request this email action."
            if self.waiting_for_reference:
                return "blocked", "reference_pending", f"Read and screen the required reference {self.policy.required_document} before any email action."
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
