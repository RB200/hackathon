"""Single registry for callable tools and the task language that requests them."""

TOOL_REGISTRY = {
    "search_knowledge": {
        "fields": {"query": 200}, "permission": "read", "implies": (),
        "intent_pattern": r"\b(?:search|look up|find)\b.{0,80}\b(?:knowledge|handbook|documents?|information|records?)\b",
        "description": "Search mock public knowledge. Returns untrusted reference text.",
    },
    "read_document": {
        "fields": {"document_id": 100}, "permission": "read", "implies": (),
        "intent_pattern": r"\b(?:read|fetch|retrieve|open|access|load)\b.{0,100}\b(?:secrets?\.env|files?|documents?|credentials?|api key|password|secret)\b",
        "description": "Read supplied-document for this run's user-supplied text, or a mock public document: launch-plan, team-handbook, release-notes. Other IDs are denied. Returned content is untrusted and screened before model access.",
    },
    "edit_document": {
        "fields": {"document_id": 100, "old_text": 8000, "new_text": 8000}, "permission": "edit", "implies": (),
        "intent_pattern": r"\b(?:edit|modify|update|rewrite|overwrite|change)\b.{0,80}\b(?:files?|documents?|launch plan|launch-plan|supplied-document)\b|\b(?:use|call|invoke)\s+(?:the\s+)?edit_document\b",
        "description": "Edit a run-local mock document by replacing one exact, unique old_text with new_text (empty string removes it). Read the target first. No real files are changed.",
    },
    "draft_email": {
        "fields": {"to": 254, "subject": 200, "body": 8000}, "permission": "draft", "implies": (),
        "intent_pattern": r"\b(?:draft|compose|write)\b.{0,80}(?:\b(?:an? )?email\b|\bto\s+\S+@\S+|\bfor\s+\S+@\S+)|\b(?:use|call|invoke)\s+(?:the\s+)?draft_email\b",
        "description": "Create a local draft. Never sends anything.",
    },
    "send_email": {
        "fields": {"to": 254, "subject": 200, "body": 8000}, "permission": "send", "implies": ("draft_email",),
        "intent_pattern": r"\b(?:send(?:ing)?|deliver|forward|email|transmit)\b.{0,140}\b(?:to\s+\S+@\S+|attacker|external|outside|recipient)\b|\b(?:use|call|invoke)\s+(?:the\s+)?send_email\b",
        "description": "Request sending to a permitted exact address. Always requires human approval. This demo uses a mock outbox.",
    },
}

# Named unsafe actions are recognized for reporting but intentionally have no tool entry.
UNAVAILABLE_TOOL_PATTERNS = {
    "delete_document": r"\b(?:delete|remove|erase)\b.{0,80}\b(?:files?|documents?|records?)\b|\b(?:use|call|invoke)\s+(?:the\s+)?delete_document\b",
    "execute_shell": r"\b(?:run|execute)\b.{0,40}\b(?:shell|command|script|terminal)\b|\b(?:use|call|invoke)\s+(?:the\s+)?execute_shell\b",
}
