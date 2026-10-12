"""Conservative evidence helpers. Inferred requests never count as tool calls."""

import copy
import re


TOOL_PATTERNS = {
    "read_document": r"\b(?:read|fetch|retrieve|open|access|load)\b.{0,100}\b(?:secrets?\.env|files?|documents?|credentials?|api key|password|secret)\b",
    "search_knowledge": r"\b(?:search|look up|find)\b.{0,80}\b(?:knowledge|handbook|documents?|information|records?)\b",
    "draft_email": r"\b(?:draft|compose|write)\b.{0,40}\b(?:an? )?email\b",
    "send_email": r"\b(?:send|deliver|forward|email|transmit)\b.{0,140}\b(?:to\s+\S+@\S+|attacker|external|outside|recipient)\b",
    "delete_document": r"\b(?:delete|remove|erase)\b.{0,80}\b(?:files?|documents?|records?)\b",
    "execute_shell": r"\b(?:run|execute)\b.{0,40}\b(?:shell|command|script|terminal)\b",
}
NEGATION = re.compile(r"\b(?:do not|don't|never|must not|should not|cannot|can't|avoid|without)\b[^,;.!?\n]{0,90}$", re.I)
EDUCATIONAL = re.compile(r"\b(?:example|training|educational|quoted|documentation|illustration)\b", re.I)
QUOTED = re.compile(r'"[^"\n]+"|“[^”\n]+”|`[^`\n]+`|\'[^\'\n]+\'')


def sentences(text):
    for match in re.finditer(r"[^\n]+", text):
        start = match.start()
        for separator in re.finditer(r"[.!?](?=\s|$)", match.group()):
            end = match.start() + separator.end()
            yield start, end, text[start:end]
            start = end
        if start < match.end():
            yield start, match.end(), text[start:match.end()]


def contextual_span(text, start, end):
    for left, right, sentence in sentences(text):
        if left <= start < right:
            return left, max(right, end), sentence.strip()
    return start, end, text[start:end]


def is_reference_or_negated(text, start, end):
    left, right, sentence = contextual_span(text, start, end)
    prefix = re.split(r"\b(?:but|however|instead|then|rather)\b|[;,:]", text[left:start], flags=re.I)[-1]
    if NEGATION.search(prefix):
        return True
    # Suppress only the quoted span of a locally identified educational example.
    # A disclaimer elsewhere never exempts subsequent instructions.
    for quote in QUOTED.finditer(text[left:right]):
        if left + quote.start() <= start and end <= left + quote.end():
            if EDUCATIONAL.search(text[left:left + quote.start()]):
                return True
    return False


def requested_tools(text):
    names = set()
    for name, pattern in TOOL_PATTERNS.items():
        for match in re.finditer(pattern, text, re.I):
            if not is_reference_or_negated(text, match.start(), match.end()):
                names.add(name)
    explicit = r"\b(?:use|call|invoke|run|execute)\s+(?:the\s+)?(read_document|search_knowledge|draft_email|send_email|delete_document|execute_shell)\b"
    for match in re.finditer(explicit, text, re.I):
        if not is_reference_or_negated(text, match.start(), match.end()):
            names.add(match.group(1).lower())
    return sorted(names)


def annotate_requested_tools(findings, document=""):
    for finding in findings:
        quote = finding.get("quote", "")
        position = document.find(quote) if quote else -1
        evidence = contextual_span(document, position, position + len(quote))[2] if position >= 0 else quote
        finding["requested_tools"] = requested_tools(evidence)
    return findings


def group_findings(findings):
    """Merge overlapping evidence of the same category, retaining each detector."""
    groups = []
    for original in findings:
        finding = copy.deepcopy(original)
        signal = {key: finding[key] for key in ("source", "quote", "reason") if key in finding}
        group = next((item for item in groups if item["category"] == finding["category"]
                      and (finding["quote"] in item["quote"] or item["quote"] in finding["quote"])), None)
        if group is None:
            finding["signals"] = [signal]
            groups.append(finding)
            continue
        if signal not in group["signals"]:
            group["signals"].append(signal)
        group["requested_tools"] = sorted(set(group.get("requested_tools", [])) | set(finding.get("requested_tools", [])))
        if len(finding["quote"]) > len(group["quote"]):
            group["quote"] = finding["quote"]
        if finding.get("source") == "llm":
            group["reason"] = finding["reason"]
    return groups
