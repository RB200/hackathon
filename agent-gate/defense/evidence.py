"""Conservative evidence helpers. Inferred requests never count as tool calls."""

import copy
import re

from .tools import TOOL_REGISTRY, UNAVAILABLE_TOOL_PATTERNS


TOOL_PATTERNS = {name: spec["intent_pattern"] for name, spec in TOOL_REGISTRY.items()}
TOOL_PATTERNS.update(UNAVAILABLE_TOOL_PATTERNS)
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
    found = set()
    for name, pattern in TOOL_PATTERNS.items():
        for match in re.finditer(pattern, text, re.I):
            if not is_reference_or_negated(text, match.start(), match.end()):
                found.add(name)
    tool_names_pattern = "|".join(re.escape(name) for name in TOOL_PATTERNS)
    explicit = rf"\b(?:use|call|invoke|run|execute)\s+(?:the\s+)?({tool_names_pattern})\b"
    for match in re.finditer(explicit, text, re.I):
        if not is_reference_or_negated(text, match.start(), match.end()):
            found.add(match.group(1).lower())
    return sorted(found)


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
