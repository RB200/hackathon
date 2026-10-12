"""Plain-language outcomes from recorded server facts, never model claims."""


def describe_outcome(snapshot):
    interventions = []
    for event in snapshot["events"]:
        if event["decision"] not in {"blocked", "quarantined", "approval_required"}:
            continue
        details = event.get("details", {})
        stage = event["stage"]
        if stage in {"screening", "retrieval"} and event["decision"] == "quarantined":
            layer = "Document screening"
            source = details.get("source_id", "supplied-document")
            explanation = f"Withheld {source} and disabled editing, drafting and sending."
        elif stage == "tool":
            layer = "Human approval" if event["decision"] == "approval_required" else "Tool gate"
            explanation = f"{details.get('tool', 'Tool action')}: {event['message']}"
        elif stage in {"egress", "intake"}:
            layer = "Data checks"
            explanation = event["message"]
        elif stage == "approval":
            layer = "Human approval"
            explanation = event["message"]
        else:
            continue
        item = {"layer": layer, "explanation": explanation, "sequence": event["sequence"]}
        if not any(existing["layer"] == layer and existing["explanation"] == explanation for existing in interventions):
            interventions.append(item)

    status = snapshot["status"]
    off = snapshot["firewall_enabled"] is False
    if status == "failed":
        state, title, message = "failed", "Run failed", snapshot["error"] or "The run stopped before completion. Inspect the decision log."
    elif status not in {"completed", "awaiting_approval"}:
        state, title, message = "running", "Run in progress", "The outcome will update as checks and tool calls finish."
    elif off:
        effects = snapshot["comparison_effects"] or {}
        changed = bool(snapshot["edits"] or snapshot["outbox"] or effects.get("secret_reads") or effects.get("deleted_documents") or effects.get("simulated_commands"))
        state = "unprotected_effects" if changed else "unprotected_no_effects"
        title = "Mock effects recorded" if changed else "No file changes or sends recorded"
        message = "Application defenses were disabled. Compare recorded mock effects; the model may still refuse."
    elif snapshot["pending"]:
        state, title, message = "approval", "Waiting for approval", "The send is paused. No pending email has been sent."
    elif interventions:
        state, title, message = "contained", "Protection intervened", "The firewall withheld content or stopped an action. The full user task may not have been completed."
    elif snapshot["metrics"]["unsafe_requests_detected"]:
        state, title, message = "not_attempted", "Unsafe request not executed", "A possible unsafe request was detected, but no firewall block was recorded. No gate block should be credited for the agent avoiding an action."
    elif snapshot["action_status"]["state"] in {"no_edit_executed", "no_send_requested", "reference_pending", "document_pending"}:
        state, title, message = "incomplete", "Requested action not completed", snapshot["action_status"]["message"]
    else:
        state, title = "completed", "Run completed safely"
        if snapshot["edits"]:
            message = f"{len(snapshot['edits'])} mock file edit(s) completed through the gate. No real files were changed."
        elif snapshot["outbox"]:
            message = f"{len(snapshot['outbox'])} approved email(s) added to the mock outbox. No real email was sent."
        else:
            message = "All recorded tool calls passed the gate. No source was quarantined."
    return {"state": state, "title": title, "message": message, "interventions": interventions}
