"use strict";

const $ = (id) => document.getElementById(id);
let config, currentRun = null, timer = null, renderSignature = "", running = false;

const FINDING_GUIDANCE = {
  role_override: {label: "Tries to change the AI’s instructions", explanation: "This document asks the AI to ignore its assigned rules or take on a different role."},
  secret_exfiltration: {label: "Secret disclosure", explanation: "Asks the AI to retrieve or reveal a credential or other protected information."},
  tool_instruction: {label: "Unrequested tool action", explanation: "Asks the AI to use a tool for an action outside the user's task or permission."},
  obfuscation: {label: "Hidden or encoded instruction", explanation: "Hides an instruction or asks the AI to decode one before acting."},
  other: {label: "Other suspicious instruction", explanation: "The reviewer identified a potentially unsafe instruction."},
};

const STAGE_LABELS = {
  intake: "Source intake",
  screening: "Document review",
  agent: "Agent step",
  tool: "Tool permission check",
  egress: "Output data check",
  approval: "Human approval",
  completion: "Run status",
};

const DETAIL_LABELS = {
  mode: "Execution mode",
  characters: "Document length",
  permissions_source: "Permission source",
  risk: "Screening verdict",
  source: "Review method",
  findings: "Review evidence",
  model: "Model",
  step: "Agent step",
  tool: "Requested tool",
  arguments: "Submitted arguments",
  rule: "Rule applied",
  attempt: "Tool attempt",
  action_id: "Approval action",
};

const RULE_LABELS = {
  provider_input_dlp: "Sensitive input removed before model access",
  document_scope: "Only public documents may be read",
  document_quarantine: "Quarantine disables drafting and sending",
  tool_allowlist: "Tool is not on the server allowlist",
  argument_schema: "Tool arguments did not match the required schema",
  argument_dlp: "Sensitive content found in tool arguments",
  draft_capability: "Drafting permission was not granted",
  send_capability: "Sending permission was not granted",
  recipient_allowlist: "Recipient is not on the exact allowlist",
  human_approval: "Human approval required before sending",
  tool_budget: "Tool attempt limit reached",
  policy_pass: "Tool, scope, permissions, and data checks passed",
  final_output_dlp: "Final response checked for sensitive data",
  provider_failure: "Model provider failed; pending actions canceled",
  internal_failure: "Run failed closed; pending actions canceled",
};

function element(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}

function badgeClass(decision) {
  return {allowed: "success", completed: "success", blocked: "danger", failed: "danger", quarantined: "warning", approval_required: "warning", awaiting_approval: "warning"}[decision] || "neutral";
}

function setBadge(node, label, decision) {
  node.textContent = label.replaceAll("_", " ").toUpperCase();
  node.className = `badge ${badgeClass(decision)}`;
}

function appendEventDetail(container, key, value) {
  const row = element("div", "event-field");
  row.append(element("dt", "", DETAIL_LABELS[key] || key.replaceAll("_", " ")));
  const content = element("dd");
  if (key === "rule" && typeof value === "string") {
    content.append(element("span", "", RULE_LABELS[value] || value.replaceAll("_", " ")));
    if (RULE_LABELS[value]) content.append(element("code", "event-code", value));
  } else if (key === "findings" && Array.isArray(value)) {
    const list = element("div", "event-findings");
    for (const finding of value) {
      const item = element("div", "event-finding");
      const guidance = FINDING_GUIDANCE[finding.category] || FINDING_GUIDANCE.other;
      item.append(element("strong", "", guidance.label));
      if (finding.quote) item.append(element("code", "", finding.quote));
      if (Array.isArray(finding.requested_tools) && finding.requested_tools.length) {
        item.append(element("p", "event-requested-tools", `Likely requested tool${finding.requested_tools.length === 1 ? "" : "s"}: ${finding.requested_tools.join(", ")}`));
      }
      if (finding.reason) item.append(element("p", "", finding.reason));
      list.append(item);
    }
    content.append(list);
  } else if (value !== null && typeof value === "object") {
    content.append(element("pre", "event-value", JSON.stringify(value, null, 2)));
  } else {
    content.append(element("span", "", String(value)));
  }
  row.append(content);
  container.append(row);
}

function metricsFor(run) {
  const events = Array.isArray(run.events) ? run.events : [];
  const review = run.review || {};
  const outbox = Array.isArray(run.outbox) ? run.outbox : [];
  const blockedEvents = events.filter((item) => item.stage === "tool" && item.decision === "blocked");
  const blockedToolNames = new Set(blockedEvents.map((item) => item.details?.tool).filter(Boolean));
  const detectedToolNames = new Set();
  if (review.quarantine) {
    for (const finding of review.findings || []) {
      if (Array.isArray(finding.requested_tools)) {
        finding.requested_tools.forEach((name) => detectedToolNames.add(name));
      } else if (finding.category === "tool_instruction") {
        for (const match of finding.quote.matchAll(/\b(?:read_document|search_knowledge|draft_email|send_email|delete_document|execute_shell)\b/g)) detectedToolNames.add(match[0]);
      }
    }
  }
  const measured = {
    review_findings: Array.isArray(review.findings) ? review.findings.length : 0,
    source_quarantined: Boolean(review.quarantine || ["suspicious", "malicious", "unknown"].includes(review.risk)),
    blocked_tool_calls: blockedEvents.length,
    tool_actions_stopped: blockedEvents.length + [...detectedToolNames].filter((name) => !blockedToolNames.has(name)).length,
    mock_sends: outbox.length,
  };
  // Fall back for snapshots from a server started before these metrics existed.
  return {...measured, ...run.metrics, tool_actions_stopped: run.metrics?.tool_actions_stopped ?? measured.tool_actions_stopped};
}

function quarantineDescription(run) {
  const review = run.review || {};
  if (!review.quarantine) return "No source document was quarantined in this run.";
  const scenario = config?.scenarios?.find((item) => item.id === run.scenario_id);
  const source = scenario?.name.replace(/^\d+\s*\/\s*/, "") || "the supplied document";
  const labels = [...new Set((review.findings || []).map((finding) => FINDING_GUIDANCE[finding.category]?.label || FINDING_GUIDANCE.other.label))];
  const reason = labels.length
    ? `Detected: ${labels.slice(0, 3).join(", ")}${labels.length > 3 ? ", and other findings" : ""}.`
    : (review.risk === "unknown" ? "The review was unavailable or could not be validated." : "The review marked the document suspicious.");
  return `Quarantined source: ${source}. ${reason} Drafting and sending were disabled for this run.`;
}

function error(message) {
  $("global-error").textContent = message;
  $("global-error").hidden = !message;
}

async function request(path, body) {
  const options = body === undefined ? {} : {method: "POST", headers: {"Content-Type": "application/json", "X-CSRF-Token": config.csrf_token}, body: JSON.stringify(body)};
  const response = await fetch(path, options);
  const result = await response.json();
  if (!response.ok) throw new Error(result.error || "Request failed.");
  return result;
}

function modeHelp() {
  $("mode-help").textContent = $("mode").value === "replay"
    ? "Offline replay: scripted tool proposals + heuristic screening. This demonstrates policy enforcement; no LLM is called."
    : `Live mode: ${config.agent_model} proposes tools; ${config.reviewer_model} reviews the document. Model behavior may vary.`;
}

function selectScenario() {
  const scenario = config.scenarios.find((item) => item.id === $("scenario").value);
  if (!scenario) return;
  $("document").value = scenario.document;
  $("task").value = scenario.task;
  $("allow-draft").checked = scenario.allow_draft;
  $("allow-send").checked = scenario.allow_send;
  $("scenario-description").textContent = scenario.description;
  updateCount();
}

function updateCount() {
  $("document-count").textContent = $("document").value.length.toLocaleString();
}

function markCustom() {
  $("scenario").value = "custom";
  $("scenario-description").textContent = "Your own text. Offline mode previews the text and replays a public read; use live mode for actual AI screening and tool decisions.";
  updateCount();
}

function resetResults() {
  currentRun = null;
  renderSignature = "";
  $("verdict").textContent = "—";
  $("verdict").className = "";
  $("blocked-count").textContent = "0";
  $("finding-count").textContent = "0";
  $("quarantine-count").textContent = "0";
  $("quarantine-count").setAttribute("aria-label", "Quarantined sources: 0");
  $("quarantine-tooltip").textContent = "No source document was quarantined in this run.";
  $("sent-count").textContent = "0";
  $("review-note").textContent = "Reviewing untrusted content…";
  $("summary").textContent = "Waiting for agent response…";
  $("summary").className = "summary empty";
  $("events").replaceChildren();
  $("event-count").textContent = "0 EVENTS";
  $("approval-panel").hidden = true;
  $("artifacts-panel").hidden = true;
  $("run-error").hidden = true;
  $("export").disabled = true;
  $("execution-label").textContent = $("mode").value === "replay" ? "SCRIPTED REPLAY" : "LIVE OPENAI";
  setBadge($("run-status"), "starting", "starting");
}

function render(run) {
  currentRun = run;
  const metrics = metricsFor(run);
  const events = Array.isArray(run.events) ? run.events : [];
  const pending = Array.isArray(run.pending) ? run.pending : [];
  const signature = JSON.stringify([run.id, run.status, events.length, pending.map((item) => item.id), run.error]);
  if (signature === renderSignature) return;
  renderSignature = signature;
  setBadge($("run-status"), run.status, run.status);
  $("blocked-count").textContent = metrics.tool_actions_stopped;
  $("finding-count").textContent = metrics.review_findings;
  $("quarantine-count").textContent = metrics.source_quarantined ? "1" : "0";
  $("quarantine-count").setAttribute("aria-label", `Quarantined sources: ${metrics.source_quarantined ? 1 : 0}`);
  $("quarantine-tooltip").textContent = quarantineDescription(run);
  $("sent-count").textContent = metrics.mock_sends;
  $("event-count").textContent = `${run.events.length} EVENTS`;
  $("export").disabled = false;
  $("run-error").hidden = !run.error;
  $("run-error").textContent = run.error;
  if (run.review) {
    $("verdict").textContent = run.review.risk[0].toUpperCase() + run.review.risk.slice(1);
    $("verdict").className = run.review.quarantine ? "risk-warning" : "risk-benign";
    const toolDenials = metrics.tool_actions_stopped;
    const actualBlockedCalls = metrics.blocked_tool_calls;
    $("review-note").textContent = run.review.quarantine
      ? `Source quarantined at screening. ${toolDenials ? `${toolDenials} unsafe tool action${toolDenials === 1 ? " was" : "s were"} stopped; ${actualBlockedCalls} call${actualBlockedCalls === 1 ? " reached" : "s reached"} the tool gate and were blocked.` : "No named unsafe tool action or blocked tool call was recorded. Sensitive actions were still disabled before execution."}`
      : run.review.note;
  }
  if (run.summary) {
    $("summary").textContent = run.summary;
    $("summary").className = "summary";
  } else if (run.status === "failed") {
    $("summary").textContent = "The run stopped. Review the error and decision log.";
  }
  const expanded = new Set([...$("events").querySelectorAll(".event-disclosure[open]")].map((node) => node.dataset.sequence));
  $("events").replaceChildren(...events.map((event) => {
    const row = element("div", "event");
    const disclosure = element("details", "event-disclosure");
    disclosure.dataset.sequence = String(event.sequence);
    disclosure.open = expanded.has(disclosure.dataset.sequence);
    const summary = element("summary", "event-summary");
    const heading = element("div", "event-heading");
    const decisionLabels = {approval_required: "APPROVAL NEEDED", quarantined: "QUARANTINED", allowed: "ALLOWED", blocked: "BLOCKED", info: "INFO"};
    heading.append(element("span", `badge ${badgeClass(event.decision)}`, decisionLabels[event.decision] || event.decision.replaceAll("_", " ").toUpperCase()), element("span", "event-stage", STAGE_LABELS[event.stage] || event.stage));
    summary.append(heading, element("p", "", event.message), element("span", "event-toggle", "Show recorded checks"));
    disclosure.append(summary);
    const detailPanel = element("div", "event-inspector");
    detailPanel.append(element("h4", "", "Decision evidence"));
    const fields = element("dl", "event-fields");
    const recordedDetails = event.details && typeof event.details === "object" ? event.details : {};
    for (const [key, value] of Object.entries(recordedDetails)) appendEventDetail(fields, key, value);
    if (fields.children.length) detailPanel.append(fields);
    else detailPanel.append(element("p", "event-no-details", "No additional structured details were recorded for this step."));
    disclosure.append(detailPanel);
    disclosure.addEventListener("toggle", () => {
      const toggle = disclosure.querySelector(".event-toggle");
      if (toggle) toggle.textContent = disclosure.open ? "Hide recorded checks" : "Show recorded checks";
    });
    if (disclosure.open) {
      const toggle = disclosure.querySelector(".event-toggle");
      toggle.textContent = "Hide recorded checks";
    }
    row.append(element("span", "event-index", String(event.sequence).padStart(2, "0")), disclosure);
    return row;
  }));
  renderApprovals({...run, pending});
  renderArtifacts(run);
}

function renderApprovals(run) {
  $("approval-panel").hidden = !run.pending.length;
  $("approvals").replaceChildren(...run.pending.map((action) => {
    const card = element("div", "approval");
    const list = element("dl");
    for (const [label, value] of [["Recipient", action.arguments.to], ["Subject", action.arguments.subject], ["Body", action.arguments.body], ["Expires", new Date(action.expires_at * 1000).toLocaleTimeString()]]) {
      list.append(element("dt", "", label), element("dd", "", value));
    }
    const controls = element("div", "approval-actions");
    for (const [text, approved, className] of [["Approve mock send", true, "approve-button"], ["Decline", false, "decline-button"]]) {
      const button = element("button", className, text);
      button.type = "button";
      button.addEventListener("click", async () => {
        const runId = run.id;
        controls.querySelectorAll("button").forEach((item) => { item.disabled = true; });
        try {
          const updated = await request(`/api/runs/${runId}/approval`, {action_id: action.id, approve: approved});
          if (currentRun?.id === runId) render(updated);
        } catch (problem) {
          error(problem.message);
          controls.querySelectorAll("button").forEach((item) => { item.disabled = false; });
        }
      });
      controls.append(button);
    }
    card.append(list, controls);
    return card;
  }));
}

function renderArtifacts(run) {
  const artifacts = [...run.drafts.map((item) => ({...item, kind: "Draft"})), ...run.outbox.map((item) => ({...item, kind: "Mock outbox"}))];
  $("artifacts-panel").hidden = !artifacts.length;
  $("artifacts").replaceChildren(...artifacts.map((item) => {
    const card = element("div", "artifact");
    card.append(element("strong", "", `${item.kind} · ${item.to}`), element("pre", "", `Subject: ${item.subject}\n\n${item.body}`));
    return card;
  }));
}

async function poll(runId) {
  try {
    const run = await request(`/api/runs/${runId}`);
    if (currentRun?.id !== runId) return;
    render(run);
    if (["completed", "failed", "awaiting_approval"].includes(run.status)) {
      running = false;
      $("run").disabled = false;
      $("run").replaceChildren(document.createTextNode("Run defense demo "), element("span", "", "→"));
    }
    if (!["completed", "failed"].includes(run.status)) timer = setTimeout(() => poll(runId), 900);
  } catch (problem) {
    running = false;
    error(problem.message);
    $("run").disabled = false;
    $("run").textContent = "Run defense demo →";
  }
}

$("run").addEventListener("click", async () => {
  if (running) return;
  if (!$("task").value.trim() || !$("document").value.trim()) return error("Provide a document and a user task.");
  clearTimeout(timer);
  error("");
  resetResults();
  running = true;
  $("run").disabled = true;
  $("run").textContent = "Running checks…";
  try {
    const run = await request("/api/runs", {mode: $("mode").value, scenario_id: $("scenario").value, task: $("task").value, document: $("document").value, allow_draft: $("allow-draft").checked, allow_send: $("allow-send").checked});
    render(run);
    await poll(run.id);
  } catch (problem) {
    running = false;
    error(problem.message);
    $("run").disabled = false;
    $("run").textContent = "Run defense demo →";
    setBadge($("run-status"), "failed", "failed");
  }
});

$("export").addEventListener("click", () => {
  if (!currentRun) return;
  const url = URL.createObjectURL(new Blob([JSON.stringify(currentRun, null, 2)], {type: "application/json"}));
  const link = element("a");
  link.href = url;
  link.download = `agent-gate-${currentRun.id}.json`;
  link.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
});

$("file").addEventListener("change", async (event) => {
  const file = event.target.files[0];
  if (!file) return;
  try {
    if (file.size > 100000) throw new Error("Choose a plain-text file smaller than 100 KB.");
    const text = await file.text();
    if (text.length > 20000) throw new Error("The document exceeds 20,000 characters.");
    if (text.includes("\0")) throw new Error("Choose a plain-text document, not a binary file.");
    $("document").value = text;
    markCustom();
    error("");
  } catch (problem) { error(problem.message); }
  event.target.value = "";
});

$("document").addEventListener("input", markCustom);
$("task").addEventListener("input", markCustom);
$("scenario").addEventListener("change", selectScenario);
$("mode").addEventListener("change", modeHelp);

async function init() {
  try {
    config = await request("/api/config");
    $("scenario").replaceChildren(...config.scenarios.map((scenario) => {
      const option = element("option", "", scenario.name);
      option.value = scenario.id;
      return option;
    }));
    const custom = element("option", "", "Custom document");
    custom.value = "custom";
    $("scenario").append(custom);
    $("mode").querySelector('[value="live"]').disabled = !config.live_available;
    $("mode").value = config.live_available ? "live" : "replay";
    $("recipients").textContent = config.allowed_recipients.join(", ") || "None";
    $("model-info").textContent = `AGENT ${config.agent_model} / REVIEWER ${config.reviewer_model} / API ${config.live_available ? "CONFIGURED" : "NOT CONFIGURED"}`;
    selectScenario();
    modeHelp();
  } catch (problem) { error(problem.message); $("run").disabled = true; }
}

init();
