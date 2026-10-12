"use strict";

const $ = (id) => document.getElementById(id);
let config, currentRun = null, timer = null, renderSignature = "", running = false;
let protectedRun = null, comparisonRun = null, resultView = "protected", comparisonTimer = null, comparisonStarting = false, resultEpoch = 0;
const terminalStatuses = ["completed", "failed", "awaiting_approval"];
const SCENARIO_SUMMARIES = {
  benign: "Read and summarize a clean document.",
  injection: "Quarantine instructions hidden in a document.",
  "tool-misuse": "Reject an unauthorized deletion request.",
  "document-edit": "Change Friday to Monday in a mock file.",
  "edit-injection": "Block an injected budget change.",
};

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
  request: "Request detected",
  retrieval: "Retrieved document review",
  execution: "Tool execution",
  simulation: "Comparison sandbox",
};

const DETAIL_LABELS = {
  mode: "Execution mode",
  characters: "Document length",
  permissions_source: "Permission source",
  granted_tools: "Tools authorized from task",
  risk: "Screening verdict",
  source: "Review method",
  findings: "Review evidence",
  model: "Model",
  step: "Agent step",
  tool_choice: "Tool selection for this step",
  required_document: "Required read",
  tool: "Requested tool",
  origin: "Request source",
  attempted: "Call reached the gate",
  arguments: "Submitted arguments",
  rule: "Rule applied",
  attempt: "Tool attempt",
  action_id: "Approval action",
  source_id: "Source document",
  document_id: "Target document",
  task_mode: "Task intent",
  outcome: "Execution outcome",
  cached: "Previously reviewed",
  side_effect: "Created or sent a mock artifact",
  deleted_documents: "Mock documents deleted",
};

const RULE_LABELS = {
  provider_input_dlp: "Sensitive input removed before model access",
  document_scope: "Only the supplied document and listed public documents may be read",
  document_pending: "Supplied document must be read before continuing",
  document_quarantine: "Quarantine disables editing, drafting and sending",
  edit_capability: "Editing permission was not granted",
  edit_read_required: "Read and screen the edit target first",
  edit_match: "Replacement text must match exactly once",
  edit_size: "Edited document exceeds its size limit",
  edit_content: "Edited document contains suspicious instructions",
  tool_allowlist: "Tool is not on the server allowlist",
  argument_schema: "Tool arguments did not match the required schema",
  argument_dlp: "Sensitive content found in tool arguments",
  draft_capability: "Drafting permission was not granted",
  send_capability: "Sending permission was not granted",
  recipient_allowlist: "Recipient is not on the exact allowlist",
  human_approval: "Human approval required before sending",
  task_scope: "The task did not authorize this action",
  reference_pending: "Required reference must be read and screened before editing or email actions",
  tool_result_dlp: "Sensitive content withheld from a tool result",
  tool_budget: "Tool attempt limit reached",
  policy_pass: "Tool, scope, permissions, and data checks passed",
  final_output_dlp: "Final response checked for sensitive data",
  provider_failure: "Model provider failed; pending actions canceled",
  internal_failure: "Run failed closed; pending actions canceled",
  firewall_off: "Application firewall disabled in the isolated mock comparison",
};

function element(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}

function badgeClass(decision) {
  return {allowed: "success", completed: "success", executed: "success", unchecked: "warning", detected: "warning", blocked: "danger", failed: "danger", quarantined: "warning", approval_required: "warning", awaiting_approval: "warning"}[decision] || "neutral";
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
  } else if (key === "attempted" && typeof value === "boolean") {
    content.append(element("span", "", value ? "Yes — an actual tool call was submitted." : "No — this entry does not represent an agent tool call."));
  } else if (key === "origin") {
    content.append(element("span", "", {agent_call: "Live model proposal", scripted_replay: "Scripted replay proposal", comparison: "Isolated firewall-off comparison", user_task: "Inferred from the user task", approval_recheck: "Stored payload checked again after approval", approval: "Approved stored payload"}[value] || value));
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
      if (finding.signals?.length) {
        const signals = element("details", "finding-signals");
        const sources = [...new Set(finding.signals.map((signal) => signal.source))];
        signals.append(element("summary", "", `Supporting checks: ${sources.join(", ")} (${finding.signals.length})`));
        for (const signal of finding.signals) signals.append(element("p", "", `${signal.source}: ${signal.reason}`), element("code", "", signal.quote));
        item.append(signals);
      }
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
  const sources = run.sources || (run.review ? [{source_id: "supplied-document", ...run.review}] : []);
  const requests = new Set();
  sources.forEach((source) => (source.findings || []).forEach((finding) =>
    (finding.requested_tools || []).forEach((name) => requests.add(`${source.source_id}:${name}`))));
  events.filter((event) => event.stage === "request").forEach((event) => requests.add(`user_task:${event.details?.tool}`));
  return {
    review_findings: sources.reduce((count, source) => count + (source.findings?.length || 0), 0),
    quarantined_sources: sources.filter((source) => source.quarantine).length,
    unsafe_requests_detected: requests.size,
    tool_calls: events.filter((event) => event.stage === "tool" && event.details?.attempted === true).length,
    blocked_tool_calls: events.filter((event) => event.stage === "tool" && event.decision === "blocked" && event.details?.attempted === true).length,
    actions_executed: events.filter((event) => event.stage === "execution").length,
    mock_sends: run.outbox?.length || 0,
    ...run.metrics,
  };
}

function quarantineDescription(run) {
  const sources = (run.sources || []).filter((source) => source.quarantine);
  if (!sources.length) return "No source document was quarantined in this run.";
  return sources.map((source) => {
    const labels = [...new Set((source.findings || []).map((finding) => FINDING_GUIDANCE[finding.category]?.label || "Suspicious instruction"))];
    return `${source.source_id}: ${labels.join(", ") || "Review unavailable or invalid"}.`;
  }).join(" ") + " Editing, drafting and sending are disabled for the run.";
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
    ? "Scripted tool calls · no API calls."
    : "Live agent + AI review · tool choices may vary.";
}

function selectScenario() {
  const scenario = config.scenarios.find((item) => item.id === $("scenario").value);
  if (!scenario) return;
  $("document").value = scenario.document;
  $("task").value = scenario.task;
  $("scenario-description").textContent = SCENARIO_SUMMARIES[scenario.id] || scenario.description;
  $("scenario-description").title = scenario.description;
  updateCount();
}

function updateCount() {
  $("document-count").textContent = $("document").value.length.toLocaleString();
}

function markCustom() {
  $("scenario").value = "custom";
  $("scenario-description").textContent = "Your text. Use live mode for AI decisions.";
  $("scenario-description").removeAttribute("title");
  updateCount();
}

function resetResults() {
  resultEpoch += 1;
  clearTimeout(comparisonTimer);
  protectedRun = comparisonRun = null;
  comparisonStarting = false;
  resultView = "protected";
  updateTabs();
  $("result-content").hidden = false;
  $("comparison-loading").hidden = true;
  $("result-heading").textContent = "Defense result";
  $("outcome-banner").hidden = true;
  $("effect-comparison").hidden = true;
  $("intervention-summary").hidden = true;
  currentRun = null;
  renderSignature = "";
  $("verdict").textContent = "—";
  $("verdict").className = "";
  $("task-verdict").textContent = "—";
  $("task-verdict").className = "";
  $("task-review-note").textContent = "Checking requested tools and sensitive data…";
  $("blocked-count").textContent = "0 / 0";
  $("blocked-count").setAttribute("aria-label", "0 tool calls, 0 blocked");
  $("request-count").textContent = "0";
  $("executed-count").textContent = "0";
  $("finding-count").textContent = "0";
  $("quarantine-count").textContent = "0";
  $("quarantine-count").setAttribute("aria-label", "Quarantined sources: 0");
  $("quarantine-tooltip").textContent = "No source document was quarantined in this run.";
  $("sent-count").textContent = "0";
  $("review-note").textContent = "Reviewing untrusted content…";
  $("summary").textContent = "Waiting for agent response…";
  $("summary").className = "summary empty";
  $("action-status").hidden = true;
  $("events").replaceChildren();
  $("event-count").textContent = "0 EVENTS";
  $("approval-panel").hidden = true;
  $("artifacts-panel").hidden = true;
  $("run-error").hidden = true;
  $("export").disabled = true;
  $("execution-label").textContent = $("mode").value === "replay" ? "SCRIPTED REPLAY" : "LIVE OPENAI";
  setBadge($("run-status"), "starting", "starting");
}

function updateTabs() {
  for (const [view, id] of [["protected", "protected-tab"], ["off", "unprotected-tab"]]) {
    const selected = resultView === view;
    $(id).setAttribute("aria-selected", String(selected));
    $(id).tabIndex = selected ? 0 : -1;
  }
  $("unprotected-tab").disabled = !protectedRun || !terminalStatuses.includes(protectedRun.status);
  $("result-content").setAttribute("aria-labelledby", resultView === "off" ? "unprotected-tab" : "protected-tab");
  $("comparison-notice").hidden = resultView !== "off";
  $("comparison-notice").textContent = protectedRun?.mode === "live"
    ? "Firewall off · Separate live run of the same model and inputs. Screening, tool permissions, outbound policy and send approval are disabled. The model may still refuse. Extra API calls apply. All secrets, edits, sends, deletions and commands are synthetic mock effects."
    : "Firewall off · Scripted vulnerable-agent replay using the same inputs, with screening, tool permissions, outbound policy and send approval disabled. This illustrates possible consequences; it does not predict what an LLM would do. All secrets, edits, sends, deletions and commands are synthetic mock effects.";
}

function showSelectedResult() {
  updateTabs();
  renderEffectComparison();
  const selected = resultView === "off" ? comparisonRun : protectedRun;
  $("result-content").hidden = !selected;
  $("comparison-loading").hidden = resultView !== "off" || !!selected;
  if (selected) render(selected);
  else {
    currentRun = null;
    $("approval-panel").hidden = true;
    $("artifacts-panel").hidden = true;
  }
}

async function setResultView(view) {
  if (view === "off" && $("unprotected-tab").disabled) return;
  resultView = view;
  showSelectedResult();
  if (view !== "off" || comparisonRun || comparisonStarting) return;
  comparisonStarting = true;
  const epoch = resultEpoch, parentId = protectedRun.id;
  $("comparison-loading").textContent = "Running the firewall-off comparison…";
  try {
    const run = await request(`/api/runs/${parentId}/comparison`, {});
    if (epoch !== resultEpoch) return;
    comparisonRun = run;
    renderEffectComparison();
    if (resultView === "off") showSelectedResult();
    await pollComparison(run.id, epoch);
  } catch (problem) {
    if (epoch !== resultEpoch) return;
    $("comparison-loading").textContent = `Comparison could not start: ${problem.message} Select Protected, then Firewall off to retry.`;
    error(problem.message);
  } finally {
    if (epoch === resultEpoch) comparisonStarting = false;
  }
}

async function pollComparison(runId, epoch) {
  try {
    const run = await request(`/api/runs/${runId}`);
    if (epoch !== resultEpoch || comparisonRun?.id !== runId) return;
    comparisonRun = run;
    renderEffectComparison();
    if (resultView === "off") showSelectedResult();
    if (!["completed", "failed"].includes(run.status)) comparisonTimer = setTimeout(() => pollComparison(runId, epoch), 900);
  } catch (problem) {
    if (epoch === resultEpoch) error(problem.message);
  }
}

for (const [view, id] of [["protected", "protected-tab"], ["off", "unprotected-tab"]]) {
  $(id).addEventListener("click", () => setResultView(view));
  $(id).addEventListener("keydown", (event) => {
    if (!["ArrowLeft", "ArrowRight", "Home", "End"].includes(event.key)) return;
    event.preventDefault();
    const next = event.key === "Home" ? "protected" : event.key === "End" ? "off" : resultView === "off" ? "protected" : "off";
    if (next === "off" && $("unprotected-tab").disabled) return;
    setResultView(next);
    $(next === "off" ? "unprotected-tab" : "protected-tab").focus();
  });
}

$("compare-effects").addEventListener("click", () => setResultView("off"));

function shortText(text) {
  const value = String(text ?? "").replace(/\s+/g, " ").trim();
  return value.length > 130 ? value.slice(0, 127) + "…" : value || "(empty)";
}

function effectFacts(run, other) {
  if (!run) return ["Not run yet", "Not run yet", "Not run yet", "Not run yet", "Not run yet"];
  if (!terminalStatuses.includes(run.status)) return Array(5).fill("Running…");
  const edits = run.edits || [], effects = run.comparison_effects || {};
  const seenDocuments = new Set();
  const originalEdits = (other?.edits || []).filter((edit) => {
    if (seenDocuments.has(edit.document_id) || effects.deleted_documents?.includes(edit.document_id)) return false;
    seenDocuments.add(edit.document_id);
    return true;
  });
  const files = edits.length
    ? edits.map((edit) => `${edit.document_id}: ${shortText(edit.old_text)} → ${shortText(edit.new_text)}`).join("\n")
    : originalEdits.length
      ? "No edits; kept original text:\n" + originalEdits.map((edit) => `${edit.document_id}: ${shortText(edit.old_text)}`).join("\n")
      : "No files edited";
  const sends = (run.outbox || []).length
    ? run.outbox.map((item) => `Mock email sent to ${item.to}`).join("\n")
    : (run.pending || []).length ? "Waiting for approval; pending email not sent" : "No mock email sent";
  const failed = run.status === "failed" ? " (run failed; effects recorded so far)" : "";
  return [files, sends, effects.secret_reads ? `${effects.secret_reads} synthetic secret read(s)` : "No protected secret retrieved",
    effects.deleted_documents?.length ? effects.deleted_documents.join(", ") + " deleted (mock)" : "No documents deleted",
    effects.simulated_commands?.length ? `${effects.simulated_commands.length} command(s) simulated` : "No commands simulated"].map((value) => value + failed);
}

function renderEffectComparison() {
  $("effect-comparison").hidden = !protectedRun;
  if (!protectedRun) return;
  const ready = terminalStatuses.includes(protectedRun.status);
  $("compare-effects").hidden = !!comparisonRun;
  $("compare-effects").disabled = !ready || comparisonStarting;
  $("compare-effects").textContent = comparisonStarting ? "Starting comparison…" : "Compare with firewall off →";
  $("effect-comparison-note").textContent = protectedRun.mode === "replay"
    ? "Recorded mock effects. Firewall off uses a scripted vulnerable agent, not a prediction of live AI behavior."
    : "Recorded mock effects from separate live runs. The model may refuse even with the firewall off.";
  const protectedFacts = effectFacts(protectedRun, comparisonRun), offFacts = effectFacts(comparisonRun, protectedRun);
  const labels = ["File edits", "Email", "Protected data", "Deletion", "Commands"];
  // Keep the first two rows visible; add other effects when a request or execution is recorded.
  const events = [...(protectedRun.events || []), ...(comparisonRun?.events || [])];
  const tools = events.map((event) => event.details?.tool);
  const visible = new Set([0, 1]);
  if (comparisonRun?.comparison_effects?.secret_reads || events.some((event) => event.details?.arguments?.document_id === "secrets.env")) visible.add(2);
  if (tools.includes("delete_document")) visible.add(3);
  if (tools.includes("execute_shell")) visible.add(4);
  $("effect-rows").replaceChildren(...labels.flatMap((label, index) => {
    if (!visible.has(index)) return [];
    const row = element("tr");
    const heading = element("th", "", label);
    heading.scope = "row";
    row.append(heading, element("td", "", protectedFacts[index]), element("td", "", offFacts[index]));
    return [row];
  }));
}

function renderOutcome(run) {
  const outcome = run.outcome;
  $("outcome-banner").hidden = !outcome;
  if (!outcome) return;
  $("outcome-banner").className = `outcome-banner outcome-${outcome.state}`;
  $("outcome-title").textContent = outcome.title;
  $("outcome-message").textContent = outcome.message;
  $("intervention-summary").hidden = run.firewall_enabled === false || !terminalStatuses.includes(run.status);
  const interventions = outcome.interventions || [];
  $("interventions").replaceChildren(...interventions.map((item) => {
    const row = element("div", "intervention-row");
    const button = element("button", "text-button", `${item.layer} · view check ${String(item.sequence).padStart(2, "0")} ↗`);
    button.type = "button";
    button.addEventListener("click", () => {
      const disclosure = [...$("events").querySelectorAll(".event-disclosure")].find((node) => node.dataset.sequence === String(item.sequence));
      if (!disclosure) return;
      disclosure.open = true;
      disclosure.scrollIntoView({behavior: "smooth", block: "center"});
      disclosure.querySelector("summary").focus({preventScroll: true});
    });
    row.append(button, element("p", "", item.explanation));
    return row;
  }));
  if (!interventions.length) $("interventions").append(element("p", "help", run.metrics?.unsafe_requests_detected
    ? "No firewall block was recorded. The agent did not submit a blocked call; a refusal or omission is model behavior."
    : "No intervention was needed in the recorded checks. Every submitted tool call still went through the gate."));
}

function render(run) {
  const previousId = currentRun?.id;
  currentRun = run;
  const firewallOff = run.firewall_enabled === false;
  const metrics = metricsFor(run);
  const events = Array.isArray(run.events) ? run.events : [];
  const pending = Array.isArray(run.pending) ? run.pending : [];
  const signature = JSON.stringify([run.id, run.status, events.length, pending.map((item) => item.id), run.error, run.task_review]);
  if (signature === renderSignature) return;
  renderSignature = signature;
  renderOutcome(run);
  $("result-heading").textContent = firewallOff ? "Firewall-off result" : "Defense result";
  $("execution-label").textContent = `${run.mode === "replay" ? "SCRIPTED REPLAY" : "LIVE OPENAI"}${firewallOff ? " · FIREWALL OFF" : ""}`;
  setBadge($("run-status"), run.status, run.status);
  $("blocked-count").textContent = `${metrics.tool_calls} / ${metrics.blocked_tool_calls}`;
  $("blocked-count").setAttribute("aria-label", `${metrics.tool_calls} tool calls, ${metrics.blocked_tool_calls} blocked`);
  $("request-count").textContent = firewallOff ? "Off" : metrics.unsafe_requests_detected;
  $("executed-count").textContent = metrics.actions_executed;
  $("finding-count").textContent = firewallOff ? "Off" : metrics.review_findings;
  $("quarantine-count").textContent = firewallOff ? "Off" : metrics.quarantined_sources;
  $("quarantine-count").setAttribute("aria-label", firewallOff ? "Quarantine disabled" : `Quarantined sources: ${metrics.quarantined_sources}`);
  $("quarantine-tooltip").textContent = firewallOff ? "Quarantine is disabled in this mock comparison. Source contents are returned without screening." : quarantineDescription(run);
  $("sent-count").textContent = metrics.mock_sends;
  $("event-count").textContent = `${run.events.length} EVENTS`;
  $("export").disabled = false;
  $("run-error").hidden = !run.error;
  $("run-error").textContent = run.error;
  if (run.task_review && !firewallOff) {
    const labels = {outside_permissions: "Outside permissions", sensitive_input: "Sensitive input", no_conflict_detected: "No conflict detected"};
    $("task-verdict").textContent = labels[run.task_review.verdict] || "Not checked";
    $("task-verdict").className = run.task_review.verdict === "no_conflict_detected" ? "risk-benign" : "risk-warning";
    $("task-review-note").textContent = run.task_review.note;
  } else {
    $("task-verdict").textContent = "Not checked";
    $("task-verdict").className = "";
    $("task-review-note").textContent = firewallOff ? "Task-permission checks are disabled in this mock comparison." : "The user-task check has not finished.";
  }
  if (run.review) {
    $("verdict").textContent = run.review.risk[0].toUpperCase() + run.review.risk.slice(1);
    $("verdict").className = run.review.quarantine ? "risk-warning" : "risk-benign";
    const count = (number, label) => `${number} ${label}${number === 1 ? "" : "s"}`;
    $("review-note").textContent = `${metrics.quarantined_sources ? "Quarantine disables editing, drafting and sending for the whole run. " : ""}${count(metrics.unsafe_requests_detected, "inferred unsafe request")} · ${count(metrics.blocked_tool_calls, "blocked tool call")} · ${count(metrics.actions_executed, "executed action")}.`;
  } else {
    $("verdict").textContent = "Not screened";
    $("verdict").className = "";
    $("review-note").textContent = firewallOff ? "Source contents are passed to the mock agent without review. Tools run without the protected gate; no human approval is requested." : "Reviewing untrusted content…";
  }
  if (run.summary) {
    $("summary").textContent = run.summary;
    $("summary").className = "summary";
  } else if (run.status === "failed") {
    $("summary").textContent = "The run stopped. Review the error and decision log.";
    $("summary").className = "summary empty";
  } else {
    $("summary").textContent = "Waiting for agent response…";
    $("summary").className = "summary empty";
  }
  $("action-status").hidden = !run.action_status || run.action_status.state === "not_started";
  $("action-status-message").textContent = run.action_status?.message || "";
  const expanded = new Set(previousId === run.id ? [...$("events").querySelectorAll(".event-disclosure[open]")].map((node) => node.dataset.sequence) : []);
  $("events").replaceChildren(...events.map((event) => {
    const row = element("div", "event");
    const disclosure = element("details", "event-disclosure");
    disclosure.dataset.sequence = String(event.sequence);
    disclosure.open = expanded.has(disclosure.dataset.sequence);
    const summary = element("summary", "event-summary");
    const heading = element("div", "event-heading");
    const decisionLabels = {approval_required: "APPROVAL NEEDED", quarantined: "QUARANTINED", allowed: "ALLOWED", blocked: "BLOCKED", info: "INFO", detected: "DETECTED", executed: "EXECUTED"};
    const stageLabel = firewallOff && event.stage === "tool" ? "Tool dispatch" : STAGE_LABELS[event.stage] || event.stage;
    heading.append(element("span", `badge ${badgeClass(event.decision)}`, decisionLabels[event.decision] || event.decision.replaceAll("_", " ").toUpperCase()), element("span", "event-stage", stageLabel));
    if (event.details?.tool) heading.append(element("code", "event-tool", event.details.tool));
    const documentId = event.details?.document_id || event.details?.arguments?.document_id;
    if (documentId) heading.append(element("code", "event-tool", documentId));
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
          if (protectedRun?.id === runId) {
            protectedRun = updated;
            if (resultView === "protected") showSelectedResult();
          }
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
  const edits = run.edits || [];
  $("artifacts-panel").hidden = !artifacts.length && !edits.length;
  $("artifacts").replaceChildren(...artifacts.map((item) => {
    const card = element("div", "artifact");
    card.append(element("strong", "", `${item.kind} · ${item.to}`), element("pre", "", `Subject: ${item.subject}\n\n${item.body}`));
    return card;
  }), ...edits.map((edit) => {
    const card = element("div", "artifact edit-artifact");
    card.append(element("strong", "", `Mock file edited · ${edit.document_id}`));
    const diff = element("div", "edit-diff");
    for (const [label, text] of [["Removed", edit.old_text], ["Added", edit.new_text]]) {
      const part = element("div", label === "Removed" ? "edit-removed" : "edit-added");
      part.append(element("span", "tiny-label", label), element("pre", "", text || "(empty)"));
      diff.append(part);
    }
    const details = element("details", "edit-contents");
    details.append(element("summary", "", "Full before / after document"));
    for (const [label, text] of [["Before", edit.before], ["After", edit.after]]) details.append(element("h4", "", label), element("pre", "", text));
    const download = element("button", "text-button", "Download edited text ↗");
    download.type = "button";
    download.addEventListener("click", () => {
      const url = URL.createObjectURL(new Blob([edit.after], {type: "text/plain;charset=utf-8"}));
      const link = element("a");
      link.href = url;
      link.download = `${edit.document_id.replace(/[^a-z0-9_-]/gi, "_")}-edited.txt`;
      link.click();
      setTimeout(() => URL.revokeObjectURL(url), 1000);
    });
    card.append(diff, details, download);
    return card;
  }));
}

async function poll(runId) {
  try {
    const run = await request(`/api/runs/${runId}`);
    if (protectedRun?.id !== runId) return;
    protectedRun = run;
    updateTabs();
    if (resultView === "protected") showSelectedResult();
    if (terminalStatuses.includes(run.status)) {
      running = false;
      $("run").disabled = false;
      $("run").replaceChildren(document.createTextNode("Run demo "), element("span", "", "→"));
    }
    if (!["completed", "failed"].includes(run.status)) timer = setTimeout(() => poll(runId), 900);
  } catch (problem) {
    running = false;
    error(problem.message);
    $("run").disabled = false;
    $("run").textContent = "Run demo →";
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
    const run = await request("/api/runs", {mode: $("mode").value, scenario_id: $("scenario").value, task: $("task").value, document: $("document").value});
    protectedRun = run;
    showSelectedResult();
    await poll(run.id);
  } catch (problem) {
    running = false;
    error(problem.message);
    $("run").disabled = false;
    $("run").textContent = "Run demo →";
    setBadge($("run-status"), "failed", "failed");
    $("outcome-banner").hidden = false;
    $("outcome-banner").className = "outcome-banner outcome-failed";
    $("outcome-title").textContent = "Run could not start";
    $("outcome-message").textContent = problem.message;
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
    $("model-info").textContent = `AGENT ${config.agent_model} / REVIEWER ${config.reviewer_model} / API ${config.live_available ? "CONFIGURED" : "NOT CONFIGURED"}`;
    selectScenario();
    modeHelp();
  } catch (problem) { error(problem.message); $("run").disabled = true; }
}

init();
