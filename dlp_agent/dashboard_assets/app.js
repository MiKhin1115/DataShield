const state = {
  user: null, permissions: new Set(), incidents: [], summary: null,
  policies: [], users: [], roles: [], analysts: [], usbDevices: [], aiStatus: null,
  timer: null, currentView: "overview"
};

const incidentStatuses = ["Open", "Investigating", "Resolved", "False Positive", "Escalated", "Pending User Confirmation", "Pending Manager Approval", "Closed"];

const colors = {
  Public: "#21835a", Internal: "#1769aa", Confidential: "#b56a09", Restricted: "#c43d3d",
  Allow: "#21835a", Alert: "#b56a09", Block: "#c43d3d"
};
const fieldLabels = {
  file_classification: "File classification", sensitive_data_type: "Sensitive data type",
  sensitive_data_count: "Sensitive data count", file_size: "File size (bytes)",
  file_extension: "File extension", usb_authorized: "USB authorized",
  user_name: "User name", department: "Department", risk_score: "Risk score",
  transfer_time: "Transfer time (HH:MM)"
};
const operatorLabels = {
  equals: "Equals", not_equals: "Does not equal", contains: "Contains",
  greater_than: "Greater than", greater_or_equal: "Greater than or equal",
  less_than: "Less than", less_or_equal: "Less than or equal"
};

const byId = (id) => document.getElementById(id);
const escapeHtml = (value) => String(value ?? "").replace(/[&<>'"]/g, (char) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", "'": "&#39;", '"': "&quot;" }[char]));
const labelize = (value) => String(value ?? "").replaceAll("_", " ").replace(/\b\w/g, (letter) => letter.toUpperCase());
const can = (permission) => state.permissions.has(permission);

async function api(url, options = {}) {
  const method = options.method || "GET";
  const headers = { ...(options.headers || {}) };
  if (options.body) headers["Content-Type"] = "application/json";
  if (method !== "GET") headers["X-DLP-Request"] = "dashboard";
  const response = await fetch(url, { ...options, headers });
  const data = await response.json().catch(() => ({}));
  if (response.status === 401) {
    showLogin();
    throw new Error(data.error || "Authentication required");
  }
  if (!response.ok) throw new Error(data.error || "Request failed");
  return data;
}

function formatDate(value) {
  if (!value) return "Unknown time";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString([], { dateStyle: "medium", timeStyle: "short" });
}

function riskColor(score) {
  if (score >= 75) return colors.Block;
  if (score >= 35) return colors.Alert;
  return colors.Allow;
}

function riskLevel(score) {
  if (score >= 75) return "Critical";
  if (score >= 50) return "High";
  if (score >= 25) return "Medium";
  return "Low";
}

function incidentStatus(value) {
  return !value || value === "New" ? "Open" : value;
}

function statusClass(value) {
  return incidentStatus(value).toLowerCase().replaceAll(" ", "-");
}

function isoDateValue(id) {
  const value = byId(id).value;
  if (!value) return "";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? "" : date.toISOString();
}

async function initialize() {
  try {
    const session = await api("/api/me");
    if (session.authenticated) showApplication(session.user, session.permissions);
    else showLogin();
  } catch (_) {
    showLogin();
  }
}

function showLogin() {
  state.user = null;
  state.permissions = new Set();
  state.aiStatus = null;
  byId("login-view").hidden = false;
  byId("app-shell").hidden = true;
  window.clearInterval(state.timer);
}

function showApplication(user, permissions) {
  state.user = user;
  state.permissions = new Set(permissions);
  byId("login-view").hidden = true;
  byId("app-shell").hidden = false;
  byId("current-user").textContent = user.username;
  byId("current-role").textContent = user.role;
  document.querySelectorAll("[data-permission]").forEach((element) => {
    element.hidden = !can(element.dataset.permission);
  });
  loadAnalysts();
  if (can("ai_analysis.view")) loadAiStatus();
  switchView("overview");
  scheduleRefresh();
}

async function login(event) {
  event.preventDefault();
  const error = byId("login-error");
  error.hidden = true;
  try {
    const result = await api("/api/login", {
      method: "POST",
      body: JSON.stringify({ username: byId("login-username").value, password: byId("login-password").value })
    });
    byId("login-form").reset();
    showApplication(result.user, result.permissions);
  } catch (requestError) {
    error.textContent = requestError.message;
    error.hidden = false;
  }
}

async function logout() {
  try { await api("/api/logout", { method: "POST" }); } catch (_) { /* session is cleared locally */ }
  showLogin();
}

function switchView(viewName) {
  state.currentView = viewName;
  document.querySelectorAll(".page-view").forEach((view) => { view.hidden = view.id !== `view-${viewName}`; });
  document.querySelectorAll(".nav-button").forEach((button) => { button.classList.toggle("active", button.dataset.view === viewName); });
  if (viewName === "overview") loadDashboard(false);
  if (viewName === "incidents") loadIncidents();
  if (viewName === "policies") loadPolicies();
  if (viewName === "access") loadAccess();
  if (viewName === "audit") loadAudit();
}

async function loadDashboard(showMessage = false) {
  try {
    state.summary = await api("/api/summary");
    renderSummary();
    if (showMessage) showToast("Dashboard refreshed");
  } catch (error) { if (state.user) showToast(error.message); }
}

async function loadIncidents() {
  const presetDays = Number(byId("date-preset").value || 0);
  const explicitFrom = isoDateValue("date-from");
  const presetFrom = presetDays ? new Date(Date.now() - presetDays * 86400000).toISOString() : "";
  const params = new URLSearchParams({
    search: byId("search").value,
    incident_id: byId("filter-incident-id").value,
    user_name: byId("filter-user-name").value,
    computer_name: byId("filter-computer-name").value,
    usb_name: byId("filter-usb-name").value,
    usb_serial: byId("filter-usb-serial").value,
    file_name: byId("filter-file-name").value,
    file_type: byId("filter-file-type").value,
    assigned_to: byId("filter-assignee").value,
    assignment_state: byId("filter-assignment-state").value,
    classification: byId("classification").value,
    risk_level: byId("risk-level").value,
    decision: byId("decision").value,
    status: byId("incident-status").value,
    min_risk: byId("min-risk").value || "0",
    max_risk: byId("max-risk").value || "100",
    date_from: explicitFrom || presetFrom,
    date_to: isoDateValue("date-to")
  });
  const advancedValues = ["filter-incident-id", "filter-user-name", "filter-computer-name", "filter-usb-name", "filter-usb-serial", "filter-file-name", "filter-file-type", "filter-assignee", "filter-assignment-state", "classification", "date-from", "date-to"].filter((id) => byId(id).value).length;
  byId("advanced-filter-count").textContent = advancedValues ? `(${advancedValues} active)` : "";
  try {
    const data = await api(`/api/incidents?${params}`);
    state.incidents = data.incidents;
    renderIncidents();
  } catch (error) { showToast(error.message); }
}

async function loadAnalysts() {
  try {
    const data = await api("/api/analysts");
    state.analysts = data.analysts || [];
    const selected = byId("filter-assignee").value;
    byId("filter-assignee").innerHTML = `<option value="">All analysts</option>${state.analysts.map((analyst) => `<option value="${escapeHtml(analyst.username)}">${escapeHtml(analyst.username)}</option>`).join("")}`;
    byId("filter-assignee").value = selected;
  } catch (error) { if (state.user) showToast(error.message); }
}

function renderSummary() {
  const summary = state.summary;
  byId("total-incidents").textContent = summary.total_incidents;
  byId("high-risk").textContent = summary.high_risk_incidents;
  byId("average-risk").textContent = summary.average_risk_score;
  const blocked = summary.decisions.Block || 0;
  byId("blocked-count").textContent = blocked;
  byId("blocked-rate").textContent = `${summary.total_incidents ? Math.round(blocked / summary.total_incidents * 100) : 0}% of activity`;
  byId("latest-event").textContent = summary.latest_event_time ? `Latest ${formatDate(summary.latest_event_time)}` : "No activity recorded";
  renderBarChart(summary.classifications);
  renderDecisions(summary.decisions);
  renderSensitiveTypes(summary.sensitive_types);
}

function renderBarChart(values) {
  const labels = ["Public", "Internal", "Confidential", "Restricted"];
  const maximum = Math.max(1, ...labels.map((label) => values[label] || 0));
  byId("classification-chart").innerHTML = labels.map((label) => {
    const value = values[label] || 0;
    return `<div class="bar-item"><span class="bar-label">${label}</span><div class="bar-track"><span class="bar-fill" style="width:${value / maximum * 100}%;background:${colors[label]}"></span></div><span class="bar-value">${value}</span></div>`;
  }).join("");
}

function renderDecisions(values) {
  byId("decision-chart").innerHTML = ["Allow", "Alert", "Block"].map((label) => `<div class="outcome" style="color:${colors[label]}"><span>${label}</span><strong>${values[label] || 0}</strong><div class="outcome-line"></div></div>`).join("");
}

function renderSensitiveTypes(values) {
  const entries = Object.entries(values);
  byId("sensitive-types").innerHTML = entries.length
    ? entries.slice(0, 6).map(([name, count]) => `<div class="type-row"><span class="type-name">${escapeHtml(labelize(name))}</span><span class="type-count">${count}</span></div>`).join("")
    : '<div class="empty-state"><strong>No sensitive data</strong><span>No detections recorded yet.</span></div>';
}

function renderIncidents() {
  const body = byId("incident-rows");
  byId("visible-count").textContent = state.incidents.length;
  byId("empty-state").hidden = state.incidents.length > 0;
  body.innerHTML = state.incidents.map((incident, index) => {
    const score = Number(incident.risk_score || 0);
    const classification = incident.file_classification || "Public";
    const decision = incident.policy_decision || "Allow";
    const status = incidentStatus(incident.incident_status);
    const deviceEvent = incident.incident_type === "usb_device";
    return `<tr data-index="${index}" tabindex="0">
      <td><span class="primary-cell">${escapeHtml(formatDate(incident.event_time))}</span><span class="secondary-cell">${escapeHtml(incident.incident_id)}</span></td>
      <td><span class="primary-cell">${escapeHtml(incident.user_name)}</span><span class="secondary-cell">${escapeHtml(incident.device_name)}</span></td>
      <td><span class="primary-cell">${escapeHtml(deviceEvent ? "USB device insertion" : incident.file_name)}</span><span class="secondary-cell">${deviceEvent ? "Device authorization event" : `${incident.finding_count || 0} findings${incident.duplicate_incident_count ? ` | ${incident.duplicate_incident_count} duplicate` : ""}`}</span></td>
      <td><span class="badge badge-${classification.toLowerCase()}">${escapeHtml(classification)}</span></td>
      <td><div class="risk"><span>${score}</span><span class="risk-meter"><span style="width:${score}%;background:${riskColor(score)}"></span></span></div><span class="secondary-cell">${riskLevel(score)}</span></td>
      <td><span class="badge decision-${decision.toLowerCase()}">${escapeHtml(decision)}</span></td>
      <td><span class="badge status-${statusClass(status)}">${escapeHtml(status)}</span></td>
      <td><span class="primary-cell">${escapeHtml(incident.assigned_to || "Unassigned")}</span></td>
    </tr>`;
  }).join("");
  body.querySelectorAll("tr").forEach((row) => {
    const open = () => showIncident(state.incidents[Number(row.dataset.index)]);
    row.addEventListener("click", open);
    row.addEventListener("keydown", (event) => { if (event.key === "Enter" || event.key === " ") open(); });
  });
}

function showIncident(incident) {
  const findings = Array.isArray(incident.sensitive_findings) ? incident.sensitive_findings : [];
  const hashes = incident.file_hashes || {};
  const classification = incident.file_classification || "Public";
  const decision = incident.policy_decision || "Allow";
  const score = Number(incident.risk_score || 0);
  const deviceEvent = incident.incident_type === "usb_device";
  byId("detail-id").textContent = incident.incident_id || "Incident";
  const tabs = [
    ["overview", "Overview"],
    ...(can("ai_analysis.view") ? [["ai", "AI analysis"]] : []),
    ["investigation", "Investigation"],
    ...(can("evidence.view") ? [["evidence", "Evidence"]] : []),
    ["timeline", "Timeline"]
  ];
  byId("detail-content").innerHTML = `<div class="incident-workspace-layout">
    <aside class="incident-summary-rail">
      <div class="incident-score"><span>Risk score</span><strong style="color:${riskColor(score)}">${score}/100</strong><small>${escapeHtml(riskLevel(score))} priority</small></div>
      <div class="rail-facts">
        ${railFact(deviceEvent ? "Event type" : "Classification", deviceEvent ? "USB insertion" : classification)}
        ${railFact("Policy action", decision)}
        ${railFact("Status", incidentStatus(incident.incident_status))}
        ${railFact("Assigned to", incident.assigned_to || "Unassigned")}
        ${railFact("User", incident.user_name || "Unknown")}
        ${railFact("USB device", incident.device_name || "Unknown")}
      </div>
    </aside>
    <div class="incident-main">
      <nav class="detail-tabs" aria-label="Incident detail sections" role="tablist">${tabs.map(([value, label], index) => `<button class="detail-tab${index === 0 ? " active" : ""}" data-detail-tab="${value}" type="button" role="tab" aria-selected="${index === 0}">${label}</button>`).join("")}</nav>
      <section class="detail-panel" data-detail-panel="overview" role="tabpanel"><dl class="detail-grid">
        ${detail("Time", formatDate(incident.event_time))}${detail("User / department", `${incident.user_name || "Unknown"} / ${incident.department || "Unknown"}`)}
        ${detail("Computer / IP", `${incident.computer_name || "Not recorded"} / ${(incident.ip_addresses || []).join(", ") || "No address"}`)}${detail("USB authorization", incident.usb_authorization_status || "Unknown")}
        ${detail("USB device", `${incident.device_name || "Unknown"} (${incident.device_id || "Unknown"})`)}${detail("USB serial", incident.usb_serial_number || "Not reported")}
        ${detail("USB manufacturer", incident.usb_manufacturer || "Not reported")}${detail("USB model", incident.usb_model || "Not reported")}
        ${deviceEvent ? `${detail("Event", "USB device insertion")}${detail("Enforcement result", incident.action_taken || decision)}` : `${detail("File", incident.file_name)}${detail("File type / size", `${incident.file_type || "Unknown"} / ${Number(incident.file_size || 0).toLocaleString()} bytes`)}`}
        ${detail("Classification", classification)}${detail("Risk / priority", `${score}/100 (${riskLevel(score)})`)}
        ${detail("Investigation status", incidentStatus(incident.incident_status))}${detail("Assigned analyst", incident.assigned_to || "Unassigned")}
        ${detail("Action taken", incident.action_taken || decision)}${detail("Matched policies", (incident.matched_policy_names || []).join(", ") || "Baseline policy")}
        ${deviceEvent ? "" : `${detail("File path", incident.file_path, true)}
        <div class="detail-field full"><dt>File fingerprints</dt><dd class="hash-list"><span class="hash-value">SHA-256: ${escapeHtml(hashes.sha256 || "Not recorded")}</span><span class="hash-value">SHA-1: ${escapeHtml(hashes.sha1 || "Not recorded")}</span><span class="hash-value">MD5: ${escapeHtml(hashes.md5 || "Not recorded")}</span></dd></div>
        <div class="detail-field full"><dt>Sensitive data found</dt><dd>${findings.length ? `<ul class="finding-list">${findings.map((item) => `<li><strong>${escapeHtml(labelize(item.kind))}</strong> | ${escapeHtml(item.severity)} | ${escapeHtml(item.match)}</li>`).join("")}</ul>` : "None"}</dd></div>`}
        ${detail("Policy reasons", (incident.policy_reasons || []).join("; "), true)}
      </dl></section>
      ${can("ai_analysis.view") ? `<section class="detail-panel" data-detail-panel="ai" role="tabpanel" hidden>${aiAnalysisSection(incident)}</section>` : ""}
      <section class="detail-panel" data-detail-panel="investigation" role="tabpanel" hidden>${can("incidents.update") ? workflowForm(incident) : ""}${caseNotesSection(incident)}${investigationHistorySection(incident)}</section>
      ${can("evidence.view") ? `<section class="detail-panel" data-detail-panel="evidence" role="tabpanel" hidden>${evidenceSection(incident)}</section>` : ""}
      <section class="detail-panel" data-detail-panel="timeline" role="tabpanel" hidden>${timelineSection(incident)}</section>
    </div>
  </div>`;
  const workflow = byId("incident-workflow");
  if (workflow) workflow.addEventListener("submit", (event) => updateIncident(event, incident.incident_id));
  setupIncidentTabs();
  byId("incident-dialog").showModal();
  if (can("ai_analysis.view")) loadAiAnalyses(incident.incident_id);
}

function railFact(label, value) {
  return `<div class="rail-fact"><span>${escapeHtml(label)}</span><strong>${escapeHtml(value || "Unknown")}</strong></div>`;
}

function setupIncidentTabs() {
  const dialog = byId("incident-dialog");
  const tabs = [...dialog.querySelectorAll("[data-detail-tab]")];
  const panels = [...dialog.querySelectorAll("[data-detail-panel]")];
  tabs.forEach((tab) => tab.addEventListener("click", () => {
    tabs.forEach((item) => {
      const active = item === tab;
      item.classList.toggle("active", active);
      item.setAttribute("aria-selected", String(active));
    });
    panels.forEach((panel) => { panel.hidden = panel.dataset.detailPanel !== tab.dataset.detailTab; });
  }));
}

function aiAnalysisSection(incident) {
  if (!can("ai_analysis.view")) return "";
  return `<section id="ai-analysis-panel" class="ai-analysis-panel" data-incident-id="${escapeHtml(incident.incident_id)}">
    <div class="ai-heading"><div><h3>AI incident analysis</h3><span>Advisory summary and investigation guidance</span></div></div>
    <div class="ai-loading" role="status">Loading AI analysis...</div>
  </section>`;
}

async function loadAiStatus() {
  if (!can("ai_analysis.view")) return null;
  try {
    state.aiStatus = await api("/api/ai/status");
    return state.aiStatus;
  } catch (error) {
    state.aiStatus = null;
    return null;
  }
}

async function loadAiAnalyses(incidentId) {
  const panel = byId("ai-analysis-panel");
  if (!panel || panel.dataset.incidentId !== incidentId) return;
  try {
    const [status, result] = await Promise.all([
      state.aiStatus ? Promise.resolve(state.aiStatus) : loadAiStatus(),
      api(`/api/incidents/${encodeURIComponent(incidentId)}/ai-analysis`)
    ]);
    if (!byId("ai-analysis-panel") || byId("ai-analysis-panel").dataset.incidentId !== incidentId) return;
    renderAiAnalysisPanel(incidentId, status, result.analyses || []);
  } catch (error) {
    renderAiPanelError(incidentId, error.message);
  }
}

function renderAiAnalysisPanel(incidentId, status, analyses) {
  const panel = byId("ai-analysis-panel");
  if (!panel || panel.dataset.incidentId !== incidentId) return;
  const latest = analyses[0];
  const configured = Boolean(status?.configured);
  const canGenerate = configured && can("ai_analysis.generate");
  const action = canGenerate
    ? `<button id="generate-ai-analysis" class="button button-primary ai-generate-button" type="button">${latest ? "Regenerate analysis" : "Generate analysis"}</button>`
    : "";
  const heading = `<div class="ai-heading"><div><h3>AI incident analysis</h3><span>Advisory summary and investigation guidance</span></div>${action}</div>`;

  if (!configured) {
    panel.innerHTML = `${heading}<div class="ai-setup"><strong>OpenRouter is not configured</strong><span>Add <code>OPENROUTER_API_KEY</code> to <code>.env</code>, then restart the dashboard.</span></div>`;
    return;
  }
  if (!latest) {
    panel.innerHTML = `${heading}<div class="ai-empty"><strong>No AI analysis yet</strong><span>${canGenerate ? "Generate an advisory review from sanitized incident metadata." : "An Administrator or SOC Analyst can generate an advisory review."}</span></div><p class="ai-privacy">Only category-level metadata is sent. File contents, names, paths, hashes, USB serials, and detected values are excluded.</p>`;
  } else {
    panel.innerHTML = `${heading}${aiAnalysisMarkup(latest, analyses.length)}<p class="ai-privacy">AI guidance is advisory. It cannot change the official risk score, classification, or policy action.</p>`;
  }
  const button = byId("generate-ai-analysis");
  if (button) button.addEventListener("click", () => generateAiAnalysis(incidentId, Boolean(latest)));
}

function aiAnalysisMarkup(analysis, historyCount) {
  const recommendations = Array.isArray(analysis.recommendations) ? analysis.recommendations : [];
  const explanations = Array.isArray(analysis.risk_explanation) ? analysis.risk_explanation : [];
  const questions = Array.isArray(analysis.investigation_questions) ? analysis.investigation_questions : [];
  return `<div class="ai-official-values">
      <span><small>Official risk</small><strong>${escapeHtml(analysis.official_risk_score)}/100 (${escapeHtml(analysis.official_risk_level)})</strong></span>
      <span><small>Classification</small><strong>${escapeHtml(analysis.official_classification)}</strong></span>
      <span><small>Policy action</small><strong>${escapeHtml(analysis.official_action)}</strong></span>
    </div>
    <div class="ai-summary"><h4>Summary</h4><p>${escapeHtml(analysis.summary)}</p></div>
    <div class="ai-columns">
      <div><h4>Why the risk is elevated</h4><ul>${explanations.map((item) => `<li>${escapeHtml(item)}</li>`).join("")}</ul></div>
      <div><h4>Investigation questions</h4><ul>${questions.map((item) => `<li>${escapeHtml(item)}</li>`).join("")}</ul></div>
    </div>
    <div class="ai-recommendations"><h4>Recommended next steps</h4><ol>${recommendations.map((item) => `<li><span class="ai-priority ai-priority-${escapeHtml(String(item.priority || "medium").toLowerCase())}">${escapeHtml(item.priority)}</span><div><strong>${escapeHtml(item.action)}</strong><p>${escapeHtml(item.rationale)}</p></div></li>`).join("")}</ol></div>
    <div class="ai-meta"><span>Generated ${escapeHtml(formatDate(analysis.generated_at))} by ${escapeHtml(analysis.generated_by)}</span><span>Model: ${escapeHtml(analysis.model_used || analysis.model_requested)}</span><span>${historyCount} saved ${historyCount === 1 ? "analysis" : "analyses"}</span></div>`;
}

async function generateAiAnalysis(incidentId, force) {
  const button = byId("generate-ai-analysis");
  if (button) { button.disabled = true; button.textContent = "Generating..."; }
  const progress = startAiProgress();
  try {
    const result = await api(`/api/incidents/${encodeURIComponent(incidentId)}/ai-analysis`, {
      method: "POST", body: JSON.stringify({ force })
    });
    completeAiProgress(progress);
    const history = await api(`/api/incidents/${encodeURIComponent(incidentId)}/ai-analysis`);
    renderAiAnalysisPanel(incidentId, state.aiStatus, history.analyses || [result.analysis]);
    showToast(result.cached ? "Cached AI analysis loaded" : "AI analysis generated");
  } catch (error) {
    window.clearInterval(progress?.timer);
    renderAiPanelError(incidentId, error.message, true);
  }
}

function startAiProgress() {
  const panel = byId("ai-analysis-panel");
  const heading = panel?.querySelector(".ai-heading");
  if (!panel || !heading) return null;
  panel.querySelector(".ai-progress")?.remove();
  const element = document.createElement("div");
  element.className = "ai-progress";
  element.innerHTML = `<div class="ai-progress-heading"><span>Estimated progress</span><strong class="ai-progress-value">8%</strong></div><div class="ai-progress-track" role="progressbar" aria-label="Estimated AI analysis progress" aria-valuemin="0" aria-valuemax="100" aria-valuenow="8"><span style="width:8%"></span></div><p class="ai-progress-stage">Preparing sanitized incident metadata</p>`;
  heading.insertAdjacentElement("afterend", element);
  let percent = 8;
  const timer = window.setInterval(() => {
    const increment = percent < 35 ? 4 : percent < 70 ? 2 : 1;
    percent = Math.min(90, percent + increment);
    updateAiProgress(element, percent);
  }, 650);
  return { element, timer };
}

function updateAiProgress(element, percent, finalLabel = "") {
  if (!element?.isConnected) return;
  const value = element.querySelector(".ai-progress-value");
  const track = element.querySelector(".ai-progress-track");
  const fill = track?.querySelector("span");
  const stage = element.querySelector(".ai-progress-stage");
  if (value) value.textContent = `${percent}%`;
  if (track) track.setAttribute("aria-valuenow", String(percent));
  if (fill) fill.style.width = `${percent}%`;
  if (stage) stage.textContent = finalLabel || (percent < 25 ? "Preparing sanitized incident metadata" : percent < 70 ? "Waiting for OpenRouter analysis" : "Validating and saving the response");
}

function completeAiProgress(progress) {
  if (!progress) return;
  window.clearInterval(progress.timer);
  updateAiProgress(progress.element, 100, "Analysis complete");
}

function renderAiPanelError(incidentId, message, retry = false) {
  const panel = byId("ai-analysis-panel");
  if (!panel || panel.dataset.incidentId !== incidentId) return;
  const button = retry && can("ai_analysis.generate")
    ? `<button id="generate-ai-analysis" class="button button-secondary ai-generate-button" type="button">Try again</button>` : "";
  panel.innerHTML = `<div class="ai-heading"><div><h3>AI incident analysis</h3><span>Advisory summary and investigation guidance</span></div>${button}</div><div class="ai-error" role="alert"><strong>Analysis unavailable</strong><span>${escapeHtml(message)}</span></div>`;
  const retryButton = byId("generate-ai-analysis");
  if (retryButton) retryButton.addEventListener("click", () => generateAiAnalysis(incidentId, true));
}

function caseNotesSection(incident) {
  const notes = Array.isArray(incident.investigation_notes) ? [...incident.investigation_notes].reverse() : [];
  return `<section class="case-notes-panel"><h3>Case notes</h3>${notes.length ? `<ol class="case-note-list">${notes.map((note) => {
    const attachments = Array.isArray(note.attachments) ? note.attachments : [];
    const attachmentMarkup = attachments.length ? `<div class="note-attachments">${attachments.map((attachment) => can("case_attachments.download") ? `<a href="/api/incidents/${encodeURIComponent(incident.incident_id)}/attachments/${encodeURIComponent(attachment.attachment_id)}">${escapeHtml(attachment.file_name)} (${Number(attachment.file_size || 0).toLocaleString()} bytes)</a>` : `<span>${escapeHtml(attachment.file_name)} (${Number(attachment.file_size || 0).toLocaleString()} bytes)</span>`).join("")}</div>` : "";
    return `<li><div class="note-heading"><strong>${escapeHtml(note.author || "Unknown analyst")}</strong><time>${escapeHtml(formatDate(note.event_time))}</time></div><p>${escapeHtml(note.text)}</p>${attachmentMarkup}<span class="note-id">${escapeHtml(note.note_id || "Legacy note")}</span></li>`;
  }).join("")}</ol>` : `<div class="empty-state"><strong>No case notes</strong><span>Analyst findings and approvals will appear here.</span></div>`}</section>`;
}

function investigationHistorySection(incident) {
  const statuses = Array.isArray(incident.status_history) ? [...incident.status_history].reverse() : [];
  const assignments = Array.isArray(incident.assignment_history) ? [...incident.assignment_history].reverse() : [];
  const historyList = (items, render) => items.length ? `<ol class="history-list">${items.map(render).join("")}</ol>` : `<span class="history-empty">No changes recorded</span>`;
  return `<section class="history-panel"><h3>Investigation history</h3><div class="history-grid"><div><h4>Status history</h4>${historyList(statuses, (item) => `<li><strong>${escapeHtml(item.previous_status)} to ${escapeHtml(item.new_status)}</strong><span>${escapeHtml(item.changed_by)} | ${escapeHtml(formatDate(item.event_time))}</span><p>${escapeHtml(item.reason)}</p></li>`)}</div><div><h4>Assignment history</h4>${historyList(assignments, (item) => `<li><strong>${escapeHtml(item.previous_assignee || "Unassigned")} to ${escapeHtml(item.new_assignee || "Unassigned")}</strong><span>${escapeHtml(item.changed_by)} | ${escapeHtml(formatDate(item.event_time))}</span><p>${escapeHtml(item.reason)}</p></li>`)}</div></div></section>`;
}

function evidenceSection(incident) {
  if (!can("evidence.view")) return "";
  const evidence = incident.evidence;
  if (!evidence || evidence.collection_error) {
    return `<section class="evidence-panel"><h3>Evidence collection</h3><div class="empty-state"><strong>No evidence package</strong><span>${escapeHtml(evidence?.collection_error || "This incident was recorded before evidence collection or did not meet the high-risk threshold.")}</span></div></section>`;
  }
  const download = can("evidence.download") && evidence.protected_copy_preserved
    ? `<a class="button button-primary" href="/api/evidence/${encodeURIComponent(evidence.evidence_id)}/download">Download protected copy</a>` : "";
  return `<section class="evidence-panel"><h3>Evidence collection</h3><div class="evidence-summary"><div><span>Evidence ID</span><strong>${escapeHtml(evidence.evidence_id)}</strong></div><div><span>Collected</span><strong>${escapeHtml(formatDate(evidence.collected_at))}</strong></div><div><span>Retained until</span><strong>${escapeHtml(formatDate(evidence.retained_until))}</strong></div><div><span>Encryption</span><strong>${escapeHtml(evidence.encryption)}</strong></div><div><span>Encrypted copy</span><strong>${evidence.protected_copy_preserved ? "Preserved" : "Metadata only"}</strong></div><div><span>Manifest SHA-256</span><strong>${escapeHtml(evidence.manifest_sha256)}</strong></div></div><div class="evidence-actions"><span class="integrity-ok">Integrity hashes recorded</span>${download}</div></section>`;
}

function timelineSection(incident) {
  const events = Array.isArray(incident.timeline) && incident.timeline.length
    ? [...incident.timeline].sort((left, right) => String(left.event_time).localeCompare(String(right.event_time)))
    : [{ event_time: incident.event_time, title: "Incident recorded", details: "Legacy incident without detailed event telemetry" }];
  return `<section class="timeline-panel"><h3>Incident timeline</h3><ol class="timeline">${events.map((event) => `<li class="timeline-item"><time class="timeline-time">${escapeHtml(timelineTime(event.event_time))}</time><span class="timeline-marker"></span><div class="timeline-content"><strong>${escapeHtml(event.title)}</strong>${event.details ? `<span>${escapeHtml(event.details)}</span>` : ""}</div></li>`).join("")}</ol></section>`;
}

function timelineTime(value) {
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? "--:--:--" : date.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
}

function workflowForm(incident) {
  const status = incidentStatus(incident.incident_status);
  const currentAssignee = incident.assigned_to || "";
  const analystOptions = state.analysts.map((analyst) => analyst.username);
  if (currentAssignee && !analystOptions.includes(currentAssignee)) analystOptions.unshift(currentAssignee);
  return `<form id="incident-workflow" class="workflow-panel"><h3>Investigation workflow</h3><div class="workflow-grid"><label>Status<select id="workflow-status">${incidentStatuses.map((value) => `<option${value === status ? " selected" : ""}>${value}</option>`).join("")}</select></label><label>Assigned analyst<select id="workflow-assignee"><option value="">Unassigned</option>${analystOptions.map((value) => `<option value="${escapeHtml(value)}"${value === currentAssignee ? " selected" : ""}>${escapeHtml(value)}</option>`).join("")}</select></label><label class="full">Reason for status or assignment change<textarea id="workflow-reason" rows="2" maxlength="1000" placeholder="Required when status or assignment changes"></textarea></label><label class="full">Add case note<textarea id="workflow-note" rows="3" maxlength="5000" placeholder="Notes are permanent and recorded in the audit log"></textarea></label><label class="full attachment-field">Optional attachment<input id="workflow-attachment" type="file"><span>Maximum 2 MB. Attachments cannot be edited or deleted.</span></label></div><p id="workflow-error" class="form-error" hidden></p><div class="workflow-actions"><button class="button button-primary" type="submit">Save investigation update</button></div></form>`;
}

async function updateIncident(event, incidentId) {
  event.preventDefault();
  try {
    const file = byId("workflow-attachment").files[0];
    const attachment = file ? await attachmentPayload(file) : null;
    const updated = await api(`/api/incidents/${encodeURIComponent(incidentId)}`, {
      method: "POST", body: JSON.stringify({ incident_status: byId("workflow-status").value, assigned_to: byId("workflow-assignee").value, change_reason: byId("workflow-reason").value, note: byId("workflow-note").value, attachment })
    });
    const index = state.incidents.findIndex((item) => item.incident_id === incidentId);
    if (index >= 0) state.incidents[index] = updated;
    byId("incident-dialog").close(); renderIncidents(); showIncident(updated);
    showToast("Incident updated");
  } catch (error) { byId("workflow-error").textContent = error.message; byId("workflow-error").hidden = false; }
}

function attachmentPayload(file) {
  if (file.size > 2 * 1024 * 1024) return Promise.reject(new Error("Attachment exceeds the 2 MB limit"));
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onerror = () => reject(new Error("Attachment could not be read"));
    reader.onload = () => resolve({ file_name: file.name, content_type: file.type || "application/octet-stream", data_base64: String(reader.result).split(",", 2)[1] || "" });
    reader.readAsDataURL(file);
  });
}

function detail(label, value, full = false) {
  return `<div class="detail-field${full ? " full" : ""}"><dt>${escapeHtml(label)}</dt><dd>${escapeHtml(value || "Not available")}</dd></div>`;
}

async function loadPolicies() {
  try { const data = await api("/api/policies"); state.policies = data.policies; renderPolicies(); }
  catch (error) { showToast(error.message); }
}

function renderPolicies() {
  byId("policy-empty").hidden = state.policies.length > 0;
  byId("policy-rows").innerHTML = state.policies.map((policy) => `<tr>
    <td><strong>${policy.priority}</strong></td><td><span class="primary-cell">${escapeHtml(policy.name)}</span><span class="secondary-cell">${escapeHtml(policy.policy_id)}</span></td>
    <td><div class="condition-summary">${policy.conditions.map(conditionText).join("; ")}</div></td><td><span class="badge decision-${policy.action.toLowerCase()}">${policy.action}</span></td>
    <td>${can("policies.manage") ? `<label class="state-toggle"><input class="policy-toggle" data-id="${policy.policy_id}" type="checkbox"${policy.enabled ? " checked" : ""}>${policy.enabled ? "Enabled" : "Disabled"}</label>` : (policy.enabled ? "Enabled" : "Disabled")}</td>
    <td><div class="table-actions">${can("policies.manage") ? `<button class="table-button policy-edit" data-id="${policy.policy_id}" type="button">Edit</button><button class="table-button danger policy-delete" data-id="${policy.policy_id}" type="button">Delete</button>` : "Read only"}</div></td>
  </tr>`).join("");
  document.querySelectorAll(".policy-toggle").forEach((input) => input.addEventListener("change", togglePolicy));
  document.querySelectorAll(".policy-edit").forEach((button) => button.addEventListener("click", () => openPolicy(button.dataset.id)));
  document.querySelectorAll(".policy-delete").forEach((button) => button.addEventListener("click", () => deletePolicy(button.dataset.id)));
}

function conditionText(condition) {
  const type = condition.data_type ? `${labelize(condition.data_type)} count` : fieldLabels[condition.field];
  return `${escapeHtml(type)} ${escapeHtml(operatorLabels[condition.operator] || condition.operator)} ${escapeHtml(condition.value)}`;
}

function openPolicy(policyId = "") {
  const policy = state.policies.find((item) => item.policy_id === policyId);
  byId("policy-form").reset();
  byId("policy-error").hidden = true;
  byId("policy-id").value = policyId;
  byId("policy-dialog-title").textContent = policy ? "Edit policy" : "Create policy";
  byId("policy-name").value = policy?.name || "";
  byId("policy-description").value = policy?.description || "";
  byId("policy-priority").value = policy?.priority || 100;
  byId("policy-action").value = policy?.action || "Alert";
  byId("policy-risk").value = policy?.risk_score_override ?? "";
  byId("policy-enabled").checked = policy?.enabled ?? true;
  byId("policy-notify").checked = policy?.notify_soc ?? true;
  byId("condition-list").innerHTML = "";
  (policy?.conditions || [{ field: "file_classification", operator: "equals", value: "Restricted" }]).forEach(addConditionRow);
  byId("policy-dialog").showModal();
}

function addConditionRow(condition = {}) {
  const row = document.createElement("div");
  row.className = "condition-row";
  row.innerHTML = `<select class="condition-field" aria-label="Condition field">${Object.entries(fieldLabels).map(([value, label]) => `<option value="${value}"${condition.field === value ? " selected" : ""}>${label}</option>`).join("")}</select><select class="condition-operator" aria-label="Condition operator">${Object.entries(operatorLabels).map(([value, label]) => `<option value="${value}"${condition.operator === value ? " selected" : ""}>${label}</option>`).join("")}</select><input class="condition-type" aria-label="Sensitive data type" placeholder="Data type, e.g. bank_account" value="${escapeHtml(condition.data_type || "")}"><input class="condition-value" aria-label="Condition value" placeholder="Value" value="${escapeHtml(condition.value ?? "")}"><button class="remove-condition" type="button" aria-label="Remove condition">&times;</button>`;
  byId("condition-list").appendChild(row);
  const field = row.querySelector(".condition-field");
  const type = row.querySelector(".condition-type");
  const refresh = () => { type.hidden = field.value !== "sensitive_data_count"; };
  field.addEventListener("change", refresh);
  row.querySelector(".remove-condition").addEventListener("click", () => { if (byId("condition-list").children.length > 1) row.remove(); });
  refresh();
}

function collectPolicy() {
  const numericFields = new Set(["sensitive_data_count", "file_size", "risk_score"]);
  const conditions = [...document.querySelectorAll(".condition-row")].map((row) => {
    const field = row.querySelector(".condition-field").value;
    const rawValue = row.querySelector(".condition-value").value;
    return { field, operator: row.querySelector(".condition-operator").value, value: numericFields.has(field) ? Number(rawValue) : rawValue, data_type: row.querySelector(".condition-type").value };
  });
  return { name: byId("policy-name").value, description: byId("policy-description").value, priority: Number(byId("policy-priority").value), action: byId("policy-action").value, risk_score_override: byId("policy-risk").value, enabled: byId("policy-enabled").checked, notify_soc: byId("policy-notify").checked, conditions };
}

async function savePolicy(event) {
  event.preventDefault();
  const id = byId("policy-id").value;
  try {
    await api(id ? `/api/policies/${encodeURIComponent(id)}` : "/api/policies", { method: id ? "PUT" : "POST", body: JSON.stringify(collectPolicy()) });
    byId("policy-dialog").close(); await loadPolicies(); showToast(id ? "Policy updated" : "Policy created");
  } catch (error) { byId("policy-error").textContent = error.message; byId("policy-error").hidden = false; }
}

async function togglePolicy(event) {
  const policy = state.policies.find((item) => item.policy_id === event.target.dataset.id);
  try { await api(`/api/policies/${encodeURIComponent(policy.policy_id)}`, { method: "PUT", body: JSON.stringify({ ...policy, enabled: event.target.checked }) }); await loadPolicies(); showToast("Policy state updated"); }
  catch (error) { event.target.checked = !event.target.checked; showToast(error.message); }
}

async function deletePolicy(id) {
  if (!window.confirm("Delete this policy?")) return;
  try { await api(`/api/policies/${encodeURIComponent(id)}`, { method: "DELETE" }); await loadPolicies(); showToast("Policy deleted"); }
  catch (error) { showToast(error.message); }
}

async function loadAccess() {
  try {
    const [users, devices] = await Promise.all([api("/api/users"), api("/api/usb-devices")]);
    state.users = users.users; state.roles = users.roles; state.usbDevices = devices.devices;
    renderUsers(); renderUsbDevices();
  } catch (error) { showToast(error.message); }
}

function renderUsers() {
  byId("user-rows").innerHTML = state.users.map((user) => `<tr><td><span class="primary-cell">${escapeHtml(user.username)}</span><span class="secondary-cell">${escapeHtml(user.user_id)}</span></td><td>${escapeHtml(user.department || "Unknown")}</td><td>${escapeHtml(user.role)}</td><td>${user.enabled ? "Enabled" : "Disabled"}</td><td><button class="table-button user-edit" data-id="${user.user_id}" type="button">Edit</button></td></tr>`).join("");
  document.querySelectorAll(".user-edit").forEach((button) => button.addEventListener("click", () => openUser(button.dataset.id)));
}

function openUser(userId = "") {
  const user = state.users.find((item) => item.user_id === userId);
  byId("user-form").reset(); byId("user-error").hidden = true; byId("user-id").value = userId;
  byId("user-dialog-title").textContent = user ? "Edit user" : "Create user";
  byId("user-name").value = user?.username || ""; byId("user-name").disabled = Boolean(user);
  byId("user-department").value = user?.department || "";
  byId("user-role").innerHTML = state.roles.map((role) => `<option${role === user?.role ? " selected" : ""}>${role}</option>`).join("");
  byId("user-enabled").checked = user?.enabled ?? true;
  byId("user-password").required = !user;
  byId("user-dialog").showModal();
}

async function saveUser(event) {
  event.preventDefault();
  const id = byId("user-id").value;
  const value = { username: byId("user-name").value, department: byId("user-department").value, role: byId("user-role").value, password: byId("user-password").value, enabled: byId("user-enabled").checked };
  try { await api(id ? `/api/users/${encodeURIComponent(id)}` : "/api/users", { method: id ? "PUT" : "POST", body: JSON.stringify(value) }); byId("user-dialog").close(); await loadAccess(); showToast(id ? "User updated" : "User created"); }
  catch (error) { byId("user-error").textContent = error.message; byId("user-error").hidden = false; }
}

function renderUsbDevices() {
  byId("usb-empty").hidden = state.usbDevices.length > 0;
  byId("usb-rows").innerHTML = state.usbDevices.map((device) => `<tr><td>${escapeHtml(device.name)}</td><td>${escapeHtml(device.device_id)}</td><td><span class="badge ${device.status === "authorized" ? "decision-allow" : device.status === "blocked" ? "decision-block" : "decision-alert"}">${escapeHtml(labelize(device.status))}</span></td><td>${escapeHtml(formatDate(device.updated_at))}</td><td><div class="table-actions"><button class="table-button usb-edit" data-id="${escapeHtml(device.device_id)}" type="button">Edit</button><button class="table-button danger usb-delete" data-id="${escapeHtml(device.device_id)}" type="button">Delete</button></div></td></tr>`).join("");
  document.querySelectorAll(".usb-edit").forEach((button) => button.addEventListener("click", () => openUsb(button.dataset.id)));
  document.querySelectorAll(".usb-delete").forEach((button) => button.addEventListener("click", () => deleteUsb(button.dataset.id)));
}

function openUsb(deviceId = "") {
  const device = state.usbDevices.find((item) => item.device_id === deviceId);
  byId("usb-form").reset(); byId("usb-error").hidden = true;
  byId("usb-id").value = device?.device_id || ""; byId("usb-name").value = device?.name || ""; byId("usb-status").value = device?.status || "authorized";
  byId("usb-dialog").showModal();
}

async function saveUsb(event) {
  event.preventDefault();
  try { await api("/api/usb-devices", { method: "POST", body: JSON.stringify({ device_id: byId("usb-id").value, name: byId("usb-name").value, status: byId("usb-status").value }) }); byId("usb-dialog").close(); await loadAccess(); showToast("USB authorization updated"); }
  catch (error) { byId("usb-error").textContent = error.message; byId("usb-error").hidden = false; }
}

async function deleteUsb(id) {
  if (!window.confirm("Remove this USB device registration?")) return;
  try { await api(`/api/usb-devices/${encodeURIComponent(id)}`, { method: "DELETE" }); await loadAccess(); showToast("USB registration removed"); }
  catch (error) { showToast(error.message); }
}

async function loadAudit() {
  try {
    const data = await api("/api/audit");
    byId("audit-empty").hidden = data.entries.length > 0;
    byId("audit-rows").innerHTML = data.entries.map((entry) => `<tr><td>${escapeHtml(formatDate(entry.event_time))}</td><td>${escapeHtml(entry.actor)}</td><td>${escapeHtml(labelize(entry.action))}</td><td><span class="primary-cell">${escapeHtml(labelize(entry.target_type))}</span><span class="secondary-cell">${escapeHtml(entry.target_id)}</span></td><td>${escapeHtml(entry.details || "-")}</td></tr>`).join("");
  } catch (error) { showToast(error.message); }
}

function showToast(message) {
  const toast = byId("toast"); toast.textContent = message; toast.classList.add("visible");
  window.setTimeout(() => toast.classList.remove("visible"), 2200);
}

function scheduleRefresh() {
  window.clearInterval(state.timer);
  if (byId("auto-refresh").checked) state.timer = window.setInterval(() => { if (state.currentView === "overview") loadDashboard(false); if (state.currentView === "incidents") loadIncidents(); }, 10000);
}

let filterTimer;
byId("login-form").addEventListener("submit", login);
byId("logout-button").addEventListener("click", logout);
byId("workspace-nav").addEventListener("click", (event) => { const button = event.target.closest("[data-view]"); if (button) switchView(button.dataset.view); });
byId("refresh-button").addEventListener("click", () => loadDashboard(true));
byId("auto-refresh").addEventListener("change", scheduleRefresh);
byId("filters").addEventListener("input", () => { window.clearTimeout(filterTimer); filterTimer = window.setTimeout(loadIncidents, 180); });
byId("clear-filters").addEventListener("click", () => { byId("filters").reset(); loadIncidents(); });
byId("new-policy-button").addEventListener("click", () => openPolicy());
byId("add-condition").addEventListener("click", () => addConditionRow());
byId("policy-form").addEventListener("submit", savePolicy);
byId("new-user-button").addEventListener("click", () => openUser());
byId("user-form").addEventListener("submit", saveUser);
byId("new-usb-button").addEventListener("click", () => openUsb());
byId("usb-form").addEventListener("submit", saveUsb);
byId("refresh-audit").addEventListener("click", loadAudit);
document.querySelectorAll("[data-close]").forEach((button) => button.addEventListener("click", () => byId(button.dataset.close).close()));
document.querySelectorAll("dialog").forEach((dialog) => dialog.addEventListener("click", (event) => { if (event.target === dialog) dialog.close(); }));

initialize();
