"use strict";

const byId = (id) => document.getElementById(id);

function requestHeaders() {
  const headers = { Authorization: `Bearer ${byId("token").value}` };
  const approverId = byId("approverId").value.trim();
  if (approverId) headers["X-Approver-Id"] = approverId;
  return headers;
}

function textCell(value) {
  const cell = document.createElement("td");
  cell.textContent = String(value ?? "—");
  return cell;
}

function showTableMessage(message) {
  const row = document.createElement("tr");
  const cell = textCell(message);
  cell.colSpan = 6;
  row.append(cell);
  byId("rows").replaceChildren(row);
}

function actionButton(label, className, requestId, action) {
  const button = document.createElement("button");
  button.type = "button";
  button.className = className;
  button.textContent = label;
  button.addEventListener("click", () => resolveApproval(requestId, action));
  return button;
}

function approvalRow(approval) {
  const row = document.createElement("tr");
  const idCell = document.createElement("td");
  const code = document.createElement("code");
  const requestId = String(approval.id ?? "");
  code.textContent = `${requestId.slice(0, 8)}…`;
  idCell.append(code);

  const actions = document.createElement("td");
  actions.append(
    actionButton("Approve", "approve", requestId, "approve"),
    actionButton("Deny", "deny", requestId, "deny"),
  );
  row.append(
    idCell,
    textCell(approval.tool),
    textCell(approval.status),
    textCell(approval.requester_id),
    textCell(approval.created_at),
    actions,
  );
  return row;
}

async function loadApprovals() {
  const tenant = byId("tenant").value.trim();
  const status = byId("status").value;
  const response = await fetch(
    `/v1/approvals/${encodeURIComponent(tenant)}?status=${encodeURIComponent(status)}`,
    { headers: requestHeaders() },
  );
  if (!response.ok) {
    showTableMessage(`Error ${response.status}: ${await response.text()}`);
    return;
  }
  const data = await response.json();
  const approvals = Array.isArray(data.approvals) ? data.approvals : [];
  if (!approvals.length) {
    showTableMessage(`No ${status} approvals.`);
    return;
  }
  byId("rows").replaceChildren(...approvals.map(approvalRow));
}

async function resolveApproval(requestId, action) {
  const response = await fetch(`/v1/approvals/${encodeURIComponent(requestId)}/${action}`, {
    method: "POST",
    headers: requestHeaders(),
  });
  const body = await response.json().catch(() => ({}));
  byId("status").textContent = response.ok
    ? `${action} OK — status=${body.status}${body.resume_token ? " (resume token issued)" : ""}`
    : `Error ${response.status}: ${JSON.stringify(body)}`;
  await loadApprovals();
}

byId("refresh").addEventListener("click", loadApprovals);
byId("token").addEventListener("change", loadApprovals);
loadApprovals();
