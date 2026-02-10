const ticketForm = document.getElementById("ticket-form");
const ticketList = document.getElementById("ticket-list");
const incidentTypesEl = document.getElementById("incident-types");
const STORAGE_KEY = "cyber-tickets";
const TYPES_KEY = "cyber-incident-types";

const defaultTypes = [
  "Intrusion",
  "DDoS",
  "Malware",
  "Phishing",
  "Ransomware",
  "Data Exfiltration",
  "Account Takeover",
  "Insider Threat",
];

const state = {
  tickets: loadTickets(),
  incidentTypes: loadTypes(),
  selectedTicketId: null,
};

const ticketForm = document.getElementById("ticket-form");
const ticketList = document.getElementById("ticket-list");
const incidentTypes = document.getElementById("incident-types");
const chatPanel = document.getElementById("chat-panel");
const chatPlaceholder = document.getElementById("chat-placeholder");
const chatMessages = document.getElementById("chat-messages");
const chatForm = document.getElementById("chat-form");
const chatTicketId = document.getElementById("chat-ticket-id");
const chatTicketSummary = document.getElementById("chat-ticket-summary");
const statusSelect = document.getElementById("status-select");
const ticketDetails = document.getElementById("ticket-details");
const adminForm = document.getElementById("admin-form");
const notifications = document.getElementById("notifications");
const userPill = document.getElementById("user-pill");
const logoutBtn = document.getElementById("logout-btn");

const pmMessages = document.getElementById("pm-messages");
const pmForm = document.getElementById("pm-form");
const pmContextForm = document.getElementById("pm-context-form");
const pmMe = document.getElementById("pm-me");
const pmPeer = document.getElementById("pm-peer");

const state = { tickets: [], incidentTypes: [], selectedTicketId: null, user: null };

function getToken() {
  return localStorage.getItem("auth_token") || "";
}

function goLogin() {
  const hint = localStorage.getItem("auth_user");
  if (hint) {
    try {
      const user = JSON.parse(hint);
      location.href = user.role === "admin" ? "/admin-login.html" : "/user-login.html";
      return;
    } catch {}
  }
  location.href = "/user-login.html";
}

async function requestJson(path, options = {}) {
  const response = await fetch(path, {
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${getToken()}`,
      ...(options.headers || {}),
    },
    ...options,
  });
  const body = await response.json().catch(() => ({}));
  if (response.status === 401 || response.status === 403) {
    localStorage.removeItem("auth_token");
    localStorage.removeItem("auth_user");
    goLogin();
    throw new Error("Unauthorized");
  }
  if (!response.ok) throw new Error(body.error || "Request failed");
  return body;
}

function addNotification(text) {
  const node = document.createElement("div");
  node.className = "chat-message notification-item";
  node.innerHTML = `<strong>${new Date().toLocaleString()}</strong>${text}`;
  notifications.prepend(node);
}

function connectRealtime() {
  const stream = new EventSource("/api/stream");
  const handlers = {
    ticket_created: async ({ payload }) => {
      addNotification(`New ticket created: ${payload.ticketCode} (${payload.summary})`);
      await loadTickets();
    },
    ticket_message_created: async ({ payload }) => {
      addNotification(`Ticket #${payload.ticketId}: new message from ${payload.author}`);
      if (state.selectedTicketId === payload.ticketId) await loadMessages(payload.ticketId);
    },
    ticket_status_changed: async ({ payload }) => {
      addNotification(`${payload.ticketCode} status changed to ${payload.status.replaceAll("_", " ")}`);
      await loadTickets();
    },
    private_message_created: async ({ payload }) => {
      addNotification(`Private message: ${payload.sender} → ${payload.recipient}`);
      const me = pmMe.value.trim();
      const peer = pmPeer.value.trim();
      if ((payload.sender === me && payload.recipient === peer) || (payload.sender === peer && payload.recipient === me)) {
        await loadPrivateMessages();
      }
    },
    incident_type_created: async ({ payload }) => {
      addNotification(`New incident type added: ${payload.name}`);
      await loadIncidentTypes();
    },
  };

  Object.entries(handlers).forEach(([event, handler]) => {
    stream.addEventListener(event, (ev) => {
      try {
        handler(JSON.parse(ev.data));
      } catch {
        addNotification(`Realtime event parse error for ${event}`);
      }
    });
  });

  stream.onerror = () => addNotification("Realtime connection interrupted. Reconnecting...");
}

async function loadIncidentTypes() {
  state.incidentTypes = await requestJson("/api/incident-types");
  incidentTypesEl.innerHTML = "";
  state.incidentTypes.forEach((type) => {
    const label = document.createElement("label");
    label.className = "chip";
    label.innerHTML = `<input type="checkbox" name="incidentType" value="${type}" />${type}`;
    incidentTypesEl.appendChild(label);
  });
}

function formatStatus(status) {
  return status.replaceAll("_", " ");
}

function renderTickets() {
  ticketList.innerHTML = "";
  if (!state.tickets.length) {
    ticketList.innerHTML = '<p class="empty-state">No tickets yet. Create one to begin tracking.</p>';
    return;
  }
  state.tickets
    .slice()
    .sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt))
    .forEach((ticket) => {
      const card = document.createElement("article");
      card.className = `ticket-card ${ticket.id === state.selectedTicketId ? "active" : ""}`;
      card.innerHTML = `
        <div class="ticket-meta"><span>${ticket.ticketCode}</span><span>${new Date(ticket.createdAt).toLocaleString()}</span></div>
        <strong>${ticket.summary}</strong>
        <div class="ticket-meta"><span class="tag ${ticket.riskLevel}">${ticket.riskLevel}</span><span class="tag">${formatStatus(ticket.status)}</span></div>
        <div class="ticket-meta"><span>Assigned: ${ticket.assignee}</span><span>Types: ${ticket.incidentTypes.join(", ") || "None"}</span></div>
const adminForm = document.getElementById("admin-form");

function loadTickets() {
  const stored = localStorage.getItem(STORAGE_KEY);
  return stored ? JSON.parse(stored) : [];
}

function loadTypes() {
  const stored = localStorage.getItem(TYPES_KEY);
  return stored ? JSON.parse(stored) : [...defaultTypes];
}

function saveTickets() {
  localStorage.setItem(STORAGE_KEY, JSON.stringify(state.tickets));
}

function saveTypes() {
  localStorage.setItem(TYPES_KEY, JSON.stringify(state.incidentTypes));
}

function formatTicketId(sequence) {
  const now = new Date();
  const month = String(now.getMonth() + 1).padStart(2, "0");
  const year = now.getFullYear();
  const suffix = String(sequence).padStart(3, "0");
  return `${month}-${year}-${suffix}`;
}

function nextSequence() {
  const currentMonth = `${new Date().getFullYear()}-${new Date().getMonth()}`;
  const sequences = state.tickets
    .filter((ticket) => ticket.createdMonth === currentMonth)
    .map((ticket) => Number(ticket.sequence));
  return sequences.length ? Math.max(...sequences) + 1 : 1;
}

function renderIncidentTypes() {
  incidentTypes.innerHTML = "";
  state.incidentTypes.forEach((type) => {
    const label = document.createElement("label");
    label.className = "chip";
    const checkbox = document.createElement("input");
    checkbox.type = "checkbox";
    checkbox.name = "incidentType";
    checkbox.value = type;
    label.appendChild(checkbox);
    label.append(type);
    incidentTypes.appendChild(label);
  });
}

function renderTickets() {
  ticketList.innerHTML = "";
  if (state.tickets.length === 0) {
    ticketList.innerHTML = '<p class="empty-state">No tickets yet. Create one to begin tracking.</p>';
    return;
  }

  state.tickets
    .slice()
    .sort((a, b) => b.createdAt - a.createdAt)
    .forEach((ticket) => {
      const card = document.createElement("article");
      card.className = "ticket-card";
      if (ticket.id === state.selectedTicketId) {
        card.classList.add("active");
      }
      card.innerHTML = `
        <div class="ticket-meta">
          <span>${ticket.id}</span>
          <span>${new Date(ticket.createdAt).toLocaleString()}</span>
        </div>
        <strong>${ticket.summary}</strong>
        <div class="ticket-meta">
          <span class="tag ${ticket.riskLevel}">${ticket.riskLevel}</span>
          <span class="tag">${formatStatus(ticket.status)}</span>
        </div>
        <div class="ticket-meta">
          <span>Assigned: ${ticket.assignee}</span>
          <span>Types: ${ticket.incidentTypes.join(", ") || "None"}</span>
        </div>
      `;
      card.addEventListener("click", () => selectTicket(ticket.id));
      ticketList.appendChild(card);
    });
}

async function loadTickets() {
  state.tickets = await requestJson("/api/tickets");
  renderTickets();
  if (state.selectedTicketId) {
    const exists = state.tickets.find((t) => t.id === state.selectedTicketId);
    if (exists) await selectTicket(state.selectedTicketId);
  }
}

function renderTicketDetails(ticket) {
  const attachments = ticket.attachments.length ? ticket.attachments.join(", ") : "None";
  ticketDetails.innerHTML = `
    <div><span>Reported</span>${ticket.reportedDate} ${ticket.reportedTime}</div>
    <div><span>Risk Level</span>${ticket.riskLevel}</div>
    <div><span>Incident Types</span>${ticket.incidentTypes.join(", ") || "None"}</div>
    <div><span>Source IP</span>${ticket.sourceIp}</div>
    <div><span>Destination IP</span>${ticket.destinationIp}</div>
    <div><span>Compromised Systems</span>${ticket.compromisedSystems || "None"}</div>
    <div><span>Attachments</span>${attachments}</div>
  `;
}

function renderChat(messages) {
  chatMessages.innerHTML = "";
  messages.forEach((m) => {
    const n = document.createElement("div");
    n.className = "chat-message";
    n.innerHTML = `<strong>${m.author} · ${new Date(m.timestamp).toLocaleString()}</strong>${m.message}`;
    chatMessages.appendChild(n);
  });
}

async function loadMessages(ticketId) {
  renderChat(await requestJson(`/api/tickets/${ticketId}/messages`));
}

async function selectTicket(id) {
  state.selectedTicketId = id;
  const ticket = state.tickets.find((t) => t.id === id);
function formatStatus(status) {
  return status.replace(/_/g, " ");
}

function selectTicket(id) {
  state.selectedTicketId = id;
  const ticket = state.tickets.find((item) => item.id === id);
  if (!ticket) {
    chatPanel.hidden = true;
    chatPlaceholder.hidden = false;
    return;
  }
  chatPanel.hidden = false;
  chatPlaceholder.hidden = true;
  chatTicketId.textContent = ticket.ticketCode;
  chatTicketSummary.textContent = `${ticket.summary} — Assigned to ${ticket.assignee}`;
  statusSelect.value = ticket.status;
  renderTicketDetails(ticket);
  await loadMessages(ticket.id);
  renderTickets();
}

async function loadPrivateMessages() {
  const me = pmMe.value.trim();
  const peer = pmPeer.value.trim();
  if (!me || !peer) return;
  const messages = await requestJson(`/api/private-messages?me=${encodeURIComponent(me)}&peer=${encodeURIComponent(peer)}`);
  pmMessages.innerHTML = "";
  messages.forEach((m) => {
    const n = document.createElement("div");
    n.className = "chat-message";
    n.innerHTML = `<strong>${m.sender} → ${m.recipient} · ${new Date(m.timestamp).toLocaleString()}</strong>${m.message}`;
    pmMessages.appendChild(n);
  });
}

ticketForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const formData = new FormData(ticketForm);
  const types = formData.getAll("incidentType");
  const other = formData.get("incidentOther").trim();
  if (other) types.push(other);

  const ticket = await requestJson("/api/tickets", {
    method: "POST",
    body: JSON.stringify({
      reportedDate: formData.get("reportedDate"),
      reportedTime: formData.get("reportedTime"),
      riskLevel: formData.get("riskLevel"),
      summary: formData.get("summary"),
      incidentTypes: types,
      sourceIp: formData.get("sourceIp"),
      destinationIp: formData.get("destinationIp"),
      compromisedSystems: formData.get("compromisedSystems"),
      details: formData.get("details"),
      attachments: Array.from(formData.getAll("attachments")).flat().map((f) => f.name),
      assignee: formData.get("assignee"),
    }),
  });

  ticketForm.reset();
  await loadTickets();
  await selectTicket(ticket.id);
});

chatForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  if (!state.selectedTicketId) return;
  const fd = new FormData(chatForm);
  await requestJson(`/api/tickets/${state.selectedTicketId}/messages`, {
    method: "POST",
    body: JSON.stringify({ author: fd.get("author"), message: fd.get("message") }),
  });
  chatForm.reset();
  await loadMessages(state.selectedTicketId);
});

statusSelect.addEventListener("change", async (event) => {
  if (!state.selectedTicketId) return;
  await requestJson(`/api/tickets/${state.selectedTicketId}`, {
    method: "PATCH",
    body: JSON.stringify({ status: event.target.value }),
  });
  await loadTickets();
  await loadMessages(state.selectedTicketId);
});

adminForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const name = new FormData(adminForm).get("newType").trim();
  if (!name) return;
  await requestJson("/api/incident-types", { method: "POST", body: JSON.stringify({ name }) });
  adminForm.reset();
  await loadIncidentTypes();
});

pmContextForm.addEventListener("change", loadPrivateMessages);
pmForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const fd = new FormData(pmForm);
  const sender = fd.get("sender").trim();
  const message = fd.get("message").trim();
  const recipient = pmPeer.value.trim();
  if (!sender || !recipient || !message) return;
  await requestJson("/api/private-messages", {
    method: "POST",
    body: JSON.stringify({ sender, recipient, targetType: "user", message }),
  });
  pmForm.reset();
  await loadPrivateMessages();
});

logoutBtn.addEventListener("click", () => {
  localStorage.removeItem("auth_token");
  localStorage.removeItem("auth_user");
  goLogin();
});

async function init() {
  if (!getToken()) return goLogin();
  state.user = await requestJson("/api/auth/me");
  userPill.textContent = `Signed in: ${state.user.username} (${state.user.role})`;
  await loadIncidentTypes();
  await loadTickets();
  await loadPrivateMessages();
  connectRealtime();
  if (state.tickets.length > 0) await selectTicket(state.tickets[0].id);
}

init().catch((err) => {
  ticketList.innerHTML = `<p class="empty-state">${err.message}</p>`;
});
  chatTicketId.textContent = ticket.id;
  chatTicketSummary.textContent = `${ticket.summary} — Assigned to ${ticket.assignee}`;
  statusSelect.value = ticket.status;
  renderChat(ticket);
  renderTickets();
}

function renderChat(ticket) {
  chatMessages.innerHTML = "";
  ticket.chat.forEach((entry) => {
    const message = document.createElement("div");
    message.className = "chat-message";
    message.innerHTML = `<strong>${entry.author} · ${new Date(entry.timestamp).toLocaleString()}</strong>${entry.message}`;
    chatMessages.appendChild(message);
  });
}

function handleTicketSubmit(event) {
  event.preventDefault();
  const formData = new FormData(ticketForm);
  const incidentSelection = formData.getAll("incidentType");
  const other = formData.get("incidentOther").trim();
  const types = [...incidentSelection];
  if (other) {
    types.push(other);
  }

  const sequence = nextSequence();
  const createdMonth = `${new Date().getFullYear()}-${new Date().getMonth()}`;
  const ticket = {
    id: formatTicketId(sequence),
    sequence,
    createdMonth,
    createdAt: Date.now(),
    reportedDate: formData.get("reportedDate"),
    reportedTime: formData.get("reportedTime"),
    riskLevel: formData.get("riskLevel"),
    summary: formData.get("summary"),
    incidentTypes: types,
    sourceIp: formData.get("sourceIp"),
    destinationIp: formData.get("destinationIp"),
    compromisedSystems: formData.get("compromisedSystems"),
    details: formData.get("details"),
    attachments: Array.from(formData.getAll("attachments"))
      .flat()
      .map((file) => file.name),
    assignee: formData.get("assignee"),
    status: "open",
    chat: [
      {
        author: "System",
        message: `Ticket created and routed to ${formData.get("assignee")}.`,
        timestamp: Date.now(),
      },
    ],
  };

  state.tickets.push(ticket);
  saveTickets();
  ticketForm.reset();
  renderTickets();
  selectTicket(ticket.id);
}

function handleChatSubmit(event) {
  event.preventDefault();
  const ticket = state.tickets.find((item) => item.id === state.selectedTicketId);
  if (!ticket) {
    return;
  }
  const formData = new FormData(chatForm);
  ticket.chat.push({
    author: formData.get("author"),
    message: formData.get("message"),
    timestamp: Date.now(),
  });
  saveTickets();
  chatForm.reset();
  renderChat(ticket);
}

function handleStatusChange(event) {
  const ticket = state.tickets.find((item) => item.id === state.selectedTicketId);
  if (!ticket) {
    return;
  }
  ticket.status = event.target.value;
  ticket.chat.push({
    author: "System",
    message: `Status updated to ${formatStatus(ticket.status)}.`,
    timestamp: Date.now(),
  });
  saveTickets();
  renderTickets();
  renderChat(ticket);
}

function handleAdminSubmit(event) {
  event.preventDefault();
  const formData = new FormData(adminForm);
  const newType = formData.get("newType").trim();
  if (!newType || state.incidentTypes.includes(newType)) {
    return;
  }
  state.incidentTypes.push(newType);
  saveTypes();
  adminForm.reset();
  renderIncidentTypes();
}

renderIncidentTypes();
renderTickets();

if (state.tickets.length > 0) {
  selectTicket(state.tickets[0].id);
}

ticketForm.addEventListener("submit", handleTicketSubmit);
chatForm.addEventListener("submit", handleChatSubmit);
statusSelect.addEventListener("change", handleStatusChange);
adminForm.addEventListener("submit", handleAdminSubmit);
