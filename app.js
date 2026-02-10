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

const state = {
  tickets: [],
  incidentTypes: [],
  selectedTicketId: null,
};

async function requestJson(path, options = {}) {
  const response = await fetch(path, {
    headers: { "Content-Type": "application/json" },
    ...options,
  });
  if (!response.ok) {
    const error = await response.json().catch(() => ({}));
    throw new Error(error.error || "Request failed");
  }
  return response.json();
}

async function loadIncidentTypes() {
  state.incidentTypes = await requestJson("/api/incident-types");
  renderIncidentTypes();
}

async function loadTickets() {
  state.tickets = await requestJson("/api/tickets");
  renderTickets();
  if (state.tickets.length > 0) {
    selectTicket(state.tickets[0].id);
  }
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
    .sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt))
    .forEach((ticket) => {
      const card = document.createElement("article");
      card.className = "ticket-card";
      if (ticket.id === state.selectedTicketId) {
        card.classList.add("active");
      }
      card.innerHTML = `
        <div class="ticket-meta">
          <span>${ticket.ticketCode}</span>
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

function formatStatus(status) {
  return status.replace(/_/g, " ");
}

async function selectTicket(id) {
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

async function loadMessages(ticketId) {
  const messages = await requestJson(`/api/tickets/${ticketId}/messages`);
  renderChat(messages);
}

function renderChat(messages) {
  chatMessages.innerHTML = "";
  messages.forEach((entry) => {
    const message = document.createElement("div");
    message.className = "chat-message";
    message.innerHTML = `<strong>${entry.author} · ${new Date(entry.timestamp).toLocaleString()}</strong>${entry.message}`;
    chatMessages.appendChild(message);
  });
}

async function handleTicketSubmit(event) {
  event.preventDefault();
  const formData = new FormData(ticketForm);
  const incidentSelection = formData.getAll("incidentType");
  const other = formData.get("incidentOther").trim();
  const types = [...incidentSelection];
  if (other) {
    types.push(other);
  }

  const payload = {
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
  };

  const ticket = await requestJson("/api/tickets", {
    method: "POST",
    body: JSON.stringify(payload),
  });

  state.tickets.unshift(ticket);
  ticketForm.reset();
  renderTickets();
  await selectTicket(ticket.id);
}

async function handleChatSubmit(event) {
  event.preventDefault();
  const ticketId = state.selectedTicketId;
  if (!ticketId) {
    return;
  }
  const formData = new FormData(chatForm);
  await requestJson(`/api/tickets/${ticketId}/messages`, {
    method: "POST",
    body: JSON.stringify({
      author: formData.get("author"),
      message: formData.get("message"),
    }),
  });
  chatForm.reset();
  await loadMessages(ticketId);
}

async function handleStatusChange(event) {
  const ticketId = state.selectedTicketId;
  if (!ticketId) {
    return;
  }
  const updated = await requestJson(`/api/tickets/${ticketId}`, {
    method: "PATCH",
    body: JSON.stringify({ status: event.target.value }),
  });
  const index = state.tickets.findIndex((ticket) => ticket.id === ticketId);
  if (index >= 0) {
    state.tickets[index] = updated;
  }
  renderTickets();
  await loadMessages(ticketId);
}

async function handleAdminSubmit(event) {
  event.preventDefault();
  const formData = new FormData(adminForm);
  const newType = formData.get("newType").trim();
  if (!newType) {
    return;
  }
  try {
    await requestJson("/api/incident-types", {
      method: "POST",
      body: JSON.stringify({ name: newType }),
    });
    adminForm.reset();
    await loadIncidentTypes();
  } catch (error) {
    alert(error.message);
  }
}

async function init() {
  try {
    await loadIncidentTypes();
    await loadTickets();
  } catch (error) {
    ticketList.innerHTML = `<p class="empty-state">${error.message}</p>`;
  }
}

ticketForm.addEventListener("submit", handleTicketSubmit);
chatForm.addEventListener("submit", handleChatSubmit);
statusSelect.addEventListener("change", handleStatusChange);
adminForm.addEventListener("submit", handleAdminSubmit);

init();
