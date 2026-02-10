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
