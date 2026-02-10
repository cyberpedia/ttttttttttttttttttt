# Cyber Incident Ticketing System (Full Stack)

Production-style cyber incident ticketing system with:
- Ticket creation and auto ID format `MM-YYYY-###`
- Incident checklist + admin-configurable incident types
- Ticket lifecycle updates (open/in review/resolved/closed/reopened)
- Ticket thread chat
- **Private messages** between admins/moderators/supports and users/teams
- **Real-time notifications** via Server-Sent Events when tickets/messages/status updates/private messages occur

## Stack

- Front-end: HTML, CSS, Vanilla JavaScript
- Back-end: Python standard library (`http.server`)
- Database: SQLite
- Realtime: Server-Sent Events (SSE)

## Requirements

- Python 3.10+

## Run

```bash
python server.py
```

Open:

```text
http://127.0.0.1:8000/
```

## API highlights

- `GET/POST /api/incident-types`
- `GET/POST /api/tickets`
- `PATCH /api/tickets/{id}`
- `GET/POST /api/tickets/{id}/messages`
- `GET/POST /api/private-messages`
- `GET /api/stream` (SSE realtime events)

## Data

- SQLite database file: `tickets.db`

