# Cyber Incident Ticketing System (PostgreSQL + Realtime + Role Dashboards)

A full-featured SOC ticketing platform prototype with role-based panels for:
- **Admin**
- **Moderator**
- **Support**
- **User/Team**

## Core capabilities

- Login + session auth (Bearer token)
- Separate staff/user login pages
- User self-registration
- Role-aware dashboard panel with operational metrics
- Ticket creation with structured incident form
- Incident type management (staff roles)
- Ticket chat and lifecycle updates
- Private messaging (staff ↔ users/teams)
# Cyber Incident Ticketing System (PostgreSQL + Realtime)

This implementation is full-stack with:
- PostgreSQL database (requested)
- Admin and user login pages
- Ticket creation / lifecycle / chat
- Admin configurable incident types
- Private messaging (admin/mod/support ↔ users/teams)
- Realtime notifications via SSE

## Login pages

- Staff login: `/admin-login.html`
- User login/register: `/user-login.html`

## Seeded accounts

- admin / admin123
- moderator / moderator123
- support / support123
- Admin login: `/admin-login.html`
- User login: `/user-login.html`

Default seeded accounts:
- admin / admin123
- user / user123

## Requirements

- Python 3.10+
- PostgreSQL 13+

## Configure DB
## Configure database

Set `DATABASE_URL` (or use default):

```bash
export DATABASE_URL='postgresql://postgres:postgres@localhost:5432/cybertickets'
```

## Install

```bash
python -m pip install -r requirements.txt
```

## Run

```bash
python server.py
```

Open:

```text
http://127.0.0.1:8000/user-login.html
```
