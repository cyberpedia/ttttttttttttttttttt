# Cyber Incident Ticketing System (PostgreSQL + Realtime)

This implementation is full-stack with:
- PostgreSQL database (requested)
- Admin and user login pages
- Ticket creation / lifecycle / chat
- Admin configurable incident types
- Private messaging (admin/mod/support ↔ users/teams)
- Realtime notifications via SSE

## Login pages

- Admin login: `/admin-login.html`
- User login: `/user-login.html`

Default seeded accounts:
- admin / admin123
- user / user123

## Requirements

- Python 3.10+
- PostgreSQL 13+

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
