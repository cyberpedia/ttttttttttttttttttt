# Cyber Incident Ticketing System

A production-style, full-stack prototype for cyber incident ticketing. The app includes structured ticket intake, admin-configurable incident type checklists, status tracking, and responder chat. Data is persisted in a local SQLite database for testing.

## Stack

- Front-end: HTML, CSS, Vanilla JS
- Back-end: Flask (Python)
- Database: SQLite

## Requirements

- Python 3.10+

## Setup

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Run locally

```bash
python server.py
```

Then open:

```
http://127.0.0.1:8000/
```

## Notes

- Data is stored in `tickets.db` in the project root.
- This demo supports creating, updating, and chatting on tickets with a single local user.

