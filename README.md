# Cyber Incident Ticketing System (Front-End Demo)

A production-style, static front-end prototype for a cyber incident ticketing workflow. It supports ticket creation with structured incident details, configurable incident types, responder chat, and status changes. Data is stored locally in the browser for demo/testing.

## Requirements

- Python 3 (for a simple static server)

## Run locally

```bash
python -m http.server 8000
```

Then open:

```
http://127.0.0.1:8000/
```

## Notes

- This is a static front-end demo; it does not include a backend API.
- Tickets and incident types are persisted in `localStorage`.

