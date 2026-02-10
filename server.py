from __future__ import annotations

import json
import os
import queue
import sqlite3
import threading
from datetime import datetime
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "tickets.db")

MIME_TYPES = {
    ".html": "text/html; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".js": "application/javascript; charset=utf-8",
    ".png": "image/png",
    ".jpg": "image/jpeg",
    ".jpeg": "image/jpeg",
    ".svg": "image/svg+xml",
}

DEFAULT_TYPES = [
    "Intrusion",
    "DDoS",
    "Malware",
    "Phishing",
    "Ransomware",
    "Data Exfiltration",
    "Account Takeover",
    "Insider Threat",
]

clients_lock = threading.Lock()
clients: list[queue.Queue] = []


def now_iso() -> str:
    return datetime.utcnow().isoformat()


def get_db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    with get_db() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS incident_types (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT UNIQUE NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS tickets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ticket_code TEXT UNIQUE NOT NULL,
                created_at TEXT NOT NULL,
                reported_date TEXT NOT NULL,
                reported_time TEXT NOT NULL,
                risk_level TEXT NOT NULL,
                summary TEXT NOT NULL,
                incident_types TEXT NOT NULL,
                source_ip TEXT NOT NULL,
                destination_ip TEXT NOT NULL,
                compromised_systems TEXT,
                details TEXT NOT NULL,
                attachments TEXT NOT NULL,
                assignee TEXT NOT NULL,
                status TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ticket_id INTEGER NOT NULL,
                author TEXT NOT NULL,
                message TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                FOREIGN KEY(ticket_id) REFERENCES tickets(id)
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS private_messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                sender TEXT NOT NULL,
                recipient TEXT NOT NULL,
                target_type TEXT NOT NULL,
                message TEXT NOT NULL,
                timestamp TEXT NOT NULL
            )
            """
        )
        conn.commit()


def seed_incident_types() -> None:
    with get_db() as conn:
        count = conn.execute("SELECT COUNT(*) c FROM incident_types").fetchone()["c"]
        if count == 0:
            conn.executemany("INSERT INTO incident_types (name) VALUES (?)", [(x,) for x in DEFAULT_TYPES])
            conn.commit()


def event_publish(event_type: str, payload: dict) -> None:
    event = {"type": event_type, "payload": payload, "timestamp": now_iso()}
    with clients_lock:
        stale = []
        for q in clients:
            try:
                q.put_nowait(event)
            except Exception:
                stale.append(q)
        for q in stale:
            if q in clients:
                clients.remove(q)


def parse_body(handler: BaseHTTPRequestHandler) -> dict:
    length = int(handler.headers.get("Content-Length", "0"))
    raw = handler.rfile.read(length) if length > 0 else b"{}"
    try:
        return json.loads(raw.decode("utf-8") or "{}")
    except json.JSONDecodeError:
        return {}


def json_send(handler: BaseHTTPRequestHandler, payload: object, status: int = 200) -> None:
    data = json.dumps(payload).encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json; charset=utf-8")
    handler.send_header("Content-Length", str(len(data)))
    handler.end_headers()
    handler.wfile.write(data)


def serialize_ticket(row: sqlite3.Row) -> dict:
    return {
        "id": row["id"],
        "ticketCode": row["ticket_code"],
        "createdAt": row["created_at"],
        "reportedDate": row["reported_date"],
        "reportedTime": row["reported_time"],
        "riskLevel": row["risk_level"],
        "summary": row["summary"],
        "incidentTypes": json.loads(row["incident_types"]),
        "sourceIp": row["source_ip"],
        "destinationIp": row["destination_ip"],
        "compromisedSystems": row["compromised_systems"],
        "details": row["details"],
        "attachments": json.loads(row["attachments"]),
        "assignee": row["assignee"],
        "status": row["status"],
    }


def serialize_message(row: sqlite3.Row) -> dict:
    return {
        "id": row["id"],
        "ticketId": row["ticket_id"],
        "author": row["author"],
        "message": row["message"],
        "timestamp": row["timestamp"],
    }


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        path = parsed.path

        if path == "/api/stream":
            return self.handle_stream()
        if path == "/api/incident-types":
            return self.handle_get_incident_types()
        if path == "/api/tickets":
            return self.handle_get_tickets()
        if path.startswith("/api/tickets/") and path.endswith("/messages"):
            ticket_id = self.extract_ticket_id(path)
            if ticket_id is None:
                return json_send(self, {"error": "Invalid ticket id."}, 400)
            return self.handle_get_ticket_messages(ticket_id)
        if path == "/api/private-messages":
            return self.handle_get_private_messages(parsed.query)

        return self.serve_static(path)

    def do_POST(self) -> None:
        parsed = urlparse(self.path)
        path = parsed.path

        if path == "/api/incident-types":
            return self.handle_post_incident_types()
        if path == "/api/tickets":
            return self.handle_post_tickets()
        if path.startswith("/api/tickets/") and path.endswith("/messages"):
            ticket_id = self.extract_ticket_id(path)
            if ticket_id is None:
                return json_send(self, {"error": "Invalid ticket id."}, 400)
            return self.handle_post_ticket_messages(ticket_id)
        if path == "/api/private-messages":
            return self.handle_post_private_message()

        return json_send(self, {"error": "Not found."}, 404)

    def do_PATCH(self) -> None:
        path = urlparse(self.path).path
        if path.startswith("/api/tickets/"):
            ticket_id = self.extract_ticket_id(path)
            if ticket_id is None:
                return json_send(self, {"error": "Invalid ticket id."}, 400)
            return self.handle_patch_ticket(ticket_id)
        return json_send(self, {"error": "Not found."}, 404)

    def log_message(self, format: str, *args) -> None:
        return

    def extract_ticket_id(self, path: str) -> int | None:
        parts = path.strip("/").split("/")
        if len(parts) < 3:
            return None
        try:
            return int(parts[2])
        except ValueError:
            return None

    def serve_static(self, path: str) -> None:
        route = "index.html" if path in ["/", ""] else path.lstrip("/")
        file_path = os.path.join(BASE_DIR, route)
        if not os.path.isfile(file_path):
            return json_send(self, {"error": "Not found."}, 404)
        ext = os.path.splitext(file_path)[1].lower()
        mime = MIME_TYPES.get(ext, "application/octet-stream")
        with open(file_path, "rb") as f:
            data = f.read()
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", mime)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def handle_get_incident_types(self) -> None:
        with get_db() as conn:
            rows = conn.execute("SELECT name FROM incident_types ORDER BY name").fetchall()
        json_send(self, [r["name"] for r in rows])

    def handle_post_incident_types(self) -> None:
        data = parse_body(self)
        name = str(data.get("name", "")).strip()
        if not name:
            return json_send(self, {"error": "Incident type name is required."}, 400)
        with get_db() as conn:
            try:
                conn.execute("INSERT INTO incident_types (name) VALUES (?)", (name,))
                conn.commit()
            except sqlite3.IntegrityError:
                return json_send(self, {"error": "Incident type already exists."}, 409)
        event_publish("incident_type_created", {"name": name})
        json_send(self, {"name": name}, 201)

    def handle_get_tickets(self) -> None:
        with get_db() as conn:
            rows = conn.execute("SELECT * FROM tickets ORDER BY created_at DESC").fetchall()
        json_send(self, [serialize_ticket(r) for r in rows])

    def _next_ticket_code(self, conn: sqlite3.Connection) -> str:
        now = datetime.utcnow()
        prefix = f"{now.month:02d}-{now.year}-"
        row = conn.execute(
            "SELECT ticket_code FROM tickets WHERE ticket_code LIKE ? ORDER BY id DESC LIMIT 1",
            (f"{prefix}%",),
        ).fetchone()
        seq = 1
        if row:
            try:
                seq = int(row["ticket_code"].split("-")[-1]) + 1
            except ValueError:
                seq = 1
        return f"{prefix}{seq:03d}"

    def handle_post_tickets(self) -> None:
        data = parse_body(self)
        required = [
            "reportedDate", "reportedTime", "riskLevel", "summary", "incidentTypes",
            "sourceIp", "destinationIp", "details", "assignee"
        ]
        missing = [x for x in required if not data.get(x)]
        if missing:
            return json_send(self, {"error": f"Missing fields: {', '.join(missing)}"}, 400)
        with get_db() as conn:
            ticket_code = self._next_ticket_code(conn)
            created_at = now_iso()
            conn.execute(
                """
                INSERT INTO tickets (
                    ticket_code, created_at, reported_date, reported_time, risk_level, summary,
                    incident_types, source_ip, destination_ip, compromised_systems, details,
                    attachments, assignee, status
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    ticket_code, created_at, data["reportedDate"], data["reportedTime"], data["riskLevel"],
                    data["summary"], json.dumps(data.get("incidentTypes", [])), data["sourceIp"],
                    data["destinationIp"], data.get("compromisedSystems", ""), data["details"],
                    json.dumps(data.get("attachments", [])), data["assignee"], "open"
                ),
            )
            ticket_id = conn.execute("SELECT last_insert_rowid() i").fetchone()["i"]
            conn.execute(
                "INSERT INTO messages (ticket_id, author, message, timestamp) VALUES (?, ?, ?, ?)",
                (ticket_id, "System", f"Ticket created and routed to {data['assignee']}.", created_at),
            )
            conn.commit()
            row = conn.execute("SELECT * FROM tickets WHERE id = ?", (ticket_id,)).fetchone()
        ticket = serialize_ticket(row)
        event_publish("ticket_created", ticket)
        json_send(self, ticket, 201)

    def handle_patch_ticket(self, ticket_id: int) -> None:
        data = parse_body(self)
        status = str(data.get("status", "")).strip()
        if not status:
            return json_send(self, {"error": "Status is required."}, 400)
        with get_db() as conn:
            row = conn.execute("SELECT * FROM tickets WHERE id = ?", (ticket_id,)).fetchone()
            if not row:
                return json_send(self, {"error": "Ticket not found."}, 404)
            conn.execute("UPDATE tickets SET status = ? WHERE id = ?", (status, ticket_id))
            conn.execute(
                "INSERT INTO messages (ticket_id, author, message, timestamp) VALUES (?, ?, ?, ?)",
                (ticket_id, "System", f"Status updated to {status.replace('_', ' ')}.", now_iso()),
            )
            conn.commit()
            updated = conn.execute("SELECT * FROM tickets WHERE id = ?", (ticket_id,)).fetchone()
        payload = serialize_ticket(updated)
        event_publish("ticket_status_changed", payload)
        json_send(self, payload)

    def handle_get_ticket_messages(self, ticket_id: int) -> None:
        with get_db() as conn:
            ticket = conn.execute("SELECT id FROM tickets WHERE id = ?", (ticket_id,)).fetchone()
            if not ticket:
                return json_send(self, {"error": "Ticket not found."}, 404)
            rows = conn.execute(
                "SELECT * FROM messages WHERE ticket_id = ? ORDER BY timestamp ASC", (ticket_id,)
            ).fetchall()
        json_send(self, [serialize_message(r) for r in rows])

    def handle_post_ticket_messages(self, ticket_id: int) -> None:
        data = parse_body(self)
        author = str(data.get("author", "")).strip()
        message = str(data.get("message", "")).strip()
        if not author or not message:
            return json_send(self, {"error": "Author and message are required."}, 400)
        with get_db() as conn:
            ticket = conn.execute("SELECT id FROM tickets WHERE id = ?", (ticket_id,)).fetchone()
            if not ticket:
                return json_send(self, {"error": "Ticket not found."}, 404)
            timestamp = now_iso()
            conn.execute(
                "INSERT INTO messages (ticket_id, author, message, timestamp) VALUES (?, ?, ?, ?)",
                (ticket_id, author, message, timestamp),
            )
            message_id = conn.execute("SELECT last_insert_rowid() i").fetchone()["i"]
            conn.commit()
        payload = {"id": message_id, "ticketId": ticket_id, "author": author, "message": message, "timestamp": timestamp}
        event_publish("ticket_message_created", payload)
        json_send(self, payload, 201)

    def handle_get_private_messages(self, query: str) -> None:
        params = parse_qs(query)
        me = (params.get("me") or [""])[0].strip()
        peer = (params.get("peer") or [""])[0].strip()
        if not me or not peer:
            return json_send(self, {"error": "me and peer query params are required."}, 400)
        with get_db() as conn:
            rows = conn.execute(
                """
                SELECT * FROM private_messages
                WHERE (sender = ? AND recipient = ?) OR (sender = ? AND recipient = ?)
                ORDER BY timestamp ASC
                """,
                (me, peer, peer, me),
            ).fetchall()
        json_send(self, [dict(r) for r in rows])

    def handle_post_private_message(self) -> None:
        data = parse_body(self)
        sender = str(data.get("sender", "")).strip()
        recipient = str(data.get("recipient", "")).strip()
        target_type = str(data.get("targetType", "user")).strip() or "user"
        message = str(data.get("message", "")).strip()
        if not sender or not recipient or not message:
            return json_send(self, {"error": "sender, recipient, and message are required."}, 400)
        timestamp = now_iso()
        with get_db() as conn:
            conn.execute(
                "INSERT INTO private_messages (sender, recipient, target_type, message, timestamp) VALUES (?, ?, ?, ?, ?)",
                (sender, recipient, target_type, message, timestamp),
            )
            msg_id = conn.execute("SELECT last_insert_rowid() i").fetchone()["i"]
            conn.commit()
        payload = {"id": msg_id, "sender": sender, "recipient": recipient, "targetType": target_type, "message": message, "timestamp": timestamp}
        event_publish("private_message_created", payload)
        json_send(self, payload, 201)

    def handle_stream(self) -> None:
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "keep-alive")
        self.end_headers()

        q: queue.Queue = queue.Queue()
        with clients_lock:
            clients.append(q)

        try:
            self.wfile.write(b": connected\n\n")
            self.wfile.flush()
            while True:
                try:
                    event = q.get(timeout=20)
                    chunk = f"event: {event['type']}\ndata: {json.dumps(event)}\n\n".encode("utf-8")
                    self.wfile.write(chunk)
                    self.wfile.flush()
                except queue.Empty:
                    self.wfile.write(b": ping\n\n")
                    self.wfile.flush()
        except (ConnectionResetError, BrokenPipeError):
            pass
        finally:
            with clients_lock:
                if q in clients:
                    clients.remove(q)


def run() -> None:
    init_db()
    seed_incident_types()
    server = ThreadingHTTPServer(("0.0.0.0", 8000), Handler)
    print("Server running on http://0.0.0.0:8000")
    server.serve_forever()


if __name__ == "__main__":
    run()
