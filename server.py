from __future__ import annotations

import hashlib
import json
import os
import queue
import secrets
import threading
from datetime import datetime, timedelta
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

import psycopg
from psycopg.rows import dict_row

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://postgres:postgres@localhost:5432/cybertickets")

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


def db_conn():
    return psycopg.connect(DATABASE_URL, row_factory=dict_row)


def init_db() -> None:
    with db_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS users (
                    id SERIAL PRIMARY KEY,
                    username TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    role TEXT NOT NULL CHECK (role IN ('admin', 'moderator', 'support', 'user')),
                    role TEXT NOT NULL CHECK (role IN ('admin', 'user')),
                    created_at TIMESTAMP NOT NULL DEFAULT NOW()
                )
                """
            )
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS sessions (
                    token TEXT PRIMARY KEY,
                    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                    expires_at TIMESTAMP NOT NULL
                )
                """
            )
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS incident_types (
                    id SERIAL PRIMARY KEY,
                    name TEXT UNIQUE NOT NULL
                )
                """
            )
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS tickets (
                    id SERIAL PRIMARY KEY,
                    ticket_code TEXT UNIQUE NOT NULL,
                    created_at TIMESTAMP NOT NULL,
                    reported_date TEXT NOT NULL,
                    reported_time TEXT NOT NULL,
                    risk_level TEXT NOT NULL,
                    summary TEXT NOT NULL,
                    incident_types JSONB NOT NULL,
                    source_ip TEXT NOT NULL,
                    destination_ip TEXT NOT NULL,
                    compromised_systems TEXT,
                    details TEXT NOT NULL,
                    attachments JSONB NOT NULL,
                    assignee TEXT NOT NULL,
                    status TEXT NOT NULL,
                    created_by INTEGER REFERENCES users(id)
                )
                """
            )
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS messages (
                    id SERIAL PRIMARY KEY,
                    ticket_id INTEGER NOT NULL REFERENCES tickets(id) ON DELETE CASCADE,
                    author TEXT NOT NULL,
                    message TEXT NOT NULL,
                    timestamp TIMESTAMP NOT NULL
                )
                """
            )
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS private_messages (
                    id SERIAL PRIMARY KEY,
                    sender TEXT NOT NULL,
                    recipient TEXT NOT NULL,
                    target_type TEXT NOT NULL,
                    message TEXT NOT NULL,
                    attachments JSONB NOT NULL DEFAULT '[]'::jsonb,
                    timestamp TIMESTAMP NOT NULL
                )
                """
            )
            cur.execute(
                """
                ALTER TABLE private_messages
                ADD COLUMN IF NOT EXISTS attachments JSONB NOT NULL DEFAULT '[]'::jsonb
                """
            )
        conn.commit()


def hash_password(password: str) -> str:
    salt = secrets.token_hex(16)
    digest = hashlib.sha256((salt + password).encode("utf-8")).hexdigest()
    return f"{salt}${digest}"


def verify_password(password: str, stored: str) -> bool:
    salt, expected = stored.split("$", 1)
    digest = hashlib.sha256((salt + password).encode("utf-8")).hexdigest()
    return digest == expected


def seed_data() -> None:
    with db_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT COUNT(*) c FROM incident_types")
            if cur.fetchone()["c"] == 0:
                cur.executemany("INSERT INTO incident_types (name) VALUES (%s)", [(x,) for x in DEFAULT_TYPES])
            cur.execute("SELECT id FROM users WHERE username = %s", ("admin",))
            if not cur.fetchone():
                cur.execute(
                    "INSERT INTO users (username, password_hash, role) VALUES (%s, %s, 'admin')",
                    ("admin", hash_password("admin123")),
                )
            cur.execute("SELECT id FROM users WHERE username = %s", ("moderator",))
            if not cur.fetchone():
                cur.execute(
                    "INSERT INTO users (username, password_hash, role) VALUES (%s, %s, 'moderator')",
                    ("moderator", hash_password("moderator123")),
                )
            cur.execute("SELECT id FROM users WHERE username = %s", ("support",))
            if not cur.fetchone():
                cur.execute(
                    "INSERT INTO users (username, password_hash, role) VALUES (%s, %s, 'support')",
                    ("support", hash_password("support123")),
                )
            cur.execute("SELECT id FROM users WHERE username = %s", ("user",))
            if not cur.fetchone():
                cur.execute(
                    "INSERT INTO users (username, password_hash, role) VALUES (%s, %s, 'user')",
                    ("user", hash_password("user123")),
                )
        conn.commit()


def event_publish(event_type: str, payload: dict) -> None:
    event = {"type": event_type, "payload": payload, "timestamp": now_iso()}
    with clients_lock:
        for q in clients[:]:
            try:
                q.put_nowait(event)
            except Exception:
                clients.remove(q)


def parse_body(handler: BaseHTTPRequestHandler) -> dict:
    length = int(handler.headers.get("Content-Length", "0"))
    raw = handler.rfile.read(length) if length > 0 else b"{}"
    try:
        return json.loads(raw.decode("utf-8") or "{}")
    except json.JSONDecodeError:
        return {}


def json_send(handler: BaseHTTPRequestHandler, payload: object, status: int = 200) -> None:
    data = json.dumps(payload, default=str).encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json; charset=utf-8")
    handler.send_header("Content-Length", str(len(data)))
    handler.end_headers()
    handler.wfile.write(data)


def serialize_ticket(row: dict) -> dict:
    return {
        "id": row["id"],
        "ticketCode": row["ticket_code"],
        "createdAt": row["created_at"].isoformat(),
        "reportedDate": row["reported_date"],
        "reportedTime": row["reported_time"],
        "riskLevel": row["risk_level"],
        "summary": row["summary"],
        "incidentTypes": row["incident_types"],
        "sourceIp": row["source_ip"],
        "destinationIp": row["destination_ip"],
        "compromisedSystems": row["compromised_systems"],
        "details": row["details"],
        "attachments": row["attachments"],
        "assignee": row["assignee"],
        "status": row["status"],
    }


def auth_user(handler: BaseHTTPRequestHandler):
    auth = handler.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return None
    token = auth.removeprefix("Bearer ").strip()
    with db_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT u.id, u.username, u.role
                FROM sessions s
                JOIN users u ON u.id = s.user_id
                WHERE s.token = %s AND s.expires_at > NOW()
                """,
                (token,),
            )
            row = cur.fetchone()
    return row


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path

        if path == "/api/stream":
            return self.handle_stream()
        if path == "/api/auth/me":
            return self.handle_auth_me()
        if path == "/api/dashboard":
            return self.handle_dashboard()
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

    def do_POST(self):
        path = urlparse(self.path).path

        if path == "/api/auth/login":
            return self.handle_auth_login()
        if path == "/api/auth/register":
            return self.handle_auth_register()
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

    def do_PATCH(self):
        path = urlparse(self.path).path
        if path.startswith("/api/tickets/"):
            ticket_id = self.extract_ticket_id(path)
            if ticket_id is None:
                return json_send(self, {"error": "Invalid ticket id."}, 400)
            return self.handle_patch_ticket(ticket_id)
        return json_send(self, {"error": "Not found."}, 404)

    def log_message(self, fmt, *args):
        return

    def extract_ticket_id(self, path: str):
        parts = path.strip("/").split("/")
        if len(parts) < 3:
            return None
        try:
            return int(parts[2])
        except ValueError:
            return None

    def serve_static(self, path: str):
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

    def handle_auth_register(self):
        data = parse_body(self)
        username = str(data.get("username", "")).strip()
        password = str(data.get("password", "")).strip()
        role = str(data.get("role", "user")).strip()
        if role not in ["admin", "moderator", "support", "user"]:
        if role not in ["admin", "user"]:
            return json_send(self, {"error": "Invalid role."}, 400)
        if not username or not password:
            return json_send(self, {"error": "username and password are required."}, 400)
        with db_conn() as conn:
            with conn.cursor() as cur:
                try:
                    cur.execute(
                        "INSERT INTO users (username, password_hash, role) VALUES (%s, %s, %s)",
                        (username, hash_password(password), role),
                    )
                except psycopg.errors.UniqueViolation:
                    conn.rollback()
                    return json_send(self, {"error": "Username already exists."}, 409)
            conn.commit()
        return json_send(self, {"message": "Registered."}, 201)

    def handle_auth_login(self):
        data = parse_body(self)
        username = str(data.get("username", "")).strip()
        password = str(data.get("password", "")).strip()
        expected_role = str(data.get("role", "")).strip()
        with db_conn() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT id, username, password_hash, role FROM users WHERE username = %s", (username,))
                user = cur.fetchone()
                if not user or not verify_password(password, user["password_hash"]):
                    return json_send(self, {"error": "Invalid credentials."}, 401)
                if expected_role and user["role"] != expected_role:
                    return json_send(self, {"error": f"Use {user['role']} login page for this account."}, 403)
                token = secrets.token_urlsafe(32)
                expiry = datetime.utcnow() + timedelta(hours=12)
                cur.execute("INSERT INTO sessions (token, user_id, expires_at) VALUES (%s, %s, %s)", (token, user["id"], expiry))
            conn.commit()
        return json_send(self, {"token": token, "user": {"id": user["id"], "username": user["username"], "role": user["role"]}})

    def handle_auth_me(self):
        user = auth_user(self)
        if not user:
            return json_send(self, {"error": "Unauthorized."}, 401)
        return json_send(self, {"id": user["id"], "username": user["username"], "role": user["role"]})

    def handle_get_incident_types(self):
        with db_conn() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT name FROM incident_types ORDER BY name")
                rows = cur.fetchall()
        json_send(self, [r["name"] for r in rows])

    def handle_post_incident_types(self):
        user = auth_user(self)
        if not user or user["role"] not in {"admin", "moderator", "support"}:
        if not user or user["role"] != "admin":
            return json_send(self, {"error": "Admin authorization required."}, 403)
        data = parse_body(self)
        name = str(data.get("name", "")).strip()
        if not name:
            return json_send(self, {"error": "Incident type name is required."}, 400)
        with db_conn() as conn:
            with conn.cursor() as cur:
                try:
                    cur.execute("INSERT INTO incident_types (name) VALUES (%s)", (name,))
                except psycopg.errors.UniqueViolation:
                    conn.rollback()
                    return json_send(self, {"error": "Incident type already exists."}, 409)
            conn.commit()
        event_publish("incident_type_created", {"name": name})
        json_send(self, {"name": name}, 201)

    def handle_get_tickets(self):
        user = auth_user(self)
        if not user:
            return json_send(self, {"error": "Unauthorized."}, 401)
        with db_conn() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT * FROM tickets ORDER BY created_at DESC")
                rows = cur.fetchall()
        json_send(self, [serialize_ticket(r) for r in rows])

    def _next_ticket_code(self, cur) -> str:
        now = datetime.utcnow()
        prefix = f"{now.month:02d}-{now.year}-"
        cur.execute("SELECT ticket_code FROM tickets WHERE ticket_code LIKE %s ORDER BY id DESC LIMIT 1", (f"{prefix}%",))
        row = cur.fetchone()
        seq = 1
        if row:
            try:
                seq = int(row["ticket_code"].split("-")[-1]) + 1
            except ValueError:
                seq = 1
        return f"{prefix}{seq:03d}"

    def handle_post_tickets(self):
        user = auth_user(self)
        if not user:
            return json_send(self, {"error": "Unauthorized."}, 401)
        data = parse_body(self)
        required = ["reportedDate", "reportedTime", "riskLevel", "summary", "incidentTypes", "sourceIp", "destinationIp", "details", "assignee"]
        missing = [x for x in required if not data.get(x)]
        if missing:
            return json_send(self, {"error": f"Missing fields: {', '.join(missing)}"}, 400)

        with db_conn() as conn:
            with conn.cursor() as cur:
                ticket_code = self._next_ticket_code(cur)
                created_at = datetime.utcnow()
                cur.execute(
                    """
                    INSERT INTO tickets (
                        ticket_code, created_at, reported_date, reported_time, risk_level, summary,
                        incident_types, source_ip, destination_ip, compromised_systems, details,
                        attachments, assignee, status, created_by
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s::jsonb, %s, %s, %s, %s, %s::jsonb, %s, %s, %s)
                    RETURNING id
                    """,
                    (
                        ticket_code,
                        created_at,
                        data["reportedDate"],
                        data["reportedTime"],
                        data["riskLevel"],
                        data["summary"],
                        json.dumps(data.get("incidentTypes", [])),
                        data["sourceIp"],
                        data["destinationIp"],
                        data.get("compromisedSystems", ""),
                        data["details"],
                        json.dumps(data.get("attachments", [])),
                        data["assignee"],
                        "open",
                        user["id"],
                    ),
                )
                ticket_id = cur.fetchone()["id"]
                cur.execute(
                    "INSERT INTO messages (ticket_id, author, message, timestamp) VALUES (%s, %s, %s, %s)",
                    (ticket_id, "System", f"Ticket created and routed to {data['assignee']}.", created_at),
                )
                cur.execute("SELECT * FROM tickets WHERE id = %s", (ticket_id,))
                row = cur.fetchone()
            conn.commit()

        ticket = serialize_ticket(row)
        event_publish("ticket_created", ticket)
        json_send(self, ticket, 201)

    def handle_patch_ticket(self, ticket_id: int):
        user = auth_user(self)
        if not user:
            return json_send(self, {"error": "Unauthorized."}, 401)
        data = parse_body(self)
        status = str(data.get("status", "")).strip()
        if not status:
            return json_send(self, {"error": "Status is required."}, 400)
        with db_conn() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT * FROM tickets WHERE id = %s", (ticket_id,))
                row = cur.fetchone()
                if not row:
                    return json_send(self, {"error": "Ticket not found."}, 404)
                cur.execute("UPDATE tickets SET status = %s WHERE id = %s", (status, ticket_id))
                cur.execute(
                    "INSERT INTO messages (ticket_id, author, message, timestamp) VALUES (%s, %s, %s, %s)",
                    (ticket_id, "System", f"Status updated to {status.replace('_', ' ')}.", datetime.utcnow()),
                )
                cur.execute("SELECT * FROM tickets WHERE id = %s", (ticket_id,))
                updated = cur.fetchone()
            conn.commit()
        payload = serialize_ticket(updated)
        event_publish("ticket_status_changed", payload)
        json_send(self, payload)

    def handle_get_ticket_messages(self, ticket_id: int):
        user = auth_user(self)
        if not user:
            return json_send(self, {"error": "Unauthorized."}, 401)
        with db_conn() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT id FROM tickets WHERE id = %s", (ticket_id,))
                if not cur.fetchone():
                    return json_send(self, {"error": "Ticket not found."}, 404)
                cur.execute("SELECT * FROM messages WHERE ticket_id = %s ORDER BY timestamp ASC", (ticket_id,))
                rows = cur.fetchall()
        json_send(self, [{"id": r["id"], "ticketId": r["ticket_id"], "author": r["author"], "message": r["message"], "timestamp": r["timestamp"].isoformat()} for r in rows])

    def handle_post_ticket_messages(self, ticket_id: int):
        user = auth_user(self)
        if not user:
            return json_send(self, {"error": "Unauthorized."}, 401)
        data = parse_body(self)
        author = str(data.get("author", "")).strip()
        message = str(data.get("message", "")).strip()
        if not author or not message:
            return json_send(self, {"error": "Author and message are required."}, 400)
        timestamp = datetime.utcnow()
        with db_conn() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT id FROM tickets WHERE id = %s", (ticket_id,))
                if not cur.fetchone():
                    return json_send(self, {"error": "Ticket not found."}, 404)
                cur.execute(
                    "INSERT INTO messages (ticket_id, author, message, timestamp) VALUES (%s, %s, %s, %s) RETURNING id",
                    (ticket_id, author, message, timestamp),
                )
                message_id = cur.fetchone()["id"]
            conn.commit()
        payload = {"id": message_id, "ticketId": ticket_id, "author": author, "message": message, "timestamp": timestamp.isoformat()}
        event_publish("ticket_message_created", payload)
        json_send(self, payload, 201)

    def handle_get_private_messages(self, query: str):
        user = auth_user(self)
        if not user:
            return json_send(self, {"error": "Unauthorized."}, 401)
        params = parse_qs(query)
        me = (params.get("me") or [""])[0].strip()
        peer = (params.get("peer") or [""])[0].strip()
        if not me or not peer:
            return json_send(self, {"error": "me and peer query params are required."}, 400)
        with db_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT * FROM private_messages
                    WHERE (sender = %s AND recipient = %s) OR (sender = %s AND recipient = %s)
                    ORDER BY timestamp ASC
                    """,
                    (me, peer, peer, me),
                )
                rows = cur.fetchall()
        json_send(self, [
            {
                "id": r["id"],
                "sender": r["sender"],
                "recipient": r["recipient"],
                "targetType": r["target_type"],
                "message": r["message"],
                "attachments": r.get("attachments") or [],
                "timestamp": r["timestamp"].isoformat(),
            }
            for r in rows
        ])
        json_send(self, [{**r, "timestamp": r["timestamp"].isoformat()} for r in rows])

    def handle_post_private_message(self):
        user = auth_user(self)
        if not user:
            return json_send(self, {"error": "Unauthorized."}, 401)
        data = parse_body(self)
        sender = str(data.get("sender", "")).strip()
        recipient = str(data.get("recipient", "")).strip()
        target_type = str(data.get("targetType", "user")).strip() or "user"
        message = str(data.get("message", "")).strip()
        attachments = data.get("attachments", [])
        if not isinstance(attachments, list):
            attachments = []
        attachments = [str(name).strip() for name in attachments if str(name).strip()]
        if not sender or not recipient or (not message and not attachments):
            return json_send(self, {"error": "sender, recipient, and either message or attachments are required."}, 400)
        if not sender or not recipient or not message:
            return json_send(self, {"error": "sender, recipient, and message are required."}, 400)

        timestamp = datetime.utcnow()
        with db_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO private_messages (sender, recipient, target_type, message, attachments, timestamp)
                    VALUES (%s, %s, %s, %s, %s::jsonb, %s) RETURNING id
                    """,
                    (sender, recipient, target_type, message, json.dumps(attachments), timestamp),
                )
                msg_id = cur.fetchone()["id"]
            conn.commit()
        payload = {
            "id": msg_id,
            "sender": sender,
            "recipient": recipient,
            "targetType": target_type,
            "message": message,
            "attachments": attachments,
            "timestamp": timestamp.isoformat(),
        }
                    INSERT INTO private_messages (sender, recipient, target_type, message, timestamp)
                    VALUES (%s, %s, %s, %s, %s) RETURNING id
                    """,
                    (sender, recipient, target_type, message, timestamp),
                )
                msg_id = cur.fetchone()["id"]
            conn.commit()
        payload = {"id": msg_id, "sender": sender, "recipient": recipient, "targetType": target_type, "message": message, "timestamp": timestamp.isoformat()}
        event_publish("private_message_created", payload)
        json_send(self, payload, 201)

    def handle_stream(self):
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

    def handle_dashboard(self):
        user = auth_user(self)
        if not user:
            return json_send(self, {"error": "Unauthorized."}, 401)

        with db_conn() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT COUNT(*) c FROM tickets")
                total_tickets = cur.fetchone()["c"]
                cur.execute("SELECT COUNT(*) c FROM tickets WHERE status IN ('open','in_review','reopened')")
                open_tickets = cur.fetchone()["c"]
                cur.execute("SELECT COUNT(*) c FROM tickets WHERE status IN ('resolved','closed')")
                closed_tickets = cur.fetchone()["c"]
                cur.execute("SELECT COUNT(*) c FROM private_messages")
                total_pms = cur.fetchone()["c"]
                cur.execute("SELECT ticket_code, summary, risk_level, status, assignee FROM tickets ORDER BY created_at DESC LIMIT 8")
                recent = cur.fetchall()

        role = user["role"]
        queue = [dict(x) for x in recent if (role in {"admin", "moderator", "support"} or x["assignee"] == user["username"])]
        payload = {
            "role": role,
            "metrics": {
                "totalTickets": total_tickets,
                "activeTickets": open_tickets,
                "resolvedTickets": closed_tickets,
                "totalPrivateMessages": total_pms,
            },
            "queue": queue,
            "permissions": {
                "canManageIncidentTypes": role in {"admin", "moderator", "support"},
                "canModerate": role in {"admin", "moderator"},
                "canSupport": role in {"admin", "support"},
            },
        }
        json_send(self, payload)


def run() -> None:
    init_db()
    seed_data()
    server = ThreadingHTTPServer(("0.0.0.0", 8000), Handler)
    print("Server running on http://0.0.0.0:8000")
    print("Default accounts: admin/admin123, moderator/moderator123, support/support123, user/user123")
    print("Default accounts: admin/admin123 and user/user123")
    print(f"Database: {DATABASE_URL}")
    server.serve_forever()


if __name__ == "__main__":
    run()
