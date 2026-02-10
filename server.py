from __future__ import annotations

import json
import os
import sqlite3
from datetime import datetime
from typing import Any, Dict

from flask import Flask, jsonify, request, send_from_directory

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "tickets.db")

app = Flask(__name__, static_folder=BASE_DIR, static_url_path="")


def get_db() -> sqlite3.Connection:
    connection = sqlite3.connect(DB_PATH)
    connection.row_factory = sqlite3.Row
    return connection


def init_db() -> None:
    with get_db() as connection:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS incident_types (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT UNIQUE NOT NULL
            )
            """
        )
        connection.execute(
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
        connection.execute(
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
        connection.commit()


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


def seed_incident_types() -> None:
    with get_db() as connection:
        existing = connection.execute("SELECT COUNT(*) as count FROM incident_types").fetchone()[
            "count"
        ]
        if existing:
            return
        connection.executemany(
            "INSERT INTO incident_types (name) VALUES (?)", [(name,) for name in DEFAULT_TYPES]
        )
        connection.commit()


def format_ticket_code(sequence: int, when: datetime | None = None) -> str:
    now = when or datetime.utcnow()
    return f"{now.month:02d}-{now.year}-{sequence:03d}"


def next_sequence(connection: sqlite3.Connection) -> int:
    now = datetime.utcnow()
    month_prefix = f"{now.month:02d}-{now.year}-"
    row = connection.execute(
        "SELECT ticket_code FROM tickets WHERE ticket_code LIKE ? ORDER BY id DESC LIMIT 1",
        (f"{month_prefix}%",),
    ).fetchone()
    if not row:
        return 1
    last_code = row["ticket_code"]
    try:
        sequence = int(last_code.split("-")[-1])
    except ValueError:
        return 1
    return sequence + 1


def serialize_ticket(row: sqlite3.Row) -> Dict[str, Any]:
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


def serialize_message(row: sqlite3.Row) -> Dict[str, Any]:
    return {
        "id": row["id"],
        "ticketId": row["ticket_id"],
        "author": row["author"],
        "message": row["message"],
        "timestamp": row["timestamp"],
    }


@app.route("/")
def index() -> Any:
    return send_from_directory(BASE_DIR, "index.html")


@app.route("/api/incident-types", methods=["GET", "POST"])
def incident_types() -> Any:
    if request.method == "GET":
        with get_db() as connection:
            rows = connection.execute("SELECT name FROM incident_types ORDER BY name").fetchall()
        return jsonify([row["name"] for row in rows])

    data = request.get_json(silent=True) or {}
    name = str(data.get("name", "")).strip()
    if not name:
        return jsonify({"error": "Incident type name is required."}), 400
    with get_db() as connection:
        try:
            connection.execute("INSERT INTO incident_types (name) VALUES (?)", (name,))
            connection.commit()
        except sqlite3.IntegrityError:
            return jsonify({"error": "Incident type already exists."}), 409
    return jsonify({"name": name}), 201


@app.route("/api/tickets", methods=["GET", "POST"])
def tickets() -> Any:
    if request.method == "GET":
        with get_db() as connection:
            rows = connection.execute("SELECT * FROM tickets ORDER BY created_at DESC").fetchall()
        return jsonify([serialize_ticket(row) for row in rows])

    data = request.get_json(silent=True) or {}
    required_fields = [
        "reportedDate",
        "reportedTime",
        "riskLevel",
        "summary",
        "incidentTypes",
        "sourceIp",
        "destinationIp",
        "details",
        "assignee",
    ]
    missing = [field for field in required_fields if not data.get(field)]
    if missing:
        return jsonify({"error": f"Missing fields: {', '.join(missing)}"}), 400

    now = datetime.utcnow()
    with get_db() as connection:
        sequence = next_sequence(connection)
        ticket_code = format_ticket_code(sequence, now)
        incident_types = json.dumps(data.get("incidentTypes", []))
        attachments = json.dumps(data.get("attachments", []))
        compromised = data.get("compromisedSystems")
        connection.execute(
            """
            INSERT INTO tickets (
                ticket_code,
                created_at,
                reported_date,
                reported_time,
                risk_level,
                summary,
                incident_types,
                source_ip,
                destination_ip,
                compromised_systems,
                details,
                attachments,
                assignee,
                status
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                ticket_code,
                now.isoformat(),
                data["reportedDate"],
                data["reportedTime"],
                data["riskLevel"],
                data["summary"],
                incident_types,
                data["sourceIp"],
                data["destinationIp"],
                compromised,
                data["details"],
                attachments,
                data["assignee"],
                "open",
            ),
        )
        ticket_id = connection.execute("SELECT last_insert_rowid() as id").fetchone()["id"]
        connection.execute(
            "INSERT INTO messages (ticket_id, author, message, timestamp) VALUES (?, ?, ?, ?)",
            (
                ticket_id,
                "System",
                f"Ticket created and routed to {data['assignee']}.",
                now.isoformat(),
            ),
        )
        connection.commit()
        ticket_row = connection.execute("SELECT * FROM tickets WHERE id = ?", (ticket_id,)).fetchone()
    return jsonify(serialize_ticket(ticket_row)), 201


@app.route("/api/tickets/<int:ticket_id>", methods=["GET", "PATCH"])
def ticket_detail(ticket_id: int) -> Any:
    with get_db() as connection:
        ticket_row = connection.execute("SELECT * FROM tickets WHERE id = ?", (ticket_id,)).fetchone()
        if not ticket_row:
            return jsonify({"error": "Ticket not found."}), 404

        if request.method == "GET":
            return jsonify(serialize_ticket(ticket_row))

        data = request.get_json(silent=True) or {}
        status = data.get("status")
        if not status:
            return jsonify({"error": "Status is required."}), 400
        connection.execute("UPDATE tickets SET status = ? WHERE id = ?", (status, ticket_id))
        connection.execute(
            "INSERT INTO messages (ticket_id, author, message, timestamp) VALUES (?, ?, ?, ?)",
            (
                ticket_id,
                "System",
                f"Status updated to {status.replace('_', ' ')}.",
                datetime.utcnow().isoformat(),
            ),
        )
        connection.commit()
        updated = connection.execute("SELECT * FROM tickets WHERE id = ?", (ticket_id,)).fetchone()
    return jsonify(serialize_ticket(updated))


@app.route("/api/tickets/<int:ticket_id>/messages", methods=["GET", "POST"])
def ticket_messages(ticket_id: int) -> Any:
    with get_db() as connection:
        ticket_row = connection.execute("SELECT id FROM tickets WHERE id = ?", (ticket_id,)).fetchone()
        if not ticket_row:
            return jsonify({"error": "Ticket not found."}), 404

        if request.method == "GET":
            rows = connection.execute(
                "SELECT * FROM messages WHERE ticket_id = ? ORDER BY timestamp ASC", (ticket_id,)
            ).fetchall()
            return jsonify([serialize_message(row) for row in rows])

        data = request.get_json(silent=True) or {}
        author = str(data.get("author", "")).strip()
        message = str(data.get("message", "")).strip()
        if not author or not message:
            return jsonify({"error": "Author and message are required."}), 400
        timestamp = datetime.utcnow().isoformat()
        connection.execute(
            "INSERT INTO messages (ticket_id, author, message, timestamp) VALUES (?, ?, ?, ?)",
            (ticket_id, author, message, timestamp),
        )
        connection.commit()
    return jsonify({"author": author, "message": message, "timestamp": timestamp}), 201


if __name__ == "__main__":
    init_db()
    seed_incident_types()
    app.run(host="0.0.0.0", port=8000, debug=False)
