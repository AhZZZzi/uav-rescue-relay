"""
Relay server for the UAV rescue system.

Connects three kinds of clients:

  - PATIENT clients (web_app/patient): send rescue requests over
    WebSocket at /ws/patient. Each request is stored in SQLite so it
    survives even if no staff dashboard happens to be open yet, and
    even if the server process restarts (e.g. Render's free tier
    putting the service to sleep and waking it back up).

  - STAFF clients (web_app/staff): read pending requests via REST
    (GET /requests), and get a live WebSocket feed at /ws/staff for
    new requests and drone telemetry as they happen.

  - DRONE clients (the ROS2 bridge on the laptop): send telemetry and
    receive dispatch commands over WebSocket at /ws/drone.

All three only ever make OUTBOUND connections to this server, so none
of them need a public IP, port forwarding, or firewall changes. This
is the standard "relay" pattern for controlling something remotely.

Storage: SQLite file (relay.db), created automatically on first run.
Note: on Render's free tier, the filesystem persists across the
service sleeping/waking, but NOT across a fresh deploy (new code push)
unless you attach a persistent disk (paid feature). Good enough for
the pre-thesis stage; revisit before any production use.
"""

import hashlib
import json
import secrets
import sqlite3
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Set, Dict, Optional
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, Header
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import uvicorn

DB_PATH = "relay.db"

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


# ---------- Database setup ----------

@contextmanager
def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init_db():
    with get_db() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                username TEXT PRIMARY KEY,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS requests (
                id TEXT PRIMARY KEY,
                status TEXT NOT NULL,
                lat REAL,
                lon REAL,
                address TEXT,
                notes TEXT,
                received_at TEXT NOT NULL,
                dispatched_at TEXT,
                completed_at TEXT
            )
        """)
        # Migration: add address column if it doesn't exist yet
        # (handles the case where relay.db was created before this column was added)
        cols = [row["name"] for row in conn.execute("PRAGMA table_info(requests)").fetchall()]
        if "address" not in cols:
            conn.execute("ALTER TABLE requests ADD COLUMN address TEXT")
            print("[db migration] added 'address' column to requests table")

        # Seed default accounts only if the users table is empty,
        # so this doesn't reset passwords on every restart.
        existing = conn.execute("SELECT COUNT(*) AS c FROM users").fetchone()["c"]
        if existing == 0:
            conn.execute(
                "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
                ("admin", _hash("admin123"), "admin"),
            )
            conn.execute(
                "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
                ("staff", _hash("rescue123"), "staff"),
            )


def _hash(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()


def request_to_dict(row: sqlite3.Row) -> dict:
    return dict(row)


# token -> {"username": ..., "role": ...}
# Kept in memory: losing sessions on restart just means staff log in
# again, no real data is lost since requests/users live in SQLite.
active_tokens: Dict[str, dict] = {}


class LoginRequest(BaseModel):
    username: str
    password: str


class CreateStaffRequest(BaseModel):
    username: str
    password: str
    role: str = "staff"  # "staff" or "admin"


def require_staff(authorization: Optional[str] = Header(None)) -> dict:
    """Dependency that checks the Authorization: Bearer <token> header.
    Returns {"username": ..., "role": ...} for any signed-in user."""
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing or malformed token")
    token = authorization.removeprefix("Bearer ")
    session = active_tokens.get(token)
    if not session:
        raise HTTPException(status_code=401, detail="Invalid or expired token")
    return session


def require_admin(authorization: Optional[str] = Header(None)) -> dict:
    """Same as require_staff, but only allows role == admin."""
    session = require_staff(authorization)
    if session["role"] != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    return session


@app.post("/auth/login")
def login(req: LoginRequest):
    with get_db() as conn:
        user = conn.execute(
            "SELECT * FROM users WHERE username = ?", (req.username,)
        ).fetchone()
    if not user or _hash(req.password) != user["password_hash"]:
        raise HTTPException(status_code=401, detail="Invalid username or password")
    token = secrets.token_hex(24)
    active_tokens[token] = {"username": req.username, "role": user["role"]}
    return {"token": token, "username": req.username, "role": user["role"]}


@app.post("/admin/staff")
def create_staff(req: CreateStaffRequest, authorization: Optional[str] = Header(None)):
    """Admin-only: create a new staff or admin account."""
    require_admin(authorization)
    if req.role not in ("staff", "admin"):
        raise HTTPException(status_code=400, detail="Role must be 'staff' or 'admin'")
    with get_db() as conn:
        existing = conn.execute(
            "SELECT 1 FROM users WHERE username = ?", (req.username,)
        ).fetchone()
        if existing:
            raise HTTPException(status_code=400, detail="Username already exists")
        conn.execute(
            "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
            (req.username, _hash(req.password), req.role),
        )
    return {"username": req.username, "role": req.role}


@app.get("/admin/staff")
def list_staff(authorization: Optional[str] = Header(None)):
    """Admin-only: list all accounts (no password hashes returned)."""
    require_admin(authorization)
    with get_db() as conn:
        rows = conn.execute("SELECT username, role FROM users").fetchall()
    return [dict(r) for r in rows]


drone_clients: Set[WebSocket] = set()
staff_clients: Set[WebSocket] = set()


async def broadcast(clients: Set[WebSocket], message: dict):
    """Send a JSON message to every connected client in the given set."""
    dead = set()
    for ws in clients:
        try:
            await ws.send_json(message)
        except Exception:
            dead.add(ws)
    clients.difference_update(dead)


# ---------- Patient side ----------

@app.websocket("/ws/patient")
async def patient_endpoint(websocket: WebSocket):
    """The public SOS page (web_app/patient) connects here to send requests."""
    await websocket.accept()
    try:
        while True:
            data = await websocket.receive_text()
            payload = json.loads(data)

            request_id = str(uuid.uuid4())
            record = {
                "id": request_id,
                "status": "pending",
                "lat": payload.get("lat"),
                "lon": payload.get("lon"),
                "address": payload.get("address"),
                "notes": payload.get("notes"),
                "received_at": datetime.now(timezone.utc).isoformat(),
                "dispatched_at": None,
                "completed_at": None,
            }
            with get_db() as conn:
                conn.execute(
                    """INSERT INTO requests (id, status, lat, lon, address, notes, received_at)
                       VALUES (?, ?, ?, ?, ?, ?, ?)""",
                    (record["id"], record["status"], record["lat"],
                     record["lon"], record["address"], record["notes"], record["received_at"]),
                )
            print(f"[new request] {record}")

            # Confirm receipt back to the patient
            await websocket.send_json({"type": "ack", "request_id": request_id})

            # Push it live to any open staff dashboards
            await broadcast(staff_clients, {"type": "new_request", "request": record})
    except WebSocketDisconnect:
        pass


# ---------- Staff side ----------

@app.websocket("/ws/staff")
async def staff_endpoint(websocket: WebSocket, token: str = ""):
    """Staff dashboard connects here for a live feed of new requests + drone telemetry.
    Requires ?token=<token> from /auth/login in the connection URL."""
  if token not in active_tokens:
        await websocket.close(code=4401)  # custom code: unauthorized
        return
    await websocket.accept()
    staff_clients.add(websocket)
    print(f"[staff connected] total staff: {len(staff_clients)}")
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        staff_clients.discard(websocket)
        print(f"[staff disconnected] total staff: {len(staff_clients)}")


@app.get("/requests")
def list_requests(status: str = None, authorization: Optional[str] = Header(None)):
    """Fetch all stored requests, optionally filtered by status (pending/dispatched/completed).
    Requires Authorization: Bearer <token> header from /auth/login."""
    require_staff(authorization)
    with get_db() as conn:
        if status:
            rows = conn.execute(
                "SELECT * FROM requests WHERE status = ? ORDER BY received_at DESC",
                (status,),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM requests ORDER BY received_at DESC"
            ).fetchall()
    return [request_to_dict(r) for r in rows]


@app.post("/requests/{request_id}/dispatch")
async def dispatch_request(request_id: str, authorization: Optional[str] = Header(None)):
    """Staff marks a request as dispatched and the drone is sent its destination."""
    require_staff(authorization)
    with get_db() as conn:
        record = conn.execute(
            "SELECT * FROM requests WHERE id = ?", (request_id,)
        ).fetchone()
        if not record:
            raise HTTPException(status_code=404, detail="Request not found")

        dispatched_at = datetime.now(timezone.utc).isoformat()
        conn.execute(
            "UPDATE requests SET status = ?, dispatched_at = ? WHERE id = ?",
            ("dispatched", dispatched_at, request_id),
        )
        updated = conn.execute(
            "SELECT * FROM requests WHERE id = ?", (request_id,)
        ).fetchone()

    record_dict = request_to_dict(updated)

    # Tell the drone bridge where to go
    await broadcast(drone_clients, {
        "type": "dispatch",
        "request_id": request_id,
        "lat": record_dict["lat"],
        "lon": record_dict["lon"],
    })
    await broadcast(staff_clients, {"type": "request_updated", "request": record_dict})
    return record_dict


@app.post("/requests/{request_id}/complete")
async def complete_request(request_id: str, authorization: Optional[str] = Header(None)):
    """Mark a request as completed (drone delivered supplies)."""
    require_staff(authorization)
    with get_db() as conn:
        record = conn.execute(
            "SELECT * FROM requests WHERE id = ?", (request_id,)
        ).fetchone()
        if not record:
            raise HTTPException(status_code=404, detail="Request not found")

        completed_at = datetime.now(timezone.utc).isoformat()
        conn.execute(
            "UPDATE requests SET status = ?, completed_at = ? WHERE id = ?",
            ("completed", completed_at, request_id),
        )
        updated = conn.execute(
            "SELECT * FROM requests WHERE id = ?", (request_id,)
        ).fetchone()

    record_dict = request_to_dict(updated)
    await broadcast(staff_clients, {"type": "request_updated", "request": record_dict})
    return record_dict


# ---------- Drone side ----------

@app.websocket("/ws/drone")
async def drone_endpoint(websocket: WebSocket):
    """The laptop's ROS2 bridge connects here."""
    await websocket.accept()
    drone_clients.add(websocket)
    print(f"[drone connected] total drones: {len(drone_clients)}")
    try:
        while True:
            data = await websocket.receive_text()
            message = json.loads(data)
            print(f"[telemetry] {message}")
            await broadcast(staff_clients, {"type": "telemetry", "data": message})
    except WebSocketDisconnect:
        drone_clients.discard(websocket)
        print(f"[drone disconnected] total drones: {len(drone_clients)}")


@app.get("/")
def health_check():
    with get_db() as conn:
        count = conn.execute("SELECT COUNT(*) AS c FROM requests").fetchone()["c"]
    return {
        "status": "relay running",
        "drones_connected": len(drone_clients),
        "staff_connected": len(staff_clients),
        "requests_stored": count,
    }


init_db()

if __name__ == "__main__":
    import os
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
