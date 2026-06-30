"""
Relay server for the UAV rescue system.

Connects three kinds of clients:

  - PATIENT clients (web_app/patient): send rescue requests over
    WebSocket at /ws/patient. Each request is stored here so it is
    never lost, even if no staff dashboard happens to be open yet.

  - STAFF clients (web_app/staff): read pending requests via REST
    (GET /requests), and get a live WebSocket feed at /ws/staff for
    new requests and drone telemetry as they happen.

  - DRONE clients (the ROS2 bridge on the laptop): send telemetry and
    receive dispatch commands over WebSocket at /ws/drone.

All three only ever make OUTBOUND connections to this server, so none
of them need a public IP, port forwarding, or firewall changes. This
is the standard "relay" pattern for controlling something remotely.

Storage here is a simple in-memory dict — fine for the pre-thesis
stage. It resets if the server restarts; swap for a real database
later if persistence across restarts becomes important.
"""

import hashlib
import json
import secrets
import uuid
from datetime import datetime, timezone
from typing import Set, Dict, Optional
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, Header
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import uvicorn

app = FastAPI()


# ---------- Staff authentication ----------
# Prototype-level auth: hardcoded seed accounts + in-memory tokens.
# Good enough for the pre-thesis stage. Before any real deployment,
# replace this with a real user table (hashed passwords, per-user
# accounts) and proper token expiry.

def _hash(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()


# username -> {"password_hash": ..., "role": "staff" | "admin"}
USERS: Dict[str, dict] = {
    "admin": {"password_hash": _hash("admin123"), "role": "admin"},
    "staff": {"password_hash": _hash("rescue123"), "role": "staff"},
}

# token -> {"username": ..., "role": ...}
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
    user = USERS.get(req.username)
    if not user or _hash(req.password) != user["password_hash"]:
        raise HTTPException(status_code=401, detail="Invalid username or password")
    token = secrets.token_hex(24)
    active_tokens[token] = {"username": req.username, "role": user["role"]}
    return {"token": token, "username": req.username, "role": user["role"]}


@app.post("/admin/staff")
def create_staff(req: CreateStaffRequest, authorization: Optional[str] = Header(None)):
    """Admin-only: create a new staff or admin account."""
    require_admin(authorization)
    if req.username in USERS:
        raise HTTPException(status_code=400, detail="Username already exists")
    if req.role not in ("staff", "admin"):
        raise HTTPException(status_code=400, detail="Role must be 'staff' or 'admin'")
    USERS[req.username] = {"password_hash": _hash(req.password), "role": req.role}
    return {"username": req.username, "role": req.role}


@app.get("/admin/staff")
def list_staff(authorization: Optional[str] = Header(None)):
    """Admin-only: list all accounts (no password hashes returned)."""
    require_admin(authorization)
    return [{"username": u, "role": v["role"]} for u, v in USERS.items()]

# Allow the web app (served from a different origin/port) to call the
# REST endpoints below. Tighten this to your actual domain once deployed.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

drone_clients: Set[WebSocket] = set()
staff_clients: Set[WebSocket] = set()

# The persistent store. Key = request id, value = the request record.
# Status moves: "pending" -> "dispatched" -> "completed"
requests_store: Dict[str, dict] = {}


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
                "notes": payload.get("notes"),
                "received_at": datetime.now(timezone.utc).isoformat(),
            }
            requests_store[request_id] = record
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
            # Staff dashboard doesn't need to send anything over this socket;
            # dispatch actions go through the REST endpoint below.
            await websocket.receive_text()
    except WebSocketDisconnect:
        staff_clients.discard(websocket)
        print(f"[staff disconnected] total staff: {len(staff_clients)}")


@app.get("/requests")
def list_requests(status: str = None, staff_user: str = None, authorization: Optional[str] = Header(None)):
    """Fetch all stored requests, optionally filtered by status (pending/dispatched/completed).
    Requires Authorization: Bearer <token> header from /auth/login."""
    require_staff(authorization)
    records = list(requests_store.values())
    if status:
        records = [r for r in records if r["status"] == status]
    records.sort(key=lambda r: r["received_at"], reverse=True)
    return records


@app.post("/requests/{request_id}/dispatch")
async def dispatch_request(request_id: str, authorization: Optional[str] = Header(None)):
    """Staff marks a request as dispatched and the drone is sent its destination."""
    require_staff(authorization)
    record = requests_store.get(request_id)
    if not record:
        raise HTTPException(status_code=404, detail="Request not found")

    record["status"] = "dispatched"
    record["dispatched_at"] = datetime.now(timezone.utc).isoformat()

    # Tell the drone bridge where to go
    await broadcast(drone_clients, {
        "type": "dispatch",
        "request_id": request_id,
        "lat": record["lat"],
        "lon": record["lon"],
    })
    # Update any open staff dashboards
    await broadcast(staff_clients, {"type": "request_updated", "request": record})
    return record


@app.post("/requests/{request_id}/complete")
async def complete_request(request_id: str, authorization: Optional[str] = Header(None)):
    """Mark a request as completed (drone delivered supplies)."""
    require_staff(authorization)
    record = requests_store.get(request_id)
    if not record:
        raise HTTPException(status_code=404, detail="Request not found")

    record["status"] = "completed"
    record["completed_at"] = datetime.now(timezone.utc).isoformat()
    await broadcast(staff_clients, {"type": "request_updated", "request": record})
    return record


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
            # Forward telemetry live to any open staff dashboards
            await broadcast(staff_clients, {"type": "telemetry", "data": message})
    except WebSocketDisconnect:
        drone_clients.discard(websocket)
        print(f"[drone disconnected] total drones: {len(drone_clients)}")


@app.get("/")
def health_check():
    return {
        "status": "relay running",
        "drones_connected": len(drone_clients),
        "staff_connected": len(staff_clients),
        "requests_stored": len(requests_store),
    }


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)