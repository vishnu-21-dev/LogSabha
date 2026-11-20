"""The QuickPay web app.

For every login, query, export and outbound call it posts ONE entry to its own App witness.
An entry holds only: the kind of event, the request_id, a direction, a destination, a size and a
short result. Never a customer row, a name, an email, a username or a password.

All outbound calls go through the network gateway, used as a plain HTTP proxy, and carry the
request_id in an X-Request-ID header.
"""
import json
import re
import secrets
import time
from contextlib import asynccontextmanager
from dataclasses import dataclass
from typing import Optional
from urllib.parse import urlsplit

import requests
from fastapi import FastAPI, Header, HTTPException, Query, Request
from pydantic import BaseModel, Field

from svc.poster import EntryPoster

from . import db


@dataclass
class Settings:
    db_path: str
    witness_url: str          # this app's own App witness
    gateway_url: str          # the gateway, used as an HTTP proxy
    demo_password: str        # FAKE demo login password
    customers: int = 200
    max_export_bytes: int = 20_000_000
    label: str = ""
    outbound_timeout: tuple = (5, 60)


class LoginIn(BaseModel):
    username: str = Field(max_length=64)
    password: str = Field(max_length=128)


class ExportIn(BaseModel):
    destination_url: str = Field(max_length=512)
    bytes: int = Field(ge=1)
    purpose: str = Field(default="", max_length=32)


PURPOSE_OK = re.compile(r"^[a-z0-9-]{0,32}$")


def create_app(settings: Settings, poster: Optional[EntryPoster] = None) -> FastAPI:
    db.init_db(settings.db_path, settings.demo_password, settings.customers)
    entries = poster or EntryPoster(settings.witness_url)

    @asynccontextmanager
    async def lifespan(app):
        yield
        entries.close()

    app = FastAPI(title="QuickPay (fake fintech demo)", lifespan=lifespan)
    app.state.poster = entries

    @app.middleware("http")
    async def fresh_request_id(request: Request, call_next):
        # A new random 128-bit id for EVERY request. Anything the client sent as
        # X-Request-ID (or in the body) is ignored: the app never trusts it.
        request.state.request_id = secrets.token_hex(16)
        response = await call_next(request)
        response.headers["X-Request-ID"] = request.state.request_id
        return response

    def log(request, event_type, direction, dst, size, result):
        entries.post(event_type, request.state.request_id, direction, dst, size, result)

    def session_user(authorization):
        if not authorization or not authorization.lower().startswith("bearer "):
            return None
        token = authorization[7:].strip()
        with db.connect(settings.db_path) as con:
            row = con.execute("SELECT username FROM sessions WHERE token=?", (token,)).fetchone()
        return row["username"] if row else None

    @app.get("/status")
    def status():
        return {"service": "demo_app", "label": settings.label, "entries_sent": entries.sent,
                "entries_pending": entries.pending()}

    @app.post("/login")
    def login(body: LoginIn, request: Request):
        with db.connect(settings.db_path) as con:
            row = con.execute("SELECT salt, password_hash FROM staff WHERE username=?", (body.username,)).fetchone()
            ok = bool(row) and db.check_password(body.password, row["salt"], row["password_hash"])
            token = secrets.token_hex(16) if ok else None
            if ok:
                con.execute("INSERT INTO sessions VALUES(?,?,?)", (token, body.username, time.time()))
        answer = {"token": token} if ok else {"error": "denied"}
        log(request, "login", "in", "/login", len(json.dumps(answer)), "ok" if ok else "denied")
        if not ok:
            raise HTTPException(status_code=401, detail="denied")
        return answer

    @app.get("/customers")
    def query_customers(request: Request, limit: int = Query(10, ge=1, le=100), city: Optional[str] = None,
                        authorization: Optional[str] = Header(default=None)):
        if session_user(authorization) is None:
            log(request, "query", "in", "customers", 0, "denied")
            raise HTTPException(status_code=401, detail="log in first")
        sql, args = "SELECT id, name, email, city, balance_cents FROM customers", []
        if city:
            sql += " WHERE city = ?"
            args.append(city)
        with db.connect(settings.db_path) as con:
            rows = [dict(r) for r in con.execute(sql + " ORDER BY id LIMIT ?", (*args, limit)).fetchall()]
        answer = {"customers": rows}
        # only a count and a size go into the entry, never the rows themselves
        log(request, "query", "local", "customers", len(json.dumps(answer)), "ok:rows=%d" % len(rows))
        return answer

    @app.post("/export")
    def export(body: ExportIn, request: Request, authorization: Optional[str] = Header(default=None)):
        rid = request.state.request_id
        target = urlsplit(body.destination_url)
        if session_user(authorization) is None:
            log(request, "export", "in", target.netloc or "-", 0, "denied")
            raise HTTPException(status_code=401, detail="log in first")
        if target.scheme != "http" or not target.netloc:
            raise HTTPException(status_code=400, detail="destination must be a plain http:// URL (demo)")
        if body.bytes > settings.max_export_bytes:
            raise HTTPException(status_code=400, detail="too many bytes for the demo")
        if not PURPOSE_OK.match(body.purpose):
            raise HTTPException(status_code=400, detail="purpose may only use a-z, 0-9 and -")

        label = ";purpose=" + body.purpose if body.purpose else ""
        log(request, "export", "in", target.netloc, body.bytes, "accepted" + label)

        with db.connect(settings.db_path) as con:
            rows = con.execute("SELECT id, name, email, city, balance_cents FROM customers ORDER BY id").fetchall()
        chunk = ("\n".join(json.dumps(dict(r)) for r in rows) + "\n").encode("utf-8")
        payload = (chunk * (body.bytes // len(chunk) + 1))[:body.bytes]

        session = requests.Session()
        session.trust_env = False                      # use exactly the proxy we are told to use
        session.proxies = {"http": settings.gateway_url}
        try:
            reply = session.post(body.destination_url, data=payload, timeout=settings.outbound_timeout,
                                 headers={"X-Request-ID": rid, "Content-Type": "application/octet-stream"})
            status_code = reply.status_code
            result = "ok:%d" % status_code if 200 <= status_code < 300 else "error:http_%d" % status_code
        except requests.Timeout:
            status_code, result = None, "error:timeout"
        except requests.RequestException:
            status_code, result = None, "error:gateway_unreachable"
        finally:
            session.close()
        log(request, "outbound_call", "out", target.netloc, len(payload), result)

        if not result.startswith("ok"):
            raise HTTPException(status_code=502, detail="the outbound call failed: " + result)
        return {"request_id": rid, "destination": target.netloc, "bytes": len(payload), "status": status_code}

    return app
