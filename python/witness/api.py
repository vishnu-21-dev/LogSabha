"""HTTP side of the witness (FastAPI, JSON)."""
from contextlib import asynccontextmanager
from typing import Optional

from fastapi import Body, FastAPI, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from .core import PeerRejected, Witness


class EntryIn(BaseModel):
    event_type: str = Field(min_length=1, max_length=64)
    request_id: Optional[str] = Field(default=None, max_length=128)
    direction: Optional[str] = Field(default=None, max_length=32)
    dst: Optional[str] = Field(default=None, max_length=256)
    bytes: int = Field(ge=0)
    result: Optional[str] = Field(default=None, max_length=128)


def create_app(witness: Witness, run_loops: bool = True) -> FastAPI:
    @asynccontextmanager
    async def lifespan(app):
        if run_loops:
            witness.start()
        yield
        witness.stop()   # writes the signed shutdown marker

    app = FastAPI(title="LogSabha witness: " + witness.name, lifespan=lifespan)

    @app.get("/status")
    def status():
        return witness.status()

    @app.post("/entries")
    def add_entry(entry: EntryIn):
        try:
            return witness.add_entry(entry.event_type, entry.request_id, entry.direction,
                                     entry.dst, entry.bytes, entry.result)
        except ValueError as err:
            raise HTTPException(status_code=400, detail=str(err))

    @app.post("/peer/header")
    def peer_header(payload: dict = Body(...)):
        try:
            return witness.handle_peer_header(payload)
        except PeerRejected as err:
            return JSONResponse(status_code=err.code, content={"error": err.reason})

    return app
