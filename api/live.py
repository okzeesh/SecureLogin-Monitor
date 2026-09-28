"""In-process fan-out so dashboard clients see new login events immediately."""

from __future__ import annotations

import asyncio
import json
from collections.abc import AsyncIterator


class LiveBroker:
    def __init__(self) -> None:
        self._subscribers: set[asyncio.Queue[str]] = set()
        self._loop: asyncio.AbstractEventLoop | None = None

    def bind_loop(self, loop: asyncio.AbstractEventLoop) -> None:
        self._loop = loop

    def publish(self, payload: dict) -> None:
        message = json.dumps(payload, default=str)
        loop = self._loop
        if loop is None or loop.is_closed():
            return

        def put_all() -> None:
            for queue in list(self._subscribers):
                queue.put_nowait(message)

        loop.call_soon_threadsafe(put_all)

    def add(self, queue: asyncio.Queue[str]) -> None:
        self._subscribers.add(queue)

    def discard(self, queue: asyncio.Queue[str]) -> None:
        self._subscribers.discard(queue)


broker = LiveBroker()


async def event_stream() -> AsyncIterator[str]:
    queue: asyncio.Queue[str] = asyncio.Queue()
    broker.add(queue)
    try:
        yield "event: ready\ndata: {}\n\n"
        while True:
            try:
                message = await asyncio.wait_for(queue.get(), timeout=20)
                yield f"data: {message}\n\n"
            except TimeoutError:
                yield ": keepalive\n\n"
    finally:
        broker.discard(queue)
