import asyncio
import time

class RateLimiter:
    def __init__(self, calls_per_minute: int):
        self.delay = 60.0 / calls_per_minute
        self._last_call = 0.0
        self._lock = None

    async def acquire(self):
        if self._lock is None:
            self._lock = asyncio.Lock()
        async with self._lock:
            now = time.monotonic()
            wait = self.delay - (now - self._last_call)
            if wait > 0:
                await asyncio.sleep(wait)
            self._last_call = time.monotonic()
