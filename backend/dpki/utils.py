import asyncio
import json
import logging
from base64 import b64decode
from datetime import date, datetime, timezone
from typing import TYPE_CHECKING
from uuid import uuid4

from csp import ed25519
from csp.base import Key
from csp.provider import CSProvider

if TYPE_CHECKING:
    from logging import Logger
    from typing import Coroutine


class JSONEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, datetime):
            return (obj if obj.tzinfo else obj.replace(tzinfo=timezone.utc)).isoformat().replace('+00:00', 'Z')
        elif isinstance(obj, date):
            return obj.isoformat()
        return json.JSONEncoder.default(self, obj)


def load_from_key_file(key_file: str) -> 'Key':
    with open(key_file, 'r') as file:
        obj = json.load(file)
        assert obj['type'].startswith('tendermint/PrivKey')
        if obj['type'].endswith('PrivKeyEd25519'):
            csp = CSProvider()
            return csp.key_import(b64decode(obj['value'])[:32], ed25519.KeyOpts())
        raise NotImplementedError(f"Key loader for {obj['type']} not yet implemented")


class Service:
    """ Base service
    """

    def __init__(self, logger: 'Logger' = None):
        self.logger = logger or logging.root
        self.tasks = dict()
        self._running = False

    async def start(self):
        async def idle_loop():
            while self._running:
                await asyncio.sleep(0.001)

        if self._running:
            raise RuntimeError('Already started')
        try:
            self._running = True
            await idle_loop()
        except asyncio.CancelledError:
            pass
        finally:
            self._running = False

    async def stop(self):
        if self._running:
            self._running = False
            tasks = [*self.tasks.values()]
            [task.cancel() for task in tasks]
            await asyncio.gather(*tasks, return_exceptions=True)
            self.tasks = []

    def create_task(self, coro: 'Coroutine', cid: str = None):
        cid = cid or str(uuid4())
        self.tasks[cid] = asyncio.create_task(coro)
        self.tasks[cid].add_done_callback(lambda *args: self.tasks.pop(cid))
