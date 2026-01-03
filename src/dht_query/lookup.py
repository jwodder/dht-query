from __future__ import annotations
from .types import InetAddr


async def lookup(info_hash: bytes) -> list[InetAddr]:
    raise NotImplementedError
