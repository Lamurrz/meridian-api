from contextlib import asynccontextmanager
from typing import AsyncGenerator

from neo4j import AsyncGraphDatabase, AsyncDriver

from app.config import settings

_driver: AsyncDriver | None = None


async def get_driver() -> AsyncDriver:
    global _driver
    if _driver is None:
        _driver = AsyncGraphDatabase.driver(
            settings.neo4j_uri,
            auth=settings.neo4j_auth,
        )
    return _driver


async def close_driver() -> None:
    global _driver
    if _driver is not None:
        await _driver.close()
        _driver = None


async def verify_connectivity() -> bool:
    try:
        driver = await get_driver()
        await driver.verify_connectivity()
        return True
    except Exception:
        return False


@asynccontextmanager
async def get_session() -> AsyncGenerator:
    driver = await get_driver()
    async with driver.session() as session:
        yield session
