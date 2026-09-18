import asyncio
from fastapi import APIRouter
from fastapi.concurrency import run_in_threadpool

from app.schemas import IOCBulkRequest, IOCRequest
from app.services.ioc_service import lookup_indicator

router = APIRouter(prefix="/api/ioc", tags=["IOC"])


@router.post("/lookup")
def lookup(request: IOCRequest) -> dict:
    return lookup_indicator(request.indicator)


@router.post("/bulk")
async def bulk_lookup(payload: IOCBulkRequest) -> list[dict]:
    return await asyncio.gather(
        *(run_in_threadpool(lookup_indicator, indicator) for indicator in payload.indicators)
    )
