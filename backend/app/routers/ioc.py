from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from app.services.virustotal import enrich_ioc

router = APIRouter(prefix="/ioc", tags=["IOC"])


class IOCRequest(BaseModel):
    value: str


@router.post("/enrich")
async def enrich(body: IOCRequest):
    if not body.value or not body.value.strip():
        raise HTTPException(status_code=400, detail="IOC value cannot be empty")
    try:
        result = await enrich_ioc(body.value.strip())
        return result
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"VirusTotal error: {str(e)}")
