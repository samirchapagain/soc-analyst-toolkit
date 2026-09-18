from fastapi import APIRouter
from app.schemas import DetectRequest
from app.services.detection_service import DETECTION_RULES, detect
router = APIRouter(prefix="/api/detect", tags=["Detection"])
@router.post("")
def run_detection(payload: DetectRequest): return detect(payload.text, payload.content_type)
@router.get("/rules")
@router.post("/rules")
def rules(): return DETECTION_RULES
