import uuid
from typing import List, Optional
from fastapi import APIRouter
from pydantic import BaseModel, EmailStr, Field
from ...core.config import settings

router = APIRouter()


class SMBReportRequest(BaseModel):
    business_name: str = Field(..., min_length=2)
    contact_email: Optional[EmailStr] = None
    assets: List[str] = []


class SMBReportResponse(BaseModel):
    report_id: str
    status: str
    risk_level: str
    summary: str
    next_steps: List[str]


@router.post("/report_generation", response_model=SMBReportResponse, summary="Generate SMB security report")
def generate_smb_report(payload: SMBReportRequest) -> SMBReportResponse:
    """Return a placeholder SMB report with a generated identifier."""
    report_id = uuid.uuid4().hex
    risk_level = settings.SMB_DEFAULT_RISK_LEVEL
    return SMBReportResponse(
        report_id=report_id,
        status="generated",
        risk_level=risk_level,
        summary=(
            f"Template report for {payload.business_name}. This endpoint currently returns "
            "static data and should be wired to real scoring logic."
        ),
        next_steps=[
            "Schedule a full vulnerability assessment",
            "Implement MFA across critical services",
            "Create a regular backup and recovery drill",
        ],
    )
