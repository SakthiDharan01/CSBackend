from typing import List, Literal
from fastapi import APIRouter
from pydantic import BaseModel, EmailStr, HttpUrl, Field
from ...core.config import settings

router = APIRouter()


class SecurityComponent(BaseModel):
    name: str
    score: float = Field(..., ge=0, le=100)
    description: str


class SecurityScoreResponse(BaseModel):
    target: str
    kind: Literal["email", "website"]
    overall_score: float = Field(..., ge=0, le=100)
    components: List[SecurityComponent]
    recommendations: List[str]


class EmailSecurityRequest(BaseModel):
    email: EmailStr


class WebsiteSecurityRequest(BaseModel):
    url: HttpUrl


@router.post("/email", response_model=SecurityScoreResponse, summary="Evaluate email security")
def email_security_score(payload: EmailSecurityRequest) -> SecurityScoreResponse:
    """Return a placeholder security score for an email address."""
    base_score = settings.SECURITY_DEFAULT_SCORE
    components = [
        SecurityComponent(name="DMARC", score=base_score * 0.9, description="Placeholder DMARC assessment."),
        SecurityComponent(name="SPF", score=base_score * 0.85, description="Placeholder SPF assessment."),
        SecurityComponent(name="Phishing Risk", score=base_score * 0.8, description="Placeholder phishing risk."),
    ]
    overall = sum(component.score for component in components) / len(components)
    return SecurityScoreResponse(
        target=payload.email,
        kind="email",
        overall_score=round(overall, 2),
        components=components,
        recommendations=[
            "Enable DMARC with a reject policy",
            "Harden SPF and DKIM alignment",
            "Educate users on phishing detection",
        ],
    )


@router.post("/website", response_model=SecurityScoreResponse, summary="Evaluate website security")
def website_security_score(payload: WebsiteSecurityRequest) -> SecurityScoreResponse:
    """Return a placeholder security score for a website URL."""
    base_score = settings.SECURITY_DEFAULT_SCORE
    components = [
        SecurityComponent(name="TLS", score=base_score * 0.92, description="Placeholder TLS assessment."),
        SecurityComponent(name="Content Security Policy", score=base_score * 0.7, description="Placeholder CSP review."),
        SecurityComponent(name="Vulnerability Scan", score=base_score * 0.78, description="Placeholder scan summary."),
    ]
    overall = sum(component.score for component in components) / len(components)
    return SecurityScoreResponse(
        target=payload.url,
        kind="website",
        overall_score=round(overall, 2),
        components=components,
        recommendations=[
            "Force HTTPS and HSTS",
            "Deploy a strict Content Security Policy",
            "Run routine vulnerability scans",
        ],
    )
