import asyncio
import base64
import io
import os
import socket
import ssl
import uuid
from datetime import datetime
from typing import List, Optional

import pandas as pd
import requests
from fastapi import APIRouter, BackgroundTasks, File, Form, HTTPException, UploadFile
from fastapi.responses import FileResponse
from pydantic import BaseModel, EmailStr, Field
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

from ...core.config import settings

router = APIRouter()


class SMBReportRequest(BaseModel):
    business_name: str = Field(..., min_length=2)
    contact_email: Optional[EmailStr] = None
    assets: List[str] = []


class EmployeeData(BaseModel):
    name: str
    email: EmailStr
    role: str


class AssetData(BaseModel):
    url: str
    asset_type: str


class SMBReportDataRequest(BaseModel):
    company_name: str
    industry: str
    employee_count: str
    contact_name: str
    contact_email: EmailStr
    security_priorities: List[str]
    employees_data: List[EmployeeData]
    assets_data: List[AssetData]


class SMBReportResponse(BaseModel):
    report_id: str
    status: str
    risk_level: str
    summary: str
    next_steps: List[str]


async def check_email_breach(email: str) -> dict:
    """Check if email appears in data breaches using XposedOrNot (best effort)."""
    try:
        url = f"https://api.xposedornot.com/v1/check-email/{email}"
        response = requests.get(url, timeout=10)
        if response.status_code == 200:
            data = response.json()
            breaches = data.get("breaches_details", [])
            return {
                "email": email,
                "is_breached": len(breaches) > 0,
                "breach_count": len(breaches),
                "breaches": [b.get("breach", "Unknown") for b in breaches[:3]],
                "severity": "CRITICAL" if len(breaches) > 0 else "SAFE",
                "owasp": "A07:2025 - Authentication Failures" if len(breaches) > 0 else None,
            }
    except Exception as exc:  # noqa: BLE001
        return {
            "email": email,
            "is_breached": False,
            "breach_count": 0,
            "breaches": [],
            "severity": "UNKNOWN",
            "error": str(exc),
        }


async def check_ssl_certificate(domain: str) -> dict:
    """Check SSL certificate validity (non-intrusive)."""
    try:
        domain = domain.replace("https://", "").replace("http://", "").split("/")[0]
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                expiry_str = cert["notAfter"]
                expiry_date = datetime.strptime(expiry_str, "%b %d %H:%M:%S %Y %Z")
                days_remaining = (expiry_date - datetime.now()).days
                return {
                    "domain": domain,
                    "has_ssl": True,
                    "expiry_date": expiry_date.strftime("%Y-%m-%d"),
                    "days_remaining": days_remaining,
                    "severity": "CRITICAL"
                    if days_remaining < 0
                    else "MEDIUM"
                    if days_remaining < 30
                    else "SAFE",
                    "owasp": "A04:2025 - Cryptographic Failures" if days_remaining < 30 else None,
                }
    except Exception as exc:  # noqa: BLE001
        return {
            "domain": domain,
            "has_ssl": False,
            "severity": "CRITICAL",
            "error": str(exc),
            "owasp": "A04:2025 - Cryptographic Failures",
        }


async def check_security_headers(url: str) -> dict:
    """Check for common security headers (safe HTTP request)."""
    try:
        if not url.startswith("http"):
            url = f"https://{url}"
        response = requests.get(url, timeout=10, allow_redirects=True)
        headers = response.headers
        required_headers = {
            "X-Frame-Options": "Prevents clickjacking attacks",
            "Content-Security-Policy": "Mitigates XSS attacks",
            "Strict-Transport-Security": "Enforces HTTPS",
            "X-Content-Type-Options": "Prevents MIME sniffing",
            "Referrer-Policy": "Controls referrer information",
        }
        missing = []
        present = []
        for header, description in required_headers.items():
            if header.lower() in [h.lower() for h in headers.keys()]:
                present.append(header)
            else:
                missing.append({"header": header, "reason": description})

        score = int((len(present) / len(required_headers)) * 100)
        return {
            "url": url,
            "score": score,
            "grade": "A"
            if score >= 90
            else "B"
            if score >= 70
            else "C"
            if score >= 50
            else "F",
            "missing_headers": missing,
            "severity": "HIGH" if score < 50 else "MEDIUM" if score < 70 else "LOW",
            "owasp": "A02:2025 - Security Misconfiguration" if len(missing) > 0 else None,
        }
    except Exception as exc:  # noqa: BLE001
        return {
            "url": url,
            "score": 0,
            "grade": "F",
            "severity": "HIGH",
            "error": str(exc),
            "owasp": "A02:2025 - Security Misconfiguration",
        }


async def check_malware_virustotal(url: str, api_key: Optional[str] = None) -> dict:
    """Check URL against VirusTotal when API key is available (passive)."""
    if not api_key:
        return {
            "url": url,
            "is_malicious": False,
            "detections": 0,
            "severity": "SAFE",
            "note": "VirusTotal API key not configured",
        }
    try:
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        headers = {"x-apikey": api_key}
        endpoint = f"https://www.virustotal.com/api/v3/urls/{url_id}"
        response = requests.get(endpoint, headers=headers, timeout=10)
        if response.status_code == 200:
            data = response.json()
            stats = data["data"]["attributes"]["last_analysis_stats"]
            malicious = stats.get("malicious", 0)
            return {
                "url": url,
                "is_malicious": malicious > 0,
                "detections": malicious,
                "severity": "CRITICAL" if malicious > 5 else "HIGH" if malicious > 0 else "SAFE",
                "owasp": "A06:2025 - Insecure Design" if malicious > 0 else None,
            }
    except Exception as exc:  # noqa: BLE001
        return {
            "url": url,
            "is_malicious": False,
            "detections": 0,
            "severity": "UNKNOWN",
            "error": str(exc),
        }


def generate_google_dorks(domain: str) -> dict:
    dorks = {
        "Exposed Documents": f"site:{domain} filetype:pdf OR filetype:docx OR filetype:xlsx",
        "Backup Files": f"site:{domain} filetype:bak OR filetype:sql OR filetype:zip",
        "Admin Panels": f"site:{domain} inurl:admin OR inurl:login OR inurl:dashboard",
        "Config Files": f"site:{domain} filetype:env OR filetype:config OR filetype:ini",
        "Database Dumps": f"site:{domain} filetype:sql OR intext:\"INSERT INTO\"",
    }
    return {dork_name: f"https://www.google.com/search?q={query}" for dork_name, query in dorks.items()}


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


def generate_pdf_report(file_path: str, data: dict) -> None:
    """Generate PDF report using ReportLab (sync)."""
    doc = SimpleDocTemplate(file_path, pagesize=letter, topMargin=0.5 * inch, bottomMargin=0.5 * inch)
    story: List = []
    styles = getSampleStyleSheet()

    title_style = ParagraphStyle(
        "CustomTitle",
        parent=styles["Heading1"],
        fontSize=24,
        textColor=colors.HexColor("#1a237e"),
        spaceAfter=30,
        alignment=TA_CENTER,
    )

    heading_style = ParagraphStyle(
        "CustomHeading",
        parent=styles["Heading2"],
        fontSize=14,
        textColor=colors.HexColor("#283593"),
        spaceAfter=12,
        spaceBefore=12,
    )

    story.append(Spacer(1, 1 * inch))
    story.append(Paragraph("🛡️ CYBERSHIELD LITE", title_style))
    story.append(Paragraph("Security Assessment Report", styles["Heading2"]))
    story.append(Spacer(1, 0.3 * inch))

    company_data = [
        ["Company Name:", data["company_info"]["name"]],
        ["Industry:", data["company_info"]["industry"]],
        ["Report Date:", data["scan_summary"]["timestamp"]],
        ["Contact:", data["company_info"]["contact"]],
    ]
    company_table = Table(company_data, colWidths=[2 * inch, 4 * inch])
    company_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (0, -1), colors.grey),
                ("TEXTCOLOR", (0, 0), (0, -1), colors.whitesmoke),
                ("ALIGN", (0, 0), (-1, -1), "LEFT"),
                ("FONTNAME", (0, 0), (-1, -1), "Helvetica"),
                ("FONTSIZE", (0, 0), (-1, -1), 10),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 12),
                ("GRID", (0, 0), (-1, -1), 1, colors.black),
            ]
        )
    )
    story.append(company_table)
    story.append(PageBreak())

    story.append(Paragraph("EXECUTIVE SUMMARY", title_style))
    story.append(Spacer(1, 0.2 * inch))
    summary_data = [
        ["Metric", "Value", "Risk Level"],
        ["Total Employees Scanned", str(data["scan_summary"]["total_employees"]), "INFO"],
        [
            "Breached Email Accounts",
            str(data["scan_summary"]["breached_emails"]),
            "CRITICAL" if data["scan_summary"]["breached_emails"] > 0 else "SAFE",
        ],
        ["Total Assets Scanned", str(data["scan_summary"]["total_assets"]), "INFO"],
        [
            "Insecure Websites (No SSL)",
            str(data["scan_summary"]["insecure_assets"]),
            "CRITICAL" if data["scan_summary"]["insecure_assets"] > 0 else "SAFE",
        ],
    ]
    summary_table = Table(summary_data, colWidths=[2.5 * inch, 1.5 * inch, 1.5 * inch])
    summary_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1a237e")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
                ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, 0), 12),
                ("BOTTOMPADDING", (0, 0), (-1, 0), 12),
                ("GRID", (0, 0), (-1, -1), 1, colors.black),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.lightgrey]),
            ]
        )
    )
    story.append(summary_table)
    story.append(Spacer(1, 0.3 * inch))

    story.append(Paragraph("A07:2025 - AUTHENTICATION FAILURES", heading_style))
    story.append(Paragraph("Employee Credential Exposure Analysis", styles["Normal"]))
    story.append(Spacer(1, 0.1 * inch))
    breached_emails = [e for e in data["email_findings"] if e.get("is_breached")]
    if breached_emails:
        email_table_data = [["Employee", "Email", "Breach Count", "Exposed In"]]
        for email in breached_emails[:10]:
            email_table_data.append(
                [
                    email.get("name", "N/A"),
                    email["email"],
                    str(email.get("breach_count", 0)),
                    ", ".join(email.get("breaches", [])[:2]),
                ]
            )
        email_table = Table(email_table_data, colWidths=[1.5 * inch, 2 * inch, 1 * inch, 2 * inch])
        email_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.red),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
                    ("ALIGN", (0, 0), (-1, -1), "LEFT"),
                    ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                    ("FONTSIZE", (0, 0), (-1, -1), 8),
                    ("GRID", (0, 0), (-1, -1), 1, colors.black),
                    ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.lightgrey]),
                ]
            )
        )
        story.append(email_table)
        story.append(Spacer(1, 0.2 * inch))
        story.append(
            Paragraph(
                f"<b>Recommendation:</b> Force immediate password reset for {len(breached_emails)} affected accounts. "
                "Implement Multi-Factor Authentication (MFA) organization-wide.",
                styles["Normal"],
            )
        )
    else:
        story.append(Paragraph("✅ No employee credentials found in known breach databases.", styles["Normal"]))
    story.append(PageBreak())

    story.append(Paragraph("A02:2025 & A04:2025 - MISCONFIGURATION & CRYPTOGRAPHY", heading_style))
    story.append(Spacer(1, 0.1 * inch))
    asset_table_data = [["Asset URL", "SSL Status", "Header Score", "Overall Risk"]]
    for asset in data["asset_findings"]:
        ssl_status = "✅ Valid" if asset["ssl"].get("has_ssl") else "❌ Missing"
        header_score = asset["headers"].get("grade", "F")
        risk = (
            "HIGH"
            if not asset["ssl"].get("has_ssl")
            else "MEDIUM"
            if asset["headers"].get("score", 0) < 70
            else "LOW"
        )
        asset_table_data.append([asset["url"][:40], ssl_status, header_score, risk])

    asset_table = Table(asset_table_data, colWidths=[2.5 * inch, 1.5 * inch, 1 * inch, 1 * inch])
    asset_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1a237e")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
                ("ALIGN", (0, 0), (-1, -1), "LEFT"),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 9),
                ("GRID", (0, 0), (-1, -1), 1, colors.black),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.lightgrey]),
            ]
        )
    )
    story.append(asset_table)
    story.append(Spacer(1, 0.3 * inch))

    story.append(Paragraph("STRATEGIC RECOMMENDATIONS", heading_style))
    recommendations = [
        "1. Install SSL certificates on all non-HTTPS domains immediately (Use Let's Encrypt for free certificates)",
        "2. Implement security headers: X-Frame-Options, CSP, HSTS on all web properties",
        "3. Deploy password manager and MFA for all employees within 7 days",
        "4. Conduct quarterly security awareness training focusing on phishing prevention",
        "5. Subscribe to CyberShield Premium for continuous monitoring and automated alerts",
    ]
    for rec in recommendations:
        story.append(Paragraph(rec, styles["Normal"]))
        story.append(Spacer(1, 0.1 * inch))
    doc.build(story)


@router.post(
    "/report",
    summary="Generate SMB security report from CSV uploads",
    description="Accepts employee and asset CSVs, performs passive checks, and returns report metadata.",
)
async def generate_smb_report_from_csv(
    background_tasks: BackgroundTasks,
    company_name: str = Form(...),
    industry: str = Form(...),
    employee_count: str = Form(...),
    contact_name: str = Form(...),
    contact_email: EmailStr = Form(...),
    security_priorities: str = Form(...),
    employees_csv: UploadFile = File(...),
    assets_csv: UploadFile = File(...),
):
    """Generate comprehensive SMB security report (passive checks only)."""
    try:
        employees_df = pd.read_csv(io.BytesIO(await employees_csv.read()))
        assets_df = pd.read_csv(io.BytesIO(await assets_csv.read()))
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=400, detail=f"Invalid CSV upload: {exc}")

    if "email" not in [c.lower() for c in employees_df.columns]:
        raise HTTPException(status_code=400, detail="Employee CSV must include an 'Email' column")
    if not any(col.lower() == "url" for col in assets_df.columns):
        raise HTTPException(status_code=400, detail="Assets CSV must include a 'URL' column")

    employees_df.columns = [c.lower() for c in employees_df.columns]
    assets_df.columns = [c.lower() for c in assets_df.columns]

    email_results = []
    for _, row in employees_df.iterrows():
        result = await check_email_breach(row.get("email"))
        result["name"] = row.get("name", "N/A")
        result["role"] = row.get("role", "Employee")
        email_results.append(result)
        await asyncio.sleep(0.2)

    asset_results = []
    for _, row in assets_df.iterrows():
        url = row.get("url")
        ssl_check, headers_check, vt_check = await asyncio.gather(
            check_ssl_certificate(url),
            check_security_headers(url),
            check_malware_virustotal(url, settings.VIRUSTOTAL_API_KEY),
        )
        asset_results.append({"url": url, "ssl": ssl_check, "headers": headers_check, "malware": vt_check})
        await asyncio.sleep(0.2)

    report_data = {
        "company_info": {
            "name": company_name,
            "industry": industry,
            "employee_count": employee_count,
            "contact": contact_name,
            "email": contact_email,
            "security_priorities": security_priorities,
        },
        "scan_summary": {
            "total_employees": len(employees_df),
            "total_assets": len(assets_df),
            "breached_emails": sum(1 for e in email_results if e.get("is_breached")),
            "insecure_assets": sum(1 for a in asset_results if not a["ssl"].get("has_ssl")),
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        },
        "email_findings": email_results,
        "asset_findings": asset_results,
        "google_dorks": generate_google_dorks(company_name),
    }

    report_id = str(uuid.uuid4())[:8]
    os.makedirs("reports", exist_ok=True)
    pdf_path = f"reports/cybershield_{company_name.replace(' ', '_')}_{report_id}.pdf"

    background_tasks.add_task(generate_pdf_report, pdf_path, report_data)

    return {
        "status": "success",
        "report_id": report_id,
        "download_url": f"/smb/download/{report_id}",
        "summary": report_data["scan_summary"],
        "message": "Report generation started",
    }


@router.post(
    "/report/json",
    summary="Generate SMB security report from JSON payload",
    description="Accepts employee and asset lists (JSON), performs passive checks, and returns report metadata.",
)
async def generate_smb_report_from_json(payload: SMBReportDataRequest, background_tasks: BackgroundTasks):
    if not payload.employees_data:
        raise HTTPException(status_code=400, detail="At least one employee is required")
    if not payload.assets_data:
        raise HTTPException(status_code=400, detail="At least one asset is required")

    email_results = []
    for employee in payload.employees_data:
        result = await check_email_breach(employee.email)
        result["name"] = employee.name
        result["role"] = employee.role
        email_results.append(result)
        await asyncio.sleep(0.2)

    asset_results = []
    for asset in payload.assets_data:
        ssl_check, headers_check, vt_check = await asyncio.gather(
            check_ssl_certificate(asset.url),
            check_security_headers(asset.url),
            check_malware_virustotal(asset.url, settings.VIRUSTOTAL_API_KEY),
        )
        asset_results.append(
            {
                "url": asset.url,
                "type": asset.asset_type,
                "ssl": ssl_check,
                "headers": headers_check,
                "malware": vt_check,
            }
        )
        await asyncio.sleep(0.2)

    report_data = {
        "company_info": {
            "name": payload.company_name,
            "industry": payload.industry,
            "employee_count": payload.employee_count,
            "contact": payload.contact_name,
            "email": payload.contact_email,
            "security_priorities": payload.security_priorities,
        },
        "scan_summary": {
            "total_employees": len(payload.employees_data),
            "total_assets": len(payload.assets_data),
            "breached_emails": sum(1 for e in email_results if e.get("is_breached")),
            "insecure_assets": sum(1 for a in asset_results if not a["ssl"].get("has_ssl")),
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        },
        "email_findings": email_results,
        "asset_findings": asset_results,
        "google_dorks": generate_google_dorks(payload.company_name),
    }

    report_id = str(uuid.uuid4())[:8]
    os.makedirs("reports", exist_ok=True)
    pdf_path = f"reports/cybershield_{payload.company_name.replace(' ', '_')}_{report_id}.pdf"
    background_tasks.add_task(generate_pdf_report, pdf_path, report_data)

    return {
        "status": "success",
        "report_id": report_id,
        "download_url": f"/smb/download/{report_id}",
        "summary": report_data["scan_summary"],
        "message": "Report generation started",
    }


@router.get("/download/{report_id}", summary="Download generated SMB report PDF")
async def download_report(report_id: str):
    report_dir = "reports"
    if not os.path.isdir(report_dir):
        raise HTTPException(status_code=404, detail="Report not found")
    for filename in os.listdir(report_dir):
        if report_id in filename:
            return FileResponse(os.path.join(report_dir, filename), media_type="application/pdf", filename=filename)
    raise HTTPException(status_code=404, detail="Report not found")
