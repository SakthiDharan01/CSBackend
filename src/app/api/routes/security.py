import re
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Dict, List, Literal, Optional
from urllib.parse import urlparse

import httpx
import requests
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
    breach_findings: Optional[dict] = None
    google_dorks: Optional[Dict[str, str]] = None
    malware_search_urls: Optional[List[str]] = None


class EmailSecurityRequest(BaseModel):
    email: EmailStr


class WebsiteSecurityRequest(BaseModel):
    url: HttpUrl


class WebsiteAssessmentRequest(BaseModel):
    url: HttpUrl


class EmailAnalysisResponse(BaseModel):
    email: EmailStr
    risk_score: int
    risk_level: Literal["Low", "Medium", "High", "Critical"]
    flags: List[str]
    details: Dict[str, Any]
    sources: Dict[str, Any]


def generate_google_dorks_for_domain(domain: str) -> Dict[str, str]:
    clean = str(domain).replace("https://", "").replace("http://", "").strip("/")
    return {
        "Exposed Emails": f"https://www.google.com/search?q=\"@{clean}\"+filetype:txt+OR+filetype:csv",
        "Exposed Configs": f"https://www.google.com/search?q=site:{clean}+ext:env+OR+ext:ini+OR+ext:config",
        "Admin Panels": f"https://www.google.com/search?q=site:{clean}+inurl:admin+OR+inurl:login+OR+inurl:dashboard",
        "Backups": f"https://www.google.com/search?q=site:{clean}+ext:bak+OR+ext:sql+OR+ext:zip",
        "Git/SVN": f"https://www.google.com/search?q=site:{clean}+%5C.git+OR+%5C.svn",
        "Malware Listings": f"https://www.google.com/search?q=site:urlhaus.abuse.ch+{clean}+OR+site:virustotal.com+{clean}",
    }


def google_dorks_for_email(email: str) -> Dict[str, str]:
    return {
        "Email Exposures": f"https://www.google.com/search?q=\"{email}\"+filetype:txt+OR+filetype:csv+OR+filetype:xls",
        "Paste Sites": f"https://www.google.com/search?q=\"{email}\"+site:pastebin.com+OR+site:paste.ee",
    }


def malware_search_urls(domain: str) -> List[str]:
    clean = str(domain).replace("https://", "").replace("http://", "").strip("/")
    return [
        f"https://urlhaus.abuse.ch/browse.php?search={clean}",
        f"https://www.virustotal.com/gui/domain/{clean}/relations",
        f"https://urlscan.io/search/#{clean}",
    ]


def hibp_email_breach(email: str, api_key: str) -> dict:
    if not api_key:
        return {"status": "not_configured", "email": email}
    headers = {
        "hibp-api-key": api_key,
        "user-agent": "CyberShield-Backend/1.0",
    }
    url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}"
    try:
        response = requests.get(url, headers=headers, timeout=10, params={"truncateResponse": "false"})
        if response.status_code == 404:
            return {"status": "clear", "email": email, "breaches": []}
        if response.status_code == 200:
            breaches = response.json()
            return {
                "status": "breached",
                "email": email,
                "breach_count": len(breaches),
                "breaches": [b.get("Name") for b in breaches],
            }
        return {"status": "unknown", "email": email, "http_status": response.status_code}
    except Exception as exc:  # noqa: BLE001
        return {"status": "error", "email": email, "error": str(exc)}


EMAIL_REGEX = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"


def validate_email_syntax(email: str) -> bool:
    return re.match(EMAIL_REGEX, email) is not None


def extract_domain(email: str) -> str:
    return email.split("@")[-1]


def check_emailrep(email: str) -> Dict[str, Any]:
    try:
        resp = requests.get(f"https://emailrep.io/{email}", timeout=3)
        if resp.status_code == 200:
            data = resp.json()
            return {
                "reputation": data.get("reputation", "unknown"),
                "suspicious": data.get("suspicious", False),
                "blacklisted": data.get("details", {}).get("blacklisted", False),
                "malicious_activity": data.get("details", {}).get("malicious_activity", False),
                "spam": data.get("details", {}).get("spam", False),
                "free": data.get("details", {}).get("free", False),
                "suspicious_tld": data.get("details", {}).get("suspicious_tld", False),
                "days_since_domain_creation": data.get("details", {}).get("days_since_domain_creation", 0),
                "free_provider": data.get("details", {}).get("free_provider", False),
            }
    except Exception:  # noqa: BLE001
        pass
    return {}


def check_leakcheck(email: str) -> Dict[str, Any]:
    try:
        resp = requests.get(f"https://leakcheck.io/api/public?check={email}", timeout=3)
        if resp.status_code == 200:
            data = resp.json()
            return {
                "found": data.get("found", 0),
                "sources": data.get("sources", []),
                "fields": data.get("fields", []),
            }
    except Exception:  # noqa: BLE001
        pass
    return {}


def check_verifier(email: str) -> Dict[str, Any]:
    try:
        resp = requests.get(f"https://verifier.meetchopra.com/verify/{email}", timeout=3)
        if resp.status_code == 200:
            data = resp.json()
            return {
                "status": data.get("status", "unknown"),
                "smtp_check": data.get("smtp_check", False),
                "deliverable": data.get("deliverable", False),
                "disposable": data.get("disposable", False),
            }
    except Exception:  # noqa: BLE001
        pass
    return {}


def check_https(domain: str) -> bool:
    try:
        resp = requests.get(f"https://{domain}", timeout=3, allow_redirects=True)
        return resp.url.startswith("https://")
    except Exception:  # noqa: BLE001
        return False


def hibp_breach_free(email: str) -> Dict[str, Any]:
    """Wrapper using configured HIBP key when present; graceful otherwise."""
    api_key = settings.HIBP_API_KEY
    result = hibp_email_breach(email, api_key)
    if not api_key:
        result.setdefault("status", "not_configured")
    return result


def run_parallel_checks(email: str) -> Dict[str, Any]:
    domain = extract_domain(email)
    checks = {
        "emailrep": lambda: check_emailrep(email),
        "leakcheck": lambda: check_leakcheck(email),
        "hibp": lambda: hibp_breach_free(email),
        "verifier": lambda: check_verifier(email),
        "https": lambda: check_https(domain),
    }
    results: Dict[str, Any] = {}
    with ThreadPoolExecutor(max_workers=5) as executor:
        future_map = {executor.submit(func): name for name, func in checks.items()}
        for future in as_completed(future_map):
            name = future_map[future]
            try:
                results[name] = future.result()
            except Exception as exc:  # noqa: BLE001
                results[name] = {"error": str(exc)}
    return results


def calculate_risk_score(results: Dict[str, Any]) -> int:
    score = 0
    emailrep = results.get("emailrep", {})
    if emailrep.get("reputation") == "low" or emailrep.get("suspicious"):
        score += 20
    if emailrep.get("free") or emailrep.get("suspicious_tld"):
        score += 15
    if emailrep.get("free_provider"):
        score += 10
    if emailrep.get("days_since_domain_creation", 0) < 30:
        score += 10

    leakcheck = results.get("leakcheck", {})
    score += leakcheck.get("found", 0) * 10
    sensitive_fields = {"password", "username", "name", "address", "phone"}
    for field in leakcheck.get("fields", []) or []:
        if field in sensitive_fields:
            score += 5

    hibp = results.get("hibp", {})
    for breach in hibp.get("breaches", []) or []:
        data_classes = breach.get("DataClasses", []) or []
        if "Passwords" in data_classes or any("financial" in dc.lower() for dc in data_classes):
            score += 5

    verifier = results.get("verifier", {})
    if verifier.get("status") == "invalid":
        score += 10
    if not verifier.get("deliverable", True):
        score += 15
    if verifier.get("disposable"):
        score += 25

    if not results.get("https", False):
        score += 10

    return min(score, 100)


def get_risk_level(score: int) -> str:
    if score <= 20:
        return "Low"
    if score <= 50:
        return "Medium"
    if score <= 75:
        return "High"
    return "Critical"


def generate_flags(results: Dict[str, Any]) -> List[str]:
    flags: List[str] = []
    emailrep = results.get("emailrep", {})
    if emailrep.get("reputation") == "low" or emailrep.get("suspicious"):
        flags.append("High fraud risk")
    if emailrep.get("free") or emailrep.get("suspicious_tld"):
        flags.append("Likely burner account")
    if emailrep.get("free_provider"):
        flags.append("Free email provider used")
    if emailrep.get("days_since_domain_creation", 0) < 30:
        flags.append("Very new domain (suspicious)")

    leakcheck = results.get("leakcheck", {})
    if leakcheck.get("found", 0) > 0:
        flags.append(f"Appears in {leakcheck['found']} breaches")

    verifier = results.get("verifier", {})
    if verifier.get("status") == "invalid":
        flags.append("Invalid email format")
    if not verifier.get("deliverable", True):
        flags.append("Mailbox doesn't exist")
    if verifier.get("disposable"):
        flags.append("Disposable email detected")

    if not results.get("https", False):
        flags.append("Domain lacks HTTPS")

    return flags


def generate_details(results: Dict[str, Any]) -> Dict[str, Any]:
    details: Dict[str, Any] = {}
    emailrep = results.get("emailrep", {})
    details["reputation"] = emailrep.get("reputation", "unknown")
    details["disposable"] = results.get("verifier", {}).get("disposable", False)
    details["domain_age_days"] = emailrep.get("days_since_domain_creation", 0)
    details["https_enabled"] = results.get("https", False)

    leakcheck = results.get("leakcheck", {})
    details["breaches"] = [source.get("name") for source in leakcheck.get("sources", []) or []]
    details["hibp_status"] = results.get("hibp", {}).get("status")

    return details


@router.post("/email", response_model=SecurityScoreResponse, summary="Evaluate email security")
def email_security_score(payload: EmailSecurityRequest) -> SecurityScoreResponse:
    """Return security score plus breach OSINT (HIBP if configured)."""
    base_score = settings.SECURITY_DEFAULT_SCORE
    components = [
        SecurityComponent(name="DMARC", score=base_score * 0.9, description="Placeholder DMARC assessment."),
        SecurityComponent(name="SPF", score=base_score * 0.85, description="Placeholder SPF assessment."),
        SecurityComponent(name="Phishing Risk", score=base_score * 0.8, description="Placeholder phishing risk."),
    ]
    hibp_result = hibp_email_breach(payload.email, settings.HIBP_API_KEY)
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
        breach_findings=hibp_result,
        google_dorks=google_dorks_for_email(payload.email),
    )


@router.post(
    "/email/analyze",
    response_model=EmailAnalysisResponse,
    summary="Deep email OSINT analysis",
    description=(
        "Runs passive reputation and breach checks (EmailRep, LeakCheck, HIBP if configured, Verifier, HTTPS) "
        "and returns a consolidated risk score, flags, and details."
    ),
)
def analyze_email(payload: EmailSecurityRequest) -> EmailAnalysisResponse:
    email = payload.email
    if not validate_email_syntax(email):
        # Pydantic already validates, but keep explicit safety net
        raise ValueError("Invalid email format")

    results = run_parallel_checks(email)
    risk_score = calculate_risk_score(results)
    risk_level = get_risk_level(risk_score)
    flags = generate_flags(results)
    details = generate_details(results)

    return EmailAnalysisResponse(
        email=email,
        risk_score=risk_score,
        risk_level=risk_level,
        flags=flags,
        details=details,
        sources=results,
    )


@router.post("/website", response_model=SecurityScoreResponse, summary="Evaluate website security")
def website_security_score(payload: WebsiteSecurityRequest) -> SecurityScoreResponse:
    """Return a placeholder security score for a website URL."""
    url_str = str(payload.url)
    url_clean = url_str[:-1] if url_str.endswith("/") else url_str
    base_score = settings.SECURITY_DEFAULT_SCORE
    components = [
        SecurityComponent(name="TLS", score=base_score * 0.92, description="Placeholder TLS assessment."),
        SecurityComponent(name="Content Security Policy", score=base_score * 0.7, description="Placeholder CSP review."),
        SecurityComponent(name="Vulnerability Scan", score=base_score * 0.78, description="Placeholder scan summary."),
    ]
    overall = sum(component.score for component in components) / len(components)
    return SecurityScoreResponse(
        target=url_clean,
        kind="website",
        overall_score=round(overall, 2),
        components=components,
        recommendations=[
            "Force HTTPS and HSTS",
            "Deploy a strict Content Security Policy",
            "Run routine vulnerability scans",
        ],
        google_dorks=generate_google_dorks_for_domain(url_clean),
        malware_search_urls=malware_search_urls(url_clean),
    )


COMMON_PORTS: Dict[int, str] = {
    80: "http",
    443: "https",
    21: "ftp",
    22: "ssh",
    25: "smtp",
    110: "pop3",
    143: "imap",
    465: "smtps",
    587: "smtp-submission",
    993: "imaps",
    995: "pop3s",
    3306: "mysql",
    5432: "postgresql",
    8080: "http-alt",
    8443: "https-alt",
}

PORT_RISK: Dict[int, str] = {
    80: "MEDIUM",
    443: "LOW",
    21: "HIGH",
    22: "MEDIUM",
    25: "MEDIUM",
    110: "MEDIUM",
    143: "MEDIUM",
    465: "LOW",
    587: "LOW",
    993: "LOW",
    995: "LOW",
    3306: "HIGH",
    5432: "HIGH",
    8080: "MEDIUM",
    8443: "LOW",
}

RECOMMENDED_HEADERS: Dict[str, str] = {
    "Strict-Transport-Security": "Enforces HTTPS for clients",
    "Content-Security-Policy": "Mitigates XSS and data injection",
    "X-Frame-Options": "Prevents clickjacking",
    "X-Content-Type-Options": "Prevents MIME sniffing",
    "Referrer-Policy": "Controls referrer leakage",
}


def _extract_hostname(target: str) -> str:
    target = str(target)
    parsed = urlparse(target)
    if parsed.hostname:
        return parsed.hostname
    return target.replace("http://", "").replace("https://", "").split("/")[0]


def resolve_domain(target: str) -> List[str]:
    hostname = _extract_hostname(target)
    try:
        infos = socket.getaddrinfo(hostname, None)
        return sorted({info[4][0] for info in infos})
    except socket.gaierror:
        return []


def probe_open_ports(hostname: str, ports: Dict[int, str]) -> List[dict]:
    open_ports: List[dict] = []
    for port, service in ports.items():
        try:
            with socket.create_connection((hostname, port), timeout=0.4):
                open_ports.append(
                    {
                        "port": port,
                        "service": service,
                        "risk_level": PORT_RISK.get(port, "MEDIUM"),
                    }
                )
        except (socket.timeout, ConnectionRefusedError, OSError):
            continue
    return open_ports


def check_security_headers(url: str) -> dict:
    parsed = urlparse(url)
    target = url
    if not parsed.scheme:
        target = f"https://{url}"

    headers: dict = {}
    try:
        with httpx.Client(follow_redirects=True, timeout=4.0) as client:
            response = client.head(target)
            if response.status_code >= 400:
                response = client.get(target)
            headers = dict(response.headers)
    except httpx.RequestError:
        return {"present": [], "missing": list(RECOMMENDED_HEADERS.keys()), "score": 0, "severity": "HIGH"}

    present = []
    missing = []
    header_keys_lower = {h.lower() for h in headers.keys()}
    for header, reason in RECOMMENDED_HEADERS.items():
        if header.lower() in header_keys_lower:
            present.append(header)
        else:
            missing.append({"header": header, "reason": reason})

    score = int((len(present) / len(RECOMMENDED_HEADERS)) * 100) if RECOMMENDED_HEADERS else 100
    severity = "LOW" if score >= 80 else "MEDIUM" if score >= 50 else "HIGH"
    return {"present": present, "missing": missing, "score": score, "severity": severity}


def derive_vulnerabilities(open_ports: List[dict], header_check: dict, resolved_ips: List[str]) -> List[dict]:
    vulns: List[dict] = []
    if not resolved_ips:
        vulns.append(
            {
                "category": "DNS",
                "description": "Domain could not be resolved; services may be unreachable.",
                "severity": "HIGH",
            }
        )

    for port_entry in open_ports:
        port = port_entry["port"]
        service = port_entry["service"]
        risk = port_entry["risk_level"]
        if port in (21, 22):
            vulns.append(
                {
                    "category": "Service Exposure",
                    "description": f"{service.upper()} exposed on port {port}; ensure it requires strong authentication and is access-controlled.",
                    "severity": risk,
                }
            )
        if port in (3306, 5432):
            vulns.append(
                {
                    "category": "Database Exposure",
                    "description": f"Database service exposed on port {port}; restrict to internal networks only.",
                    "severity": "HIGH",
                }
            )
        if port == 80 and all(p["port"] != 443 for p in open_ports):
            vulns.append(
                {
                    "category": "Transport Security",
                    "description": "HTTP exposed without HTTPS; data in transit may be unencrypted.",
                    "severity": "MEDIUM",
                }
            )

    missing_headers = header_check.get("missing", [])
    if missing_headers:
        vulns.append(
            {
                "category": "Security Headers",
                "description": f"Missing headers: {', '.join(h['header'] for h in missing_headers)}",
                "severity": header_check.get("severity", "MEDIUM"),
            }
        )

    return vulns


def compute_security_score(open_ports: List[dict], header_check: dict, resolved_ips: List[str]) -> int:
    score = 100
    if not resolved_ips:
        score -= 25

    for port_entry in open_ports:
        risk = port_entry.get("risk_level", "MEDIUM")
        if risk == "HIGH":
            score -= 15
        elif risk == "MEDIUM":
            score -= 8
        else:
            score -= 4

    missing_count = len(header_check.get("missing", []))
    score -= missing_count * 3
    score = max(0, min(100, score))
    return score


def overall_risk_from_score(score: int) -> str:
    if score >= 80:
        return "LOW"
    if score >= 60:
        return "MEDIUM"
    return "HIGH"


def build_recommended_actions(vulns: List[dict], header_check: dict) -> List[str]:
    actions: List[str] = []
    for v in vulns:
        if v["category"] == "Database Exposure":
            actions.append("Restrict database ports to internal networks or VPN; enforce authentication and TLS.")
        elif v["category"] == "Service Exposure":
            actions.append("Limit SSH/FTP access by IP allowlisting and enable MFA where possible.")
        elif v["category"] == "Transport Security":
            actions.append("Enforce HTTPS with valid TLS certificates and redirect HTTP to HTTPS.")
        elif v["category"] == "DNS":
            actions.append("Verify DNS records and hosting status; ensure the domain resolves correctly.")

    for missing in header_check.get("missing", []):
        header = missing.get("header")
        if header:
            actions.append(f"Add the {header} header: {missing.get('reason', 'improves web security')}.")

    if not actions:
        actions.append("Maintain regular security reviews and monitoring for new exposures.")
    return actions


@router.post(
    "/assessment",
    summary="Passive website assessment",
    description=(
        "Performs passive, consent-based checks for a target URL: DNS resolution, limited open-port detection, "
        "basic header review, and risk estimation. No exploitation or intrusive actions are performed."
    ),
)
def website_passive_assessment(payload: WebsiteAssessmentRequest) -> dict:
    url_str = str(payload.url)
    url_clean = url_str[:-1] if url_str.endswith("/") else url_str
    hostname = _extract_hostname(url_clean)
    resolved_ips = resolve_domain(url_clean)
    open_ports = probe_open_ports(hostname, COMMON_PORTS) if resolved_ips else []
    header_check = check_security_headers(url_clean)
    vulnerabilities = derive_vulnerabilities(open_ports, header_check, resolved_ips)
    score = compute_security_score(open_ports, header_check, resolved_ips)
    risk = overall_risk_from_score(score)
    actions = build_recommended_actions(vulnerabilities, header_check)

    return {
        "url": url_clean,
        "open_ports": open_ports,
        "possible_vulnerabilities": vulnerabilities,
        "security_score": score,
        "overall_risk": risk,
        "recommended_actions": actions,
        "google_dorks": generate_google_dorks_for_domain(url_clean),
        "malware_search_urls": malware_search_urls(url_clean),
        "disclaimer": "Results are based on passive analysis of publicly accessible information.",
    }
