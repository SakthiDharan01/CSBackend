# CyberShield Backend (FastAPI Template)

Starter FastAPI template to power the CyberShield frontend. It exposes placeholder endpoints for security scoring and SMB report generation so the Next.js UI can be wired up quickly.

## Endpoints
- `GET /health` — simple availability check.
- `POST /security_score/email` — accepts `{ "email": "user@example.com" }` and returns a mock email security score.
- `POST /security_score/website` — accepts `{ "url": "https://example.com" }` and returns a mock website security score.
- `POST /smb/report_generation` — accepts `{ "business_name": "Acme", "assets": ["website"] }` plus optional `contact_email` and returns a stub SMB security report.

## Quickstart
1. Create and activate a virtual environment (optional but recommended).
2. Install dependencies:
   - `pip install -r requirements.txt`
3. Copy the environment template and adjust values if needed:
   - `cp .env.example .env`
4. Run the API (serves at http://127.0.0.1:8000 by default):
   - `uvicorn app.main:app --reload --app-dir src`
5. Open interactive docs:
   - Swagger UI: http://127.0.0.1:8000/docs
   - ReDoc: http://127.0.0.1:8000/redoc

## Testing
- Ensure `PYTHONPATH=./src` (or use the provided `tests/conftest.py` path shim) and run:
  - `pytest -q`

## Notes
- Logic is intentionally placeholder: replace component scoring and report generation with real scanners and data sources.
- Settings are loaded from `.env` (see `.env.example`).
