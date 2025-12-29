# bug-detector-50993-51124

BackendAPIandUserManagement

Quick start
- Install requirements: pip install -r BackendAPIandUserManagement/requirements.txt
- Create environment: copy BackendAPIandUserManagement/.env.example to .env and set variables (JWT_SECRET, FRONTEND_ORIGIN, DATABASE_DSN, ANALYSIS_ENGINE_URL, INTEGRATION_SERVICE_URL).
- DB DSN: If DATABASE_DSN is not set, the backend will try to read db_connection.txt (containing a line with postgresql://...) and will auto-convert to asyncpg DSN. Otherwise it falls back to SQLite.
- Run: uvicorn api.main:app --host 0.0.0.0 --port 8000 --reload --app-dir BackendAPIandUserManagement/src

CORS
- CORS is enabled from FRONTEND_ORIGIN (single or comma-separated list).

Integration health
- GET /health/integration returns a JSON summary checking:
  - DB connectivity
  - SourceCodeAnalysisEngine reachability (ports 3001)
  - IntegrationService reachability (ports 3003)
- 200 when all OK, 503 otherwise.

Auth flow (end-to-end)
1) Register or use seeded admin (admin/admin123).
2) POST /auth/login with JSON {"username":"admin","password":"admin123"} to get access_token.
3) Use Authorization: Bearer <token> for subsequent calls.
4) Frontend must set REACT_APP_BACKEND_BASE_URL to point to this backend (e.g., http://localhost:8000) and store JWT after login. All API calls include Authorization header.

Jobs and external services
- Submit job: POST /jobs (requires 'jobs:write') with {"repository_url":"https://repo","branch":"main","language":"python"}.
- Backend forwards to AnalysisEngine /analyze and stores the returned engine job_id, if available.
- List jobs: GET /jobs shows engine_job_id when present.
- Get job: GET /jobs/{id} fetches results from AnalysisEngine /results/{engine_job_id} when available.
- Stub helpers:
  - GET /_stubs/analysis/results/{job_id}
  - GET /_stubs/integrations/endpoints
- Notifications: POST /notifications persists a notification and calls IntegrationService /integrations/trigger with a "notify" payload.

Verification checklist
- With DB running and DSN set (or db_connection.txt present):
  - GET /health/integration => {"database":{"ok":true}, "analysis_engine":{"ok":true}, "integration_service":{"ok":true}}
  - Login to obtain JWT, then:
    - GET /users -> 403 unless you grant 'users:read' or use admin account.
    - POST /jobs -> returns {"job_id": "...", "engine_job_id": "..."} and appears in GET /jobs.
    - GET /jobs/{job_id} -> includes engine_results when AnalysisEngine has produced them.
    - POST /notifications -> returns queued and triggers IntegrationService.

Environment for frontend
- In WebDashboardFrontend create .env.local with:
  REACT_APP_BACKEND_BASE_URL=http://localhost:8000

Notes
- The backend seeds an admin user and basic permissions on first start when database is empty.
- For PostgreSQL schema management, apply provided schema externally; the app will not run migrations automatically (it creates tables only in SQLite dev mode).