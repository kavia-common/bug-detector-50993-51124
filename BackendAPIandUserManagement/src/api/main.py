from __future__ import annotations

import base64
import csv
import io
import json
import os
from datetime import datetime, timedelta, timezone
from typing import AsyncGenerator, Dict, List, Optional, Sequence, Tuple

import httpx
from fastapi import Depends, FastAPI, HTTPException, Query, Response, Security
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, Text, func, select
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship
from starlette.responses import StreamingResponse
from dotenv import load_dotenv
import hashlib
import hmac

# --------------------------------------------------------------------------------------
# Settings and configuration
# --------------------------------------------------------------------------------------

class Settings(BaseModel):
    """Runtime configuration loaded from environment and db_connection.txt."""
    app_name: str = "Bug Detector Backend API"
    app_version: str = "1.0.0"
    jwt_secret: str = Field(default="change-me", description="Secret used to sign JWTs")
    jwt_algorithm: str = "HS256"
    access_token_expires_minutes: int = 60
    cors_origins: List[str] = Field(default_factory=lambda: ["http://localhost:3000"])
    database_url: str = "sqlite+aiosqlite:///./dev.db"
    analysis_engine_url: str = "http://localhost:3001"
    integration_service_url: str = "http://localhost:3003"
    backend_base_url: Optional[str] = None

# PUBLIC_INTERFACE
def load_settings() -> Settings:
    """Load settings from .env and db_connection.txt if present.

    Environment variables:
    - DATABASE_DSN (preferred) or DATABASE_URL: async SQLAlchemy URL, e.g., postgresql+asyncpg://...
    - JWT_SECRET: JWT signing secret
    - FRONTEND_ORIGIN: single origin or comma-separated list for CORS
    - ANALYSIS_ENGINE_URL: base URL to SourceCodeAnalysisEngine
    - INTEGRATION_SERVICE_URL: base URL to IntegrationService
    - BACKEND_BASE_URL: public base URL for this backend (optional)
    """
    load_dotenv()
    # database: priority .env DATABASE_DSN, then DATABASE_URL, then db_connection.txt parsing, else default sqlite
    db_url = os.getenv("DATABASE_DSN") or os.getenv("DATABASE_URL")
    if not db_url:
        # ALWAYS read connection from db_connection.txt if present
        here = os.path.dirname(__file__)
        candidates = [
            os.path.join(here, "..", "..", "db_connection.txt"),
            os.path.join(here, "..", "db_connection.txt"),
            "db_connection.txt",
        ]
        for candidate in candidates:
            if os.path.exists(candidate):
                try:
                    with open(candidate, "r", encoding="utf-8") as f:
                        txt = f.read().strip()
                    # common format: "psql postgresql://user:pass@host:5432/dbname"
                    if "postgresql://" in txt:
                        start = txt.find("postgresql://")
                        db_url = txt[start:].strip()
                        # ensure async driver for SQLAlchemy
                        if db_url.startswith("postgresql://"):
                            db_url = db_url.replace("postgresql://", "postgresql+asyncpg://", 1)
                        break
                except Exception:
                    pass
    if not db_url:
        db_url = "sqlite+aiosqlite:///./dev.db"

    jwt_secret = os.getenv("JWT_SECRET", "change-me")
    # prefer FRONTEND_ORIGIN, fallback to CORS_ORIGINS
    cors = os.getenv("FRONTEND_ORIGIN") or os.getenv("CORS_ORIGINS", "http://localhost:3000")
    cors_list = [c.strip() for c in cors.split(",") if c.strip()]
    analysis_url = os.getenv("ANALYSIS_ENGINE_URL", "http://localhost:3001")
    integration_url = os.getenv("INTEGRATION_SERVICE_URL", "http://localhost:3003")
    backend_base = os.getenv("BACKEND_BASE_URL")
    return Settings(
        database_url=db_url,
        jwt_secret=jwt_secret,
        cors_origins=cors_list or ["http://localhost:3000"],
        analysis_engine_url=analysis_url,
        integration_service_url=integration_url,
        backend_base_url=backend_base,
    )

settings = load_settings()

# --------------------------------------------------------------------------------------
# App and CORS
# --------------------------------------------------------------------------------------

openapi_tags = [
       {"name": "health", "description": "Health and diagnostics"},
       {"name": "auth", "description": "Authentication endpoints"},
       {"name": "users", "description": "User management"},
       {"name": "roles", "description": "Role and permission management"},
       {"name": "jobs", "description": "Analysis jobs"},
       {"name": "reports", "description": "Bug reports and export"},
       {"name": "notifications", "description": "Notification operations"},
       {"name": "metrics", "description": "Metrics and system info"},
]

app = FastAPI(
    title=settings.app_name,
    version=settings.app_version,
    description="REST API for job orchestration, bug report management, user authentication, and integration.",
    openapi_tags=openapi_tags,
)

# Enable CORS using FRONTEND_ORIGIN or defaults
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --------------------------------------------------------------------------------------
# Database (SQLAlchemy Async)
# --------------------------------------------------------------------------------------

class Base(DeclarativeBase):
    pass

# Association tables modeled as explicit classes for CRUD simplicity
class UserRole(Base):
    __tablename__ = "UserRole"
    user_id: Mapped[int] = mapped_column(ForeignKey("User.id", ondelete="CASCADE"), primary_key=True)
    role_id: Mapped[int] = mapped_column(ForeignKey("Role.id", ondelete="CASCADE"), primary_key=True)

class RolePermission(Base):
    __tablename__ = "RolePermission"
    role_id: Mapped[int] = mapped_column(ForeignKey("Role.id", ondelete="CASCADE"), primary_key=True)
    permission_id: Mapped[int] = mapped_column(ForeignKey("Permission.id", ondelete="CASCADE"), primary_key=True)

class User(Base):
    __tablename__ = "User"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    username: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    email: Mapped[str] = mapped_column(String(128), unique=True, nullable=False)
    password_hash: Mapped[str] = mapped_column(String(256), nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    is_superuser: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    mfa_secret: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=func.now(), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=func.now(), onupdate=func.now(), nullable=False)

    roles: Mapped[List["Role"]] = relationship(secondary="UserRole", back_populates="users")

class Role(Base):
    __tablename__ = "Role"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(32), unique=True, nullable=False)
    description: Mapped[Optional[str]] = mapped_column(String(256))
    created_at: Mapped[datetime] = mapped_column(DateTime, default=func.now(), nullable=False)

    users: Mapped[List[User]] = relationship(secondary="UserRole", back_populates="roles")
    permissions: Mapped[List["Permission"]] = relationship(secondary="RolePermission", back_populates="roles")

class Permission(Base):
    __tablename__ = "Permission"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    description: Mapped[Optional[str]] = mapped_column(String(256))

    roles: Mapped[List[Role]] = relationship(secondary="RolePermission", back_populates="permissions")

class BugReport(Base):
    __tablename__ = "BugReport"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    title: Mapped[str] = mapped_column(String(256), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text)
    # expected enums by schema: low, medium, high, critical
    severity: Mapped[str] = mapped_column(String(16), nullable=False)
    # expected enums by schema: open, in_progress, resolved, closed
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="open")
    assigned_to: Mapped[Optional[int]] = mapped_column(ForeignKey("User.id"))
    created_by: Mapped[int] = mapped_column(ForeignKey("User.id"), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=func.now(), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=func.now(), onupdate=func.now(), nullable=False)
    exported: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

class BugReportComment(Base):
    __tablename__ = "BugReportComment"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    bug_report_id: Mapped[int] = mapped_column(ForeignKey("BugReport.id", ondelete="CASCADE"), nullable=False)
    user_id: Mapped[int] = mapped_column(ForeignKey("User.id"), nullable=False)
    comment: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=func.now(), nullable=False)

class BugReportAttachment(Base):
    __tablename__ = "BugReportAttachment"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    bug_report_id: Mapped[int] = mapped_column(ForeignKey("BugReport.id", ondelete="CASCADE"), nullable=False)
    file_path: Mapped[str] = mapped_column(String(256), nullable=False)
    uploaded_by: Mapped[int] = mapped_column(ForeignKey("User.id"), nullable=False)
    uploaded_at: Mapped[datetime] = mapped_column(DateTime, default=func.now(), nullable=False)

class AnalysisJob(Base):
    __tablename__ = "AnalysisJob"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    source_code_id: Mapped[int] = mapped_column(ForeignKey("BugReport.id"), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="pending")
    started_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    created_by: Mapped[int] = mapped_column(ForeignKey("User.id"), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=func.now(), nullable=False)

class AuditLog(Base):
    __tablename__ = "AuditLog"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[Optional[int]] = mapped_column(ForeignKey("User.id"), nullable=True)
    action: Mapped[str] = mapped_column(String(128), nullable=False)
    target_type: Mapped[str] = mapped_column(String(64), nullable=False)
    target_id: Mapped[int] = mapped_column(Integer, nullable=False)
    timestamp: Mapped[datetime] = mapped_column(DateTime, default=func.now(), nullable=False)
    details: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

class SystemConfig(Base):
    __tablename__ = "SystemConfig"
    key: Mapped[str] = mapped_column(String(64), primary_key=True)
    value: Mapped[str] = mapped_column(Text, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=func.now(), onupdate=func.now(), nullable=False)

class Notification(Base):
    __tablename__ = "Notification"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("User.id"), nullable=False)
    type: Mapped[str] = mapped_column(String(32), nullable=False)
    message: Mapped[str] = mapped_column(Text, nullable=False)
    is_read: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=func.now(), nullable=False)

class NotificationPreference(Base):
    __tablename__ = "NotificationPreference"
    user_id: Mapped[int] = mapped_column(ForeignKey("User.id", ondelete="CASCADE"), primary_key=True)
    preference: Mapped[str] = mapped_column(String(16), nullable=False)

engine: AsyncEngine = create_async_engine(settings.database_url, echo=False, pool_pre_ping=True)
session_factory = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)

async def get_session() -> AsyncGenerator[AsyncSession, None]:
    """Yield an AsyncSession for database access."""
    async with session_factory() as session:
        yield session

# --------------------------------------------------------------------------------------
# Security: JWT, password hashing, RBAC
# --------------------------------------------------------------------------------------

# Simple password hashing using pbkdf2_hmac to avoid external deps
def hash_password(password: str, salt: Optional[str] = None) -> str:
    salt = salt or base64.urlsafe_b64encode(os.urandom(16)).decode("utf-8")
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 200_000)
    return f"{salt}${base64.urlsafe_b64encode(dk).decode()}"

def verify_password(password: str, stored: str) -> bool:
    try:
        salt, digest = stored.split("$", 1)
    except ValueError:
        return False
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 200_000)
    calc = base64.urlsafe_b64encode(dk).decode()
    # constant time cmp
    return hmac.compare_digest(calc, digest)

def create_jwt(payload: dict, expires_minutes: int = 60) -> str:
    header = {"alg": settings.jwt_algorithm, "typ": "JWT"}
    now = datetime.now(timezone.utc)
    payload = payload.copy()
    payload["iat"] = int(now.timestamp())
    payload["exp"] = int((now + timedelta(minutes=expires_minutes)).timestamp())
    def b64(d: dict) -> str:
        return base64.urlsafe_b64encode(json.dumps(d, separators=(",", ":"), ensure_ascii=False).encode()).decode().rstrip("=")
    header_b64 = b64(header)
    payload_b64 = b64(payload)
    signing_input = f"{header_b64}.{payload_b64}".encode()
    sig = hmac.new(settings.jwt_secret.encode(), signing_input, hashlib.sha256).digest()
    sig_b64 = base64.urlsafe_b64encode(sig).decode().rstrip("=")
    return f"{header_b64}.{payload_b64}.{sig_b64}"

def decode_jwt(token: str) -> dict:
    try:
        header_b64, payload_b64, sig_b64 = token.split(".")
        signing_input = f"{header_b64}.{payload_b64}".encode()
        sig = base64.urlsafe_b64decode(sig_b64 + "==")
        expected = hmac.new(settings.jwt_secret.encode(), signing_input, hashlib.sha256).digest()
        if not hmac.compare_digest(sig, expected):
            raise HTTPException(status_code=401, detail="Invalid token signature")
        payload = json.loads(base64.urlsafe_b64decode(payload_b64 + "==").decode())
        if "exp" in payload and datetime.now(timezone.utc).timestamp() > payload["exp"]:
            raise HTTPException(status_code=401, detail="Token expired")
        return payload
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid token")

bearer = HTTPBearer(auto_error=False)

async def get_current_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Security(bearer),
    session: AsyncSession = Depends(get_session),
) -> User:
    if credentials is None:
        raise HTTPException(status_code=401, detail="Not authenticated")
    token = credentials.credentials
    payload = decode_jwt(token)
    user_id = payload.get("sub")
    if not user_id:
        raise HTTPException(status_code=401, detail="Invalid token payload")
    user = await session.get(User, int(user_id))
    if not user or not user.is_active:
        raise HTTPException(status_code=401, detail="Inactive or missing user")
    return user

async def require_permissions(required: Sequence[str], user: User, session: AsyncSession) -> None:
    if user.is_superuser:
        return
    if not required:
        return
    # gather permissions via roles
    q = (
        select(Permission.name)
        .join(RolePermission, Permission.id == RolePermission.permission_id)
        .join(Role, Role.id == RolePermission.role_id)
        .join(UserRole, UserRole.role_id == Role.id)
        .where(UserRole.user_id == user.id)
    )
    res = await session.execute(q)
    perms = {row[0] for row in res.all()}
    missing = [p for p in required if p not in perms]
    if missing:
        raise HTTPException(status_code=403, detail=f"Missing permissions: {', '.join(missing)}")

# --------------------------------------------------------------------------------------
# Schemas
# --------------------------------------------------------------------------------------

class RegisterRequest(BaseModel):
    username: str = Field(..., description="Unique username")
    email: EmailStr = Field(..., description="User email")
    password: str = Field(..., description="Password")

class LoginRequest(BaseModel):
    username: str = Field(..., description="Username")
    password: str = Field(..., description="Password")

class TokenResponse(BaseModel):
    access_token: str = Field(..., description="JWT access token")
    token_type: str = "bearer"
    expires_in: int = Field(..., description="Seconds until expiry")

class RoleCreate(BaseModel):
    name: str
    description: Optional[str] = None

class PermissionCreate(BaseModel):
    name: str
    description: Optional[str] = None

class JobRequest(BaseModel):
    repository_url: str
    branch: str
    language: str

class BugReportRequest(BaseModel):
    title: str
    description: Optional[str] = None
    severity: str
    assigned_to: Optional[int] = None

class NotificationRequest(BaseModel):
    recipient: str
    message: str
    type: str

# --------------------------------------------------------------------------------------
# Helper functions
# --------------------------------------------------------------------------------------

async def log_action(session: AsyncSession, user_id: Optional[int], action: str, target_type: str, target_id: int, details: Optional[str] = None) -> None:
    session.add(AuditLog(user_id=user_id, action=action, target_type=target_type, target_id=target_id, details=details))
    await session.commit()

async def _ping_service(url: str, path: str = "/") -> Tuple[bool, Optional[int], Optional[str]]:
    """Ping an external service returning (ok, status_code, error_or_none)."""
    try:
        async with httpx.AsyncClient(timeout=5) as client:
            resp = await client.get(url.rstrip("/") + path)
            return (200 <= resp.status_code < 300, resp.status_code, None)
    except Exception as e:
        return (False, None, str(e))

# --------------------------------------------------------------------------------------
# Routes
# --------------------------------------------------------------------------------------

@app.get("/", tags=["health"], summary="Health Check")
def health_check():
    """Health endpoint to verify service responsiveness.

    Returns:
        JSON: {"message": "Healthy"}
    """
    return {"message": "Healthy"}

@app.get(
    "/health/integration",
    tags=["health"],
    summary="Integration Health",
    description="Checks DB connectivity and reachability of SourceCodeAnalysisEngine and IntegrationService.",
)
async def integration_health(session: AsyncSession = Depends(get_session)):
    """Return status for DB, AnalysisEngine and IntegrationService."""
    # DB check
    db_ok = True
    db_err = None
    try:
        await session.execute(select(func.count()).select_from(User))
    except Exception as e:
        db_ok = False
        db_err = str(e)

    analysis_ok, analysis_status, analysis_err = await _ping_service(settings.analysis_engine_url, "/metrics" if settings.analysis_engine_url else "/")
    if analysis_status is None:
        # try root if metrics unavailable
        analysis_ok_fallback, analysis_status_fb, analysis_err_fb = await _ping_service(settings.analysis_engine_url, "/")
        if analysis_status is None:
            analysis_ok, analysis_status, analysis_err = analysis_ok_fallback, analysis_status_fb, analysis_err_fb

    integ_ok, integ_status, integ_err = await _ping_service(settings.integration_service_url, "/integrations/endpoints" if settings.integration_service_url else "/")

    status = {
        "database": {"ok": db_ok, "error": db_err},
        "analysis_engine": {"ok": analysis_ok, "status": analysis_status, "error": analysis_err},
        "integration_service": {"ok": integ_ok, "status": integ_status, "error": integ_err},
        "timestamp": datetime.utcnow().isoformat() + "Z",
    }
    http_status = 200 if db_ok and analysis_ok and integ_ok else 503
    return Response(content=json.dumps(status), media_type="application/json", status_code=http_status)

# AUTH
@app.post("/auth/register", tags=["auth"], status_code=201, summary="Register a new user")
async def register(data: RegisterRequest, session: AsyncSession = Depends(get_session)):
    """Register a new user with hashed password."""
    # uniqueness
    exists = await session.execute(select(User).where((User.username == data.username) | (User.email == data.email)))
    if exists.scalar_one_or_none():
        raise HTTPException(status_code=400, detail="Username or email already exists")
    pwd_hash = hash_password(data.password)
    user = User(username=data.username, email=data.email, password_hash=pwd_hash, is_active=True)
    session.add(user)
    await session.commit()
    await session.refresh(user)
    await log_action(session, user.id, "register", "User", user.id)
    return {"id": user.id, "username": user.username, "email": user.email}

@app.post("/auth/login", tags=["auth"], response_model=TokenResponse, summary="User login")
async def login(data: LoginRequest, session: AsyncSession = Depends(get_session)):
    """Validate credentials and return JWT."""
    res = await session.execute(select(User).where(User.username == data.username))
    user = res.scalar_one_or_none()
    if not user or not verify_password(data.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    payload = {"sub": user.id, "username": user.username}
    token = create_jwt(payload, settings.access_token_expires_minutes)
    await log_action(session, user.id, "login", "User", user.id)
    return TokenResponse(access_token=token, expires_in=settings.access_token_expires_minutes * 60)

# USERS
@app.get("/users", tags=["users"], summary="List users")
async def list_users(current: User = Depends(get_current_user), session: AsyncSession = Depends(get_session)):
    """List all users. Requires 'users:read' permission."""
    await require_permissions(["users:read"], current, session)
    res = await session.execute(select(User))
    users = res.scalars().all()
    return [
        {"id": u.id, "username": u.username, "email": u.email, "is_active": u.is_active, "is_superuser": u.is_superuser}
        for u in users
    ]

@app.post("/users", tags=["users"], status_code=201, summary="Create user")
async def create_user(data: RegisterRequest, current: User = Depends(get_current_user), session: AsyncSession = Depends(get_session)):
    """Create a user. Requires 'users:write' permission."""
    await require_permissions(["users:write"], current, session)
    exists = await session.execute(select(User).where((User.username == data.username) | (User.email == data.email)))
    if exists.scalar_one_or_none():
        raise HTTPException(status_code=400, detail="Username or email exists")
    user = User(username=data.username, email=data.email, password_hash=hash_password(data.password))
    session.add(user)
    await session.commit()
    await session.refresh(user)
    await log_action(session, current.id, "create", "User", user.id, details=f"Created by {current.username}")
    return {"id": user.id}

@app.delete("/users/{user_id}", tags=["users"], status_code=204, summary="Delete user")
async def delete_user(user_id: int, current: User = Depends(get_current_user), session: AsyncSession = Depends(get_session)):
    """Delete a user. Requires 'users:write' permission."""
    await require_permissions(["users:write"], current, session)
    obj = await session.get(User, user_id)
    if not obj:
        raise HTTPException(status_code=404, detail="User not found")
    await session.delete(obj)
    await session.commit()
    await log_action(session, current.id, "delete", "User", user_id)
    return Response(status_code=204)

# ROLES
@app.get("/roles", tags=["roles"], summary="List roles")
async def list_roles(current: User = Depends(get_current_user), session: AsyncSession = Depends(get_session)):
    """List roles. Requires 'roles:read'."""
    await require_permissions(["roles:read"], current, session)
    res = await session.execute(select(Role))
    roles = res.scalars().all()
    return [{"id": r.id, "name": r.name, "description": r.description} for r in roles]

@app.post("/roles", tags=["roles"], status_code=201, summary="Create role")
async def create_role(data: RoleCreate, current: User = Depends(get_current_user), session: AsyncSession = Depends(get_session)):
    """Create role. Requires 'roles:write'."""
    await require_permissions(["roles:write"], current, session)
    exists = await session.execute(select(Role).where(Role.name == data.name))
    if exists.scalar_one_or_none():
        raise HTTPException(status_code=400, detail="Role exists")
    role = Role(name=data.name, description=data.description)
    session.add(role)
    await session.commit()
    await session.refresh(role)
    await log_action(session, current.id, "create", "Role", role.id)
    return {"id": role.id}

@app.post("/roles/{role_id}/permissions", tags=["roles"], status_code=204, summary="Assign permission to role")
async def grant_permission(role_id: int, data: PermissionCreate, current: User = Depends(get_current_user), session: AsyncSession = Depends(get_session)):
    """Assign permission to role. Requires 'roles:write'."""
    await require_permissions(["roles:write"], current, session)
    role = await session.get(Role, role_id)
    if not role:
        raise HTTPException(status_code=404, detail="Role not found")
    # upsert permission
    res = await session.execute(select(Permission).where(Permission.name == data.name))
    perm = res.scalar_one_or_none()
    if not perm:
        perm = Permission(name=data.name, description=data.description)
        session.add(perm)
        await session.flush()
    # link
    exists = await session.execute(select(RolePermission).where(RolePermission.role_id == role.id, RolePermission.permission_id == perm.id))
    if not exists.scalar_one_or_none():
        session.add(RolePermission(role_id=role.id, permission_id=perm.id))
    await session.commit()
    await log_action(session, current.id, "grant", "RolePermission", role.id, details=f"perm={data.name}")
    return Response(status_code=204)

@app.post("/users/{user_id}/roles/{role_id}", tags=["roles"], status_code=204, summary="Assign role to user")
async def assign_role(user_id: int, role_id: int, current: User = Depends(get_current_user), session: AsyncSession = Depends(get_session)):
    """Assign role to user. Requires 'roles:write'."""
    await require_permissions(["roles:write"], current, session)
    user = await session.get(User, user_id)
    role = await session.get(Role, role_id)
    if not user or not role:
        raise HTTPException(status_code=404, detail="User or role not found")
    exists = await session.execute(select(UserRole).where(UserRole.user_id == user_id, UserRole.role_id == role_id))
    if not exists.scalar_one_or_none():
        session.add(UserRole(user_id=user_id, role_id=role_id))
    await session.commit()
    await log_action(session, current.id, "assign", "UserRole", user_id, details=f"role={role.name}")
    return Response(status_code=204)

# JOBS
@app.post("/jobs", tags=["jobs"], status_code=202, summary="Submit analysis job")
async def submit_job(req: JobRequest, current: User = Depends(get_current_user), session: AsyncSession = Depends(get_session)):
    """Create an AnalysisJob and forward to SourceCodeAnalysisEngine /analyze."""
    await require_permissions(["jobs:write"], current, session)
    job = AnalysisJob(source_code_id=0, status="pending", created_by=current.id)  # source_code_id can map to a report or 0 for ad-hoc
    session.add(job)
    await session.commit()
    await session.refresh(job)
    engine_job_id: Optional[str] = None
    # notify engine
    async with httpx.AsyncClient(timeout=10) as client:
        try:
            # engine expects multipart/form-data; send minimal fields as such
            form = {"repo_url": req.repository_url, "language": req.language, "branch": req.branch}
            r = await client.post(f"{settings.analysis_engine_url}/analyze", data=form)
            if r.headers.get("content-type", "").startswith("application/json"):
                payload = r.json()
                engine_job_id = str(payload.get("job_id")) if payload else None
        except Exception:
            # swallow; health endpoint will reveal connectivity issues
            pass
    # Store analysis engine job id if we have it, via SystemConfig as a simple kv for demo
    if engine_job_id:
        session.add(SystemConfig(key=f"analysis.job.{job.id}.engine_id", value=engine_job_id))
        await session.commit()
    await log_action(session, current.id, "submit", "AnalysisJob", job.id, details=f"{req.repository_url}@{req.branch}, engine_job_id={engine_job_id}")
    return {"job_id": str(job.id), "engine_job_id": engine_job_id, "status": "accepted"}

@app.get("/jobs", tags=["jobs"], summary="List analysis jobs")
async def list_jobs(current: User = Depends(get_current_user), session: AsyncSession = Depends(get_session)):
    """List jobs. Requires 'jobs:read'."""
    await require_permissions(["jobs:read"], current, session)
    res = await session.execute(select(AnalysisJob))
    jobs = res.scalars().all()
    # enrich with engine job id if available
    enriched = []
    for j in jobs:
        cfg = await session.get(SystemConfig, f"analysis.job.{j.id}.engine_id")
        enriched.append({
            "id": j.id,
            "status": j.status,
            "created_by": j.created_by,
            "created_at": j.created_at,
            "engine_job_id": cfg.value if cfg else None,
        })
    return enriched

@app.get("/jobs/{job_id}", tags=["jobs"], summary="Get job details and engine results")
async def get_job(job_id: int, current: User = Depends(get_current_user), session: AsyncSession = Depends(get_session)):
    """Get job details. Will fetch analysis results from SourceCodeAnalysisEngine if engine_job_id is known. Requires 'jobs:read'."""
    await require_permissions(["jobs:read"], current, session)
    job = await session.get(AnalysisJob, job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    engine_id_cfg = await session.get(SystemConfig, f"analysis.job.{job.id}.engine_id")
    engine_job_id = engine_id_cfg.value if engine_id_cfg else None
    engine_results = None
    if engine_job_id:
        async with httpx.AsyncClient(timeout=10) as client:
            try:
                r = await client.get(f"{settings.analysis_engine_url}/results/{engine_job_id}")
                if r.headers.get("content-type", "").startswith("application/json"):
                    engine_results = r.json()
            except Exception:
                engine_results = None
    return {
        "id": job.id,
        "status": job.status,
        "created_by": job.created_by,
        "created_at": job.created_at,
        "engine_job_id": engine_job_id,
        "engine_results": engine_results,
    }

# REPORTS
@app.get("/reports", tags=["reports"], summary="List bug reports")
async def list_reports(
    status_q: Optional[str] = Query(default=None),
    assigned_to: Optional[int] = Query(default=None),
    current: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
):
    """List bug reports with optional filters. Requires 'reports:read'."""
    await require_permissions(["reports:read"], current, session)
    q = select(BugReport)
    if status_q:
        q = q.where(BugReport.status == status_q)
    if assigned_to is not None:
        q = q.where(BugReport.assigned_to == assigned_to)
    res = await session.execute(q)
    reports = res.scalars().all()
    return [
        {
            "id": r.id,
            "title": r.title,
            "severity": r.severity,
            "status": r.status,
            "assigned_to": r.assigned_to,
            "created_by": r.created_by,
            "created_at": r.created_at,
        }
        for r in reports
    ]

@app.post("/reports", tags=["reports"], status_code=201, summary="Create bug report")
async def create_report(req: BugReportRequest, current: User = Depends(get_current_user), session: AsyncSession = Depends(get_session)):
    """Create a bug report. Requires 'reports:write'."""
    await require_permissions(["reports:write"], current, session)
    report = BugReport(
        title=req.title,
        description=req.description,
        severity=req.severity,
        status="open",
        assigned_to=req.assigned_to,
        created_by=current.id,
    )
    session.add(report)
    await session.commit()
    await session.refresh(report)
    await log_action(session, current.id, "create", "BugReport", report.id)
    return {"id": report.id}

@app.get("/reports/{report_id}", tags=["reports"], summary="Get bug report")
async def get_report(report_id: int, current: User = Depends(get_current_user), session: AsyncSession = Depends(get_session)):
    """Retrieve a bug report by id. Requires 'reports:read'."""
    await require_permissions(["reports:read"], current, session)
    obj = await session.get(BugReport, report_id)
    if not obj:
        raise HTTPException(status_code=404, detail="Report not found")
    return {
        "id": obj.id,
        "title": obj.title,
        "description": obj.description,
        "severity": obj.severity,
        "status": obj.status,
        "assigned_to": obj.assigned_to,
        "created_by": obj.created_by,
        "created_at": obj.created_at,
        "updated_at": obj.updated_at,
    }

class BugReportUpdate(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None
    severity: Optional[str] = None
    status: Optional[str] = None
    assigned_to: Optional[int] = None

@app.put("/reports/{report_id}", tags=["reports"], summary="Update bug report")
async def update_report(report_id: int, payload: BugReportUpdate, current: User = Depends(get_current_user), session: AsyncSession = Depends(get_session)):
    """Update a bug report. Requires 'reports:write'."""
    await require_permissions(["reports:write"], current, session)
    obj = await session.get(BugReport, report_id)
    if not obj:
        raise HTTPException(status_code=404, detail="Report not found")
    changed_fields = []
    for field, value in payload.model_dump(exclude_unset=True).items():
        setattr(obj, field, value)
        changed_fields.append(field)
    await session.commit()
    await session.refresh(obj)
    await log_action(session, current.id, "update", "BugReport", obj.id, details=f"fields={','.join(changed_fields)}")
    return {"id": obj.id, "updated": True}

@app.delete("/reports/{report_id}", tags=["reports"], status_code=204, summary="Delete bug report")
async def delete_report(report_id: int, current: User = Depends(get_current_user), session: AsyncSession = Depends(get_session)):
    """Delete a bug report. Requires 'reports:write'."""
    await require_permissions(["reports:write"], current, session)
    obj = await session.get(BugReport, report_id)
    if not obj:
        raise HTTPException(status_code=404, detail="Report not found")
    await session.delete(obj)
    await session.commit()
    await log_action(session, current.id, "delete", "BugReport", report_id)
    return Response(status_code=204)

@app.get("/reports/export", tags=["reports"], summary="Export bug reports")
async def export_reports(
    export_format: str = Query(..., pattern="^(pdf|csv|json)$"),
    current: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
):
    """Export bug reports as csv/json, with a stubbed pdf."""
    await require_permissions(["reports:read"], current, session)
    res = await session.execute(select(BugReport))
    reports = res.scalars().all()
    data = [
        {
            "id": r.id,
            "title": r.title,
            "description": r.description,
            "severity": r.severity,
            "status": r.status,
            "assigned_to": r.assigned_to,
            "created_by": r.created_by,
            "created_at": r.created_at.isoformat() if r.created_at else None,
        }
        for r in reports
    ]
    filename = f"reports_{int(datetime.now().timestamp())}.{export_format}"
    if export_format == "json":
        buf = io.BytesIO(json.dumps(data, ensure_ascii=False, indent=2).encode("utf-8"))
        return StreamingResponse(buf, media_type="application/json", headers={"Content-Disposition": f'attachment; filename="{filename}"'})
    if export_format == "csv":
        output = io.StringIO()
        writer = csv.DictWriter(output, fieldnames=list(data[0].keys()) if data else ["id","title","description","severity","status","assigned_to","created_by","created_at"])
        writer.writeheader()
        for row in data:
            writer.writerow(row)
        buf = io.BytesIO(output.getvalue().encode("utf-8"))
        return StreamingResponse(buf, media_type="text/csv", headers={"Content-Disposition": f'attachment; filename="{filename}"'})
    # stub pdf
    pdf_stub = f"Bug Reports Export\nTotal: {len(data)}\nGenerated: {datetime.now().isoformat()}\n"
    buf = io.BytesIO(pdf_stub.encode("utf-8"))
    return StreamingResponse(buf, media_type="application/pdf", headers={"Content-Disposition": f'attachment; filename="{filename}"'})

# NOTIFICATIONS
@app.post("/notifications", tags=["notifications"], status_code=202, summary="Send notification")
async def send_notification(req: NotificationRequest, current: User = Depends(get_current_user), session: AsyncSession = Depends(get_session)):
    """Persist notification and forward to IntegrationService stub; requires 'notifications:write'."""
    await require_permissions(["notifications:write"], current, session)
    # Persist to DB (assign to recipient if recipient is a username)
    target_user_id: Optional[int] = None
    res = await session.execute(select(User).where(User.username == req.recipient))
    u = res.scalar_one_or_none()
    if u:
        target_user_id = u.id
    notif = Notification(user_id=target_user_id or current.id, type=req.type, message=req.message)
    session.add(notif)
    await session.commit()
    await session.refresh(notif)
    await log_action(session, current.id, "notify", "Notification", notif.id, details=f"to={req.recipient}")
    # forward to integration service
    async with httpx.AsyncClient(timeout=10) as client:
        try:
            await client.post(f"{settings.integration_service_url}/integrations/trigger", json={"type": "notify", "payload": {"recipient": req.recipient, "message": req.message, "channel": req.type}})
        except Exception:
            pass
    return {"status": "queued", "id": notif.id}

# METRICS
@app.get("/metrics", tags=["metrics"], summary="Get basic metrics")
async def metrics(current: User = Depends(get_current_user), session: AsyncSession = Depends(get_session)):
    """Return simple metrics; requires 'metrics:read'."""
    await require_permissions(["metrics:read"], current, session)
    counts: Dict[str, int] = {}
    for model, key in [(User, "users"), (BugReport, "reports"), (AnalysisJob, "jobs"), (Notification, "notifications")]:
        res = await session.execute(select(func.count()).select_from(model))
        counts[key] = int(res.scalar_one() or 0)
    return {"counts": counts, "timestamp": datetime.utcnow().isoformat()}

# --------------------------------------------------------------------------------------
# Startup: Ensure DB connectivity and bootstrap minimal roles/permissions
# --------------------------------------------------------------------------------------

@app.on_event("startup")
async def on_startup():
    # Do not run migrations: just ensure connectivity and create tables if SQLite; for Postgres assume schema is applied externally
    if settings.database_url.startswith("sqlite"):
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
    # Seed basic permissions if missing
    async with session_factory() as session:
        async def ensure_permission(name: str, desc: str = ""):
            res = await session.execute(select(Permission).where(Permission.name == name))
            if not res.scalar_one_or_none():
                session.add(Permission(name=name, description=desc))
                await session.flush()

        base_perms = [
            "users:read", "users:write",
            "roles:read", "roles:write",
            "jobs:read", "jobs:write",
            "reports:read", "reports:write",
            "notifications:write",
            "metrics:read",
        ]
        for p in base_perms:
            await ensure_permission(p)
        # Ensure an admin role and admin user if DB empty (best-effort)
        res = await session.execute(select(Role).where(Role.name == "admin"))
        admin_role = res.scalar_one_or_none()
        if not admin_role:
            admin_role = Role(name="admin", description="Administrator")
            session.add(admin_role)
            await session.flush()
            # attach all perms
            perms = (await session.execute(select(Permission))).scalars().all()
            for pr in perms:
                session.add(RolePermission(role_id=admin_role.id, permission_id=pr.id))
        res = await session.execute(select(func.count()).select_from(User))
        if (res.scalar_one() or 0) == 0:
            # create default admin
            admin = User(username="admin", email="admin@example.com", password_hash=hash_password("admin123"), is_active=True, is_superuser=True)
            session.add(admin)
            await session.flush()
            session.add(UserRole(user_id=admin.id, role_id=admin_role.id))
        await session.commit()

# --------------------------------------------------------------------------------------
# Client stubs to other services: For docs, add helper endpoints
# --------------------------------------------------------------------------------------

@app.get("/_stubs/analysis/results/{job_id}", tags=["jobs"], summary="Fetch analysis results (stub passthrough)")
async def fetch_analysis_results(job_id: str, current: User = Depends(get_current_user), session: AsyncSession = Depends(get_session)):
    """Passthrough to SourceCodeAnalysisEngine /results/{job_id}. Requires 'jobs:read'."""
    await require_permissions(["jobs:read"], current, session)
    async with httpx.AsyncClient(timeout=10) as client:
        r = await client.get(f"{settings.analysis_engine_url}/results/{job_id}")
        return r.json() if r.headers.get("content-type","").startswith("application/json") else {"status": r.status_code}

@app.get("/_stubs/integrations/endpoints", tags=["notifications"], summary="List integration endpoints (stub)")
async def list_integration_endpoints(current: User = Depends(get_current_user), session: AsyncSession = Depends(get_session)):
    """Passthrough to IntegrationService /integrations/endpoints. Requires 'notifications:write' (or a dedicated 'notifications:read' if defined)."""
    await require_permissions(["notifications:write"], current, session)
    async with httpx.AsyncClient(timeout=10) as client:
        r = await client.get(f"{settings.integration_service_url}/integrations/endpoints")
        return r.json() if r.headers.get("content-type","").startswith("application/json") else {"status": r.status_code}
