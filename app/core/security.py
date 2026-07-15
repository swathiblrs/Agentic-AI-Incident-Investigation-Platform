from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Annotated

import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel

from app.core.config import get_settings
from app.models.schemas import IncidentDomain, UserRole

bearer_scheme = HTTPBearer(auto_error=False)


ROLE_DOMAIN_ACCESS = {
    UserRole.security_analyst: {IncidentDomain.security},
    UserRole.sre: {IncidentDomain.production, IncidentDomain.cloud},
    UserRole.data_engineer: {IncidentDomain.data},
    UserRole.it_ops: {IncidentDomain.it},
    UserRole.admin: set(IncidentDomain),
}


class AuthRequest(BaseModel):
    username: str
    password: str
    role: UserRole = UserRole.admin


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"


class CurrentUser(BaseModel):
    username: str
    role: UserRole = UserRole.admin


def create_access_token(username: str, role: UserRole = UserRole.admin) -> str:
    settings = get_settings()
    now = datetime.now(UTC)
    payload = {
        "sub": username,
        "role": role.value,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=settings.jwt_expire_minutes)).timestamp()),
    }
    return jwt.encode(payload, settings.jwt_secret_key, algorithm=settings.jwt_algorithm)


def authenticate_demo_user(username: str, password: str) -> bool:
    settings = get_settings()
    return username == settings.demo_username and password == settings.demo_password


def get_current_user(
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(bearer_scheme)],
) -> CurrentUser:
    settings = get_settings()
    if not settings.auth_required:
        return CurrentUser(username="local-dev", role=UserRole.admin)

    if credentials is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing bearer token.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    try:
        payload = jwt.decode(
            credentials.credentials,
            settings.jwt_secret_key,
            algorithms=[settings.jwt_algorithm],
        )
    except jwt.PyJWTError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid bearer token.",
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc

    username = payload.get("sub")
    if not isinstance(username, str) or not username:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token subject.")
    role_value = payload.get("role", UserRole.admin.value)
    try:
        role = UserRole(role_value)
    except ValueError:
        role = UserRole.admin
    return CurrentUser(username=username, role=role)


def ensure_domain_access(user: CurrentUser, domain: IncidentDomain) -> None:
    allowed = ROLE_DOMAIN_ACCESS[user.role]
    if domain not in allowed:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Role {user.role.value} cannot access {domain.value} incidents.",
        )
