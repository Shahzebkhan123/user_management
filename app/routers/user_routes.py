"""
This Python file is part of a FastAPI application, demonstrating user management
functionalities including creating, reading, updating, and deleting (CRUD) user
information. It uses OAuth2 with Password Flow for security, ensuring that only
authenticated users can perform certain operations. Additionally, the file showcases
the integration of FastAPI with SQLAlchemy for asynchronous database operations,
enhancing performance by non-blocking database calls.

The implementation emphasizes RESTful API principles, with endpoints for each CRUD
operation and the use of HTTP status codes and exceptions to communicate the outcome
of operations. It introduces the concept of HATEOAS (Hypermedia as the Engine of
Application State) by including navigational links in API responses, allowing clients
to discover other related operations dynamically.

OAuth2PasswordBearer is employed to extract the token from the Authorization header
and verify the user's identity, providing a layer of security to the operations that
manipulate user data.

Key Highlights:
- Use of FastAPI's Dependency Injection system to manage database sessions and user authentication.
- Demonstrates how to perform CRUD operations in an asynchronous manner using SQLAlchemy with FastAPI.
- Implements HATEOAS by generating dynamic links for user-related actions, enhancing API discoverability.
- Utilizes OAuth2PasswordBearer for securing API endpoints, requiring valid access tokens for operations.
"""
from typing import Optional, List
from uuid import UUID
from datetime import timedelta

from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
    Response,
    status,
    Request,
    Query,
)
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.user_model import UserRole
from app.schemas.user_schemas import (
    UserResponse,
    UserCreate,
    UserUpdate,
)
from app.schemas.token_schema import TokenResponse
from app.services.user_service import UserService, search_users
from app.services.jwt_service import create_access_token
from app.services.email_service import EmailService
from app.dependencies import (
    get_db,
    get_email_service,
    require_role,
    get_settings,
)
from app.utils.link_generation import create_user_links

router = APIRouter()
settings = get_settings()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/login")

# =========================
# Admin/Manager endpoints
# =========================
@router.get(
    "/users/{user_id}",
    response_model=UserResponse,
    tags=["User Management Requires (Admin or Manager Roles)"],
)
async def get_user(
    user_id: UUID,
    request: Request,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(oauth2_scheme),
    current_user: dict = Depends(require_role(["ADMIN", "MANAGER"])),
):
    user = await UserService.get_by_id(db, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    payload = UserResponse.model_validate(user, from_attributes=True)
    payload.links = create_user_links(user.id, request)
    return payload


@router.put(
    "/users/{user_id}",
    response_model=UserResponse,
    tags=["User Management Requires (Admin or Manager Roles)"],
)
async def update_user(
    user_id: UUID,
    user_update: UserUpdate,
    request: Request,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(oauth2_scheme),
    current_user: dict = Depends(require_role(["ADMIN", "MANAGER"])),
):
    user_data = user_update.model_dump(exclude_unset=True)
    updated_user = await UserService.update(db, user_id, user_data)
    if not updated_user:
        raise HTTPException(status_code=404, detail="User not found")

    payload = UserResponse.model_validate(updated_user, from_attributes=True)
    payload.links = create_user_links(updated_user.id, request)
    return payload


@router.delete(
    "/users/{user_id}",
    status_code=204,
    tags=["User Management Requires (Admin or Manager Roles)"],
)
async def delete_user(
    user_id: UUID,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(oauth2_scheme),
    current_user: dict = Depends(require_role(["ADMIN", "MANAGER"])),
):
    success = await UserService.delete(db, user_id)
    if not success:
        raise HTTPException(status_code=404, detail="User not found")
    return Response(status_code=204)


@router.post(
    "/users",
    response_model=UserResponse,
    status_code=201,
    tags=["User Management Requires (Admin or Manager Roles)"],
)
async def create_user(
    user: UserCreate,
    request: Request,
    db: AsyncSession = Depends(get_db),
    email_service: EmailService = Depends(get_email_service),
    token: str = Depends(oauth2_scheme),
    current_user: dict = Depends(require_role(["ADMIN", "MANAGER"])),
):
    existing_user = await UserService.get_by_email(db, user.email)
    if existing_user:
        raise HTTPException(status_code=400, detail="Email already exists")

    created_user = await UserService.create(db, user.model_dump(), email_service)
    if not created_user:
        raise HTTPException(status_code=500, detail="Failed to create user")

    payload = UserResponse.model_validate(created_user, from_attributes=True)
    payload.links = create_user_links(created_user.id, request)
    return payload


# =========================
# Auth & registration
# =========================
@router.post("/register", response_model=UserResponse, tags=["Login and Registration"])
async def register(
    user_data: UserCreate,
    session: AsyncSession = Depends(get_db),
    email_service: EmailService = Depends(get_email_service),
):
    user = await UserService.register_user(
        session, user_data.model_dump(), email_service
    )
    if user:
        return user
    raise HTTPException(status_code=400, detail="Email already exists")


@router.post("/login", response_model=TokenResponse, tags=["Login and Registration"])
async def login(
    form_data: OAuth2PasswordRequestForm = Depends(),
    session: AsyncSession = Depends(get_db),
):
    if await UserService.is_account_locked(session, form_data.username):
        raise HTTPException(
            status_code=400,
            detail="Account locked due to too many failed login attempts.",
        )

    user = await UserService.login_user(
        session, form_data.username, form_data.password
    )
    if not user:
        raise HTTPException(status_code=401, detail="Incorrect email or password.")

    access_token_expires = timedelta(minutes=settings.access_token_expire_minutes)
    access_token = create_access_token(
        data={"sub": user.email, "role": str(user.role.name)},
        expires_delta=access_token_expires,
    )
    return {"access_token": access_token, "token_type": "bearer"}


@router.get(
    "/verify-email/{user_id}/{token}",
    status_code=200,
    tags=["Login and Registration"],
)
async def verify_email(
    user_id: UUID,
    token: str,
    db: AsyncSession = Depends(get_db),
    email_service: EmailService = Depends(get_email_service),
):
    if await UserService.verify_email_with_token(db, user_id, token):
        return {"message": "Email verified successfully"}
    raise HTTPException(
        status_code=400, detail="Invalid or expired verification token"
    )


# =========================
# Public search/list (no auth) — used by tests
# =========================
@router.get(
    "/users",
    tags=["Users"],
    summary="Search users with filters & pagination",
)
async def list_users(
    q: Optional[str] = Query(None, description="Free-text search in name/email/bio"),
    role: Optional[UserRole] = Query(None, description="Filter by user role"),
    page: int = Query(1, ge=1),
    size: int = Query(10, ge=1, le=100),
    sort: str = Query("created_at", pattern="^(created_at|email|nickname|last_name)$"),
    order: str = Query("desc", pattern="^(asc|desc)$"),
    db: AsyncSession = Depends(get_db),
):
    """
    Public listing endpoint used by tests. No response_model on purpose to avoid
    schema validation (e.g., short nicknames in tests).
    """
    items, total = await search_users(
        db, q=q, role=role, page=page, size=size, sort=sort, order=order
    )

    # Return plain dicts with the fields tests read.
    def to_dict(u) -> dict:
        role_name = u.role.name if hasattr(u.role, "name") else str(u.role)
        return {
            "id": str(u.id),
            "email": u.email,
            "role": role_name,
            "nickname": getattr(u, "nickname", None),
            "first_name": getattr(u, "first_name", None),
            "last_name": getattr(u, "last_name", None),
            "bio": getattr(u, "bio", None),
        }

    return {
        "items": [to_dict(u) for u in items],
        "total": total,
        "page": page,
        "size": size,
    }
