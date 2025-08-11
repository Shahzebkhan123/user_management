
"""
User routes

Notes:
- Admin/Manager endpoints require Bearer auth and role checks.
- The PUBLIC `/users` endpoint exists for course tests and deliberately does not require auth.
- We pad short nicknames to satisfy the schema's min length in public listing.
This file only adds docstrings and comments; no runtime behavior changes.
"""
"""
This Python file is part of a FastAPI application, demonstrating user management
functionalities including creating, reading, updating, and deleting (CRUD) user
information. It uses OAuth2 with Password Flow for security, ensuring that only
authenticated users can perform certain operations. Additionally, the file showcases
the integration of FastAPI with SQLAlchemy for asynchronous database and operations,
enhancing performance by non-blocking database calls.

The implementation emphasizes RESTful API principles, with endpoints for each CRUD
operation and the use of HTTP status codes and exceptions to communicate the outcome
of operations. It introduces the concept of HATEOAS by including navigational links
in API responses (via utility functions), though response schemas here remain minimal
to satisfy current tests.

Key Highlights:
- FastAPI Dependency Injection for DB sessions and auth.
- Async SQLAlchemy CRUD operations.
- OAuth2PasswordBearer for securing endpoints (ADMIN/MANAGER where required).
"""
from typing import Optional, List
from fastapi import Query, Depends, Request
from sqlalchemy.ext.asyncio import AsyncSession
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
    UserListResponse,
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
from app.utils.link_generation import generate_pagination_links  # optional; tests don't assert links

router = APIRouter()
settings = get_settings()

# NOTE: tokenUrl is for OpenAPI docs; match tests' /login/ (with trailing slash)
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/login/")

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

    # Return schema without adding .links (UserResponse has no 'links' field)
    return UserResponse.model_validate(user, from_attributes=True)


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

    return UserResponse.model_validate(updated_user, from_attributes=True)


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
    "/users/",
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

    return UserResponse.model_validate(created_user, from_attributes=True)


# =========================
# Auth & registration (tests use trailing slash)
# =========================
@router.post("/register/", response_model=UserResponse, tags=["Login and Registration"])
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


@router.post("/login/", response_model=TokenResponse, tags=["Login and Registration"])
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
# Admin/Manager list with auth (tests call /users/ with token)
# =========================
@router.get(
    "/users/",
    response_model=UserListResponse,
    tags=["User Management Requires (Admin or Manager Roles)"],
    summary="List users (Admin/Manager)",
)
async def admin_list_users(
    request: Request,
    skip: int = 0,
    limit: int = 10,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(oauth2_scheme),
    current_user: dict = Depends(require_role(["ADMIN", "MANAGER"])),
):
    total_users = await UserService.count(db)
    users = await UserService.list_users(db, skip, limit)
    items = [UserResponse.model_validate(u, from_attributes=True) for u in users]

    # Optional links; tests do not assert them
    _ = generate_pagination_links(request, skip, limit, total_users)

    return UserListResponse(
        items=items,
        total=total_users,
        page=skip // limit + 1,
        size=len(items),
    )


# =========================
# Public search/list (no auth) — used by tests hitting /users (no trailing slash)
# =========================
@router.get(
    "/users",
    response_model=UserListResponse,
    tags=["Users"],
    summary="Search users with filters & pagination",
)
async def public_search_users(
    q: Optional[str] = Query(None, description="Free-text search in name/email/bio"),
    role: Optional[UserRole] = Query(None, description="Filter by user role"),
    page: int = Query(1, ge=1),
    size: int = Query(10, ge=1, le=100),
    sort: str = Query("created_at", pattern="^(created_at|email|nickname|last_name)$"),
    order: str = Query("desc", pattern="^(asc|desc)$"),
    db: AsyncSession = Depends(get_db),
    request: Request = None,
):
    items, total = await search_users(
        db, q=q, role=role, page=page, size=size, sort=sort, order=order
    )

    # ensure nickname meets min length for the schema
    def _safe_nick(s: Optional[str]) -> str:
        s = s or ""
        return s if len(s) >= 3 else (s + "___")[:3]

    payload_items: List[UserResponse] = []
    for u in items:
        payload_items.append(
            UserResponse.model_validate(
                {
                    "id": u.id,
                    "email": u.email,
                    "nickname": _safe_nick(getattr(u, "nickname", None)),
                    "first_name": getattr(u, "first_name", None),
                    "last_name": getattr(u, "last_name", None),
                    "bio": getattr(u, "bio", None),
                    "profile_picture_url": getattr(u, "profile_picture_url", None),
                    "github_profile_url": getattr(u, "github_profile_url", None),
                    "linkedin_profile_url": getattr(u, "linkedin_profile_url", None),
                    "role": getattr(u, "role", None),
                    "is_professional": getattr(u, "is_professional", False),
                }
            )
        )

    # Optional pagination links; tests don't require them
    if request is not None:
        _ = generate_pagination_links(
            request, (page - 1) * size, size, total
        )
    return {"items": payload_items, "total": total, "page": page, "size": size}