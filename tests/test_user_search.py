import uuid
import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.user_model import User, UserRole
from app.utils.security import hash_password


async def create_user(db: AsyncSession, **kw):
    """
    Helper to create a user with a unique nickname by default.
    If no nickname is provided, we derive one from the email prefix + a short UUID.
    """
    email = kw.get("email", "nick@example.com")
    # base nickname from email prefix, plus random suffix to avoid UNIQUE violations
    base_nick = email.split("@")[0] if "@" in email else "nick"
    nickname = kw.get("nickname", f"{base_nick}-{uuid.uuid4().hex[:6]}")

    u = User(
        nickname=nickname,
        email=email,
        first_name=kw.get("first_name", "Nick"),
        last_name=kw.get("last_name", "Test"),
        bio=kw.get("bio", "bio"),
        role=kw.get("role", UserRole.AUTHENTICATED),
        email_verified=True,
        hashed_password=hash_password("Secret*123"),
    )
    db.add(u)
    await db.commit()
    await db.refresh(u)
    return u


@pytest.mark.asyncio
async def test_search_by_query(async_client, db_session):
    await create_user(
        db_session,
        email="john@example.com",
        first_name="John",
        last_name="Alpha",
        bio="python dev",
    )
    await create_user(
        db_session,
        email="jane@example.com",
        first_name="Jane",
        last_name="Beta",
        bio="golang dev",
    )

    res = await async_client.get("/users", params={"q": "python"})
    assert res.status_code == 200
    data = res.json()
    assert data["total"] >= 1
    emails = [i["email"] for i in data["items"]]
    assert "john@example.com" in emails


@pytest.mark.asyncio
async def test_filter_by_role(async_client, db_session):
    await create_user(db_session, email="admin@example.com", role=UserRole.ADMIN)
    await create_user(db_session, email="user@example.com", role=UserRole.AUTHENTICATED)

    res = await async_client.get("/users", params={"role": "ADMIN"})
    assert res.status_code == 200
    for i in res.json()["items"]:
        assert i["role"] == "ADMIN"


@pytest.mark.asyncio
async def test_pagination(async_client, db_session):
    # create 15 users with unique nicknames/emails
    for n in range(15):
        await create_user(
            db_session,
            email=f"user{n}@example.com",
            nickname=f"u{n}",
        )

    res = await async_client.get("/users", params={"page": 2, "size": 5})
    assert res.status_code == 200
    data = res.json()
    assert data["page"] == 2
    assert data["size"] == 5
    assert len(data["items"]) <= 5
