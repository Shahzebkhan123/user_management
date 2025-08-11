from builtins import bool, int, str
from pathlib import Path
from pydantic import Field, AnyUrl, DirectoryPath
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    # General / server
    max_login_attempts: int = Field(default=3, description="Max failed logins before lock")
    server_base_url: AnyUrl = Field(default="http://localhost:8000", description="Base URL of the server")
    server_download_folder: str = Field(default="downloads", description="Folder for storing downloaded files")

    # Security / auth
    secret_key: str = Field(default="secret-key", description="Secret key for encryption")
    algorithm: str = Field(default="HS256", description="Algorithm used for encryption")
    debug: bool = Field(default=False, description="Debug mode outputs errors and SQLAlchemy queries")

    # JWT
    jwt_secret_key: str = Field(default="a_very_secret_key", description="JWT secret")
    jwt_algorithm: str = Field(default="HS256", description="JWT algorithm")
    access_token_expire_minutes: int = Field(default=30, description="Access token expiry (minutes)")
    refresh_token_expire_minutes: int = Field(default=1440, description="Refresh token expiry (minutes)")

    # Bootstrap admin (optional)
    admin_user: str = Field(default="admin", description="Default admin username")
    admin_password: str = Field(default="secret", description="Default admin password")

    # Database (async URL for SQLAlchemy)
    database_url: str = Field(
        default="postgresql+asyncpg://user:password@localhost:5432/myappdb",
        description="Async DB URL (use +asyncpg for app runtime)"
    )

    # Optional: DB components (not required if database_url is set)
    postgres_user: str = Field(default="user", description="PostgreSQL username")
    postgres_password: str = Field(default="password", description="PostgreSQL password")
    postgres_server: str = Field(default="localhost", description="PostgreSQL server address")
    postgres_port: str = Field(default="5432", description="PostgreSQL port")
    postgres_db: str = Field(default="myappdb", description="PostgreSQL database name")

    # Discord / OpenAI (optional)
    discord_bot_token: str = Field(default="NONE", description="Discord bot token")
    discord_channel_id: int = Field(default=1234567890, description="Default Discord channel ID")
    openai_api_key: str = Field(default="NONE", description="OpenAI API Key")

    # Email (Mailtrap or real SMTP)
    send_real_mail: bool = Field(default=False, description="If false, use mock email sender")
    smtp_server: str = Field(default="smtp.mailtrap.io", description="SMTP server")
    smtp_port: int = Field(default=2525, description="SMTP port")
    smtp_username: str = Field(default="your-mailtrap-username", description="SMTP username")
    smtp_password: str = Field(default="your-mailtrap-password", description="SMTP password")

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"


# Importable singleton
settings = Settings()
