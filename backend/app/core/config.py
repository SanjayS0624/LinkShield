from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    database_url: str
    redis_url: str
    jwt_secret_key: str = Field(min_length=32)
    jwt_access_token_expire_minutes: int = 15
    jwt_refresh_token_expire_days: int = 7
    cors_origins: str = "http://localhost:5173"
    virustotal_api_key: str = ""
    google_safe_browsing_api_key: str = ""
    openai_api_key: str = ""
    openai_explanation_model: str = "gpt-4o-mini"
    scan_limit_anonymous_per_hour: int = Field(default=5, gt=0, le=1000)
    scan_limit_authenticated_per_hour: int = Field(default=30, gt=0, le=10000)
    scan_limit_admin_per_hour: int = Field(default=300, gt=0, le=100000)

    @field_validator("database_url", mode="before")
    @classmethod
    def use_psycopg_driver(cls, value: str) -> str:
        # Render supplies PostgreSQL URLs without a SQLAlchemy driver suffix.
        if value.startswith("postgres://"):
            return "postgresql+psycopg://" + value.removeprefix("postgres://")
        if value.startswith("postgresql://"):
            return "postgresql+psycopg://" + value.removeprefix("postgresql://")
        return value

    model_config = SettingsConfigDict(case_sensitive=False)

    @property
    def allowed_origins(self) -> list[str]:
        return [origin.strip() for origin in self.cors_origins.split(",") if origin.strip()]


settings = Settings()
