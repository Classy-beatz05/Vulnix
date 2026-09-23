from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    database_url: str = "sqlite:///./vulnix.db"

    jwt_secret: str = "change-me-to-a-long-random-value"
    jwt_algorithm: str = "HS256"
    jwt_expire_minutes: int = 120

    cors_origins: str = "*"

    rate_limit_per_minute: int = 60

    max_zip_size_mb: int = 50
    max_zip_uncompressed_mb: int = 200
    max_zip_file_count: int = 5000

    check_timeout_seconds: int = 8

    class Config:
        env_file = ".env"

    @property
    def cors_origin_list(self):
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]


settings = Settings()
