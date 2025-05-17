from pydantic.v1 import BaseSettings


class Settings(BaseSettings):
    POSTGRES_USER: str = "postgres"
    POSTGRES_PASSWORD: str = "postgres"
    POSTGRES_DB: str = "postgres"
    POSTGRES_HOST: str = "127.0.0.1"
    POSTGRES_PORT: str = "5432"

    SECRET_KEY: str = '12345'
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    USER_APP_LIMITS: int = 10
    BLACKLIST_DOWNLOAD_URL: str = "https://phish.co.za/latest/"
    BLACKLIST_DOMAINS_FILE: str = "phishing-domains-ACTIVE.txt"
    BLACKLIST_IPS_FILE: str = "phishing-IPs-ACTIVE.txt"
    BLACKLIST_URLS_FILE: str = "phishing-links-ACTIVE.txt"
    DOWNLOAD_DIR: str = "download"
    TIMEOUT: int = 10
    MAX_URLS_IN_BATCH = 10

    class Config:
        env_file = ".env"


settings = Settings()