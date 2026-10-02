import os
from pydantic import BaseModel

class Settings(BaseModel):
    APP_NAME: str = "DevSecOps Demo Bank API"
    APP_VERSION: str = "1.0.0"
    ENVIRONMENT: str = os.getenv("ENVIRONMENT", "development")
    PORT: int = int(os.getenv("PORT", "8000"))
    HOST: str = os.getenv("HOST", "0.0.0.0")
    
    # Security Configuration
    # Safe retrieval with fallback for testing
    SECRET_KEY: str = os.getenv("JWT_SECRET_KEY", "insecure-dev-fallback-key-change-in-prod-32bytes!")
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60
    
    # Toggle to showcase security checks and vulnerability vectors
    ENABLE_SECURITY_DEMO_ENDPOINTS: bool = os.getenv("ENABLE_SECURITY_DEMO_ENDPOINTS", "true").lower() == "true"
    DATABASE_URL: str = os.getenv("DATABASE_URL", "sqlite:///./app_data.db")

settings = Settings()
