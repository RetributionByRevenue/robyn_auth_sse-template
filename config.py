"""
Application configuration
"""

import os
from pathlib import Path

class Config:
    """Application configuration class"""
    
    # Database
    DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./app.db")
    
    # JWT Settings
    SECRET_KEY = os.getenv("SECRET_KEY", "your_secret_key_change_in_production")
    ALGORITHM = "HS256"
    ACCESS_TOKEN_EXPIRE_HOURS = 1
    
    # Server
    PORT = int(os.getenv("PORT", 8080))
    DEBUG = os.getenv("DEBUG", "True").lower() == "true"
    
    # Paths
    BASE_DIR = Path(__file__).parent
    VIEWS_DIR = BASE_DIR / "views"
    
    # Initial Users (for seeding database)
    INITIAL_USERS = {
        "mark": "pass123",
        "luke": "pass456"
    }
