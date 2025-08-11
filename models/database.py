"""
Database configuration and session management
"""

from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from config import Config

# Database setup
engine = create_engine(
    Config.DATABASE_URL, 
    connect_args={"check_same_thread": False} if "sqlite" in Config.DATABASE_URL else {}
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

def get_db() -> Session:
    """Get database session"""
    db = SessionLocal()
    try:
        return db
    finally:
        pass  # Don't close here, let caller handle it

def init_database():
    """Initialize database tables"""
    # Import models to register them
    from models.user import User
    
    # Create all tables
    Base.metadata.create_all(bind=engine)
    
    # Seed initial users
    _seed_initial_users()

def _seed_initial_users():
    """Seed database with initial users from config"""
    from controllers.auth_controller import AuthController
    
    auth_controller = AuthController()
    
    with SessionLocal() as db:
        for username, password in Config.INITIAL_USERS.items():
            if not auth_controller.get_user_by_username(db, username):
                auth_controller.create_user(db, username, password)
                print(f"Created user: {username}")
