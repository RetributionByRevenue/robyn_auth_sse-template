"""
User model
"""

from sqlalchemy import Column, Integer, String
from models.database import Base

class User(Base):
    """User model for authentication"""
    
    __tablename__ = "users"
    
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    
    def __repr__(self):
        return f"<User(id={self.id}, username='{self.username}')>"
    
    def to_dict(self):
        """Convert user to dictionary (excluding password)"""
        return {
            "id": self.id,
            "username": self.username
        }
