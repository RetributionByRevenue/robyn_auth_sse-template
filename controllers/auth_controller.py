"""
Authentication controller - handles API authentication routes
"""

import json
from datetime import datetime, timedelta
from robyn import Response
from passlib.context import CryptContext
from jose import JWTError, jwt
from sqlalchemy.orm import Session
from models.database import SessionLocal
from models.user import User
from config import Config

class AuthController:
    """Controller for authentication API endpoints"""
    
    def __init__(self):
        self.pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
    
    def _json_response(self, data: dict, status_code: int = 200) -> Response:
        """Helper method to create JSON response"""
        return Response(
            status_code=status_code,
            description=json.dumps(data),
            headers={"Content-Type": "application/json"}
        )
    
    def _error_response(self, message: str, status_code: int = 400) -> Response:
        """Helper method to create error response"""
        return self._json_response({"error": message}, status_code)
    
    def get_password_hash(self, password: str) -> str:
        """Hash a password"""
        return self.pwd_context.hash(password)
    
    def verify_password(self, plain_password: str, hashed_password: str) -> bool:
        """Verify a password against its hash"""
        return self.pwd_context.verify(plain_password, hashed_password)
    
    def create_access_token(self, data: dict, expires_delta: timedelta = None) -> str:
        """Create a JWT access token"""
        to_encode = data.copy()
        
        if expires_delta:
            expire = datetime.utcnow() + expires_delta
        else:
            expire = datetime.utcnow() + timedelta(hours=Config.ACCESS_TOKEN_EXPIRE_HOURS)
        
        to_encode.update({"exp": expire})
        encoded_jwt = jwt.encode(to_encode, Config.SECRET_KEY, algorithm=Config.ALGORITHM)
        return encoded_jwt
    
    def decode_access_token(self, token: str) -> dict:
        """Decode and validate a JWT token"""
        try:
            payload = jwt.decode(token, Config.SECRET_KEY, algorithms=[Config.ALGORITHM])
            return payload
        except JWTError:
            return None
    
    def extract_token_from_cookie(self, cookie_header: str) -> str:
        """Extract JWT token from cookie header"""
        if not cookie_header or "access_token=" not in cookie_header:
            return None
        
        try:
            token = cookie_header.split("access_token=")[1].split(";")[0]
            return token
        except (IndexError, AttributeError):
            return None
    
    def is_token_valid(self, token: str) -> bool:
        """Check if a token is valid"""
        payload = self.decode_access_token(token)
        return payload is not None
    
    def get_user_by_id(self, db: Session, user_id: int) -> User:
        """Get user by ID"""
        return db.query(User).filter(User.id == user_id).first()
    
    def get_user_by_username(self, db: Session, username: str) -> User:
        """Get user by username"""
        return db.query(User).filter(User.username == username).first()
    
    def create_user(self, db: Session, username: str, password: str) -> User:
        """Create a new user"""
        if self.get_user_by_username(db, username):
            raise ValueError(f"User '{username}' already exists")
        
        hashed_password = self.get_password_hash(password)
        db_user = User(username=username, hashed_password=hashed_password)
        
        db.add(db_user)
        db.commit()
        db.refresh(db_user)
        
        return db_user
    
    def authenticate_user(self, db: Session, username: str, password: str) -> str:
        """Authenticate user and return JWT token"""
        user = self.get_user_by_username(db, username)
        
        if not user:
            return None
        
        if not self.verify_password(password, user.hashed_password):
            return None
        
        token = self.create_access_token(data={"sub": user.username})
        return token
    
    def validate_token(self, token: str) -> dict:
        """Validate JWT token and return payload"""
        return self.decode_access_token(token)
    
    def register_user(self, request):
        """API endpoint for user registration"""
        try:
            data = request.json()
            username = data.get("username")
            password = data.get("password")
            
            if not username or not password:
                return self._error_response("Username and password are required", 400)
            
            # Validate input
            if len(username) < 3:
                return self._error_response("Username must be at least 3 characters", 400)
            
            if len(password) < 6:
                return self._error_response("Password must be at least 6 characters", 400)
            
            with SessionLocal() as db:
                try:
                    user = self.create_user(db, username, password)
                    return self._json_response({
                        "message": f"User '{username}' created successfully",
                        "user": user.to_dict()
                    }, 201)
                except ValueError as e:
                    return self._error_response(str(e), 400)
                
        except json.JSONDecodeError:
            return self._error_response("Invalid JSON", 400)
        except Exception as e:
            return self._error_response("Internal server error", 500)
    
    def api_login(self, request):
        """API endpoint for user login - returns JWT token"""
        try:
            data = request.json()
            username = data.get("username")
            password = data.get("password")
            
            if not username or not password:
                return self._error_response("Username and password are required", 400)
            
            with SessionLocal() as db:
                token = self.authenticate_user(db, username, password)
            
            if token:
                return self._json_response({
                    "access_token": token,
                    "token_type": "bearer",
                    "username": username
                })
            else:
                return self._error_response("Invalid credentials", 401)
                
        except json.JSONDecodeError:
            return self._error_response("Invalid JSON", 400)
        except Exception as e:
            return self._error_response("Internal server error", 500)
    
    def get_current_user(self, request):
        """Get current user info from JWT token"""
        try:
            # Extract token from Authorization header
            auth_header = request.headers.get("authorization")
            if not auth_header or not auth_header.startswith("Bearer "):
                return self._error_response("Missing or invalid authorization header", 401)
            
            token = auth_header.split(" ")[1]
            payload = self.validate_token(token)
            
            if not payload:
                return self._error_response("Invalid or expired token", 401)
            
            username = payload.get("sub")
            if not username:
                return self._error_response("Invalid token payload", 401)
            
            with SessionLocal() as db:
                user = self.get_user_by_username(db, username)
                if not user:
                    return self._error_response("User not found", 404)
                
                return self._json_response({
                    "user": user.to_dict()
                })
                
        except Exception as e:
            return self._error_response("Internal server error", 500)
