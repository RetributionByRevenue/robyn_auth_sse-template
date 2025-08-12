"""
Web controller - handles web interface routes
"""

import time
import json
from datetime import datetime, timedelta
from robyn import Response, SSEResponse, SSEMessage
from robyn.templating import JinjaTemplate
from passlib.context import CryptContext
from jose import JWTError, jwt
from sqlalchemy.orm import Session
from models.database import SessionLocal
from models.user import User
from config import Config
from models.courses import courses_db
from controllers.sse_controller import sse_controller

class WebController:
    """Controller for web interface"""
    
    def __init__(self):
        self.pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
        self.template = JinjaTemplate(str(Config.VIEWS_DIR))
    
    def _is_authenticated(self, request) -> bool:
        """Check if user is authenticated"""
        try:
            cookie_header = request.headers.get("cookie")
            if not cookie_header:
                return False
            
            token = self.extract_token_from_cookie(cookie_header)
            return self.is_token_valid(token)
        except:
            return False
    
    def _get_current_user(self, request) -> str:
        """Get current username from JWT token"""
        try:
            cookie_header = request.headers.get("cookie")
            if not cookie_header:
                return None
            
            token = self.extract_token_from_cookie(cookie_header)
            payload = self.decode_access_token(token)
            
            if payload:
                return payload.get("sub")
        except:
            pass
        return None
    
    def _redirect(self, location: str) -> Response:
        """Helper method to create redirect response"""
        return Response(
            status_code=302,
            description="",
            headers={"Location": location}
        )
    
    def _json_response(self, data: dict, status_code: int = 200) -> Response:
        """Helper method to create JSON response"""
        return Response(
            status_code=status_code,
            description=json.dumps(data),
            headers={"Content-Type": "application/json"}
        )
    
    def _parse_form_data(self, body: str) -> dict:
        """Parse URL-encoded form data"""
        import urllib.parse
        form_data = {}
        if body:
            pairs = body.split('&')
            for pair in pairs:
                if '=' in pair:
                    key, value = pair.split('=', 1)
                    form_data[urllib.parse.unquote_plus(key)] = urllib.parse.unquote_plus(value)
        return form_data
    
    
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
    
    def get_user_by_username(self, db: Session, username: str) -> User:
        """Get user by username"""
        return db.query(User).filter(User.username == username).first()
    
    def authenticate_user(self, db: Session, username: str, password: str) -> str:
        """Authenticate user and return JWT token"""
        user = self.get_user_by_username(db, username)
        
        if not user:
            return None
        
        if not self.verify_password(password, user.hashed_password):
            return None
        
        token = self.create_access_token(data={"sub": user.username})
        return token
    
    def redirect_to_login(self, request):
        """Root route - redirect to login"""
        return self._redirect("/login")
    
    def login_page(self, request):
        """Display login form"""
        if self._is_authenticated(request):
            return self._redirect("/protected")
        
        return self.template.render_template(template_name="login.html")
    
    async def handle_login(self, request):
        """Process login form submission"""
        try:
            form_data = self._parse_form_data(request.body)
            username = form_data.get("username")
            password = form_data.get("password")
        except:
            return self.template.render_template(
                template_name="login.html", 
                error="Error processing form data"
            )
        
        if not username or not password:
            return self.template.render_template(
                template_name="login.html", 
                error="Username and password are required"
            )
        
        # Authenticate user
        with SessionLocal() as db:
            token = self.authenticate_user(db, username, password)
        
        if token:
            # Successful login - set cookie and redirect
            response = Response(
                status_code=302,
                description="",
                headers={
                    "Location": "/protected",
                    "Set-Cookie": f"access_token={token}; Max-Age=3600; Path=/; HttpOnly"
                }
            )
            await sse_controller.create_user_queue(username)
            return response
        else:
            # Failed login
            return self.template.render_template(
                template_name="login.html", 
                error="Invalid username or password"
            )
    
    def protected_area(self, request):
        """Protected area - requires authentication"""
        if not self._is_authenticated(request):
            return self._redirect("/login")
        
        username = self._get_current_user(request)
        if not username:
            return self._redirect("/login")
        
        courses = courses_db.get_courses()
        return self.template.render_template(
            template_name="protected.html", 
            username=username,
            courses=courses
        )
    
    async def add_course(self, request):
        """Add a new course from form submission"""
        if not self._is_authenticated(request):
            return self._redirect("/login")

        try:
            form_data = request.form_data
            print("called!")
            course_title = form_data.get("course_title")
            print(course_title)
            if course_title:
                courses_db.add_course(course_title)
                username = self._get_current_user(request)
                print(username)
                if username:
                    courses = courses_db.get_courses()
                    html = (
                        '<ul>'
                        + ''.join(f'<li>{course}</li>' for course in courses)
                        + '</ul>'
                    )
                    message_data = {"html": {f"course_list_{username}": html}}
                    print("sent:",json.dumps(message_data))
                    await sse_controller.add_to_queue(username, json.dumps(message_data))
        except Exception as e:
            print(f"Error adding course: {e}") # For debugging
        
        return self._redirect("/protected")

    def logout(self, request):
        """Logout user - clear JWT token"""
        response = Response(
            status_code=302,
            description="",
            headers={
                "Location": "/login",
                "Set-Cookie": "access_token=; Max-Age=0; Path=/; HttpOnly"
            }
        )
        return response
    
