#!/usr/bin/env python3
"""
Main application entry point
Initializes the Robyn app and sets up routes
"""

from robyn import Robyn
from controllers.auth_controller import AuthController
from controllers.web_controllers import WebController
from models.database import init_database
from models.user import User
from config import Config
import pathlib

def create_app():
    """Application factory"""
    app = Robyn(__file__)
    
    # Initialize database
    init_database()
    
    # Initialize controllers
    auth_controller = AuthController()
    web_controller = WebController()
    
    # Web Routes
    app.add_route("GET", "/", web_controller.redirect_to_login)
    app.add_route("GET", "/login", web_controller.login_page)
    app.add_route("POST", "/login", web_controller.handle_login)
    app.add_route("GET", "/protected", web_controller.protected_area)
    app.add_route("GET", "/protected/events", web_controller.stream_events)
    app.add_route("GET", "/logout", web_controller.logout)
    
    # API Routes
    app.add_route("POST", "/api/login", auth_controller.api_login)
    

    
    return app

def main():
    """Main entry point"""
    app = create_app()
    print("Server starting... Users initialized from USERS dict")
    app.start(port=Config.PORT)

if __name__ == "__main__":
    main()
