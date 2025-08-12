#!/usr/bin/env python3
"""
Main application entry point
Initializes the Robyn app and sets up routes
"""

from robyn import Robyn, SSEResponse, SSEMessage
from controllers.auth_controller import AuthController
from controllers.web_controllers import WebController
from controllers.sse_controller import sse_controller
from models.database import init_database
from models.user import User
from config import Config
import pathlib
import asyncio

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
    app.add_route("POST", "/add_course", web_controller.add_course)
    app.add_route("GET", "/logout", web_controller.logout)
    
    # API Routes
    app.add_route("POST", "/api/login", auth_controller.api_login)
    
    async def stream_events(request):
        username = request.path_params.get("username")
        print(f"SSE connection established for user: {username}")
        
        # Ensure user queue exists
        await sse_controller.create_user_queue(username)
        print(f"Queue created/ensured for user: {username}")
        
        async def event_generator():
            while True:
                #print(f"Checking queue for user: {username}")
                data = await sse_controller.get_from_queue(username)
                if data:
                    print(f"Yielding SSE message for {username}: {data}")
                    yield SSEMessage(data)
                # else:
                #     print(f"No data in queue for user: {username}")
                await asyncio.sleep(0.1)

        return SSEResponse(event_generator())

    app.add_route("GET", "/stream/:username", stream_events)

    
    return app

def main():
    """Main entry point"""
    app = create_app()
    print("Server starting... Users initialized from USERS dict")
    app.start(port=Config.PORT)

if __name__ == "__main__":
    main()
