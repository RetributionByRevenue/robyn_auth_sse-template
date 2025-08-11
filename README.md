# Robyn Authentication & SSE Template

A complete authentication and Server-Sent Events (SSE) template built with the [Robyn](https://github.com/sansyrox/robyn) Python web framework. This project demonstrates JWT-based authentication, database integration with SQLAlchemy, and real-time updates using Server-Sent Events.

## Features

- **JWT Authentication**: Secure token-based authentication with HTTP-only cookies
- **Database Integration**: SQLAlchemy ORM with SQLite database
- **Server-Sent Events (SSE)**: Real-time updates with custom SSEXI.js client library
- **Web Interface**: Login/logout functionality with protected routes
- **API Endpoints**: RESTful API for authentication
- **Password Security**: bcrypt password hashing
- **Template Engine**: Jinja2 templates for HTML rendering

## Project Structure

```
├── main.py                 # Application entry point and route configuration
├── config.py              # Configuration settings and environment variables
├── requirements.txt       # Python dependencies
├── controllers/
│   ├── auth_controller.py  # API authentication endpoints
│   └── web_controllers.py  # Web interface controllers
├── models/
│   ├── database.py        # Database configuration and initialization
│   └── user.py           # User model definition
└── views/
    ├── login.html        # Login page template
    └── protected.html    # Protected area template with SSE integration
```

## Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd robyn_auth_sse-template
```

2. Create a virtual environment:
```bash
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

4. Set environment variables (optional):
```bash
export SECRET_KEY="your_secret_key_here"
export PORT=8080
export DEBUG=True
```

## Usage

1. Start the application:
```bash
python main.py
```

2. Open your browser and navigate to `http://localhost:8080`

3. Use the default credentials to log in:
   - Username: `mark`, Password: `pass123`
   - Username: `luke`, Password: `pass456`

## API Endpoints

### Authentication API
- `POST /api/login` - User login (returns JWT token)

### Web Routes
- `GET /` - Redirect to login page
- `GET /login` - Display login form
- `POST /login` - Process login form
- `GET /protected` - Protected area (requires authentication)
- `GET /protected/events/:username` - SSE endpoint for real-time updates
- `GET /logout` - User logout

## Configuration

The application can be configured via environment variables or by modifying `config.py`:

- `SECRET_KEY`: JWT secret key (change in production)
- `DATABASE_URL`: Database connection URL (default: SQLite)
- `PORT`: Server port (default: 8080)
- `DEBUG`: Debug mode (default: True)
- `ACCESS_TOKEN_EXPIRE_HOURS`: JWT token expiration time (default: 1 hour)

## Database

The application uses SQLite by default with the following schema:

### Users Table
- `id`: Primary key (Integer)
- `username`: Unique username (String)
- `hashed_password`: bcrypt hashed password (String)

Initial users are created automatically from the `INITIAL_USERS` configuration.

## Server-Sent Events (SSE)

The application includes a custom SSE implementation with the SSEXI.js client library that supports:

- Automatic connection management
- JavaScript execution from server messages
- HTML content updates
- Auto-reconnection on connection loss
- Custom event dispatching

### SSE Message Format

```json
{
  "js": {
    "exec": "console.log('News updated!')"
  },
  "html": {
    "elementId": "<div>New content</div>"
  }
}
```

## Security Features

- **Password Hashing**: bcrypt with configurable rounds
- **JWT Tokens**: Secure token-based authentication
- **HTTP-Only Cookies**: Prevents XSS attacks on tokens
- **CSRF Protection**: Form-based authentication with proper validation
- **Input Validation**: Username/password requirements and sanitization

## Development

### Adding New Routes

1. Add route handlers to the appropriate controller
2. Register routes in `main.py`
3. Update templates if needed

### Database Migrations

The application automatically creates tables on startup. For schema changes:

1. Modify models in `models/`
2. Update database initialization in `models/database.py`
3. Consider adding migration scripts for production

## Dependencies

Key dependencies include:

- **robyn**: Fast Python web framework
- **SQLAlchemy**: SQL toolkit and ORM
- **bcrypt**: Password hashing
- **python-jose**: JWT token handling
- **passlib**: Password hashing utilities
- **Jinja2**: Template engine

## License

This project is provided as a template for educational and development purposes.

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## Troubleshooting

### Common Issues

1. **Database errors**: Ensure SQLite is available and the app has write permissions
2. **JWT errors**: Check that `SECRET_KEY` is set and consistent
3. **SSE connection issues**: Verify browser support and network configuration
4. **Template not found**: Ensure `views/` directory contains the required HTML files

### Debug Mode

Enable debug mode by setting `DEBUG=True` in your environment or `config.py` for detailed error messages and auto-reload.