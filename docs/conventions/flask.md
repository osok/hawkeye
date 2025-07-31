# Flask Conventions

## Project Structure
```
src/app/
├── __init__.py      # App factory
├── models/          # SQLAlchemy models
├── api/             # Blueprint modules
├── services/        # Business logic
├── utils/           # Decorators, validators
└── config/          # Settings
```

## App Factory Pattern
- `create_app(config_name)` function in `__init__.py`
- Initialize extensions: db, migrate, jwt, cors, limiter
- Register blueprints with URL prefixes: `/api/auth`, `/api/users`
- Separate functions: `register_blueprints()`, `register_error_handlers()`

## Configuration
- Pydantic settings converted to Flask config dict
- Function: `get_flask_config() -> dict`
- Environment-based config selection
- Required: `SECRET_KEY`, `DATABASE_URL`, `JWT_SECRET_KEY`

## Blueprint Organization
- One blueprint per major feature: `auth_bp`, `users_bp`
- Route patterns: `@bp.route('/endpoint', methods=['POST'])`
- All routes return: `success_response(data)` or `error_response(message, code)`
- Use decorators: `@validate_json(ModelClass)`, `@jwt_required()`

## Request Validation
- Pydantic models for request validation
- Decorator pattern: `@validate_json(RequestModel)`
- Automatic validation error responses with field details
- Pattern: `data = request.get_json()` after validation

## Response Standardization
- `success_response(data, status_code=200)` for success
- `error_response(message, status_code, details=None)` for errors
- Consistent structure: `{'success': bool, 'data': any, 'error': str}`
- Pagination: `paginated_response(items, page, per_page, total)`

## Authentication & Authorization
- JWT tokens with Flask-JWT-Extended
- `@jwt_required()` for protected routes
- `@admin_required` custom decorator for admin-only endpoints
- Current user: `get_jwt_identity()` returns user ID

## Service Layer
- Business logic separated from route handlers
- Services injected into routes: `user_service = UserService()`
- Method pattern: `def create_user(self, data: dict) -> User`
- Services handle database transactions and rollbacks

## Error Handling
- Global error handlers for common exceptions
- `@app.errorhandler(ExceptionType)` for each exception type
- Validation errors return field-level details
- Database errors logged and sanitized for response

## API Security
- Rate limiting with Flask-Limiter
- CORS configuration for frontend integration
- Input sanitization and validation
- Proper HTTP status codes (200, 201, 400, 401, 403, 404, 500)

## Testing Pattern
- Test client from `app.test_client()`
- Fixtures for app context and auth headers
- Test database setup/teardown per function
- Pattern: arrange, act, assert with clear test names

## Best Practices
- Use blueprints for organization
- Validate all inputs with Pydantic
- Separate business logic into services
- Handle errors gracefully with proper status codes
- Use JWT for stateless authentication
- Implement rate limiting and CORS
- Log important operations and errors
