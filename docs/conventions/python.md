# Python Coding Conventions

## Project Structure
```
project-name/
├── src/package_name/
│   ├── models/
│   ├── services/
│   ├── utils/
│   └── config/
├── tests/
├── venv/
├── application.py
├── requirements.txt
├── .env
└── README.md
```

## Environment & Dependencies
- Always use `python -m venv venv` for virtual environments,create this first after the task list
- Use pip with requirements.txt (not Poetry/pipenv)
- Store configuration in .env files with Pydantic BaseSettings classes
- Entry point: `application.py` in root that imports from `src/`

## Code Style
- Use Black for formatting, Ruff for linting, mypy for type checking
- Type hints on all function signatures: `def func(param: Type) -> ReturnType:`
- Import order: stdlib, third-party, local (separated by blank lines)
- Prefer Pydantic models over dataclasses for data validation
- Use `str | None` over `Optional[str]` when possible

## Error Handling
- Custom exceptions for business logic: `class UserNotFoundError(Exception):`
- Specific exception types, not bare `except:`
- Always include meaningful error messages
- Log errors before re-raising

## Configuration Pattern
- Pydantic BaseSettings class reading from .env
- Use `@lru_cache()` decorator for settings singleton
- Field validation with `Field(..., env="ENV_VAR")`
- Separate settings classes for different concerns

## Models & Data
- Use Pydantic BaseModel for all data structures
- Validators with `@validator` decorator
- Enums for constants: `class Status(str, Enum):`
- Hybrid properties for computed fields
- `to_dict()` method excluding sensitive data by default

## Testing
- pytest in `tests/` directory at project root
- Fixtures in `conftest.py`
- Pattern: `test_feature/test_specific_case.py`
- Mock external dependencies, test business logic

## Logging
- Standard logging with appropriate levels
- Format: timestamp, name, level, message, location
- File + console handlers
- Use `logger = logging.getLogger(__name__)`

## Service Layer
- Business logic in service classes
- Services take repositories as dependencies
- Pattern: `def method(self, input: InputModel) -> OutputModel:`
- Async methods when dealing with I/O operations

## Best Practices
- Single responsibility principle for functions/classes
- Dependency injection for services
- Environment variables for all config
- Meaningful names, no abbreviations
- Keep functions under 20 lines when possible
