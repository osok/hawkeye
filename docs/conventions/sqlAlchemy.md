# SQLAlchemy Conventions

## Project Structure
```
src/
├── models/
│   ├── base.py         # Base model + mixins
│   └── {entity}.py     # Individual models
├── repositories/
│   ├── base_repository.py
│   └── {entity}_repository.py
└── database/
    ├── connection.py   # Engine & session
    └── session.py      # Session management
```

## Database Configuration
- Pydantic settings for database config
- Connection pooling with `QueuePool`
- Settings: `database_url`, `pool_size`, `max_overflow`, `pool_pre_ping`
- Engine creation with performance optimizations

## Base Model Pattern
- Abstract `BaseModel` with common fields: `id`, `created_at`, `updated_at`, `is_active`
- Methods: `to_dict()`, `update_from_dict(data)`, `__repr__()`
- Use `declarative_base()` for model inheritance
- Server defaults for timestamps: `server_default=func.now()`

## Model Mixins
- `TimestampMixin`: created_at, updated_at fields
- `SoftDeleteMixin`: deleted_at, is_deleted fields with `soft_delete()` method
- `AuditMixin`: created_by, updated_by foreign keys
- `SlugMixin`: slug field with `generate_slug(text)` method

## Model Definitions
- Inherit from `BaseModel` + relevant mixins
- Use `@hybrid_property` for computed fields
- Relationship patterns: `relationship("Model", back_populates="field")`
- Validation with `@validator` decorator
- Custom methods: `set_password()`, `check_password()`, `validate_email()`

## Repository Pattern
- Generic `BaseRepository[ModelType]` with CRUD operations
- Methods: `get_by_id()`, `get_all()`, `create()`, `update()`, `delete()`
- Custom repositories extend base with model-specific methods
- Error handling with logging and transaction rollback

## Advanced Queries
- Eager loading: `joinedload()`, `selectinload()`, `contains_eager()`
- Complex filtering with `and_()`, `or_()`, subqueries
- Aggregation with `func.count()`, `func.avg()`, etc.
- Raw SQL for complex analytics when needed

## Session Management
- `SessionLocal` factory from `sessionmaker()`
- Context manager: `with get_db() as session:`
- Dependency injection for Flask/FastAPI
- Proper session cleanup in finally blocks

## Migration Strategy
- Alembic for schema migrations
- Auto-generation: `flask db migrate -m "message"`
- Manual review of generated migrations
- Separate upgrade/downgrade functions

## Performance Optimization
- Database indexes on frequently queried columns
- Connection pooling configuration
- Query performance monitoring with event listeners
- Bulk operations for large datasets: `bulk_insert_mappings()`

## Error Handling
- Specific exception handling: `IntegrityError`, `DataError`
- Transaction rollback on errors
- Logging with context (model, operation, parameters)
- Custom exceptions for business logic errors

## Testing Patterns
- In-memory SQLite for tests: `sqlite:///:memory:`
- Per-test database setup/teardown
- Repository testing with mock sessions
- Model validation testing

## Best Practices
- Use soft delete instead of hard delete
- Implement audit trails for sensitive data
- Use database constraints and foreign keys
- Index frequently queried columns
- Monitor query performance
- Use transactions appropriately
- Separate read/write operations when scaling
- Use connection pooling in production
