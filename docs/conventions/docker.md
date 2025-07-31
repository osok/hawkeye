# Docker Conventions

## Project Structure
```
project/
├── docker/
│   ├── Dockerfile.dev
│   ├── Dockerfile.prod
│   └── nginx/nginx.conf
├── docker-compose.yml
├── docker-compose.dev.yml
├── docker-compose.prod.yml
├── .dockerignore
└── scripts/
    ├── docker-entrypoint.sh
    └── wait-for-it.sh
```

## Dockerfile Patterns

### Development
- Base: `python:3.11-slim`
- Non-root user: `appuser`
- Volume mount for live code reloading
- Install dev dependencies
- Expose port 8000

### Production
- Multi-stage build (builder + production)
- Minimal production image
- Health check endpoint
- Security: non-root user, minimal packages
- Optimized layer caching (requirements first)

## Docker Compose Structure

### Development Services
- app: live reload with volume mounts
- db: PostgreSQL with persistent volume
- redis: for caching/sessions
- pgadmin: database management UI

### Production Services
- app: optimized production image
- nginx: reverse proxy with SSL
- db: PostgreSQL with resource limits
- redis: persistent storage
- certbot: SSL certificate management

## Environment Configuration
- `.env` file with all configuration
- Separate dev/prod environment files
- Required variables: `APP_NAME`, `DB_*`, `SECRET_KEY`
- SSL variables for production: `DOMAIN`, `SSL_EMAIL`

## Scripts & Utilities

### Docker Entrypoint Script
- Wait for database connectivity
- Run migrations automatically
- Create superuser if needed
- Support multiple modes: dev, prod, worker, migrate, shell
- Graceful error handling and logging

### Wait Script
- Wait for service availability (database, redis)
- Timeout handling
- Used in service dependencies

## Service Dependencies
- Database health checks before app start
- Proper service ordering in compose
- Restart policies: `unless-stopped`
- Resource limits in production

## Volume Management
- Named volumes for persistent data
- Bind mounts for development
- Exclude volumes: node_modules, venv
- Backup strategies for production data

## Networking
- Custom bridge networks
- Service discovery by name
- Port exposure only where needed
- SSL termination at nginx

## Health Monitoring
- Application health check endpoints: `/health`, `/ready`, `/live`
- Docker health checks in Dockerfile
- Service health in compose files
- Logging configuration with drivers

## Security Practices
- Non-root container users
- Minimal base images
- Secret management (avoid .env in production)
- SSL/TLS in production
- Regular image updates

## Development Workflow
- `make dev` - start development stack
- `make shell` - access app container
- `make migrate` - run database migrations
- `make test` - run test suite
- `make logs` - view service logs

## Production Deployment
- `make prod` - start production stack
- SSL certificate automation
- Database backup scripts
- Log aggregation and monitoring
- Rolling updates strategy

## Best Practices
- Use specific image tags, not `latest`
- Multi-stage builds for production
- Proper .dockerignore to reduce context
- Health checks for all services
- Resource limits and monitoring
- Automated SSL certificate renewal
- Regular security updates
- Database backup automation
