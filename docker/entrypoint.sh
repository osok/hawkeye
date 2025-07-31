#!/bin/bash
# HawkEye Docker Entrypoint Script
# Handles initialization, configuration, and command execution

set -e

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

# Print HawkEye banner
print_banner() {
    cat << 'EOF'
    ██╗  ██╗ █████╗ ██╗    ██╗██╗  ██╗███████╗██╗   ██╗███████╗
    ██║  ██║██╔══██╗██║    ██║██║ ██╔╝██╔════╝╚██╗ ██╔╝██╔════╝
    ███████║███████║██║ █╗ ██║█████╔╝ █████╗   ╚████╔╝ █████╗  
    ██╔══██║██╔══██║██║███╗██║██╔═██╗ ██╔══╝    ╚██╔╝  ██╔══╝  
    ██║  ██║██║  ██║╚███╔███╔╝██║  ██╗███████╗   ██║   ███████╗
    ╚═╝  ╚═╝╚═╝  ╚═╝ ╚══╝╚══╝ ╚═╝  ╚═╝╚══════╝   ╚═╝   ╚══════╝
    
    Hidden Application Weaknesses & Key Entry-point Yielding Evaluator
    MCP Security Reconnaissance Tool
EOF
}

# Environment variable defaults
export HAWKEYE_CONFIG="${HAWKEYE_CONFIG:-/app/config/hawkeye.yaml}"
export HAWKEYE_LOG_LEVEL="${HAWKEYE_LOG_LEVEL:-INFO}"
export HAWKEYE_DATA_DIR="${HAWKEYE_DATA_DIR:-/app/data}"
export HAWKEYE_RESULTS_DIR="${HAWKEYE_RESULTS_DIR:-/app/results}"
export HAWKEYE_LOGS_DIR="${HAWKEYE_LOGS_DIR:-/app/logs}"

# Create required directories
create_directories() {
    log_info "Creating required directories..."
    
    local dirs=(
        "$HAWKEYE_DATA_DIR"
        "$HAWKEYE_RESULTS_DIR"
        "$HAWKEYE_LOGS_DIR"
        "/app/temp"
    )
    
    for dir in "${dirs[@]}"; do
        if [[ ! -d "$dir" ]]; then
            mkdir -p "$dir"
            log_info "Created directory: $dir"
        fi
    done
    
    # Set proper permissions
    chmod 755 "$HAWKEYE_DATA_DIR" "$HAWKEYE_RESULTS_DIR" "$HAWKEYE_LOGS_DIR"
    chmod 1777 /app/temp  # Sticky bit for temp directory
}

# Initialize configuration
init_config() {
    log_info "Initializing configuration..."
    
    # Check if config file exists
    if [[ ! -f "$HAWKEYE_CONFIG" ]]; then
        log_warn "Configuration file not found: $HAWKEYE_CONFIG"
        
        # Try to copy from example
        local example_config="/app/config/hawkeye.yaml.example"
        if [[ -f "$example_config" ]]; then
            log_info "Copying example configuration..."
            cp "$example_config" "$HAWKEYE_CONFIG"
            log_success "Configuration initialized from example"
        else
            log_error "No example configuration found!"
            exit 1
        fi
    fi
    
    # Validate configuration
    if ! python -c "import yaml; yaml.safe_load(open('$HAWKEYE_CONFIG'))" 2>/dev/null; then
        log_error "Invalid YAML configuration file: $HAWKEYE_CONFIG"
        exit 1
    fi
    
    log_success "Configuration validated"
}

# Wait for dependencies
wait_for_dependencies() {
    log_info "Waiting for dependencies..."
    
    # Wait for Redis if configured
    if [[ -n "$HAWKEYE_REDIS_URL" ]]; then
        log_info "Waiting for Redis..."
        local redis_host=$(echo "$HAWKEYE_REDIS_URL" | sed -n 's/.*:\/\/\([^:]*\):.*/\1/p')
        local redis_port=$(echo "$HAWKEYE_REDIS_URL" | sed -n 's/.*:\([0-9]*\)\/.*/\1/p')
        
        timeout 30 bash -c "until nc -z $redis_host $redis_port; do sleep 1; done"
        log_success "Redis is ready"
    fi
    
    # Wait for PostgreSQL if configured
    if [[ -n "$HAWKEYE_DATABASE_URL" ]]; then
        log_info "Waiting for PostgreSQL..."
        local db_host=$(echo "$HAWKEYE_DATABASE_URL" | sed -n 's/.*@\([^:]*\):.*/\1/p')
        local db_port=$(echo "$HAWKEYE_DATABASE_URL" | sed -n 's/.*:\([0-9]*\)\/.*/\1/p')
        
        timeout 30 bash -c "until nc -z $db_host $db_port; do sleep 1; done"
        log_success "PostgreSQL is ready"
    fi
}

# Run database migrations
run_migrations() {
    if [[ -n "$HAWKEYE_DATABASE_URL" ]]; then
        log_info "Running database migrations..."
        
        if command -v alembic >/dev/null 2>&1; then
            cd /app
            alembic upgrade head
            log_success "Database migrations completed"
        else
            log_warn "Alembic not found, skipping migrations"
        fi
    fi
}

# Health check function
health_check() {
    log_info "Performing health check..."
    
    # Check if HawkEye can import properly
    if ! python -c "import hawkeye" 2>/dev/null; then
        log_error "Failed to import HawkEye module"
        return 1
    fi
    
    # Check configuration
    if ! python application.py config validate 2>/dev/null; then
        log_error "Configuration validation failed"
        return 1
    fi
    
    # Check dependencies
    if [[ -n "$HAWKEYE_REDIS_URL" ]]; then
        if ! python -c "import redis; r=redis.from_url('$HAWKEYE_REDIS_URL'); r.ping()" 2>/dev/null; then
            log_error "Redis connection failed"
            return 1
        fi
    fi
    
    log_success "Health check passed"
    return 0
}

# Setup signal handlers
setup_signal_handlers() {
    # Graceful shutdown on SIGTERM
    trap 'log_info "Received SIGTERM, shutting down gracefully..."; exit 0' TERM
    
    # Handle SIGINT (Ctrl+C)
    trap 'log_info "Received SIGINT, shutting down..."; exit 0' INT
}

# Main initialization
main_init() {
    print_banner
    log_info "Starting HawkEye initialization..."
    
    # Setup signal handlers
    setup_signal_handlers
    
    # Create directories
    create_directories
    
    # Initialize configuration
    init_config
    
    # Wait for dependencies
    wait_for_dependencies
    
    # Run migrations
    run_migrations
    
    log_success "HawkEye initialization completed"
}

# Command handling
handle_command() {
    local cmd="$1"
    shift
    
    case "$cmd" in
        "health-check")
            health_check
            ;;
        "scan")
            log_info "Starting HawkEye scan..."
            exec python application.py scan "$@"
            ;;
        "detect")
            log_info "Starting MCP detection..."
            exec python application.py detect "$@"
            ;;
        "report")
            log_info "Generating reports..."
            exec python application.py report "$@"
            ;;
        "config")
            log_info "Configuration management..."
            exec python application.py config "$@"
            ;;
        "server")
            log_info "Starting HawkEye server..."
            exec python application.py server "$@"
            ;;
        "worker")
            log_info "Starting Celery worker..."
            exec celery -A hawkeye.services.celery worker --loglevel="$HAWKEYE_LOG_LEVEL" "$@"
            ;;
        "beat")
            log_info "Starting Celery beat scheduler..."
            exec celery -A hawkeye.services.celery beat --loglevel="$HAWKEYE_LOG_LEVEL" "$@"
            ;;
        "shell")
            log_info "Starting interactive shell..."
            exec python application.py shell "$@"
            ;;
        "bash")
            log_info "Starting bash shell..."
            exec /bin/bash "$@"
            ;;
        "python")
            log_info "Starting Python interpreter..."
            exec python "$@"
            ;;
        *)
            # Default: run as HawkEye command
            log_info "Running HawkEye command: $cmd"
            exec python application.py "$cmd" "$@"
            ;;
    esac
}

# Main execution
main() {
    # Initialize if not in health check mode
    if [[ "$1" != "health-check" ]]; then
        main_init
    fi
    
    # Handle the command
    if [[ $# -eq 0 ]]; then
        log_info "No command specified, showing help..."
        exec python application.py --help
    else
        handle_command "$@"
    fi
}

# Execute main function with all arguments
main "$@" 