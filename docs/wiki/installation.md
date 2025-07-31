# 🚀 HawkEye Installation Guide
## Complete Setup and Deployment Instructions with AI Provider Configuration

### Version 2.0 - Updated with AI Analysis Setup

---

## Table of Contents

1. [System Requirements](#system-requirements)
2. [Quick Installation](#quick-installation)
3. [AI Provider Setup](#ai-provider-setup)
4. [Platform-Specific Installation](#platform-specific-installation)
5. [Docker Installation](#docker-installation)
6. [Development Setup](#development-setup)
7. [Configuration](#configuration)
8. [Verification](#verification)
9. [Troubleshooting](#troubleshooting)
10. [Uninstallation](#uninstallation)

---

## System Requirements

### Minimum Requirements

- **Operating System**: Linux, macOS, or Windows
- **Python**: Version 3.8 or higher
- **Memory**: 512MB RAM (2GB recommended for large scans, 4GB for AI analysis)
- **Storage**: 200MB for installation, additional space for logs and results
- **Network**: Internet access for installation and AI provider APIs

### Recommended Requirements for AI Analysis

- **Operating System**: Linux (Ubuntu 20.04+ or CentOS 8+)
- **Python**: Version 3.9 or higher
- **Memory**: 8GB RAM (for AI analysis with large datasets)
- **Storage**: 2GB available space
- **CPU**: Multi-core processor for optimal parallel processing
- **Network**: Stable internet connection for AI provider APIs
- **API Keys**: OpenAI, Anthropic, or Local LLM endpoint access

### Supported Platforms

| Platform | Version | Status | AI Analysis Support | Notes |
|----------|---------|--------|-------------------|-------|
| Ubuntu | 18.04+ | ✅ Fully Supported | ✅ Full Support | Recommended platform |
| Debian | 10+ | ✅ Fully Supported | ✅ Full Support | |
| CentOS | 7+ | ✅ Fully Supported | ✅ Full Support | |
| RHEL | 7+ | ✅ Fully Supported | ✅ Full Support | |
| macOS | 10.15+ | ✅ Fully Supported | ✅ Full Support | |
| Windows | 10+ | ⚠️ Limited Support | ⚠️ Limited Support | Some features may be limited |
| Docker | Any | ✅ Fully Supported | ✅ Full Support | Recommended for containers |

---

## Quick Installation

### One-Line Installation

For most users, this single command will install HawkEye:

```bash
curl -sSL https://raw.githubusercontent.com/yourusername/hawkeye/main/install.sh | bash
```

### Manual Quick Setup

```bash
# 1. Clone the repository
git clone https://github.com/yourusername/hawkeye.git
cd hawkeye

# 2. Create virtual environment
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Configure AI providers (optional but recommended)
cp env.example .env
# Edit .env file with your API keys (see AI Provider Setup section)

# 5. Verify installation
python application.py --version
python application.py info
```

---

## AI Provider Setup

HawkEye's AI-powered threat analysis requires configuration of at least one AI provider. This section covers setup for all supported providers.

### Supported AI Providers

| Provider | Models | Cost | Privacy | Setup Difficulty |
|----------|--------|------|---------|-----------------|
| **OpenAI** | GPT-4, GPT-3.5-turbo | $$ | Cloud | Easy |
| **Anthropic** | Claude-3, Claude-2 | $$ | Cloud | Easy |
| **Local LLM** | Ollama, etc. | Free | Local | Medium |

### 1. OpenAI Setup

#### Step 1: Create OpenAI Account
1. Visit [OpenAI Platform](https://platform.openai.com/)
2. Create an account or sign in
3. Add billing information (required for API access)

#### Step 2: Generate API Key
1. Navigate to [API Keys](https://platform.openai.com/api-keys)
2. Click "Create new secret key"
3. Copy the key (you won't see it again)

#### Step 3: Configure HawkEye
```bash
# Method 1: Environment file (recommended)
echo "AI_PROVIDER=openai" >> .env
echo "AI_OPENAI_API_KEY=your_api_key_here" >> .env

# Method 2: Environment variables
export AI_PROVIDER=openai
export AI_OPENAI_API_KEY=your_api_key_here

# Method 3: Configuration file
python application.py config set ai.provider openai
python application.py config set ai.openai.api_key your_api_key_here
```

#### Step 4: Test Configuration
```bash
# Test OpenAI connection
python -c "
import openai
import os
from dotenv import load_dotenv
load_dotenv()
client = openai.OpenAI(api_key=os.getenv('AI_OPENAI_API_KEY'))
print('✅ OpenAI connection successful')
"

# Test with HawkEye
python application.py detect local --output test.json
python application.py analyze-threats --input test.json --cost-limit 0.50
```

### 2. Anthropic Setup

#### Step 1: Create Anthropic Account
1. Visit [Anthropic Console](https://console.anthropic.com/)
2. Create an account or sign in
3. Add billing information

#### Step 2: Generate API Key
1. Navigate to [API Keys](https://console.anthropic.com/settings/keys)
2. Click "Create Key"
3. Copy the key

#### Step 3: Configure HawkEye
```bash
# Method 1: Environment file (recommended)
echo "AI_PROVIDER=anthropic" >> .env
echo "AI_ANTHROPIC_API_KEY=your_api_key_here" >> .env

# Method 2: Environment variables
export AI_PROVIDER=anthropic
export AI_ANTHROPIC_API_KEY=your_api_key_here

# Method 3: Configuration file
python application.py config set ai.provider anthropic
python application.py config set ai.anthropic.api_key your_api_key_here
```

#### Step 4: Test Configuration
```bash
# Test Anthropic connection
python -c "
import anthropic
import os
from dotenv import load_dotenv
load_dotenv()
client = anthropic.Anthropic(api_key=os.getenv('AI_ANTHROPIC_API_KEY'))
print('✅ Anthropic connection successful')
"

# Test with HawkEye
python application.py detect local --output test.json
python application.py analyze-threats --input test.json --cost-limit 0.50
```

### 3. Local LLM Setup (Ollama)

#### Step 1: Install Ollama
```bash
# Linux/macOS
curl -fsSL https://ollama.com/install.sh | sh

# Windows
# Download from https://ollama.com/download/windows

# Alternative: Docker
docker run -d -v ollama:/root/.ollama -p 11434:11434 --name ollama ollama/ollama
```

#### Step 2: Install Models
```bash
# Install recommended models for threat analysis
ollama pull llama3.1:8b      # Fast, good quality
ollama pull llama3.1:70b     # High quality, slower
ollama pull codellama:13b    # Good for technical analysis

# Verify installation
ollama list
```

#### Step 3: Configure HawkEye
```bash
# Method 1: Environment file (recommended)
echo "AI_PROVIDER=local_llm" >> .env
echo "AI_LOCAL_LLM_ENDPOINT=http://localhost:11434" >> .env
echo "AI_LOCAL_LLM_MODEL=llama3.1:8b" >> .env

# Method 2: Environment variables
export AI_PROVIDER=local_llm
export AI_LOCAL_LLM_ENDPOINT=http://localhost:11434
export AI_LOCAL_LLM_MODEL=llama3.1:8b
```

#### Step 4: Test Configuration
```bash
# Test Ollama connection
curl http://localhost:11434/api/tags

# Test with HawkEye
python application.py detect local --output test.json
python application.py analyze-threats --input test.json
```

### 4. Multi-Provider Setup (Recommended)

Configure multiple providers for redundancy and cost optimization:

```bash
# Primary provider
echo "AI_PROVIDER=anthropic" >> .env
echo "AI_ANTHROPIC_API_KEY=your_anthropic_key" >> .env

# Fallback provider
echo "AI_FALLBACK_PROVIDER=openai" >> .env
echo "AI_OPENAI_API_KEY=your_openai_key" >> .env

# Local LLM for privacy-sensitive analysis
echo "AI_LOCAL_LLM_ENDPOINT=http://localhost:11434" >> .env
echo "AI_LOCAL_LLM_MODEL=llama3.1:8b" >> .env
```

### 5. Cost Management

#### Set Global Cost Limits
```bash
# Set in environment file
echo "AI_MAX_COST_PER_ANALYSIS=1.00" >> .env
echo "AI_MAX_DAILY_COST=25.00" >> .env

# Or via command line for each analysis
python application.py analyze-threats --input results.json --cost-limit 5.0
```

#### Monitor Usage
```bash
# Check current usage
python application.py config show | grep -i cost

# View analysis statistics
python -c "
from src.hawkeye.detection.ai_threat import AIThreatAnalyzer
analyzer = AIThreatAnalyzer()
stats = analyzer.get_analysis_stats()
print(f'Total cost: ${stats[\"total_cost\"]:.4f}')
print(f'Analyses performed: {stats[\"analyses_performed\"]}')
"
```

---

## Platform-Specific Installation

### Ubuntu/Debian

#### Prerequisites

```bash
# Update package list
sudo apt update

# Install required system packages
sudo apt install -y python3 python3-pip python3-venv git curl

# Install development tools (for building some packages)
sudo apt install -y build-essential python3-dev libssl-dev libffi-dev

# Install additional dependencies for AI features
sudo apt install -y python3-tk  # For matplotlib if using visualization
```

#### Installation

```bash
# Clone repository
git clone https://github.com/yourusername/hawkeye.git
cd hawkeye

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Upgrade pip
pip install --upgrade pip

# Install dependencies
pip install -r requirements.txt

# Configure AI providers
cp env.example .env
nano .env  # Edit with your API keys

# Verify installation
python application.py info
```

### CentOS/RHEL

#### Prerequisites

```bash
# Install EPEL repository (for additional packages)
sudo yum install -y epel-release

# Install required packages
sudo yum install -y python3 python3-pip python3-devel git curl gcc openssl-devel libffi-devel

# Alternative for newer versions
sudo dnf install -y python3 python3-pip python3-devel git curl gcc openssl-devel libffi-devel
```

#### Installation

```bash
# Clone repository
git clone https://github.com/yourusername/hawkeye.git
cd hawkeye

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install --upgrade pip
pip install -r requirements.txt

# Configure
cp env.example .env
vi .env  # Edit with your API keys

# Verify
python application.py info
```

### macOS

#### Prerequisites

```bash
# Install Homebrew (if not already installed)
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Install Python 3.9+
brew install python@3.9 git curl

# Alternative: Use system Python with pyenv
brew install pyenv
pyenv install 3.9.0
pyenv global 3.9.0
```

#### Installation

```bash
# Clone repository
git clone https://github.com/yourusername/hawkeye.git
cd hawkeye

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install --upgrade pip
pip install -r requirements.txt

# Configure AI providers
cp env.example .env
open .env  # Edit with your preferred editor

# Verify installation
python application.py info
```

### Windows

#### Prerequisites

1. **Install Python 3.8+**
   - Download from [python.org](https://www.python.org/downloads/)
   - ✅ Check "Add Python to PATH" during installation

2. **Install Git**
   - Download from [git-scm.com](https://git-scm.com/download/win)

3. **Install Visual Studio Build Tools** (for some packages)
   - Download from [Microsoft](https://visualstudio.microsoft.com/visual-cpp-build-tools/)

#### Installation

```powershell
# Clone repository
git clone https://github.com/yourusername/hawkeye.git
cd hawkeye

# Create virtual environment
python -m venv venv
venv\Scripts\activate

# Install dependencies
pip install --upgrade pip
pip install -r requirements.txt

# Configure AI providers
copy env.example .env
notepad .env  # Edit with your API keys

# Verify installation
python application.py info
```

---

## Docker Installation

### Pre-Built Image

```bash
# Pull the latest image
docker pull hawkeye/hawkeye:latest

# Run with AI provider configuration
docker run -it --rm \
  -e AI_PROVIDER=anthropic \
  -e AI_ANTHROPIC_API_KEY=your_key_here \
  -v $(pwd)/results:/app/results \
  hawkeye/hawkeye:latest \
  detect local

# Run with configuration file
docker run -it --rm \
  -v $(pwd)/.env:/app/.env \
  -v $(pwd)/results:/app/results \
  hawkeye/hawkeye:latest \
  analyze-threats -i /app/results/detection.json
```

### Build from Source

```bash
# Clone repository
git clone https://github.com/yourusername/hawkeye.git
cd hawkeye

# Build image
docker build -t hawkeye-local .

# Run with AI configuration
docker run -it --rm \
  --env-file .env \
  -v $(pwd)/results:/app/results \
  hawkeye-local \
  detect local -o /app/results/local.json
```

### Docker Compose (Recommended)

Create `docker-compose.yml`:

```yaml
version: '3.8'

services:
  hawkeye:
    build: .
    environment:
      - AI_PROVIDER=anthropic
      - AI_ANTHROPIC_API_KEY=${AI_ANTHROPIC_API_KEY}
      - AI_FALLBACK_PROVIDER=openai
      - AI_OPENAI_API_KEY=${AI_OPENAI_API_KEY}
    volumes:
      - ./results:/app/results
      - ./logs:/app/logs
    networks:
      - hawkeye_network

  ollama:
    image: ollama/ollama:latest
    ports:
      - "11434:11434"
    volumes:
      - ollama_data:/root/.ollama
    networks:
      - hawkeye_network

networks:
  hawkeye_network:
    driver: bridge

volumes:
  ollama_data:
```

```bash
# Start services
docker-compose up -d

# Run analysis
docker-compose exec hawkeye python application.py detect local -o /app/results/local.json
docker-compose exec hawkeye python application.py analyze-threats -i /app/results/local.json
```

---

## Development Setup

### Clone for Development

```bash
# Fork the repository on GitHub first, then:
git clone https://github.com/YOUR_USERNAME/hawkeye.git
cd hawkeye

# Add upstream remote
git remote add upstream https://github.com/original-owner/hawkeye.git
```

### Development Environment

```bash
# Create development virtual environment
python3 -m venv venv-dev
source venv-dev/bin/activate

# Install development dependencies
pip install --upgrade pip
pip install -r requirements.txt
pip install -r requirements-dev.txt

# Install in development mode
pip install -e .
```

### Development Tools Setup

```bash
# Install pre-commit hooks
pre-commit install

# Install code quality tools
pip install black ruff mypy pytest pytest-cov

# Run code quality checks
black src/ tests/
ruff src/ tests/
mypy src/
```

### AI Development Setup

```bash
# Set up development AI environment
cp env.example .env.dev

# Edit with development API keys (use separate keys for dev)
echo "AI_PROVIDER=anthropic" >> .env.dev
echo "AI_ANTHROPIC_API_KEY=your_dev_key" >> .env.dev
echo "AI_MAX_COST_PER_ANALYSIS=0.10" >> .env.dev

# Test AI development setup
python -c "
from src.hawkeye.detection.ai_threat import AIThreatAnalyzer
analyzer = AIThreatAnalyzer()
print('✅ AI development setup successful')
"
```

---

## Configuration

### Environment Variables

HawkEye supports configuration via environment variables:

```bash
# Core settings
export HAWKEYE_DEBUG=true
export HAWKEYE_LOG_LEVEL=DEBUG
export HAWKEYE_LOG_FILE=/var/log/hawkeye.log

# AI provider settings
export AI_PROVIDER=anthropic
export AI_ANTHROPIC_API_KEY=your_key
export AI_FALLBACK_PROVIDER=openai
export AI_OPENAI_API_KEY=your_key
export AI_MAX_COST_PER_ANALYSIS=1.00
export AI_MAX_DAILY_COST=25.00

# Local LLM settings
export AI_LOCAL_LLM_ENDPOINT=http://localhost:11434
export AI_LOCAL_LLM_MODEL=llama3.1:8b
export AI_LOCAL_LLM_TIMEOUT=120

# Performance settings
export HAWKEYE_MAX_THREADS=50
export HAWKEYE_DEFAULT_TIMEOUT=30
```

### Configuration File

Create `hawkeye.yaml`:

```yaml
# Core settings
debug: false
log_level: INFO
log_file: /var/log/hawkeye.log

# AI configuration
ai:
  provider: anthropic
  fallback_provider: openai
  max_cost_per_analysis: 1.00
  max_daily_cost: 25.00
  
  anthropic:
    api_key: "your_anthropic_key"
    model: "claude-3-haiku-20240307"
    
  openai:
    api_key: "your_openai_key"
    model: "gpt-3.5-turbo"
    
  local_llm:
    endpoint: "http://localhost:11434"
    model: "llama3.1:8b"
    timeout: 120

# Scanning settings
scan:
  max_threads: 50
  default_timeout: 30
  default_ports: [3000, 8000, 8080, 9000]

# Detection settings
detection:
  enable_ai_analysis: true
  confidence_threshold: 0.5
  parallel_processing: true
  max_workers: 3
```

Use with:
```bash
python application.py --config-file hawkeye.yaml detect local
```

---

## Verification

### Basic Verification

```bash
# Check installation
python application.py --version
python application.py info

# Test basic functionality
python application.py detect local --output test_local.json
cat test_local.json | head -20
```

### AI Provider Verification

```bash
# Test each configured provider
python application.py config show | grep -i ai

# Test OpenAI (if configured)
python -c "
import os
from src.hawkeye.detection.ai_threat.ai_providers import OpenAIProvider
try:
    provider = OpenAIProvider()
    print('✅ OpenAI provider initialized successfully')
except Exception as e:
    print(f'❌ OpenAI provider failed: {e}')
"

# Test Anthropic (if configured)
python -c "
import os
from src.hawkeye.detection.ai_threat.ai_providers import AnthropicProvider
try:
    provider = AnthropicProvider()
    print('✅ Anthropic provider initialized successfully')
except Exception as e:
    print(f'❌ Anthropic provider failed: {e}')
"

# Test Local LLM (if configured)
curl -s http://localhost:11434/api/tags || echo "❌ Local LLM not running"
```

### Full Workflow Test

```bash
# Complete workflow test
echo "🧪 Testing complete HawkEye workflow with AI analysis"

# Step 1: Detection
python application.py detect local --output workflow_test.json
echo "✅ Detection completed"

# Step 2: AI Analysis (with cost limit for safety)
python application.py analyze-threats \
  --input workflow_test.json \
  --cost-limit 0.50 \
  --output workflow_analysis.json
echo "✅ AI analysis completed"

# Step 3: Report generation
python application.py analyze-threats \
  --input workflow_test.json \
  --format html \
  --cost-limit 0.50 \
  --output workflow_report.html
echo "✅ HTML report generated"

echo "🎉 Full workflow test successful!"
echo "📊 View report: workflow_report.html"
```

---

## Troubleshooting

### Common Installation Issues

#### Issue 1: Python Version
```bash
# Check Python version
python --version
python3 --version

# If too old, install newer version
# Ubuntu/Debian
sudo apt install python3.9 python3.9-venv

# macOS
brew install python@3.9
```

#### Issue 2: Virtual Environment
```bash
# If venv creation fails
python3 -m pip install --user virtualenv
python3 -m virtualenv venv

# If activation fails on Windows
venv\Scripts\activate.bat  # Instead of .ps1
```

#### Issue 3: Package Installation
```bash
# If pip install fails
pip install --upgrade pip setuptools wheel

# If specific packages fail
pip install --only-binary=all package_name

# Clear pip cache
pip cache purge
```

### AI Provider Issues

#### Issue 1: API Key Problems
```bash
# Check API key format
echo $AI_ANTHROPIC_API_KEY | head -c 20  # Should start with 'sk-ant'
echo $AI_OPENAI_API_KEY | head -c 20     # Should start with 'sk-'

# Test API key directly
curl https://api.anthropic.com/v1/models \
  -H "x-api-key: $AI_ANTHROPIC_API_KEY"
```

#### Issue 2: Network/Firewall Issues
```bash
# Test connectivity
curl -I https://api.openai.com/v1/models
curl -I https://api.anthropic.com/v1/models

# Check proxy settings
echo $HTTP_PROXY
echo $HTTPS_PROXY
```

#### Issue 3: Local LLM Issues
```bash
# Check Ollama status
systemctl status ollama  # Linux with systemd
brew services list | grep ollama  # macOS

# Check Ollama logs
journalctl -u ollama --no-pager -n 50  # Linux
brew services restart ollama  # macOS

# Test direct API
curl http://localhost:11434/api/generate \
  -d '{"model": "llama3.1:8b", "prompt": "Hello", "stream": false}'
```

### Permission Issues

```bash
# If permission denied on Linux/macOS
chmod +x application.py

# If docker permission denied
sudo usermod -a -G docker $USER
# Then logout and login again

# If log file permission denied
sudo mkdir -p /var/log/hawkeye
sudo chown $USER:$USER /var/log/hawkeye
```

### Performance Issues

```bash
# If analysis is slow
export AI_MAX_WORKERS=1  # Reduce parallel processing
python application.py analyze-threats \
  --input results.json \
  --sequential-processing

# If memory issues
python application.py analyze-threats \
  --input results.json \
  --confidence-threshold 0.8  # Filter results

# Monitor resource usage
htop  # Or Activity Monitor on macOS
```

---

## Uninstallation

### Standard Uninstallation

```bash
# Remove virtual environment
rm -rf venv

# Remove project directory
cd ..
rm -rf hawkeye

# Remove configuration files (optional)
rm ~/.hawkeye.yaml
rm .env
```

### Complete Cleanup

```bash
# Remove all HawkEye files
rm -rf hawkeye/
rm -rf ~/.hawkeye/
rm -rf /var/log/hawkeye/

# Remove Docker images (if used)
docker rmi hawkeye/hawkeye:latest
docker rmi hawkeye-local

# Remove Ollama models (if no longer needed)
ollama rm llama3.1:8b
ollama rm llama3.1:70b
```

### Clean Environment Variables

```bash
# Remove from shell profile (.bashrc, .zshrc, etc.)
# Remove lines containing:
# export AI_PROVIDER=
# export AI_ANTHROPIC_API_KEY=
# export AI_OPENAI_API_KEY=
# etc.

# Or temporarily unset
unset AI_PROVIDER
unset AI_ANTHROPIC_API_KEY
unset AI_OPENAI_API_KEY
```

---

## Next Steps

After successful installation, see:

- 📖 **[Workflow Guide](workflow_guide.md)** - Step-by-step usage scenarios with AI analysis
- 📋 **[User Manual](user_manual.md)** - Comprehensive usage guide
- 🤖 **[AI Threat Analysis README](../AI_THREAT_ANALYSIS_README.md)** - Deep dive into AI capabilities
- 🔧 **[API Documentation](api/README.md)** - Developer reference

For support, visit our [GitHub Issues](https://github.com/yourusername/hawkeye/issues) or [Discussions](https://github.com/yourusername/hawkeye/discussions).

---

**HawkEye** - *Seeing beyond the visible, securing the invisible.* 