# 🔧 HawkEye Troubleshooting Guide
## Diagnostic Procedures and Problem Resolution

### Version 1.0 

---

## Table of Contents

1. [Quick Diagnostic Checklist](#quick-diagnostic-checklist)
2. [Installation Issues](#installation-issues)
3. [Network Connectivity Problems](#network-connectivity-problems)
4. [Scanning Issues](#scanning-issues)
5. [Performance Problems](#performance-problems)
6. [Configuration Issues](#configuration-issues)
7. [Reporting Problems](#reporting-problems)
8. [Error Messages](#error-messages)
9. [Log Analysis](#log-analysis)
10. [Advanced Diagnostics](#advanced-diagnostics)

---

## Quick Diagnostic Checklist

Before diving into detailed troubleshooting, run through this quick checklist:

### Basic System Check

```bash
# 1. Verify Python version
python --version
# Expected: Python 3.8 or higher

# 2. Check virtual environment
which python
# Expected: Path should include 'venv' if using virtual environment

# 3. Verify HawkEye installation
python application.py --version
# Expected: HawkEye version information

# 4. Test basic connectivity
ping 8.8.8.8
# Expected: Successful ping responses

# 5. Check available disk space
df -h
# Expected: Sufficient space for logs and results

# 6. Verify permissions
ls -la application.py
# Expected: Read and execute permissions
```

### Quick Health Check

```bash
# Run HawkEye health check
python application.py health-check

# Expected output:
# ✅ Python version: OK (3.8+)
# ✅ Dependencies: OK
# ✅ Configuration: OK
# ✅ Network access: OK
# ✅ Disk space: OK
# ✅ Permissions: OK
```

---

## Installation Issues

### Problem: Python Version Incompatibility

**Symptoms:**
- `SyntaxError` when running HawkEye
- Import errors for modern Python features
- Version warnings during startup

**Diagnosis:**
```bash
python --version
python3 --version
```

**Solutions:**

1. **Install Python 3.8+:**
```bash
# Ubuntu/Debian
sudo apt update
sudo apt install python3.8 python3.8-venv python3.8-pip

# CentOS/RHEL
sudo yum install python38 python38-pip

# macOS (using Homebrew)
brew install python@3.8

# Windows
# Download from python.org and install
```

2. **Use Python 3.8+ explicitly:**
```bash
python3.8 -m venv venv
source venv/bin/activate
python3.8 -m pip install -r requirements.txt
```

### Problem: Dependency Installation Failures

**Symptoms:**
- `pip install` errors
- Missing module errors
- Compilation failures

**Diagnosis:**
```bash
pip install -r requirements.txt --verbose
pip check
```

**Solutions:**

1. **Update pip and setuptools:**
```bash
pip install --upgrade pip setuptools wheel
```

2. **Install system dependencies:**
```bash
# Ubuntu/Debian
sudo apt install build-essential python3-dev libssl-dev libffi-dev

# CentOS/RHEL
sudo yum groupinstall "Development Tools"
sudo yum install python3-devel openssl-devel libffi-devel

# macOS
xcode-select --install
```

3. **Use pre-compiled wheels:**
```bash
pip install --only-binary=all -r requirements.txt
```

### Problem: Virtual Environment Issues

**Symptoms:**
- Cannot activate virtual environment
- Wrong Python version in venv
- Package conflicts

**Diagnosis:**
```bash
which python
echo $VIRTUAL_ENV
pip list
```

**Solutions:**

1. **Recreate virtual environment:**
```bash
deactivate
rm -rf venv
python3.8 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

2. **Fix activation script:**
```bash
# Linux/macOS
source venv/bin/activate

# Windows
venv\Scripts\activate.bat
```

---

## Network Connectivity Problems

### Problem: DNS Resolution Failures

**Symptoms:**
- `getaddrinfo failed` errors
- Cannot resolve hostnames
- Timeouts on domain names

**Diagnosis:**
```bash
nslookup google.com
dig google.com
python -c "import socket; print(socket.gethostbyname('google.com'))"
```

**Solutions:**

1. **Configure DNS servers:**
```bash
# Temporary fix
echo "nameserver 8.8.8.8" | sudo tee /etc/resolv.conf

# Permanent fix (Ubuntu)
sudo systemctl edit systemd-resolved
# Add:
# [Resolve]
# DNS=8.8.8.8 1.1.1.1
```

2. **Use IP addresses instead:**
```bash
python application.py scan --target 192.168.1.100
```

### Problem: Firewall Blocking

**Symptoms:**
- Connection timeouts
- "Connection refused" errors
- Partial scan results

**Diagnosis:**
```bash
# Test specific ports
telnet 192.168.1.100 3000
nc -zv 192.168.1.100 3000

# Check local firewall
sudo iptables -L
sudo ufw status
```

**Solutions:**

1. **Configure firewall rules:**
```bash
# Allow outbound connections
sudo iptables -A OUTPUT -p tcp --dport 3000 -j ACCEPT
sudo iptables -A OUTPUT -p tcp --dport 8000 -j ACCEPT

# UFW
sudo ufw allow out 3000
sudo ufw allow out 8000
```

2. **Temporary firewall disable (testing only):**
```bash
sudo ufw disable
# Remember to re-enable: sudo ufw enable
```

### Problem: Network Interface Issues

**Symptoms:**
- "No route to host" errors
- Cannot bind to interface
- Wrong source IP

**Diagnosis:**
```bash
ip route show
ifconfig
netstat -rn
```

**Solutions:**

1. **Specify source interface:**
```bash
python application.py scan --target 192.168.1.0/24 --interface eth0
```

2. **Fix routing:**
```bash
sudo ip route add 192.168.1.0/24 via 192.168.1.1 dev eth0
```

---

## Scanning Issues

### Problem: Scan Timeouts

**Symptoms:**
- Many timeout errors
- Slow scan progress
- Incomplete results

**Diagnosis:**
```bash
# Test manual connection
timeout 5 bash -c "</dev/tcp/192.168.1.100/3000"
echo $?  # 0 = success, 124 = timeout
```

**Solutions:**

1. **Increase timeout values:**
```bash
python application.py scan --target 192.168.1.0/24 --timeout 15
```

2. **Reduce concurrency:**
```bash
python application.py scan --target 192.168.1.0/24 --threads 10
```

3. **Add retry attempts:**
```bash
python application.py scan --target 192.168.1.0/24 --retry 3
```

### Problem: Permission Denied Errors

**Symptoms:**
- Cannot bind to ports
- Socket permission errors
- Access denied messages

**Diagnosis:**
```bash
# Check current user permissions
id
groups

# Test port binding
python -c "import socket; s=socket.socket(); s.bind(('', 80))"
```

**Solutions:**

1. **Use unprivileged ports:**
```bash
python application.py scan --target 192.168.1.0/24 --source-port 32768-65535
```

2. **Run with appropriate permissions:**
```bash
sudo python application.py scan --target 192.168.1.0/24
```

3. **Use capabilities (Linux):**
```bash
sudo setcap cap_net_raw+ep $(which python)
```

### Problem: Rate Limiting Issues

**Symptoms:**
- "Rate limit exceeded" errors
- Scanning stops unexpectedly
- Network congestion warnings

**Diagnosis:**
```bash
# Monitor network usage
iftop
nethogs
```

**Solutions:**

1. **Reduce scan rate:**
```bash
python application.py scan --target 192.168.1.0/24 --rate-limit 25
```

2. **Add delays:**
```bash
python application.py scan --target 192.168.1.0/24 --delay 100
```

3. **Use adaptive rate limiting:**
```bash
python application.py scan --target 192.168.1.0/24 --adaptive-rate
```

---

## Performance Problems

### Problem: High Memory Usage

**Symptoms:**
- Out of memory errors
- System slowdown
- Swap usage increase

**Diagnosis:**
```bash
# Monitor memory usage
top -p $(pgrep -f "python.*application.py")
ps aux | grep python
free -h
```

**Solutions:**

1. **Reduce thread count:**
```bash
python application.py scan --target 192.168.1.0/24 --threads 25
```

2. **Scan smaller ranges:**
```bash
python application.py scan --target 192.168.1.0/25
python application.py scan --target 192.168.1.128/25
```

3. **Enable memory optimization:**
```bash
python application.py scan --target 192.168.1.0/24 --memory-optimize
```

### Problem: Slow Scanning Performance

**Symptoms:**
- Very slow scan progress
- Low CPU utilization
- Long completion times

**Diagnosis:**
```bash
# Monitor system resources
htop
iostat 1
sar -u 1
```

**Solutions:**

1. **Increase thread count:**
```bash
python application.py scan --target 192.168.1.0/24 --threads 100
```

2. **Optimize network settings:**
```bash
# Increase socket buffer sizes
echo 'net.core.rmem_max = 16777216' | sudo tee -a /etc/sysctl.conf
echo 'net.core.wmem_max = 16777216' | sudo tee -a /etc/sysctl.conf
sudo sysctl -p
```

3. **Use performance mode:**
```bash
python application.py scan --target 192.168.1.0/24 --performance-mode
```

### Problem: Disk Space Issues

**Symptoms:**
- "No space left on device" errors
- Cannot write log files
- Scan results truncated

**Diagnosis:**
```bash
df -h
du -sh logs/
du -sh results/
```

**Solutions:**

1. **Clean up old files:**
```bash
# Remove old logs (older than 30 days)
find logs/ -name "*.log" -mtime +30 -delete

# Compress old results
find results/ -name "*.json" -mtime +7 -exec gzip {} \;
```

2. **Configure log rotation:**
```bash
# Add to /etc/logrotate.d/hawkeye
/path/to/hawkeye/logs/*.log {
    daily
    rotate 7
    compress
    delaycompress
    missingok
    notifempty
}
```

---

## Configuration Issues

### Problem: Configuration File Not Found

**Symptoms:**
- "Config file not found" errors
- Default settings used unexpectedly
- Configuration warnings

**Diagnosis:**
```bash
# Check config file locations
ls -la hawkeye.yaml
ls -la ~/.hawkeye/config.yaml
ls -la /etc/hawkeye/config.yaml
```

**Solutions:**

1. **Create configuration file:**
```bash
python application.py config init
```

2. **Specify config file explicitly:**
```bash
python application.py --config /path/to/config.yaml scan --target 192.168.1.0/24
```

3. **Use environment variables:**
```bash
export HAWKEYE_CONFIG=/path/to/config.yaml
python application.py scan --target 192.168.1.0/24
```

### Problem: Invalid Configuration Values

**Symptoms:**
- Configuration validation errors
- Unexpected behavior
- Parameter warnings

**Diagnosis:**
```bash
python application.py config validate
python application.py config show
```

**Solutions:**

1. **Reset to defaults:**
```bash
python application.py config reset
```

2. **Fix specific values:**
```bash
python application.py config set scanning.threads 50
python application.py config set scanning.timeout 10
```

3. **Validate configuration:**
```yaml
# Example valid configuration
scanning:
  default_threads: 50        # Must be positive integer
  default_timeout: 10        # Must be positive number
  rate_limit: 100           # Must be positive integer

logging:
  level: INFO               # Must be: DEBUG, INFO, WARNING, ERROR
  file: hawkeye.log         # Must be writable path
```

---

## Reporting Problems

### Problem: Report Generation Failures

**Symptoms:**
- "Cannot generate report" errors
- Empty or corrupted reports
- Template errors

**Diagnosis:**
```bash
# Check input file
file scan_results.json
python -m json.tool scan_results.json > /dev/null

# Check template files
ls -la src/hawkeye/reporting/templates/
```

**Solutions:**

1. **Validate input data:**
```bash
python application.py validate-results --input scan_results.json
```

2. **Use different format:**
```bash
python application.py report --input scan_results.json --format csv
```

3. **Regenerate with debug:**
```bash
python application.py --debug report --input scan_results.json --format html
```

### Problem: Template Rendering Issues

**Symptoms:**
- HTML template errors
- Missing report sections
- Formatting problems

**Diagnosis:**
```bash
# Check template syntax
python -c "from jinja2 import Template; Template(open('template.html').read())"
```

**Solutions:**

1. **Use default template:**
```bash
python application.py report --input scan_results.json --template default
```

2. **Reinstall templates:**
```bash
python application.py install-templates --force
```

---

## Error Messages

### Common Error Messages and Solutions

#### `ModuleNotFoundError: No module named 'hawkeye'`

**Cause:** Python path issues or missing installation

**Solution:**
```bash
# Ensure virtual environment is activated
source venv/bin/activate

# Install in development mode
pip install -e .

# Or add to Python path
export PYTHONPATH="${PYTHONPATH}:$(pwd)/src"
```

#### `ConnectionRefusedError: [Errno 111] Connection refused`

**Cause:** Target service not running or firewall blocking

**Solution:**
```bash
# Verify target service
telnet 192.168.1.100 3000

# Check for firewall rules
sudo iptables -L | grep 3000
```

#### `OSError: [Errno 24] Too many open files`

**Cause:** File descriptor limit exceeded

**Solution:**
```bash
# Increase file descriptor limit
ulimit -n 4096

# Make permanent (add to ~/.bashrc)
echo "ulimit -n 4096" >> ~/.bashrc

# Reduce thread count
python application.py scan --target 192.168.1.0/24 --threads 25
```

#### `PermissionError: [Errno 13] Permission denied`

**Cause:** Insufficient permissions for file or network operations

**Solution:**
```bash
# Fix file permissions
chmod 755 application.py
chmod 644 config.yaml

# Use sudo for network operations (if needed)
sudo python application.py scan --target 192.168.1.0/24
```

#### `TimeoutError: timed out`

**Cause:** Network timeouts or slow responses

**Solution:**
```bash
# Increase timeout
python application.py scan --target 192.168.1.0/24 --timeout 30

# Reduce concurrency
python application.py scan --target 192.168.1.0/24 --threads 10
```

---

## Log Analysis

### Understanding Log Levels

```bash
# View different log levels
grep "ERROR" hawkeye.log    # Critical errors
grep "WARNING" hawkeye.log  # Warnings and issues
grep "INFO" hawkeye.log     # General information
grep "DEBUG" hawkeye.log    # Detailed debugging
```

### Common Log Patterns

#### Network Issues
```bash
# Connection problems
grep -E "(Connection refused|Connection timed out|No route to host)" hawkeye.log

# DNS issues
grep -E "(Name resolution|getaddrinfo)" hawkeye.log

# Rate limiting
grep -E "(Rate limit|Too many requests)" hawkeye.log
```

#### Performance Issues
```bash
# Memory problems
grep -E "(Memory|Out of memory|MemoryError)" hawkeye.log

# Timeout issues
grep -E "(Timeout|timed out)" hawkeye.log

# Thread issues
grep -E "(Thread|ThreadPool)" hawkeye.log
```

### Log Analysis Tools

```bash
# Real-time log monitoring
tail -f hawkeye.log

# Log statistics
awk '{print $3}' hawkeye.log | sort | uniq -c | sort -nr

# Error summary
grep "ERROR" hawkeye.log | awk '{print $4}' | sort | uniq -c
```

---

## Advanced Diagnostics

### Network Debugging

```bash
# Packet capture for debugging
sudo tcpdump -i any -w hawkeye_debug.pcap host 192.168.1.100

# Analyze with Wireshark
wireshark hawkeye_debug.pcap

# Network trace
sudo strace -e trace=network python application.py scan --target 192.168.1.100
```

### System Resource Monitoring

```bash
# Monitor system calls
sudo strace -c python application.py scan --target 192.168.1.100

# Monitor file operations
sudo lsof -p $(pgrep -f "python.*application.py")

# Monitor network connections
sudo netstat -tulpn | grep python
```

### Performance Profiling

```bash
# CPU profiling
python -m cProfile -o profile.stats application.py scan --target 192.168.1.100

# Analyze profile
python -c "import pstats; p=pstats.Stats('profile.stats'); p.sort_stats('cumulative'); p.print_stats(20)"

# Memory profiling
pip install memory_profiler
python -m memory_profiler application.py scan --target 192.168.1.100
```

### Debug Mode

```bash
# Enable maximum debugging
python application.py --debug --verbose scan --target 192.168.1.100

# Debug specific components
export HAWKEYE_DEBUG_SCANNER=1
export HAWKEYE_DEBUG_DETECTION=1
export HAWKEYE_DEBUG_REPORTING=1
```

---

## Getting Help

### Self-Help Resources

1. **Check documentation:**
   - User manual: `docs/user_manual.md`
   - Security guidelines: `docs/security_guidelines.md`
   - API documentation: `docs/api/`

2. **Run diagnostics:**
   ```bash
   python application.py health-check
   python application.py config validate
   python application.py test-connectivity
   ```

3. **Enable verbose logging:**
   ```bash
   python application.py --debug --verbose scan --target 192.168.1.100
   ```

### Collecting Debug Information

When reporting issues, collect this information:

```bash
# System information
uname -a
python --version
pip list

# HawkEye information
python application.py --version
python application.py health-check

# Configuration
python application.py config show

# Recent logs
tail -100 hawkeye.log

# Network configuration
ip addr show
ip route show
```

### Support Channels

- **GitHub Issues**: Report bugs and feature requests
- **Documentation**: Check latest documentation
- **Community Forums**: Ask questions and share solutions
- **Security Issues**: Report to security@hawkeye-project.org

---

## Preventive Measures

### Regular Maintenance

```bash
# Weekly maintenance script
cat > maintenance.sh << 'EOF'
#!/bin/bash

# Update dependencies
pip install --upgrade -r requirements.txt

# Clean old logs
find logs/ -name "*.log" -mtime +30 -delete

# Validate configuration
python application.py config validate

# Run health check
python application.py health-check

# Update documentation
python application.py update-docs
EOF

chmod +x maintenance.sh
```

### Monitoring Setup

```bash
# Set up monitoring
cat > monitor.sh << 'EOF'
#!/bin/bash

# Check disk space
df -h | awk '$5 > 80 {print "WARNING: Disk usage high on " $6}'

# Check memory usage
free | awk 'NR==2{printf "Memory Usage: %s/%sMB (%.2f%%)\n", $3,$2,$3*100/$2 }'

# Check log errors
ERROR_COUNT=$(grep -c "ERROR" hawkeye.log)
if [ $ERROR_COUNT -gt 10 ]; then
    echo "WARNING: High error count in logs: $ERROR_COUNT"
fi
EOF

# Run daily via cron
echo "0 9 * * * /path/to/monitor.sh" | crontab -
```

---

**Document Version**: 1.0  
**Last Updated**: Current Version  
**Next Review**: Quarterly 