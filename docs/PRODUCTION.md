# Production Deployment Guide

This guide covers deploying HyperRecon Pro v4.0 in production environments with best practices for security, performance, and reliability.

## 🎯 Production Readiness Checklist

### ✅ System Requirements
- [ ] Linux/macOS/Windows server with Python 3.8+
- [ ] Minimum 4GB RAM (8GB+ recommended for large scans)
- [ ] 50GB+ storage space for results
- [ ] Stable internet connection with adequate bandwidth
- [ ] All required tools installed and validated

### ✅ Security Requirements
- [ ] Non-root user account for running scans
- [ ] Proper file permissions configured
- [ ] Network security policies in place
- [ ] Input validation enabled
- [ ] Logging and monitoring configured

### ✅ Performance Requirements
- [ ] Resource monitoring in place
- [ ] Thread count optimized for system
- [ ] Timeout values configured appropriately
- [ ] Memory usage monitoring enabled

## 🚀 Installation Steps

### 1. System Preparation

**Create dedicated user:**
```bash
sudo useradd -m -s /bin/bash hyperrecon
sudo usermod -aG sudo hyperrecon
su - hyperrecon
```

**Install system dependencies:**
```bash
# Ubuntu/Debian
sudo apt update
sudo apt install -y python3 python3-pip git golang-go ruby-dev

# CentOS/RHEL
sudo yum install -y python3 python3-pip git golang ruby-devel

# macOS
brew install python3 go ruby
```

### 2. Tool Installation

**Install Go-based tools:**
```bash
# Set Go environment
export GOPATH=$HOME/go
export PATH=$PATH:$GOPATH/bin

# Install required tools
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install -v github.com/OJ/gobuster/v3@latest

# Install optional tools
go install github.com/tomnomnom/assetfinder@latest
go install github.com/tomnomnom/waybackurls@latest
go install github.com/lc/gau/v2/cmd/gau@latest
go install github.com/tomnomnom/gf@latest
go install github.com/tomnomnom/unfurl@latest
```

**Install Python tools:**
```bash
pip3 install uro
```

**Install Ruby tools:**
```bash
gem install whatweb
```

### 3. HyperRecon Pro Setup

**Clone and setup:**
```bash
cd /opt
sudo git clone https://github.com/saurabhtomar/hyperrecon-pro.git
sudo chown -R hyperrecon:hyperrecon hyperrecon-pro
cd hyperrecon-pro

# Install Python dependencies
pip3 install -r requirements.txt

# Validate installation
python3 hyperrecon.py --validate-deps
```

### 4. Configuration

**Create production configuration:**
```bash
# Copy default configs
cp config/patterns.yaml config/patterns.prod.yaml
cp config/tool_config.yaml config/tool_config.prod.yaml

# Edit production configs
nano config/tool_config.prod.yaml
```

**Production tool configuration:**
```yaml
# config/tool_config.prod.yaml
tools:
  subfinder:
    timeout: 600
    threads: 20
    config_file: "/opt/hyperrecon-pro/config/subfinder-config.yaml"
  
  httpx:
    timeout: 60
    retries: 3
    threads: 50
    
  nuclei:
    timeout: 1800
    threads: 25
    rate_limit: 150
    
  gobuster:
    timeout: 900
    threads: 30
    wordlist: "/opt/hyperrecon-pro/wordlists/directories.txt"

performance:
  max_concurrent_domains: 5
  memory_limit_gb: 6
  temp_cleanup_interval: 3600
  
logging:
  level: "INFO"
  max_file_size_mb: 100
  backup_count: 5
  
security:
  input_validation: true
  output_sanitization: true
  max_file_size_mb: 500
  allowed_extensions: [".txt", ".json", ".html", ".csv"]
```

## 🔧 Production Configuration

### Environment Variables

Create production environment file:
```bash
# /opt/hyperrecon-pro/.env.production
export HYPERRECON_ENV=production
export HYPERRECON_CONFIG_DIR=/opt/hyperrecon-pro/config
export HYPERRECON_OUTPUT_DIR=/var/hyperrecon/results
export HYPERRECON_LOG_DIR=/var/log/hyperrecon
export HYPERRECON_TEMP_DIR=/tmp/hyperrecon
export HYPERRECON_MAX_THREADS=20
export HYPERRECON_TIMEOUT=3600
export HYPERRECON_DEBUG=false
```

### Directory Structure

**Create production directories:**
```bash
sudo mkdir -p /var/hyperrecon/{results,cache,temp}
sudo mkdir -p /var/log/hyperrecon
sudo mkdir -p /etc/hyperrecon

sudo chown -R hyperrecon:hyperrecon /var/hyperrecon
sudo chown -R hyperrecon:hyperrecon /var/log/hyperrecon
sudo chown -R hyperrecon:hyperrecon /etc/hyperrecon
```

### Logging Configuration

**Setup log rotation:**
```bash
sudo tee /etc/logrotate.d/hyperrecon << EOF
/var/log/hyperrecon/*.log {
    daily
    rotate 30
    compress
    delaycompress
    missingok
    notifempty
    create 644 hyperrecon hyperrecon
    postrotate
        systemctl reload hyperrecon-service || true
    endscript
}
EOF
```

## 🛡️ Security Configuration

### File Permissions

**Set secure permissions:**
```bash
# Application files
chmod 755 /opt/hyperrecon-pro/hyperrecon.py
chmod -R 644 /opt/hyperrecon-pro/utils/*.py
chmod -R 644 /opt/hyperrecon-pro/config/*.yaml

# Data directories
chmod 750 /var/hyperrecon
chmod 750 /var/log/hyperrecon

# Temporary directories
chmod 1777 /tmp/hyperrecon
```

### Input Validation

**Enable strict validation in production:**
```python
# Add to hyperrecon.py or config
PRODUCTION_SECURITY = {
    'validate_domains': True,
    'sanitize_inputs': True,
    'max_domain_length': 253,
    'allowed_domain_chars': r'^[a-zA-Z0-9.-]+$',
    'max_concurrent_scans': 10,
    'rate_limiting': True
}
```

### Network Security

**Configure firewall rules:**
```bash
# Allow outbound HTTP/HTTPS
sudo ufw allow out 80/tcp
sudo ufw allow out 443/tcp
sudo ufw allow out 53/udp

# Block unnecessary inbound connections
sudo ufw default deny incoming
sudo ufw default allow outgoing
```

## 📊 Monitoring and Alerting

### System Monitoring

**Install monitoring tools:**
```bash
# Install system monitoring
sudo apt install -y htop iotop nethogs

# Install Python monitoring
pip3 install psutil
```

**Create monitoring script:**
```bash
#!/bin/bash
# /opt/hyperrecon-pro/scripts/monitor.sh

LOG_FILE="/var/log/hyperrecon/monitor.log"
ALERT_EMAIL="admin@company.com"

# Check disk space
DISK_USAGE=$(df /var/hyperrecon | awk 'NR==2 {print $5}' | sed 's/%//')
if [ $DISK_USAGE -gt 80 ]; then
    echo "$(date): WARNING - Disk usage at ${DISK_USAGE}%" >> $LOG_FILE
    echo "Disk usage critical: ${DISK_USAGE}%" | mail -s "HyperRecon Disk Alert" $ALERT_EMAIL
fi

# Check memory usage
MEM_USAGE=$(free | awk 'NR==2{printf "%.0f", $3*100/$2}')
if [ $MEM_USAGE -gt 90 ]; then
    echo "$(date): WARNING - Memory usage at ${MEM_USAGE}%" >> $LOG_FILE
fi

# Check running processes
HYPERRECON_PROCS=$(pgrep -f hyperrecon.py | wc -l)
echo "$(date): Active HyperRecon processes: $HYPERRECON_PROCS" >> $LOG_FILE
```

### Application Monitoring

**Create health check endpoint:**
```python
# utils/health_check.py
import os
import psutil
import json
from datetime import datetime

def get_system_health():
    """Get system health metrics"""
    return {
        'timestamp': datetime.now().isoformat(),
        'cpu_percent': psutil.cpu_percent(interval=1),
        'memory_percent': psutil.virtual_memory().percent,
        'disk_usage': psutil.disk_usage('/var/hyperrecon').percent,
        'active_processes': len([p for p in psutil.process_iter() if 'hyperrecon' in p.name()]),
        'uptime': psutil.boot_time()
    }

def check_dependencies():
    """Check if all required tools are available"""
    from utils.config import ConfigManager
    config_manager = ConfigManager()
    return config_manager.validate_dependencies()
```

## 🚀 Deployment Automation

### Systemd Service

**Create service file:**
```bash
sudo tee /etc/systemd/system/hyperrecon.service << EOF
[Unit]
Description=HyperRecon Pro Service
After=network.target

[Service]
Type=simple
User=hyperrecon
Group=hyperrecon
WorkingDirectory=/opt/hyperrecon-pro
Environment=PYTHONPATH=/opt/hyperrecon-pro
EnvironmentFile=/opt/hyperrecon-pro/.env.production
ExecStart=/usr/bin/python3 /opt/hyperrecon-pro/hyperrecon.py --daemon
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal
SyslogIdentifier=hyperrecon

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable hyperrecon
```

### Docker Deployment

**Create Dockerfile:**
```dockerfile
FROM ubuntu:22.04

# Install system dependencies
RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    golang-go \
    ruby-dev \
    git \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Create user
RUN useradd -m -s /bin/bash hyperrecon

# Set Go environment
ENV GOPATH=/home/hyperrecon/go
ENV PATH=$PATH:$GOPATH/bin

# Install Go tools
USER hyperrecon
RUN go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest && \
    go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest && \
    go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest && \
    go install -v github.com/OJ/gobuster/v3@latest

# Install Python tools
RUN pip3 install --user uro

# Copy application
COPY --chown=hyperrecon:hyperrecon . /opt/hyperrecon-pro
WORKDIR /opt/hyperrecon-pro

# Install Python dependencies
RUN pip3 install --user -r requirements.txt

# Create directories
RUN mkdir -p /var/hyperrecon/{results,cache,temp} && \
    mkdir -p /var/log/hyperrecon

# Expose health check port
EXPOSE 8080

# Run application
CMD ["python3", "hyperrecon.py", "--daemon"]
```

**Docker Compose:**
```yaml
version: '3.8'

services:
  hyperrecon:
    build: .
    container_name: hyperrecon-pro
    restart: unless-stopped
    volumes:
      - ./results:/var/hyperrecon/results
      - ./logs:/var/log/hyperrecon
      - ./config:/opt/hyperrecon-pro/config
    environment:
      - HYPERRECON_ENV=production
      - HYPERRECON_MAX_THREADS=20
    ports:
      - "8080:8080"
    healthcheck:
      test: ["CMD", "python3", "-c", "from utils.health_check import get_system_health; print('OK')"]
      interval: 30s
      timeout: 10s
      retries: 3
```

## 📈 Performance Optimization

### Resource Tuning

**Optimize for large scans:**
```yaml
# config/performance.yaml
performance:
  # Thread configuration
  max_threads: 25
  thread_pool_size: 50
  
  # Memory management
  max_memory_gb: 8
  gc_threshold: 1000
  
  # I/O optimization
  buffer_size: 8192
  batch_size: 100
  
  # Network optimization
  connection_pool_size: 100
  request_timeout: 60
  max_retries: 3
  
  # Caching
  enable_dns_cache: true
  cache_ttl: 3600
  max_cache_size: 10000
```

### Database Integration

**For large-scale deployments:**
```python
# utils/database.py
import sqlite3
import json
from datetime import datetime

class ResultsDatabase:
    def __init__(self, db_path="/var/hyperrecon/results.db"):
        self.db_path = db_path
        self.init_database()
    
    def init_database(self):
        """Initialize database schema"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                domain TEXT NOT NULL,
                scan_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                status TEXT DEFAULT 'running',
                results TEXT,
                metadata TEXT
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def save_scan_results(self, domain, results, metadata=None):
        """Save scan results to database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO scans (domain, results, metadata, status)
            VALUES (?, ?, ?, 'completed')
        ''', (domain, json.dumps(results), json.dumps(metadata or {})))
        
        conn.commit()
        conn.close()
```

## 🔍 Troubleshooting

### Common Issues

**1. Tool Installation Issues:**
```bash
# Check Go installation
go version

# Check PATH
echo $PATH | grep go

# Reinstall tools
go clean -modcache
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
```

**2. Permission Issues:**
```bash
# Fix ownership
sudo chown -R hyperrecon:hyperrecon /opt/hyperrecon-pro
sudo chown -R hyperrecon:hyperrecon /var/hyperrecon

# Fix permissions
chmod +x /opt/hyperrecon-pro/hyperrecon.py
```

**3. Memory Issues:**
```bash
# Monitor memory usage
watch -n 1 'free -h && ps aux | grep hyperrecon'

# Adjust thread count
python3 hyperrecon.py -d example.com -t 5
```

### Log Analysis

**Check application logs:**
```bash
# View recent logs
tail -f /var/log/hyperrecon/hyperrecon.log

# Search for errors
grep -i error /var/log/hyperrecon/*.log

# Analyze performance
grep -i "execution time" /var/log/hyperrecon/*.log
```

## 📋 Maintenance

### Regular Tasks

**Daily:**
- Check disk space and clean old results
- Monitor system resources
- Review error logs

**Weekly:**
- Update tool databases (nuclei templates, etc.)
- Backup configuration files
- Review performance metrics

**Monthly:**
- Update tools to latest versions
- Review and update patterns
- Performance optimization review

### Backup Strategy

**Automated backup script:**
```bash
#!/bin/bash
# /opt/hyperrecon-pro/scripts/backup.sh

BACKUP_DIR="/backup/hyperrecon"
DATE=$(date +%Y%m%d_%H%M%S)

# Create backup directory
mkdir -p $BACKUP_DIR/$DATE

# Backup configuration
cp -r /opt/hyperrecon-pro/config $BACKUP_DIR/$DATE/

# Backup recent results (last 7 days)
find /var/hyperrecon/results -mtime -7 -type f -exec cp {} $BACKUP_DIR/$DATE/ \;

# Backup logs
cp -r /var/log/hyperrecon $BACKUP_DIR/$DATE/

# Compress backup
tar -czf $BACKUP_DIR/hyperrecon_backup_$DATE.tar.gz -C $BACKUP_DIR $DATE
rm -rf $BACKUP_DIR/$DATE

# Keep only last 30 backups
find $BACKUP_DIR -name "hyperrecon_backup_*.tar.gz" -mtime +30 -delete
```

## 🎯 Best Practices

### Security
- Run with minimal required permissions
- Regularly update all tools and dependencies
- Monitor for suspicious activity
- Implement rate limiting for external requests
- Validate all inputs and sanitize outputs

### Performance
- Monitor resource usage continuously
- Optimize thread counts based on system capacity
- Implement proper caching strategies
- Use connection pooling for HTTP requests
- Clean up temporary files regularly

### Reliability
- Implement comprehensive error handling
- Use health checks and monitoring
- Set up automated backups
- Plan for disaster recovery
- Document all procedures

### Scalability
- Design for horizontal scaling
- Use load balancing for multiple instances
- Implement queue-based processing
- Consider microservices architecture
- Plan for database scaling

---

This production deployment guide ensures HyperRecon Pro v4.0 runs reliably and securely in production environments while maintaining optimal performance and scalability.