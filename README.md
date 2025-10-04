# 🚀 HyperRecon Pro v4.0

[![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Version](https://img.shields.io/badge/Version-4.0.0-red.svg)](CHANGELOG.md)
[![Maintenance](https://img.shields.io/badge/Maintained%3F-yes-green.svg)](https://github.com/saurabhtomar/hyperrecon-pro/graphs/commit-activity)

> **Advanced Modular Bug Bounty Reconnaissance Tool**

A comprehensive, production-ready reconnaissance framework designed for security researchers, penetration testers, and bug bounty hunters. Built with a modular architecture for scalability and maintainability.

## ✨ Features

### 🔍 **Comprehensive Reconnaissance**
- **Multi-source subdomain enumeration** (subfinder, assetfinder)
- **Historical URL collection** (waybackurls, gau) with intelligent filtering
- **Live host detection** (httpx) with status code categorization
- **Technology fingerprinting** (whatweb) with custom detection
- **Parameter discovery** (ParamSpider) with advanced extraction
- **JavaScript endpoint analysis** with automated parsing
- **Directory enumeration** (gobuster) with security-focused wordlists
- **Vulnerability scanning** (nuclei) with CVE mapping
- **Social media reconnaissance** across 16+ platforms
- **Document analysis** with sensitive data detection

### 🏗️ **Production Architecture**
- **Modular design** with clean separation of concerns
- **Graceful error handling** with detailed logging
- **Multi-threading support** for parallel processing
- **Real-time progress tracking** with workflow orchestration
- **Centralized configuration** management
- **Extensible plugin system** for custom tools

### 📊 **Advanced Reporting**
- **Interactive HTML reports** with data visualization
- **Real-time result streaming** with organized output
- **Security risk assessment** with finding categorization
- **Comprehensive statistics** and filtering metrics

## 🛠️ Installation

### Quick Start

```bash
# Clone repository
git clone https://github.com/saurabhtomar/hyperrecon-pro.git
cd hyperrecon-pro

# Install dependencies
pip install -r requirements.txt

# Run automated setup
chmod +x install.sh && ./install.sh
```

### Manual Installation

<details>
<summary>Click to expand manual installation steps</summary>

```bash
# Install Python dependencies
pip install rich colorama requests pyyaml tqdm

# Install required Go tools
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest

# Install optional tools for enhanced functionality
go install github.com/tomnomnom/assetfinder@latest
go install github.com/tomnomnom/waybackurls@latest
go install github.com/lc/gau/v2/cmd/gau@latest
go install github.com/tomnomnom/gf@latest
go install github.com/tomnomnom/unfurl@latest
go install github.com/OJ/gobuster/v3@latest

# Install Python tools
pip install uro

# Clone ParamSpider
git clone https://github.com/0xKayala/ParamSpider.git
```

</details>

## 🚀 Usage

### Basic Commands

```bash
# Single domain reconnaissance
python hyperrecon.py -d example.com

# Multiple domains with threading
python hyperrecon.py -d "example.com,test.com" -t 20

# Domain list with HTML reports
python hyperrecon.py -l domains.txt --html-reports

# Subdomain-only scan (skip enumeration)
python hyperrecon.py -s subdomain.example.com
```

### Advanced Usage

```bash
# Full scan with custom output
python hyperrecon.py -d example.com -o /path/to/output --html-reports -v

# Selective module execution
python hyperrecon.py -d example.com --no-nuclei --no-gobuster --no-dast

# High-performance scanning
python hyperrecon.py -d example.com -t 50 --debug
```

### Command Reference

<details>
<summary>Complete command-line options</summary>

```
Target Selection:
  -d, --domain DOMAIN     Target domain(s) (comma-separated)
  -l, --list LIST         File containing domain list
  -s, --subdomain SUB     Direct subdomain input (skips enumeration)

Output Control:
  -o, --output OUTPUT     Custom output directory
  -hr, --html-reports     Generate interactive HTML reports
  -v, --verbose           Enable detailed output
  --debug                 Enable debug logging

Performance:
  -t, --threads THREADS   Concurrent threads (default: 10)

Module Control:
  --no-nuclei            Disable vulnerability scanning
  --no-gobuster          Disable directory enumeration
  --no-paramspider       Disable parameter discovery
  --no-gf                Disable pattern analysis
  --no-js                Disable JavaScript analysis
  --no-tech              Disable technology detection
  --no-sensitive         Disable sensitive data detection
  --no-security          Disable security checks
  --no-dast              Disable DAST scanning
  --no-wayback           Disable Wayback Machine
  --no-gau               Disable GAU collection
  --no-social            Disable social media recon
  --no-documents         Disable document analysis

Utilities:
  --validate-deps        Check tool dependencies
  --version              Show version information
  --help                 Display help message
```

</details>

## 📁 Output Structure

```
hyperrecon_results_TIMESTAMP/
└── target_domain/
    ├── subdomains/           # Subdomain enumeration results
    ├── urls/                 # Historical URL collection
    ├── live_hosts/           # HTTP probing results
    ├── parameters/           # Parameter discovery
    ├── vulnerabilities/      # Security findings
    ├── directories/          # Directory enumeration
    ├── technology_detection/ # Tech stack identification
    ├── js_analysis/          # JavaScript endpoints
    ├── social_media_recon/   # OSINT findings
    ├── documents/            # Document analysis
    ├── extensions/           # File type organization
    ├── gf_patterns/          # Pattern matching results
    ├── security_checks/      # Security assessments
    └── hyperrecon_report.html # Interactive report
```

## ⚙️ Configuration

### Tool Configuration (`config/tool_config.yaml`)

```yaml
required_tools:
  - subfinder
  - httpx
  - nuclei

optional_tools:
  - assetfinder
  - waybackurls
  - gau
  - gobuster
  - whatweb
  - unfurl
  - gf
  - uro
  - paramspider
```

### Custom Patterns (`config/patterns.yaml`)

```yaml
sensitive_patterns:
  api_keys: "(?i)(api[_-]?key|access[_-]?token)"
  jwt_tokens: "eyJ[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+"
  aws_keys: "AKIA[0-9A-Z]{16}"
  # Add custom detection patterns
```

## 🔧 Development

### Adding New Tools

1. Create utility module in `utils/`
2. Extend `BaseUtility` class
3. Implement `execute()` method
4. Add to main workflow
5. Update configuration files

### Testing

```bash
# Run validation tests
python validate_production_deployment.py

# Check dependencies
python hyperrecon.py --validate-deps
```

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guidelines](CONTRIBUTING.md) for details.

1. Fork the repository
2. Create feature branch (`git checkout -b feature/amazing-feature`)
3. Commit changes (`git commit -m 'Add amazing feature'`)
4. Push to branch (`git push origin feature/amazing-feature`)
5. Open Pull Request

## 📋 Changelog

See [CHANGELOG.md](CHANGELOG.md) for version history and updates.

## 📄 License

This project is licensed under the MIT License - see [LICENSE](LICENSE) for details.

## 👨‍💻 Author

**Saurabh Tomar**
- 🐙 GitHub: [@saurabhtomar](https://github.com/shanithakuralg)
- 💼 LinkedIn: [saurabhtomar](https://www.linkedin.com/in/saurabh-tomar-b3095b21b/)
- 🐦 Portfolio: [@saurabhtomar](Comming soon)

## 🙏 Acknowledgments

- [ProjectDiscovery](https://projectdiscovery.io/) for exceptional security tools
- [Tom Hudson](https://github.com/tomnomnom) for reconnaissance utilities
- Bug bounty community for continuous feedback and support

## ⚠️ Legal Disclaimer

This tool is intended for **authorized security testing and educational purposes only**. Users must ensure compliance with applicable laws and regulations. The author assumes no responsibility for misuse or illegal activities.

---

<div align="center">

**⭐ Star this repository if HyperRecon Pro helps your security research!**

[Report Bug](https://github.com/saurabhtomar/hyperrecon/issues) • [Request Feature](https://github.com/saurabhtomar/hyperrecon/issues) • [Documentation](docs/)

</div>