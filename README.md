# HyperRecon Pro v4.0 - Advanced Modular Bug Bounty Scanner

[![Python Version](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://python.org)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Production Ready](https://img.shields.io/badge/production-ready-brightgreen.svg)](docs/PRODUCTION.md)

🚀 **HyperRecon Pro v4.0** is a comprehensive, modular reconnaissance tool designed for bug bounty hunters and security professionals. This refactored version features clean architecture, enhanced error handling, and production-ready deployment capabilities.

## 🎯 Key Features

### 🏗️ Modular Architecture
- **Clean separation of concerns** with utility-based modules
- **Consistent interfaces** across all reconnaissance functions
- **Easy extensibility** for adding new features
- **Centralized configuration** management

### 🔍 Comprehensive Reconnaissance
- **Subdomain enumeration** (subfinder, assetfinder)
- **URL collection** (waybackurls, gau) with URO filtering
- **HTTP probing** (httpx) with live host detection
- **Technology detection** (whatweb + custom patterns)
- **Parameter discovery** (ParamSpider) with enhanced filtering
- **JavaScript analysis** with endpoint extraction
- **Vulnerability scanning** (nuclei) with DAST capabilities
- **Directory bruteforcing** (gobuster) with security checks
- **Social media reconnaissance** across multiple platforms
- **Sensitive data detection** with comprehensive patterns
- **Document analysis** and extension organization

### 🛡️ Production Features
- **Robust error handling** with graceful degradation
- **Dependency validation** with installation guidance
- **Performance optimization** for large datasets
- **Multi-threading support** for concurrent operations
- **Comprehensive logging** and progress tracking
- **HTML report generation** with responsive templates
- **Data integrity validation** across all operations

## 🚀 Quick Start

### Prerequisites

**Required Tools:**
- Python 3.8+
- subfinder
- httpx
- nuclei
- gobuster

**Optional Tools (for enhanced functionality):**
- assetfinder
- waybackurls
- gau
- whatweb
- uro
- gf
- unfurl

### Installation

1. **Clone the repository:**
```bash
git clone https://github.com/saurabhtomar/hyperrecon-pro.git
cd hyperrecon-pro
```

2. **Install Python dependencies:**
```bash
pip install -r requirements.txt
```

3. **Install required tools:**
```bash
# Install Go tools
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

# Install URO (Python)
pip install uro

# Install whatweb (Ruby)
gem install whatweb
```

4. **Verify installation:**
```bash
python hyperrecon.py --validate-deps
```

### Basic Usage

**Single domain scan:**
```bash
python hyperrecon.py -d example.com
```

**Multiple domains:**
```bash
python hyperrecon.py -d example.com,test.com,demo.com
```

**With HTML report:**
```bash
python hyperrecon.py -d example.com -hr
```

**Custom output directory:**
```bash
python hyperrecon.py -d example.com -o /path/to/output
```

**Verbose mode with threading:**
```bash
python hyperrecon.py -d example.com -v -t 20
```

## 📖 Detailed Usage

### Command Line Options

```
usage: hyperrecon.py [-h] [-d DOMAIN] [-l LIST] [-o OUTPUT] [-t THREADS] 
                     [-hr] [-v] [--debug] [--validate-deps] [--version]

HyperRecon Pro v4.0 - Advanced Modular Bug Bounty Scanner

optional arguments:
  -h, --help            show this help message and exit
  -d DOMAIN, --domain DOMAIN
                        Target domain(s) (comma-separated)
  -l LIST, --list LIST  File containing list of domains
  -o OUTPUT, --output OUTPUT
                        Output directory (default: hyperrecon_results_TIMESTAMP)
  -t THREADS, --threads THREADS
                        Number of threads (default: 10)
  -hr, --html-report    Generate HTML report
  -v, --verbose         Enable verbose output
  --debug               Enable debug mode
  --validate-deps       Validate tool dependencies
  --version             Show version information
```

### Advanced Usage Examples

**Scan from file with custom settings:**
```bash
python hyperrecon.py -l domains.txt -o custom_scan -t 15 -hr -v
```

**Debug mode for troubleshooting:**
```bash
python hyperrecon.py -d example.com --debug
```

**Validate all dependencies:**
```bash
python hyperrecon.py --validate-deps
```

## 🏗️ Architecture Overview

### Directory Structure
```
hyperrecon-pro/
├── hyperrecon.py              # Main orchestrator
├── utils/                     # Utility modules
│   ├── __init__.py           # Shared utilities
│   ├── config.py             # Configuration management
│   ├── file_manager.py       # File operations
│   ├── uro_filter.py         # URL deduplication
│   ├── subdomain_enum.py     # Subdomain enumeration
│   ├── url_collection.py     # URL collection
│   ├── http_probe.py         # HTTP probing
│   ├── param_scan.py         # Parameter discovery
│   ├── tech_detection.py     # Technology detection
│   ├── js_analysis.py        # JavaScript analysis
│   ├── vuln_scan.py          # Vulnerability scanning
│   ├── dir_brute.py          # Directory bruteforcing
│   ├── security_checks.py    # Security checks
│   ├── sensitive_data.py     # Sensitive data detection
│   ├── social_recon.py       # Social media recon
│   ├── document_analyzer.py  # Document analysis
│   ├── extension_organizer.py # Extension organization
│   ├── gf_pattern_analyzer.py # GF pattern analysis
│   ├── unfurl_analyzer.py    # URL analysis
│   └── report.py             # HTML report generation
├── config/                   # Configuration files
│   ├── patterns.yaml         # Detection patterns
│   └── tool_config.yaml      # Tool configurations
├── docs/                     # Documentation
├── tests/                    # Test suite
└── examples/                 # Usage examples
```

### Core Components

1. **Main Orchestrator** (`hyperrecon.py`)
   - Workflow coordination
   - User interface management
   - Progress tracking
   - Error handling coordination

2. **Utility Modules** (`utils/`)
   - Specialized reconnaissance functions
   - Consistent interfaces
   - Independent operation capability
   - Comprehensive error handling

3. **Configuration Management** (`config/`)
   - Centralized pattern management
   - Tool configuration
   - Dependency validation

## 📊 Output Structure

Each scan creates an organized directory structure:

```
hyperrecon_results_TIMESTAMP/
└── domain.com/
    ├── subdomains/
    │   ├── subdomains.txt
    │   ├── live_subdomains.txt
    │   └── subdomain_sources.json
    ├── urls/
    │   ├── all_urls.txt
    │   ├── filtered_urls.txt
    │   └── url_sources.json
    ├── parameters/
    │   ├── parameterized_urls.txt
    │   ├── parameter_patterns.txt
    │   └── parameter_analysis.json
    ├── technology_detection/
    │   ├── technologies.json
    │   ├── web_servers.txt
    │   └── frameworks.txt
    ├── vulnerabilities/
    │   ├── nuclei_results.json
    │   ├── vulnerability_summary.txt
    │   └── dast_results.json
    ├── directories/
    │   ├── discovered_directories.txt
    │   ├── security_paths.txt
    │   └── directory_analysis.json
    ├── javascript/
    │   ├── js_files.txt
    │   ├── extracted_endpoints.txt
    │   └── js_analysis.json
    ├── sensitive_data/
    │   ├── sensitive_urls.txt
    │   ├── config_files.txt
    │   └── sensitive_patterns.json
    ├── security_checks/
    │   ├── security_findings.json
    │   ├── misconfigurations.txt
    │   └── security_summary.txt
    ├── social_media_recon/
    │   ├── social_profiles.json
    │   ├── platform_results.txt
    │   └── osint_summary.txt
    ├── documents/
    │   ├── document_analysis.json
    │   ├── file_types.txt
    │   └── document_summary.txt
    ├── reports/
    │   ├── domain_report.html
    │   ├── summary.json
    │   └── scan_metadata.json
    └── logs/
        ├── scan.log
        ├── errors.log
        └── performance.log
```

## 🧪 Testing

### Run All Tests
```bash
python run_all_tests.py
```

### Production Readiness Tests
```bash
python test_production_readiness.py
```

### Individual Module Tests
```bash
python test_core_functionality.py
python test_comprehensive_validation.py
python test_command_line_integration.py
```

## 🔧 Configuration

### Pattern Configuration
Edit `config/patterns.yaml` to customize detection patterns:

```yaml
sensitive_data:
  config_files:
    - "*.config"
    - "*.ini"
    - "*.env"
  backup_files:
    - "*.bak"
    - "*.backup"
    - "*.old"
```

### Tool Configuration
Edit `config/tool_config.yaml` for tool-specific settings:

```yaml
tools:
  subfinder:
    timeout: 300
    threads: 10
  httpx:
    timeout: 30
    retries: 2
```

## 🚀 Production Deployment

### System Requirements
- **OS:** Linux/macOS/Windows
- **Python:** 3.8+
- **Memory:** 4GB+ recommended
- **Storage:** 10GB+ for large scans
- **Network:** Stable internet connection

### Performance Tuning
- **Threads:** Adjust based on system resources (default: 10)
- **Timeout:** Increase for slow networks (default: 300s)
- **Memory:** Monitor usage for large target lists

### Security Considerations
- Run with appropriate user permissions
- Validate all inputs
- Monitor resource usage
- Implement rate limiting for large scans

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Run the test suite
6. Submit a pull request

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 👨‍💻 Author

**Saurabh Tomar**
- GitHub: [@saurabhtomar](https://github.com/saurabhtomar)
- LinkedIn: [saurabhtomar](https://linkedin.com/in/saurabhtomar)
- Twitter: [@saurabhtomar](https://twitter.com/saurabhtomar)

## 🙏 Acknowledgments

- ProjectDiscovery team for excellent tools
- Bug bounty community for feedback and testing
- Open source contributors

## 📞 Support

- **Issues:** [GitHub Issues](https://github.com/saurabhtomar/hyperrecon-pro/issues)
- **Discussions:** [GitHub Discussions](https://github.com/saurabhtomar/hyperrecon-pro/discussions)
- **Documentation:** [Wiki](https://github.com/saurabhtomar/hyperrecon-pro/wiki)

---

⭐ **Star this repository if you find it useful!**