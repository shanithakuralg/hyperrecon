#!/bin/bash

# HyperRecon Pro v4.0 - Production Installation Script
# Automated installation for production environments

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Configuration
INSTALL_DIR="/opt/hyperrecon"
DATA_DIR="/var/hyperrecon"
LOG_DIR="/var/log/hyperrecon"
USER="hyperrecon"
PYTHON_MIN_VERSION="3.8"

# Function to print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_header() {
    echo -e "${CYAN}$1${NC}"
}

# Function to check if running as root
check_root() {
    if [[ $EUID -eq 0 ]]; then
        print_error "This script should not be run as root for security reasons."
        print_status "Please run as a regular user with sudo privileges."
        exit 1
    fi
    
    # Check if user has sudo privileges
    if ! sudo -n true 2>/dev/null; then
        print_error "This script requires sudo privileges."
        print_status "Please ensure your user has sudo access."
        exit 1
    fi
}

# Function to detect OS
detect_os() {
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        if command -v apt-get &> /dev/null; then
            OS="ubuntu"
            PACKAGE_MANAGER="apt-get"
        elif command -v yum &> /dev/null; then
            OS="centos"
            PACKAGE_MANAGER="yum"
        elif command -v dnf &> /dev/null; then
            OS="fedora"
            PACKAGE_MANAGER="dnf"
        else
            print_error "Unsupported Linux distribution"
            exit 1
        fi
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        OS="macos"
        PACKAGE_MANAGER="brew"
    else
        print_error "Unsupported operating system: $OSTYPE"
        exit 1
    fi
    
    print_status "Detected OS: $OS"
}

# Function to check Python version
check_python() {
    print_status "Checking Python installation..."
    
    if command -v python3 &> /dev/null; then
        PYTHON_VERSION=$(python3 -c 'import sys; print(".".join(map(str, sys.version_info[:2])))')
        print_status "Found Python $PYTHON_VERSION"
        
        # Check if version is sufficient
        if python3 -c "import sys; exit(0 if sys.version_info >= (3, 8) else 1)"; then
            print_success "Python version is sufficient"
            PYTHON_CMD="python3"
        else
            print_error "Python $PYTHON_MIN_VERSION or higher is required"
            exit 1
        fi
    else
        print_error "Python 3 is not installed"
        exit 1
    fi
}

# Function to install system dependencies
install_system_dependencies() {
    print_header "Installing System Dependencies"
    
    case $OS in
        "ubuntu")
            print_status "Updating package list..."
            sudo apt-get update -qq
            
            print_status "Installing system packages..."
            sudo apt-get install -y \
                python3 \
                python3-pip \
                python3-venv \
                git \
                curl \
                wget \
                unzip \
                golang-go \
                ruby-dev \
                build-essential
            ;;
        "centos")
            print_status "Installing system packages..."
            sudo yum install -y \
                python3 \
                python3-pip \
                git \
                curl \
                wget \
                unzip \
                golang \
                ruby-devel \
                gcc \
                gcc-c++ \
                make
            ;;
        "fedora")
            print_status "Installing system packages..."
            sudo dnf install -y \
                python3 \
                python3-pip \
                git \
                curl \
                wget \
                unzip \
                golang \
                ruby-devel \
                gcc \
                gcc-c++ \
                make
            ;;
        "macos")
            if ! command -v brew &> /dev/null; then
                print_error "Homebrew is required for macOS installation"
                print_status "Install Homebrew from: https://brew.sh"
                exit 1
            fi
            
            print_status "Installing system packages..."
            brew install python3 git golang ruby
            ;;
    esac
    
    print_success "System dependencies installed"
}

# Function to create user and directories
setup_user_and_directories() {
    print_header "Setting Up User and Directories"
    
    # Create hyperrecon user if it doesn't exist
    if ! id "$USER" &>/dev/null; then
        print_status "Creating user: $USER"
        sudo useradd -m -s /bin/bash "$USER"
        sudo usermod -aG sudo "$USER" 2>/dev/null || true  # Add to sudo group if it exists
    else
        print_status "User $USER already exists"
    fi
    
    # Create directories
    print_status "Creating directories..."
    sudo mkdir -p "$INSTALL_DIR"
    sudo mkdir -p "$DATA_DIR"/{results,cache,temp}
    sudo mkdir -p "$LOG_DIR"
    sudo mkdir -p /etc/hyperrecon
    
    # Set ownership
    sudo chown -R "$USER:$USER" "$INSTALL_DIR"
    sudo chown -R "$USER:$USER" "$DATA_DIR"
    sudo chown -R "$USER:$USER" "$LOG_DIR"
    sudo chown -R "$USER:$USER" /etc/hyperrecon
    
    # Set permissions
    sudo chmod 755 "$INSTALL_DIR"
    sudo chmod 750 "$DATA_DIR"
    sudo chmod 750 "$LOG_DIR"
    
    print_success "User and directories set up"
}

# Function to install Go tools
install_go_tools() {
    print_header "Installing Go-based Tools"
    
    # Set Go environment
    export GOPATH="$HOME/go"
    export PATH="$PATH:$GOPATH/bin"
    
    # Add to shell profile
    if [[ "$SHELL" == *"bash"* ]]; then
        PROFILE_FILE="$HOME/.bashrc"
    elif [[ "$SHELL" == *"zsh"* ]]; then
        PROFILE_FILE="$HOME/.zshrc"
    else
        PROFILE_FILE="$HOME/.profile"
    fi
    
    if ! grep -q "GOPATH" "$PROFILE_FILE" 2>/dev/null; then
        echo 'export GOPATH="$HOME/go"' >> "$PROFILE_FILE"
        echo 'export PATH="$PATH:$GOPATH/bin"' >> "$PROFILE_FILE"
        print_status "Added Go environment to $PROFILE_FILE"
    fi
    
    # Required tools
    GO_TOOLS=(
        "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
        "github.com/projectdiscovery/httpx/cmd/httpx@latest"
        "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
        "github.com/OJ/gobuster/v3@latest"
    )
    
    # Optional tools
    OPTIONAL_GO_TOOLS=(
        "github.com/tomnomnom/assetfinder@latest"
        "github.com/tomnomnom/waybackurls@latest"
        "github.com/lc/gau/v2/cmd/gau@latest"
        "github.com/tomnomnom/gf@latest"
        "github.com/tomnomnom/unfurl@latest"
    )
    
    # Install required tools
    for tool in "${GO_TOOLS[@]}"; do
        tool_name=$(basename "$tool" | cut -d'@' -f1)
        print_status "Installing $tool_name..."
        
        if go install -v "$tool"; then
            print_success "$tool_name installed"
        else
            print_error "Failed to install $tool_name"
            exit 1
        fi
    done
    
    # Install optional tools (don't fail if they don't install)
    for tool in "${OPTIONAL_GO_TOOLS[@]}"; do
        tool_name=$(basename "$tool" | cut -d'@' -f1)
        print_status "Installing $tool_name (optional)..."
        
        if go install -v "$tool"; then
            print_success "$tool_name installed"
        else
            print_warning "Failed to install $tool_name (optional)"
        fi
    done
    
    print_success "Go tools installation completed"
}

# Function to install Python tools
install_python_tools() {
    print_header "Installing Python Tools"
    
    # Install URO
    print_status "Installing URO..."
    if pip3 install --user uro; then
        print_success "URO installed"
    else
        print_warning "Failed to install URO (optional)"
    fi
    
    print_success "Python tools installation completed"
}

# Function to install Ruby tools
install_ruby_tools() {
    print_header "Installing Ruby Tools"
    
    # Install whatweb
    print_status "Installing whatweb..."
    if gem install whatweb; then
        print_success "whatweb installed"
    else
        print_warning "Failed to install whatweb (optional)"
    fi
    
    print_success "Ruby tools installation completed"
}

# Function to install HyperRecon Pro
install_hyperrecon() {
    print_header "Installing HyperRecon Pro"
    
    # Check if we're in the HyperRecon directory
    if [[ -f "hyperrecon.py" && -f "requirements.txt" ]]; then
        print_status "Installing from current directory..."
        sudo cp -r . "$INSTALL_DIR/"
    else
        print_error "HyperRecon Pro files not found in current directory"
        print_status "Please run this script from the HyperRecon Pro directory"
        exit 1
    fi
    
    # Set ownership
    sudo chown -R "$USER:$USER" "$INSTALL_DIR"
    
    # Make main script executable
    sudo chmod +x "$INSTALL_DIR/hyperrecon.py"
    
    # Install Python dependencies
    print_status "Installing Python dependencies..."
    cd "$INSTALL_DIR"
    
    if pip3 install --user -r requirements.txt; then
        print_success "Python dependencies installed"
    else
        print_error "Failed to install Python dependencies"
        exit 1
    fi
    
    print_success "HyperRecon Pro installed"
}

# Function to create systemd service
create_systemd_service() {
    print_header "Creating Systemd Service"
    
    # Create service file
    sudo tee /etc/systemd/system/hyperrecon.service > /dev/null <<EOF
[Unit]
Description=HyperRecon Pro Service
After=network.target

[Service]
Type=simple
User=$USER
Group=$USER
WorkingDirectory=$INSTALL_DIR
Environment=PYTHONPATH=$INSTALL_DIR
Environment=HYPERRECON_ENV=production
Environment=HYPERRECON_OUTPUT_DIR=$DATA_DIR/results
Environment=HYPERRECON_LOG_DIR=$LOG_DIR
ExecStart=/usr/bin/python3 $INSTALL_DIR/hyperrecon.py --daemon
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal
SyslogIdentifier=hyperrecon

[Install]
WantedBy=multi-user.target
EOF
    
    # Reload systemd and enable service
    sudo systemctl daemon-reload
    sudo systemctl enable hyperrecon
    
    print_success "Systemd service created and enabled"
}

# Function to setup log rotation
setup_log_rotation() {
    print_header "Setting Up Log Rotation"
    
    sudo tee /etc/logrotate.d/hyperrecon > /dev/null <<EOF
$LOG_DIR/*.log {
    daily
    rotate 30
    compress
    delaycompress
    missingok
    notifempty
    create 644 $USER $USER
    postrotate
        systemctl reload hyperrecon || true
    endscript
}
EOF
    
    print_success "Log rotation configured"
}

# Function to create command-line wrapper
create_cli_wrapper() {
    print_header "Creating Command-Line Wrapper"
    
    sudo tee /usr/local/bin/hyperrecon > /dev/null <<EOF
#!/bin/bash
cd $INSTALL_DIR
exec python3 hyperrecon.py "\$@"
EOF
    
    sudo chmod +x /usr/local/bin/hyperrecon
    
    print_success "Command-line wrapper created"
    print_status "You can now run 'hyperrecon' from anywhere"
}

# Function to validate installation
validate_installation() {
    print_header "Validating Installation"
    
    # Check if main script exists and is executable
    if [[ -x "$INSTALL_DIR/hyperrecon.py" ]]; then
        print_success "Main script is executable"
    else
        print_error "Main script is not executable"
        return 1
    fi
    
    # Check if Python dependencies are installed
    cd "$INSTALL_DIR"
    if python3 -c "import rich, colorama, requests, yaml, tqdm" 2>/dev/null; then
        print_success "Python dependencies are available"
    else
        print_error "Python dependencies are missing"
        return 1
    fi
    
    # Check if Go tools are available
    REQUIRED_TOOLS=("subfinder" "httpx" "nuclei" "gobuster")
    for tool in "${REQUIRED_TOOLS[@]}"; do
        if command -v "$tool" &> /dev/null; then
            print_success "$tool is available"
        else
            print_error "$tool is not available"
            return 1
        fi
    done
    
    # Run validation script if available
    if [[ -f "$INSTALL_DIR/validate_production_deployment.py" ]]; then
        print_status "Running production validation..."
        cd "$INSTALL_DIR"
        if python3 validate_production_deployment.py; then
            print_success "Production validation passed"
        else
            print_warning "Production validation found issues"
        fi
    fi
    
    print_success "Installation validation completed"
    return 0
}

# Function to print post-installation instructions
print_post_install() {
    print_header "Installation Complete!"
    
    echo
    print_success "HyperRecon Pro v4.0 has been successfully installed!"
    echo
    print_status "Installation Details:"
    echo "  • Installation Directory: $INSTALL_DIR"
    echo "  • Data Directory: $DATA_DIR"
    echo "  • Log Directory: $LOG_DIR"
    echo "  • User: $USER"
    echo
    print_status "Usage:"
    echo "  • Run: hyperrecon -d example.com"
    echo "  • Help: hyperrecon --help"
    echo "  • Validate: hyperrecon --validate-deps"
    echo
    print_status "Service Management:"
    echo "  • Start service: sudo systemctl start hyperrecon"
    echo "  • Stop service: sudo systemctl stop hyperrecon"
    echo "  • Check status: sudo systemctl status hyperrecon"
    echo "  • View logs: sudo journalctl -u hyperrecon -f"
    echo
    print_status "Configuration:"
    echo "  • Main config: $INSTALL_DIR/config/"
    echo "  • Patterns: $INSTALL_DIR/config/patterns.yaml"
    echo "  • Tools: $INSTALL_DIR/config/tool_config.yaml"
    echo
    print_status "Documentation:"
    echo "  • README: $INSTALL_DIR/README.md"
    echo "  • Production Guide: $INSTALL_DIR/docs/PRODUCTION.md"
    echo "  • Examples: $INSTALL_DIR/examples/"
    echo
    print_warning "Next Steps:"
    echo "  1. Review configuration files"
    echo "  2. Test installation: hyperrecon --validate-deps"
    echo "  3. Run a test scan: hyperrecon -d example.com"
    echo "  4. Set up monitoring and alerting"
    echo "  5. Configure backups"
    echo
    print_status "For support and documentation:"
    echo "  • GitHub: https://github.com/saurabhtomar/hyperrecon"
    echo "  • Issues: https://github.com/saurabhtomar/hyperrecon/issues"
    echo
}

# Main installation function
main() {
    print_header "HyperRecon Pro v4.0 - Production Installation"
    print_header "=============================================="
    echo
    
    # Pre-installation checks
    check_root
    detect_os
    check_python
    
    # Installation steps
    install_system_dependencies
    setup_user_and_directories
    install_go_tools
    install_python_tools
    install_ruby_tools
    install_hyperrecon
    create_systemd_service
    setup_log_rotation
    create_cli_wrapper
    
    # Validation
    if validate_installation; then
        print_post_install
        exit 0
    else
        print_error "Installation validation failed"
        print_status "Please check the errors above and try again"
        exit 1
    fi
}

# Handle script interruption
trap 'print_error "Installation interrupted"; exit 1' INT TERM

# Run main function
main "$@"