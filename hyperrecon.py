#!/usr/bin/env python3
"""
HYPERRECON PRO v4.0 - Advanced Modular Bug Bounty Scanner - REFACTORED VERSION
Author: Saurabh Tomar
GitHub: https://github.com/saurabhtomar
LinkedIn: https://linkedin.com/in/saurabhtomar
Twitter: @saurabhtomar

🔥 Refactored Features:
- Clean modular architecture with utility delegation
- Enhanced error handling and workflow orchestration
- Centralized configuration and dependency management
- Consistent interfaces across all modules
- Production-ready code organization
"""

import os
import sys
import argparse
import logging
import signal
import warnings
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock

# Import all utility modules
from utils import (
    ConfigManager, FileManager, UROFilter,
    SubdomainEnumerator, URLCollector, HTTPProber, ParamScanner,
    TechDetector, VulnScanner, DirBruteforcer, SocialRecon,
    JSAnalyzer, SensitiveDataDetector, SecurityChecker, DocumentAnalyzer, 
    ExtensionOrganizer, GFPatternAnalyzer, UnfurlAnalyzer, ReportGenerator
)

# Suppress warnings
warnings.filterwarnings('ignore')
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Check and install packages
def check_and_install_packages():
    """Check and install required packages"""
    packages = ['rich', 'colorama', 'requests', 'pyyaml', 'tqdm']
    missing_packages = []

    for package in packages:
        try:
            __import__(package)
        except ImportError:
            missing_packages.append(package)

    if missing_packages:
        print(f"Missing packages detected: {', '.join(missing_packages)}")
        print("🔧 Installing missing packages...")

        for package in missing_packages:
            try:
                import subprocess
                subprocess.check_call([sys.executable, "-m", "pip", "install", "--break-system-packages", package])
                print(f"✅ {package} installed successfully!")
            except subprocess.CalledProcessError as e:
                print(f"❌ Failed to install {package}: {e}")
                sys.exit(1)

        print("✅ All packages installed successfully!")

check_and_install_packages()

import colorama
from colorama import Fore, Style
from rich.console import Console
from rich.progress import Progress
from rich.panel import Panel
from rich.text import Text

colorama.init()
console = Console()


class WorkflowTracker:
    """
    Tracks workflow execution, data flow, and generates comprehensive summaries
    """
    
    def __init__(self, domain, console):
        self.domain = domain
        self.console = console
        self.steps = {}
        self.data_flow = {}
        self.start_time = datetime.now()
        self.current_step = None
        
    def start_step(self, step_name, description=""):
        """Start tracking a workflow step"""
        self.current_step = step_name
        self.steps[step_name] = {
            'start_time': datetime.now(),
            'description': description,
            'status': 'running',
            'input_data': {},
            'output_data': {},
            'errors': [],
            'warnings': [],
            'metadata': {}
        }
        
        if self.console:
            self.console.print(f"🔄 [cyan]Starting: {step_name}[/cyan]")
    
    def end_step(self, step_name, success=True, output_data=None, errors=None, warnings=None):
        """End tracking a workflow step"""
        if step_name in self.steps:
            step = self.steps[step_name]
            step['end_time'] = datetime.now()
            step['duration'] = (step['end_time'] - step['start_time']).total_seconds()
            step['status'] = 'completed' if success else 'failed'
            step['output_data'] = output_data or {}
            step['errors'] = errors or []
            step['warnings'] = warnings or []
            
            # Track data flow
            self.data_flow[step_name] = {
                'input_size': len(str(step.get('input_data', {}))),
                'output_size': len(str(output_data or {})),
                'success': success
            }
            
            status_icon = "✅" if success else "❌"
            if self.console:
                self.console.print(f"{status_icon} [green if success else red]{step_name} completed in {step['duration']:.2f}s[/green if success else red]")
    
    def log_data_flow(self, from_step, to_step, data_type, data_count):
        """Log data flow between steps"""
        flow_key = f"{from_step} -> {to_step}"
        if flow_key not in self.data_flow:
            self.data_flow[flow_key] = {}
        self.data_flow[flow_key][data_type] = data_count
    
    def get_workflow_summary(self):
        """Generate comprehensive workflow summary"""
        total_duration = (datetime.now() - self.start_time).total_seconds()
        
        summary = {
            'domain': self.domain,
            'total_duration': total_duration,
            'steps_completed': len([s for s in self.steps.values() if s.get('status') == 'completed']),
            'steps_failed': len([s for s in self.steps.values() if s.get('status') == 'failed']),
            'total_steps': len(self.steps),
            'data_flow': self.data_flow,
            'step_details': self.steps,
            'workflow_efficiency': self._calculate_efficiency()
        }
        
        return summary
    
    def _calculate_efficiency(self):
        """Calculate workflow efficiency metrics"""
        completed_steps = [s for s in self.steps.values() if s.get('status') == 'completed']
        if not completed_steps:
            return 0.0
        
        total_time = sum(s.get('duration', 0) for s in completed_steps)
        success_rate = len(completed_steps) / len(self.steps) if self.steps else 0
        
        return {
            'success_rate': success_rate,
            'average_step_time': total_time / len(completed_steps) if completed_steps else 0,
            'total_processing_time': total_time
        }


class HyperReconPro:
    """
    Main orchestrator class for HyperRecon Pro - Refactored for clean modular architecture
    Handles workflow orchestration, user interface, and delegates functionality to utility modules
    """
    
    def __init__(self):
        """Initialize HyperRecon Pro with modular architecture"""
        self.version = "4.0"
        self.tool_name = "HyperRecon Pro"
        self.author = "Saurabh Tomar"

        # Core configuration
        self.console = console
        self.start_time = None
        self.output_dir = None
        self.verbose = False
        self.debug = False
        self.args = None
        self.threads = 10
        self.interrupted = False

        # Progress tracking
        self.total_tasks = 0
        self.completed_tasks = 0
        self.progress_lock = Lock()

        # Enhanced feature flags - centralized configuration
        self.feature_flags = {
            'subfinder': True,
            'httpx': True,
            'waybackurls': True,
            'gau': True,
            'assetfinder': True,
            'paramspider': True,
            'nuclei': True,
            'gobuster': True,
            'whatweb': True,
            'unfurl': True,
            'uro': True,
            'gf': True,
            'social_media_recon': True,
            'html_reports': True,
            'js_analysis': True,
            'technology_detection': True,
            'sensitive_data': True,
            'security_checks': True,
            'document_analysis': True,
            'extension_organization': True,
            'gf_patterns': True,
            'unfurl_analysis': True,
            'extension_filtering': True,
            'dast_scanning': True
        }

        # Initialize core components
        self._initialize_core_components()
        self._initialize_utility_modules()
        self._setup_signal_handlers()

    def _initialize_core_components(self):
        """Initialize core system components"""
        try:
            # Setup logging
            self.setup_logging()
            
            # Initialize configuration manager
            self.config_manager = ConfigManager()
            
            # Initialize file manager
            self.file_manager = FileManager(self)
            
            # Initialize URO filter for centralized URL deduplication
            self.uro_filter = UROFilter(self)
            
        except Exception as e:
            console.print(f"❌ [red]Failed to initialize core components: {e}[/red]")
            sys.exit(1)

    def _initialize_utility_modules(self):
        """Initialize all utility modules with consistent interfaces"""
        try:
            # Core reconnaissance utilities
            self.subdomain_enumerator = SubdomainEnumerator(self)
            self.url_collector = URLCollector(self)
            self.http_prober = HTTPProber(self)
            
            # Analysis utilities
            self.param_scanner = ParamScanner(self)
            self.tech_detector = TechDetector(self)
            self.js_analyzer = JSAnalyzer(self)
            self.sensitive_data_detector = SensitiveDataDetector(self)
            
            # Security utilities
            self.vuln_scanner = VulnScanner(self)
            self.dir_bruteforcer = DirBruteforcer(self)
            self.security_checker = SecurityChecker(self)
            
            # OSINT and reporting utilities
            self.social_recon = SocialRecon(self)
            self.document_analyzer = DocumentAnalyzer(self)
            self.extension_organizer = ExtensionOrganizer(self)
            self.gf_pattern_analyzer = GFPatternAnalyzer(self)
            self.unfurl_analyzer = UnfurlAnalyzer(self)
            self.report_generator = ReportGenerator(self)
            
        except Exception as e:
            console.print(f"❌ [red]Failed to initialize utility modules: {e}[/red]")
            sys.exit(1)

    def _setup_signal_handlers(self):
        """Setup signal handlers for graceful shutdown"""
        signal.signal(signal.SIGINT, self.signal_handler)
        signal.signal(signal.SIGTERM, self.signal_handler)

    def setup_logging(self):
        """Setup logging system with enhanced configuration"""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('hyperrecon.log'),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(self.tool_name)

    def validate_dependencies(self):
        """Validate tool dependencies using ConfigManager"""
        validation_results = self.config_manager.validate_dependencies()
        
        if not validation_results['all_required_available']:
            console.print("⚠️ [yellow]Missing required tools detected:[/yellow]")
            for tool in validation_results['required_missing']:
                console.print(f"  ❌ [red]{tool}[/red]")
            
            console.print("\n📋 [cyan]Installation instructions:[/cyan]")
            from utils.base_utility import ToolValidator
            for tool in validation_results['required_missing']:
                instructions = ToolValidator.get_installation_instructions(tool)
                console.print(f"  🔧 [blue]{tool}:[/blue] {instructions}")
        
        if validation_results['optional_missing']:
            console.print("\nℹ️ [blue]Optional tools not available (functionality may be limited):[/blue]")
            for tool in validation_results['optional_missing']:
                console.print(f"  ⚠️ [yellow]{tool}[/yellow]")
        
        return validation_results

    def run_scan(self, targets, is_subdomain_input=False):
        """
        Run scan on multiple targets with enhanced workflow orchestration
        
        Args:
            targets: List of target domains/subdomains
            is_subdomain_input: Whether inputs are subdomains (skip subdomain enumeration)
            
        Returns:
            List of scan results for all targets
        """
        if len(targets) > 1:
            console.print(f"📋 [cyan]Multiple Target Mode - Processing {len(targets)} targets[/cyan]")

        all_results = []

        # Use threading if specified and multiple targets
        if self.threads > 1 and len(targets) > 1:
            console.print(f"🧵 [blue]Using {self.threads} threads for parallel processing[/blue]")

            with ThreadPoolExecutor(max_workers=self.threads) as executor:
                future_to_target = {
                    executor.submit(self.scan_single_target, target, is_subdomain_input): target 
                    for target in targets
                }

                for future in as_completed(future_to_target):
                    target = future_to_target[future]
                    try:
                        result = future.result()
                        if result:
                            all_results.append(result)
                        console.print(f"✅ [green]Completed scan for {target}[/green]")
                    except Exception as exc:
                        console.print(f"❌ [red]Error scanning {target}: {exc}[/red]")
                        if self.debug:
                            raise
        else:
            # Sequential processing
            for target in targets:
                if self.interrupted:
                    console.print("⏭️ [yellow]Skipping remaining targets due to user interrupt[/yellow]")
                    break

                result = self.scan_single_target(target, is_subdomain_input)
                if result:
                    all_results.append(result)

        return all_results

    def display_banner(self):
        """Display enhanced banner with refactored architecture highlights"""
        banner_text = f"""
===============================================================================

  🚀 HYPERRECON PRO v{self.version} - Advanced Modular Bug Bounty Scanner       
  💀 Written by: {self.author}                                      
  🌐 GitHub: github.com/saurabhtomar                                        
  🐦 Twitter: @saurabhtomar                                                 
  💼 LinkedIn: linkedin.com/in/saurabhtomar                                 

  🎯 Refactored Modular Architecture | Clean Code Organization
  🔍 Enhanced Error Handling | Centralized Configuration Management     
  📊 Consistent Utility Interfaces | Production-Ready Workflow Orchestration  
  📄 Comprehensive Testing Support | Future Enhancement Ready      

===============================================================================
✅ HyperRecon Pro v{self.version} Refactored Successfully!
ℹ️  Use --help for comprehensive usage guide
        """

        styled_banner = Panel(
            Text(banner_text, style="bold cyan"),
            style="bold blue",
            padding=(0, 1),
            title="[bold magenta]HyperRecon Pro v4.0 Refactored[/bold magenta]",
            subtitle="[yellow]by Saurabh Tomar[/yellow]"
        )
        console.print(styled_banner)

    def setup_logging(self):
        """Setup logging system"""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('hyperrecon.log'),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(self.tool_name)

    def create_output_structure(self, domain):
        """Create organized output directory structure - delegated to FileManager"""
        return self.file_manager.create_output_structure(domain, self.output_dir)

    def save_results_realtime(self, domain_path, category, filename, data, append=False):
        """Save results in real-time - delegated to FileManager"""
        return self.file_manager.save_results_realtime(domain_path, category, filename, data, append)

    def signal_handler(self, signum, frame):
        """Handle graceful shutdown with enhanced error handling"""
        if hasattr(self, '_handling_signal') and self._handling_signal:
            return

        self._handling_signal = True
        console.print(f"\n🛑 [yellow]Scan interrupted by user (Ctrl+C)[/yellow]")

        try:
            console.print("\n📦 [cyan]Choose an option:[/cyan]")
            console.print("  [bold green]1.[/bold green] [green]Continue scanning[/green]")
            console.print("  [bold yellow]2.[/bold yellow] [yellow]Skip current target[/yellow]")
            console.print("  [bold red]3.[/bold red] [red]Save state and exit[/red]")
            console.print("  [bold blue]4.[/bold blue] [blue]Force exit without saving[/blue]")

            choice = input("\n🕹️ Enter your choice (1-4): ").strip()

            if choice == '1':
                console.print("▶️ [green]Continuing scan...[/green]")
                self._handling_signal = False
                return
            elif choice == '2':
                console.print("⏭️ [yellow]Skipping current target...[/yellow]")
                self.interrupted = True
                self._handling_signal = False
                return
            elif choice == '3':
                console.print("💾 [blue]Saving state and exiting...[/blue]")
                self._save_and_exit()
            else:
                console.print("⚡ [red]Force exiting...[/red]")
                self._force_exit()
        except (KeyboardInterrupt, EOFError):
            console.print("\n💾 [blue]Force exiting...[/blue]")
            self._force_exit()

    def _save_and_exit(self):
        """Save current state and exit gracefully"""
        try:
            if hasattr(self, 'output_dir') and self.output_dir:
                import os
                os.makedirs(self.output_dir, exist_ok=True)
                console.print("✅ [green]Results saved successfully![/green]")
        except Exception as e:
            console.print(f"❌ [red]Error saving state: {e}[/red]")
        finally:
            sys.exit(0)

    def _force_exit(self):
        """Force exit without saving"""
        sys.exit(0)

    def check_tool_installed(self, tool_name):
        """Check if tool is installed - delegated to ConfigManager"""
        return self.config_manager._check_tool_available(tool_name)

    def run_command(self, cmd, timeout=120, description="", input_data=None):
        """Execute command with error handling"""
        try:
            import subprocess
            
            if description and self.verbose:
                console.print(f"🔧 [blue]{description}[/blue]")

            if input_data:
                result = subprocess.run(cmd, input=input_data, capture_output=True, text=True, timeout=timeout)
            else:
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)

            if result.returncode == 0:
                return result.stdout.strip()
            else:
                if self.verbose:
                    console.print(f"⚠️ [yellow]Command warning: {result.stderr[:100]}[/yellow]")
                return ""
        except subprocess.TimeoutExpired:
            console.print(f"⏰ [yellow]Command timeout after {timeout}s[/yellow]")
            return ""
        except Exception as e:
            if self.verbose:
                console.print(f"❌ [red]Command error: {str(e)[:100]}[/red]")
            return ""





    def url_collection(self, target, domain_path):
        """Collect URLs from multiple sources - delegated to URLCollector utility"""
        result = self.url_collector.execute(target, domain_path)
        
        if result.success and result.data.get('filtered_urls'):
            return result.data['filtered_urls']
        else:
            console.print(f"⚠️ [yellow]URL collection failed or returned no results for {target}[/yellow]")
            return []

    def http_probing(self, targets, domain_path):
        """Probe for live hosts - delegated to HTTPProber utility"""
        console.print(f"🌐 [cyan]HTTP probing {len(targets)} targets[/cyan]")
        
        result = self.http_prober.execute(targets, domain_path)
        
        if result.success and result.data.get('live_hosts'):
            live_hosts = result.data['live_hosts']
            console.print(f"✅ [green]Found {len(live_hosts)} live hosts[/green]")
            return live_hosts
        elif not result.success:
            console.print(f"❌ [red]HTTP probing failed: {result.errors}[/red]")
        
        return []

    def js_analysis(self, urls, domain_path):
        """Analyze JavaScript files - delegated to JSAnalyzer utility"""
        result = self.js_analyzer.execute(urls, domain_path)
        
        if result.success:
            return result.data
        else:
            console.print(f"⚠️ [yellow]JavaScript analysis failed: {result.errors}[/yellow]")
            return {}

    def nuclei_vulnerability_scan(self, live_hosts, domain_path):
        """Enhanced Nuclei vulnerability scan - delegated to VulnScanner module"""
        result = self.vuln_scanner.execute(live_hosts, domain_path, 'hosts')
        
        if result.get('success'):
            return result.get('detailed_results', {}).get('subdomain_vulnerabilities', {})
        else:
            console.print(f"⚠️ [yellow]Vulnerability scanning failed[/yellow]")
            return {}

    def nuclei_dast_parameter_scan(self, param_urls, domain_path):
        """Enhanced DAST scan on parameterized URLs - delegated to VulnScanner module"""
        if not self.feature_flags.get('dast_scanning', False):
            return {}
            
        result = self.vuln_scanner.execute(param_urls, domain_path, 'parameters')
        
        if result.get('success'):
            return result.get('detailed_results', {}).get('parameter_vulnerabilities', {})
        else:
            console.print(f"⚠️ [yellow]DAST parameter scanning failed[/yellow]")
            return {}

    def directory_bruteforce(self, live_hosts, domain_path):
        """Enhanced directory brute forcing - delegated to DirBruteforcer module"""
        if not live_hosts:
            return {}

        console.print(f"📁 [cyan]Enhanced directory brute force on {len(live_hosts)} hosts[/cyan]")
        
        result = self.dir_bruteforcer.execute(live_hosts, domain_path)
        
        if result.success:
            directories = result.data.get('directories', {})
            security_findings = result.data.get('security_findings', {})
            
            total_dirs = result.data.get('total_directories', 0)
            total_security = result.data.get('total_security_findings', 0)
            
            if total_dirs > 0:
                console.print(f"✅ [green]Found {total_dirs} total directories[/green]")
            
            if total_security > 0:
                console.print(f"🚨 [red]Found {total_security} security findings[/red]")
            
            # Store security findings for later use
            if hasattr(self, 'security_findings'):
                self.security_findings.update(security_findings)
            else:
                self.security_findings = security_findings
            
            return directories
        else:
            console.print(f"⚠️ [yellow]Directory bruteforcing failed: {result.data.get('error', 'Unknown error')}[/yellow]")
            return {}

    def security_checks(self, live_hosts, domain_path):
        """Check for common sensitive paths - delegated to SecurityChecker module"""
        if not live_hosts:
            return {}

        result = self.security_checker.execute(live_hosts, domain_path)
        
        if result.success:
            return result.data
        else:
            console.print(f"⚠️ [yellow]Security checks failed: {result.errors}[/yellow]")
            return {}

    def social_media_recon(self, target, domain_path):
        """Enhanced social media reconnaissance - delegated to SocialRecon module"""
        if not self.feature_flags.get('social_media_recon', True):
            return {}

        result = self.social_recon.execute(target, domain_path)
        
        if result.success:
            return result.data
        else:
            console.print(f"⚠️ [yellow]Social media reconnaissance failed: {result.errors}[/yellow]")
            return {}

    def scan_single_target(self, domain, is_subdomain_input=False):
        """
        Scan a single target with all enhanced features
        Orchestrates the complete reconnaissance workflow using utility modules
        """
        console.print(f"\n🎯 [bold cyan]Starting comprehensive scan for: {domain}[/bold cyan]")

        # Create organized output structure
        domain_path = self.create_output_structure(domain)
        results = {
            'domain': domain, 
            'scan_start': datetime.now().isoformat(), 
            'domain_path': domain_path,
            'workflow_metadata': {
                'version': self.version,
                'feature_flags': self.feature_flags.copy(),
                'threads': self.threads,
                'verbose': self.verbose
            }
        }

        # Initialize workflow tracking
        workflow_tracker = WorkflowTracker(domain, self.console)
        
        try:
            # 1. Subdomain Enumeration
            subdomains = self._execute_subdomain_enumeration(domain, domain_path, is_subdomain_input, results, workflow_tracker)

            # 2. URL Collection
            all_urls = self._execute_url_collection(subdomains, domain_path, results, workflow_tracker)

            # 3. HTTP Probing
            live_hosts = self._execute_http_probing(subdomains, domain_path, results, workflow_tracker)

            # 4. Technology Detection
            self._execute_technology_detection(live_hosts, domain_path, results, workflow_tracker)

            # 5. Parameter Discovery and Analysis
            all_param_urls = self._execute_parameter_analysis(domain, all_urls, domain_path, results, workflow_tracker)

            # 6. JavaScript Analysis
            self._execute_javascript_analysis(all_urls, domain_path, results, workflow_tracker)

            # 7. Vulnerability Scanning
            self._execute_vulnerability_scanning(live_hosts, all_param_urls, domain_path, results, workflow_tracker)

            # 8. Directory Bruteforcing
            self._execute_directory_bruteforcing(live_hosts, domain_path, results, workflow_tracker)

            # 9. Security Checks
            self._execute_security_checks(live_hosts, domain_path, results, workflow_tracker)

            # 10. Document Analysis
            self._execute_document_analysis(all_urls, domain_path, results, workflow_tracker)

            # 11. Extension Organization
            self._execute_extension_organization(all_urls, domain_path, results, workflow_tracker)

            # 12. GF Pattern Analysis
            self._execute_gf_pattern_analysis(all_urls, domain_path, results, workflow_tracker)

            # 13. Unfurl Analysis
            self._execute_unfurl_analysis(all_urls, domain_path, results, workflow_tracker)

            # 14. Social Media Reconnaissance
            self._execute_social_media_recon(domain, domain_path, results, workflow_tracker)

            # 15. Generate comprehensive results summary
            results = self._generate_comprehensive_summary(results, workflow_tracker)
            
            results['scan_end'] = datetime.now().isoformat()
            console.print(f"✅ [bold green]Scan completed for {domain}[/bold green]")

        except Exception as e:
            console.print(f"❌ [red]Error scanning {domain}: {e}[/red]")
            results['error'] = str(e)
            results['workflow_status'] = 'failed'
            if self.debug:
                raise

        return results

    def _execute_subdomain_enumeration(self, domain, domain_path, is_subdomain_input, results, workflow_tracker):
        """Execute subdomain enumeration workflow step"""
        step_name = "Subdomain Enumeration"
        workflow_tracker.start_step(step_name, "Discovering subdomains using multiple tools")
        
        try:
            if is_subdomain_input:
                # Skip subdomain enumeration for -s flag
                subdomains = [domain]  # Use provided subdomain directly
                results['subdomains'] = subdomains
                results['subdomain_stats'] = {
                    'total_found': 1,
                    'execution_time': 0,
                    'tools_used': [],
                    'sources': {'subdomain_input': 1},
                    'enumeration_skipped': True
                }
                workflow_tracker.end_step(step_name, True, {
                    'subdomains_found': 1, 
                    'source': 'subdomain_input',
                    'enumeration_skipped': True
                })
                console.print(f"🔄 [cyan]Subdomain enumeration skipped - using provided subdomain: {domain}[/cyan]")
                
            elif self.feature_flags.get('subfinder', True):
                # Normal subdomain enumeration for -d flag
                subdomain_result = self.subdomain_enumerator.execute(domain, domain_path)
                if subdomain_result.success:
                    subdomains = subdomain_result.data.get('subdomains', [])
                    results['subdomains'] = subdomains
                    results['subdomain_enumeration'] = subdomain_result.data
                    
                    # Enhanced result tracking
                    results['subdomain_stats'] = {
                        'total_found': len(subdomains),
                        'execution_time': subdomain_result.execution_time,
                        'tools_used': subdomain_result.data.get('tools_used', []),
                        'sources': subdomain_result.data.get('sources', {}),
                        'enumeration_skipped': False
                    }
                    
                    workflow_tracker.end_step(step_name, True, {
                        'subdomains_found': len(subdomains),
                        'tools_used': subdomain_result.data.get('tools_used', [])
                    })
                else:
                    console.print(f"❌ [red]Subdomain enumeration failed: {subdomain_result.errors}[/red]")
                    subdomains = [domain]  # Fallback to main domain
                    results['subdomains'] = subdomains
                    workflow_tracker.end_step(step_name, False, errors=subdomain_result.errors)
            else:
                # Subfinder disabled
                subdomains = [domain]
                results['subdomains'] = subdomains
                results['subdomain_stats'] = {
                    'total_found': 1,
                    'execution_time': 0,
                    'tools_used': [],
                    'sources': {'direct_input': 1},
                    'enumeration_skipped': True
                }
                workflow_tracker.end_step(step_name, True, {'subdomains_found': 1, 'source': 'direct_input'})
            
            # Log data flow to next steps
            workflow_tracker.log_data_flow(step_name, "URL Collection", "subdomains", len(subdomains))
            workflow_tracker.log_data_flow(step_name, "HTTP Probing", "subdomains", len(subdomains))
            
        except Exception as e:
            workflow_tracker.end_step(step_name, False, errors=[str(e)])
            raise
        
        return subdomains

    def _execute_url_collection(self, subdomains, domain_path, results, workflow_tracker):
        """Execute URL collection workflow step"""
        step_name = "URL Collection"
        workflow_tracker.start_step(step_name, f"Collecting URLs from {len(subdomains)} subdomains")
        
        try:
            all_urls = []
            url_sources = {}
            total_execution_time = 0
            
            for subdomain in subdomains:
                url_result = self.url_collector.execute(subdomain, domain_path)
                if url_result.success:
                    subdomain_urls = url_result.data.get('filtered_urls', [])
                    all_urls.extend(subdomain_urls)
                    url_sources[subdomain] = {
                        'count': len(subdomain_urls),
                        'sources': url_result.data.get('sources', {}),
                        'execution_time': url_result.execution_time
                    }
                    total_execution_time += url_result.execution_time
                else:
                    console.print(f"⚠️ [yellow]URL collection failed for {subdomain}: {url_result.errors}[/yellow]")
                    url_sources[subdomain] = {'count': 0, 'error': url_result.errors}
            
            results['urls'] = all_urls
            results['url_collection_stats'] = {
                'total_urls': len(all_urls),
                'sources': url_sources,
                'execution_time': total_execution_time,
                'subdomains_processed': len(subdomains)
            }
            
            workflow_tracker.end_step(step_name, True, {
                'urls_collected': len(all_urls),
                'subdomains_processed': len(subdomains),
                'sources': url_sources
            })
            
            # Log data flow to next steps
            workflow_tracker.log_data_flow(step_name, "Parameter Analysis", "urls", len(all_urls))
            workflow_tracker.log_data_flow(step_name, "JavaScript Analysis", "urls", len(all_urls))
            
        except Exception as e:
            workflow_tracker.end_step(step_name, False, errors=[str(e)])
            raise
        
        return all_urls

    def _execute_http_probing(self, subdomains, domain_path, results, workflow_tracker):
        """Execute HTTP probing workflow step"""
        step_name = "HTTP Probing"
        workflow_tracker.start_step(step_name, f"Probing {len(subdomains)} subdomains for live hosts")
        
        try:
            console.print(f"🌐 [cyan]HTTP probing {len(subdomains)} targets[/cyan]")
            
            result = self.http_prober.execute(subdomains, domain_path)
            
            if result.success and result.data.get('live_hosts'):
                live_hosts = result.data['live_hosts']
                console.print(f"✅ [green]Found {len(live_hosts)} live hosts[/green]")
                
                results['live_hosts'] = live_hosts
                results['http_probing_stats'] = {
                    'total_probed': len(subdomains),
                    'live_hosts_found': len(live_hosts),
                    'success_rate': len(live_hosts) / len(subdomains) if subdomains else 0,
                    'execution_time': result.execution_time,
                    'status_codes': result.data.get('status_codes', {}),
                    'technologies_detected': result.data.get('technologies', {})
                }
                
                workflow_tracker.end_step(step_name, True, {
                    'live_hosts_found': len(live_hosts),
                    'success_rate': len(live_hosts) / len(subdomains) if subdomains else 0,
                    'status_codes': result.data.get('status_codes', {})
                })
            elif not result.success:
                console.print(f"❌ [red]HTTP probing failed: {result.errors}[/red]")
                live_hosts = []
                results['live_hosts'] = live_hosts
                workflow_tracker.end_step(step_name, False, errors=result.errors)
            else:
                live_hosts = []
                results['live_hosts'] = live_hosts
                workflow_tracker.end_step(step_name, True, {'live_hosts_found': 0})
            
            # Log data flow to next steps
            workflow_tracker.log_data_flow(step_name, "Technology Detection", "live_hosts", len(live_hosts))
            workflow_tracker.log_data_flow(step_name, "Vulnerability Scanning", "live_hosts", len(live_hosts))
            workflow_tracker.log_data_flow(step_name, "Directory Bruteforcing", "live_hosts", len(live_hosts))
            workflow_tracker.log_data_flow(step_name, "Security Checks", "live_hosts", len(live_hosts))
            
        except Exception as e:
            workflow_tracker.end_step(step_name, False, errors=[str(e)])
            raise
        
        return live_hosts

    def _execute_technology_detection(self, live_hosts, domain_path, results, workflow_tracker):
        """Execute technology detection workflow step"""
        step_name = "Technology Detection"
        workflow_tracker.start_step(step_name, f"Detecting technologies on {len(live_hosts)} live hosts")
        
        try:
            if self.feature_flags.get('technology_detection', True) and live_hosts:
                tech_result = self.tech_detector.execute(live_hosts, domain_path)
                if tech_result.success:
                    results['technology'] = tech_result.data
                    results['technology_stats'] = {
                        'hosts_analyzed': len(live_hosts),
                        'technologies_found': len(tech_result.data.get('technologies', {})),
                        'execution_time': tech_result.execution_time,
                        'categories': tech_result.data.get('categories', {})
                    }
                    
                    workflow_tracker.end_step(step_name, True, {
                        'technologies_found': len(tech_result.data.get('technologies', {})),
                        'hosts_analyzed': len(live_hosts),
                        'categories': tech_result.data.get('categories', {})
                    })
                else:
                    results['technology'] = {}
                    workflow_tracker.end_step(step_name, False, errors=tech_result.errors)
            else:
                results['technology'] = {}
                skip_reason = "No live hosts" if not live_hosts else "Technology detection disabled"
                workflow_tracker.end_step(step_name, True, {'skipped': True, 'reason': skip_reason})
                
        except Exception as e:
            workflow_tracker.end_step(step_name, False, errors=[str(e)])
            raise

    def _execute_parameter_analysis(self, domain, all_urls, domain_path, results, workflow_tracker):
        """Execute parameter discovery and analysis workflow step"""
        step_name = "Parameter Analysis"
        workflow_tracker.start_step(step_name, f"Analyzing parameters from {len(all_urls)} URLs")
        
        try:
            all_param_urls = []
            
            if self.feature_flags.get('paramspider', True):
                param_targets = {
                    'domain': domain,
                    'urls': all_urls
                }
                
                param_result = self.param_scanner.execute(param_targets, domain_path)
                
                if param_result.success:
                    param_data = param_result.data
                    
                    # Extract key results for backward compatibility
                    results['parameter_urls'] = param_data.get('all_parameterized_urls', [])
                    results['gf_patterns'] = param_data.get('gf_patterns', {})
                    results['sensitive_data'] = param_data.get('sensitive_data', {})
                    results['unfurl_results'] = param_data.get('unfurl_results', {})
                    results['extensions'] = param_data.get('extension_filtering', {})
                    results['documents'] = param_data.get('document_analysis', {})
                    
                    # Store complete parameter analysis results
                    results['parameter_analysis'] = param_data
                    results['parameter_stats'] = {
                        'total_parameterized_urls': len(param_data.get('all_parameterized_urls', [])),
                        'gf_patterns_found': len(param_data.get('gf_patterns', {})),
                        'sensitive_data_found': len(param_data.get('sensitive_data', {})),
                        'execution_time': param_result.execution_time,
                        'documents_found': len(param_data.get('document_analysis', {}))
                    }
                    
                    all_param_urls = results['parameter_urls']
                    
                    workflow_tracker.end_step(step_name, True, {
                        'parameterized_urls_found': len(all_param_urls),
                        'gf_patterns': len(param_data.get('gf_patterns', {})),
                        'sensitive_data': len(param_data.get('sensitive_data', {})),
                        'documents': len(param_data.get('document_analysis', {}))
                    })
                else:
                    console.print(f"⚠️ [yellow]Parameter scanning failed: {param_result.errors}[/yellow]")
                    all_param_urls = []
                    results['parameter_urls'] = []
                    workflow_tracker.end_step(step_name, False, errors=param_result.errors)
            else:
                all_param_urls = []
                results['parameter_urls'] = []
                workflow_tracker.end_step(step_name, True, {'skipped': True, 'reason': 'Parameter scanning disabled'})
            
            # Log data flow to next steps
            workflow_tracker.log_data_flow(step_name, "Vulnerability Scanning", "parameterized_urls", len(all_param_urls))
            
        except Exception as e:
            workflow_tracker.end_step(step_name, False, errors=[str(e)])
            raise
        
        return all_param_urls

    def _execute_javascript_analysis(self, all_urls, domain_path, results, workflow_tracker):
        """Execute JavaScript analysis workflow step"""
        step_name = "JavaScript Analysis"
        workflow_tracker.start_step(step_name, f"Analyzing JavaScript from {len(all_urls)} URLs")
        
        try:
            if self.feature_flags.get('js_analysis', True) and all_urls:
                js_result = self.js_analyzer.execute(all_urls, domain_path)
                if js_result.success:
                    results['js_analysis'] = js_result.data
                    results['js_analysis_stats'] = {
                        'js_files_found': len(js_result.data.get('js_files', [])),
                        'endpoints_extracted': len(js_result.data.get('endpoints', [])),
                        'api_calls_found': len(js_result.data.get('api_calls', [])),
                        'execution_time': js_result.execution_time
                    }
                    
                    workflow_tracker.end_step(step_name, True, {
                        'js_files_found': len(js_result.data.get('js_files', [])),
                        'endpoints_extracted': len(js_result.data.get('endpoints', [])),
                        'api_calls_found': len(js_result.data.get('api_calls', []))
                    })
                else:
                    results['js_analysis'] = {}
                    workflow_tracker.end_step(step_name, False, errors=js_result.errors)
            else:
                results['js_analysis'] = {}
                skip_reason = "No URLs available" if not all_urls else "JavaScript analysis disabled"
                workflow_tracker.end_step(step_name, True, {'skipped': True, 'reason': skip_reason})
                
        except Exception as e:
            workflow_tracker.end_step(step_name, False, errors=[str(e)])
            raise

    def _execute_vulnerability_scanning(self, live_hosts, all_param_urls, domain_path, results, workflow_tracker):
        """Execute vulnerability scanning workflow step"""
        step_name = "Vulnerability Scanning"
        workflow_tracker.start_step(step_name, f"Scanning {len(live_hosts)} hosts and {len(all_param_urls)} parameterized URLs")
        
        try:
            vuln_results = {}
            dast_results = {}
            
            # Regular vulnerability scanning
            if self.feature_flags.get('nuclei', True) and live_hosts:
                vuln_results = self.nuclei_vulnerability_scan(live_hosts, domain_path)
                results['vulnerabilities'] = vuln_results
                
            # DAST parameter scanning
            if self.feature_flags.get('dast_scanning', True) and all_param_urls:
                dast_results = self.nuclei_dast_parameter_scan(all_param_urls, domain_path)
                results['dast_vulnerabilities'] = dast_results
            
            # Calculate vulnerability statistics
            total_vulns = len(vuln_results) + len(dast_results)
            results['vulnerability_stats'] = {
                'host_vulnerabilities': len(vuln_results),
                'parameter_vulnerabilities': len(dast_results),
                'total_vulnerabilities': total_vulns,
                'hosts_scanned': len(live_hosts),
                'parameters_scanned': len(all_param_urls)
            }
            
            workflow_tracker.end_step(step_name, True, {
                'vulnerabilities_found': total_vulns,
                'hosts_scanned': len(live_hosts),
                'parameters_scanned': len(all_param_urls),
                'host_vulns': len(vuln_results),
                'param_vulns': len(dast_results)
            })
            
        except Exception as e:
            workflow_tracker.end_step(step_name, False, errors=[str(e)])
            raise

    def _execute_directory_bruteforcing(self, live_hosts, domain_path, results, workflow_tracker):
        """Execute directory bruteforcing workflow step"""
        step_name = "Directory Bruteforcing"
        workflow_tracker.start_step(step_name, f"Bruteforcing directories on {len(live_hosts)} hosts")
        
        try:
            if self.feature_flags.get('gobuster', True) and live_hosts:
                directories = self.directory_bruteforce(live_hosts, domain_path)
                results['directories'] = directories
                
                # Calculate directory statistics
                total_dirs = sum(len(dirs) for dirs in directories.values())
                results['directory_stats'] = {
                    'total_directories_found': total_dirs,
                    'hosts_bruteforced': len(live_hosts),
                    'directories_per_host': total_dirs / len(live_hosts) if live_hosts else 0
                }
                
                workflow_tracker.end_step(step_name, True, {
                    'directories_found': total_dirs,
                    'hosts_bruteforced': len(live_hosts),
                    'security_findings': getattr(self, 'security_findings', {})
                })
            else:
                results['directories'] = {}
                skip_reason = "No live hosts" if not live_hosts else "Directory bruteforcing disabled"
                workflow_tracker.end_step(step_name, True, {'skipped': True, 'reason': skip_reason})
                
        except Exception as e:
            workflow_tracker.end_step(step_name, False, errors=[str(e)])
            raise

    def _execute_security_checks(self, live_hosts, domain_path, results, workflow_tracker):
        """Execute security checks workflow step"""
        step_name = "Security Checks"
        workflow_tracker.start_step(step_name, f"Performing security checks on {len(live_hosts)} hosts")
        
        try:
            if self.feature_flags.get('security_checks', True) and live_hosts:
                security_result = self.security_checker.execute(live_hosts, domain_path)
                if security_result.success:
                    results['security_checks'] = security_result.data
                    results['security_checks_stats'] = {
                        'security_issues_found': len(security_result.data.get('security_issues', {})),
                        'hosts_checked': len(live_hosts),
                        'execution_time': security_result.execution_time,
                        'checks_performed': security_result.data.get('checks_performed', 0)
                    }
                    
                    workflow_tracker.end_step(step_name, True, {
                        'security_issues_found': len(security_result.data.get('security_issues', {})),
                        'hosts_checked': len(live_hosts),
                        'checks_performed': security_result.data.get('checks_performed', 0)
                    })
                else:
                    results['security_checks'] = {}
                    workflow_tracker.end_step(step_name, False, errors=security_result.errors)
            else:
                results['security_checks'] = {}
                skip_reason = "No live hosts" if not live_hosts else "Security checks disabled"
                workflow_tracker.end_step(step_name, True, {'skipped': True, 'reason': skip_reason})
                
        except Exception as e:
            workflow_tracker.end_step(step_name, False, errors=[str(e)])
            raise

    def _execute_document_analysis(self, all_urls, domain_path, results, workflow_tracker):
        """Execute document analysis workflow step"""
        step_name = "Document Analysis"
        workflow_tracker.start_step(step_name, f"Analyzing documents from {len(all_urls)} URLs")
        
        try:
            if self.feature_flags.get('document_analysis', True) and all_urls:
                doc_result = self.document_analyzer.execute(all_urls, domain_path)
                if doc_result.success:
                    results['document_analysis'] = doc_result.data
                    results['document_stats'] = {
                        'total_documents': doc_result.data.get('total_documents', 0),
                        'sensitive_documents': doc_result.data.get('sensitive_documents', 0),
                        'total_size_mb': doc_result.data.get('summary', {}).get('total_size_mb', 0),
                        'execution_time': doc_result.execution_time,
                        'high_risk_documents': len(doc_result.data.get('summary', {}).get('high_risk_documents', []))
                    }
                    
                    workflow_tracker.end_step(step_name, True, {
                        'documents_found': doc_result.data.get('total_documents', 0),
                        'sensitive_documents': doc_result.data.get('sensitive_documents', 0),
                        'high_risk_documents': len(doc_result.data.get('summary', {}).get('high_risk_documents', []))
                    })
                    
                    # Log critical findings
                    if doc_result.data.get('sensitive_documents', 0) > 0:
                        self.console.print(f"🚨 [red]Found {doc_result.data['sensitive_documents']} documents with sensitive data![/red]")
                    
                else:
                    results['document_analysis'] = {}
                    workflow_tracker.end_step(step_name, False, errors=doc_result.errors)
            else:
                results['document_analysis'] = {}
                skip_reason = "No URLs available" if not all_urls else "Document analysis disabled"
                workflow_tracker.end_step(step_name, True, {'skipped': True, 'reason': skip_reason})
                
        except Exception as e:
            workflow_tracker.end_step(step_name, False, errors=[str(e)])
            raise

    def _execute_extension_organization(self, all_urls, domain_path, results, workflow_tracker):
        """Execute extension organization workflow step"""
        step_name = "Extension Organization"
        workflow_tracker.start_step(step_name, f"Organizing {len(all_urls)} URLs by extension")
        
        try:
            if self.feature_flags.get('extension_organization', True) and all_urls:
                ext_result = self.extension_organizer.execute(all_urls, domain_path)
                if ext_result.success:
                    results['extension_organization'] = ext_result.data
                    results['extension_stats'] = {
                        'total_extensions': ext_result.data.get('categories_found', 0),
                        'organized_urls': ext_result.data.get('organized_urls', 0),
                        'high_risk_files': ext_result.data.get('summary', {}).get('high_risk_files', 0),
                        'critical_files': ext_result.data.get('summary', {}).get('critical_files', 0),
                        'security_score': ext_result.data.get('summary', {}).get('security_score', {}).get('score', 0),
                        'execution_time': ext_result.execution_time
                    }
                    
                    workflow_tracker.end_step(step_name, True, {
                        'extensions_found': ext_result.data.get('categories_found', 0),
                        'urls_organized': ext_result.data.get('organized_urls', 0),
                        'high_risk_files': ext_result.data.get('summary', {}).get('high_risk_files', 0),
                        'security_score': ext_result.data.get('summary', {}).get('security_score', {}).get('score', 0)
                    })
                    
                    # Log important findings
                    high_risk_files = ext_result.data.get('summary', {}).get('high_risk_files', 0)
                    if high_risk_files > 0:
                        self.console.print(f"⚠️ [yellow]Found {high_risk_files} high-risk files by extension![/yellow]")
                    
                    critical_files = ext_result.data.get('summary', {}).get('critical_files', 0)
                    if critical_files > 0:
                        self.console.print(f"🚨 [red]Found {critical_files} critical files by extension![/red]")
                    
                else:
                    results['extension_organization'] = {}
                    workflow_tracker.end_step(step_name, False, errors=ext_result.errors)
            else:
                results['extension_organization'] = {}
                skip_reason = "No URLs available" if not all_urls else "Extension organization disabled"
                workflow_tracker.end_step(step_name, True, {'skipped': True, 'reason': skip_reason})
                
        except Exception as e:
            workflow_tracker.end_step(step_name, False, errors=[str(e)])
            raise

    def _execute_gf_pattern_analysis(self, all_urls, domain_path, results, workflow_tracker):
        """Execute GF pattern analysis workflow step"""
        step_name = "GF Pattern Analysis"
        workflow_tracker.start_step(step_name, f"Analyzing {len(all_urls)} URLs for vulnerability patterns")
        
        try:
            if self.feature_flags.get('gf_patterns', True) and all_urls:
                gf_result = self.gf_pattern_analyzer.execute(all_urls, domain_path)
                if gf_result.success:
                    results['gf_patterns'] = gf_result.data
                    results['gf_pattern_stats'] = {
                        'patterns_found': gf_result.data.get('patterns_found', 0),
                        'matched_urls': gf_result.data.get('matched_urls', 0),
                        'critical_vulnerabilities': gf_result.data.get('summary', {}).get('critical_vulnerabilities', 0),
                        'high_risk_vulnerabilities': gf_result.data.get('summary', {}).get('high_risk_vulnerabilities', 0),
                        'vulnerability_score': gf_result.data.get('summary', {}).get('vulnerability_score', {}).get('score', 0),
                        'execution_time': gf_result.execution_time
                    }
                    
                    workflow_tracker.end_step(step_name, True, {
                        'patterns_found': gf_result.data.get('patterns_found', 0),
                        'matched_urls': gf_result.data.get('matched_urls', 0),
                        'critical_vulnerabilities': gf_result.data.get('summary', {}).get('critical_vulnerabilities', 0),
                        'vulnerability_score': gf_result.data.get('summary', {}).get('vulnerability_score', {}).get('score', 0)
                    })
                    
                    # Log important findings
                    critical_vulns = gf_result.data.get('summary', {}).get('critical_vulnerabilities', 0)
                    if critical_vulns > 0:
                        self.console.print(f"🚨 [red]Found {critical_vulns} critical vulnerability patterns![/red]")
                    
                    high_risk_vulns = gf_result.data.get('summary', {}).get('high_risk_vulnerabilities', 0)
                    if high_risk_vulns > 0:
                        self.console.print(f"⚠️ [yellow]Found {high_risk_vulns} high-risk vulnerability patterns![/yellow]")
                    
                else:
                    results['gf_patterns'] = {}
                    workflow_tracker.end_step(step_name, False, errors=gf_result.errors)
            else:
                results['gf_patterns'] = {}
                skip_reason = "No URLs available" if not all_urls else "GF pattern analysis disabled"
                workflow_tracker.end_step(step_name, True, {'skipped': True, 'reason': skip_reason})
                
        except Exception as e:
            workflow_tracker.end_step(step_name, False, errors=[str(e)])
            raise

    def _execute_unfurl_analysis(self, all_urls, domain_path, results, workflow_tracker):
        """Execute Unfurl analysis workflow step"""
        step_name = "Unfurl Analysis"
        workflow_tracker.start_step(step_name, f"Extracting URL components from {len(all_urls)} URLs")
        
        try:
            if self.feature_flags.get('unfurl_analysis', True) and all_urls:
                unfurl_result = self.unfurl_analyzer.execute(all_urls, domain_path)
                if unfurl_result.success:
                    results['unfurl_analysis'] = unfurl_result.data
                    results['unfurl_stats'] = {
                        'unique_domains': unfurl_result.data.get('unique_domains', 0),
                        'unique_parameters': unfurl_result.data.get('unique_parameters', 0),
                        'total_components': (
                            unfurl_result.data.get('summary', {}).get('extraction_summary', {}).get('total_domains', 0) +
                            unfurl_result.data.get('summary', {}).get('extraction_summary', {}).get('total_parameters', 0) +
                            unfurl_result.data.get('summary', {}).get('extraction_summary', {}).get('total_paths', 0)
                        ),
                        'sensitive_parameters': unfurl_result.data.get('summary', {}).get('security_summary', {}).get('sensitive_parameters', 0),
                        'execution_time': unfurl_result.execution_time
                    }
                    
                    workflow_tracker.end_step(step_name, True, {
                        'domains_extracted': unfurl_result.data.get('unique_domains', 0),
                        'parameters_extracted': unfurl_result.data.get('unique_parameters', 0),
                        'sensitive_parameters': unfurl_result.data.get('summary', {}).get('security_summary', {}).get('sensitive_parameters', 0)
                    })
                    
                    # Log important findings
                    sensitive_params = unfurl_result.data.get('summary', {}).get('security_summary', {}).get('sensitive_parameters', 0)
                    if sensitive_params > 0:
                        self.console.print(f"🔍 [cyan]Found {sensitive_params} security-sensitive parameters![/cyan]")
                    
                else:
                    results['unfurl_analysis'] = {}
                    workflow_tracker.end_step(step_name, False, errors=unfurl_result.errors)
            else:
                results['unfurl_analysis'] = {}
                skip_reason = "No URLs available" if not all_urls else "Unfurl analysis disabled"
                workflow_tracker.end_step(step_name, True, {'skipped': True, 'reason': skip_reason})
                
        except Exception as e:
            workflow_tracker.end_step(step_name, False, errors=[str(e)])
            raise

    def _execute_social_media_recon(self, domain, domain_path, results, workflow_tracker):
        """Execute social media reconnaissance workflow step"""
        step_name = "Social Media Reconnaissance"
        workflow_tracker.start_step(step_name, f"Performing OSINT on {domain}")
        
        try:
            if self.feature_flags.get('social_media_recon', True):
                social_result = self.social_recon.execute(domain, domain_path)
                if social_result.success:
                    results['social_media'] = social_result.data
                    results['social_media_stats'] = {
                        'platforms_checked': len(social_result.data.get('platforms', {})),
                        'profiles_found': sum(len(profiles) for profiles in social_result.data.get('platforms', {}).values()),
                        'execution_time': social_result.execution_time
                    }
                    
                    workflow_tracker.end_step(step_name, True, {
                        'platforms_checked': len(social_result.data.get('platforms', {})),
                        'profiles_found': sum(len(profiles) for profiles in social_result.data.get('platforms', {}).values())
                    })
                else:
                    results['social_media'] = {}
                    workflow_tracker.end_step(step_name, False, errors=social_result.errors)
            else:
                results['social_media'] = {}
                workflow_tracker.end_step(step_name, True, {'skipped': True, 'reason': 'Social media recon disabled'})
                
        except Exception as e:
            workflow_tracker.end_step(step_name, False, errors=[str(e)])
            raise

    def _generate_comprehensive_summary(self, results, workflow_tracker):
        """Generate comprehensive results summary and aggregation"""
        try:
            # Get workflow summary
            workflow_summary = workflow_tracker.get_workflow_summary()
            
            # Calculate comprehensive statistics
            comprehensive_stats = {
                'scan_overview': {
                    'domain': results.get('domain'),
                    'scan_duration': workflow_summary['total_duration'],
                    'workflow_efficiency': workflow_summary['workflow_efficiency'],
                    'steps_completed': workflow_summary['steps_completed'],
                    'steps_failed': workflow_summary['steps_failed']
                },
                'discovery_summary': {
                    'subdomains_found': len(results.get('subdomains', [])),
                    'live_hosts_found': len(results.get('live_hosts', [])),
                    'urls_collected': len(results.get('urls', [])),
                    'parameterized_urls': len(results.get('parameter_urls', [])),
                    'js_files_found': len(results.get('js_analysis', {}).get('js_files', [])),
                    'directories_found': sum(len(dirs) for dirs in results.get('directories', {}).values()),
                    'technologies_detected': len(results.get('technology', {}).get('technologies', {})),
                    'documents_found': results.get('document_stats', {}).get('total_documents', 0),
                    'sensitive_documents': results.get('document_stats', {}).get('sensitive_documents', 0),
                    'extensions_organized': results.get('extension_stats', {}).get('total_extensions', 0),
                    'organized_urls': results.get('extension_stats', {}).get('organized_urls', 0),
                    'gf_patterns_found': results.get('gf_pattern_stats', {}).get('patterns_found', 0),
                    'vulnerability_patterns': results.get('gf_pattern_stats', {}).get('matched_urls', 0),
                    'unfurl_domains': results.get('unfurl_stats', {}).get('unique_domains', 0),
                    'unfurl_parameters': results.get('unfurl_stats', {}).get('unique_parameters', 0)
                },
                'security_summary': {
                    'vulnerabilities_found': len(results.get('vulnerabilities', {})),
                    'dast_vulnerabilities': len(results.get('dast_vulnerabilities', {})),
                    'security_issues': len(results.get('security_checks', {})),
                    'sensitive_data_found': len(results.get('sensitive_data', {})),
                    'sensitive_documents': results.get('document_stats', {}).get('sensitive_documents', 0),
                    'high_risk_documents': results.get('document_stats', {}).get('high_risk_documents', 0),
                    'high_risk_extensions': results.get('extension_stats', {}).get('high_risk_files', 0),
                    'critical_extensions': results.get('extension_stats', {}).get('critical_files', 0),
                    'critical_vulnerability_patterns': results.get('gf_pattern_stats', {}).get('critical_vulnerabilities', 0),
                    'high_risk_vulnerability_patterns': results.get('gf_pattern_stats', {}).get('high_risk_vulnerabilities', 0),
                    'sensitive_parameters': results.get('unfurl_stats', {}).get('sensitive_parameters', 0),
                    'total_security_findings': (
                        len(results.get('vulnerabilities', {})) +
                        len(results.get('dast_vulnerabilities', {})) +
                        len(results.get('security_checks', {})) +
                        len(results.get('sensitive_data', {})) +
                        results.get('document_stats', {}).get('sensitive_documents', 0) +
                        results.get('extension_stats', {}).get('high_risk_files', 0) +
                        results.get('gf_pattern_stats', {}).get('critical_vulnerabilities', 0) +
                        results.get('gf_pattern_stats', {}).get('high_risk_vulnerabilities', 0)
                    )
                },
                'data_flow_analysis': workflow_summary['data_flow'],
                'performance_metrics': {
                    'total_execution_time': workflow_summary['total_duration'],
                    'average_step_time': workflow_summary['workflow_efficiency']['average_step_time'],
                    'success_rate': workflow_summary['workflow_efficiency']['success_rate'],
                    'items_processed_per_second': self._calculate_processing_rate(results, workflow_summary['total_duration'])
                }
            }
            
            # Add risk assessment
            risk_assessment = self._calculate_risk_assessment(comprehensive_stats['security_summary'])
            comprehensive_stats['risk_assessment'] = risk_assessment
            
            # Store comprehensive summary
            results['comprehensive_summary'] = comprehensive_stats
            results['workflow_summary'] = workflow_summary
            results['workflow_status'] = 'completed'
            
            # Display summary to user
            self._display_scan_summary(comprehensive_stats)
            
            # Save summary to file
            self.save_results_realtime(
                results['domain_path'], 
                'summary', 
                'comprehensive_summary.json', 
                comprehensive_stats
            )
            
            return results
            
        except Exception as e:
            console.print(f"⚠️ [yellow]Failed to generate comprehensive summary: {e}[/yellow]")
            results['summary_error'] = str(e)
            return results

    def _calculate_processing_rate(self, results, total_time):
        """Calculate items processed per second"""
        if total_time <= 0:
            return 0
        
        total_items = (
            len(results.get('subdomains', [])) +
            len(results.get('urls', [])) +
            len(results.get('live_hosts', [])) +
            len(results.get('parameter_urls', []))
        )
        
        return total_items / total_time if total_time > 0 else 0

    def _calculate_risk_assessment(self, security_summary):
        """Calculate overall risk assessment"""
        total_findings = security_summary['total_security_findings']
        
        if total_findings == 0:
            risk_level = "LOW"
            risk_score = 1
        elif total_findings <= 5:
            risk_level = "MEDIUM"
            risk_score = 2
        elif total_findings <= 15:
            risk_level = "HIGH"
            risk_score = 3
        else:
            risk_level = "CRITICAL"
            risk_score = 4
        
        return {
            'risk_level': risk_level,
            'risk_score': risk_score,
            'total_findings': total_findings,
            'recommendations': self._get_risk_recommendations(risk_level, security_summary)
        }

    def _get_risk_recommendations(self, risk_level, security_summary):
        """Get recommendations based on risk level"""
        recommendations = []
        
        if security_summary['vulnerabilities_found'] > 0:
            recommendations.append("Review and patch identified vulnerabilities immediately")
        
        if security_summary['sensitive_data_found'] > 0:
            recommendations.append("Secure or remove exposed sensitive data")
        
        if security_summary['security_issues'] > 0:
            recommendations.append("Address security misconfigurations")
        
        if risk_level in ["HIGH", "CRITICAL"]:
            recommendations.append("Conduct immediate security review and remediation")
            recommendations.append("Consider engaging security professionals for assessment")
        
        if not recommendations:
            recommendations.append("Continue regular security monitoring and assessments")
        
        return recommendations

    def _display_scan_summary(self, comprehensive_stats):
        """Display comprehensive scan summary to user"""
        console.print("\n" + "="*80)
        console.print("📊 [bold cyan]COMPREHENSIVE SCAN SUMMARY[/bold cyan]")
        console.print("="*80)
        
        # Scan Overview
        overview = comprehensive_stats['scan_overview']
        console.print(f"🎯 [bold]Domain:[/bold] {overview['domain']}")
        console.print(f"⏱️ [bold]Duration:[/bold] {overview['scan_duration']:.2f} seconds")
        console.print(f"✅ [bold]Success Rate:[/bold] {overview['workflow_efficiency']['success_rate']:.1%}")
        
        # Discovery Summary
        discovery = comprehensive_stats['discovery_summary']
        console.print(f"\n🔍 [bold cyan]DISCOVERY RESULTS[/bold cyan]")
        console.print(f"   📡 Subdomains: {discovery['subdomains_found']}")
        console.print(f"   🌐 Live Hosts: {discovery['live_hosts_found']}")
        console.print(f"   🔗 URLs: {discovery['urls_collected']}")
        console.print(f"   🎯 Parameterized URLs: {discovery['parameterized_urls']}")
        console.print(f"   📜 JavaScript Files: {discovery['js_files_found']}")
        console.print(f"   📁 Directories: {discovery['directories_found']}")
        console.print(f"   🔧 Technologies: {discovery['technologies_detected']}")
        console.print(f"   📄 Documents: {discovery['documents_found']}")
        console.print(f"   🚨 Sensitive Documents: {discovery['sensitive_documents']}")
        console.print(f"   📋 Extensions Organized: {discovery['extensions_organized']}")
        console.print(f"   🔗 URLs Organized: {discovery['organized_urls']}")
        console.print(f"   🎯 GF Patterns Found: {discovery['gf_patterns_found']}")
        console.print(f"   🔍 Vulnerability Patterns: {discovery['vulnerability_patterns']}")
        console.print(f"   🌐 Unfurl Domains: {discovery['unfurl_domains']}")
        console.print(f"   📊 Unfurl Parameters: {discovery['unfurl_parameters']}")
        
        # Security Summary
        security = comprehensive_stats['security_summary']
        risk = comprehensive_stats['risk_assessment']
        console.print(f"\n🛡️ [bold red]SECURITY ASSESSMENT[/bold red]")
        console.print(f"   🚨 Risk Level: [bold {self._get_risk_color(risk['risk_level'])}]{risk['risk_level']}[/bold {self._get_risk_color(risk['risk_level'])}]")
        console.print(f"   🔍 Vulnerabilities: {security['vulnerabilities_found']}")
        console.print(f"   🎯 DAST Findings: {security['dast_vulnerabilities']}")
        console.print(f"   ⚠️ Security Issues: {security['security_issues']}")
        console.print(f"   📋 Sensitive Data: {security['sensitive_data_found']}")
        console.print(f"   📄 Sensitive Documents: {security['sensitive_documents']}")
        console.print(f"   🚨 High Risk Documents: {security['high_risk_documents']}")
        console.print(f"   📋 High Risk Extensions: {security['high_risk_extensions']}")
        console.print(f"   🔴 Critical Extensions: {security['critical_extensions']}")
        console.print(f"   🚨 Critical Vuln Patterns: {security['critical_vulnerability_patterns']}")
        console.print(f"   ⚠️ High Risk Vuln Patterns: {security['high_risk_vulnerability_patterns']}")
        console.print(f"   🔍 Sensitive Parameters: {security['sensitive_parameters']}")
        console.print(f"   📊 Total Findings: {security['total_security_findings']}")
        
        # Performance Metrics
        performance = comprehensive_stats['performance_metrics']
        console.print(f"\n⚡ [bold green]PERFORMANCE METRICS[/bold green]")
        console.print(f"   🏃 Processing Rate: {performance['items_processed_per_second']:.2f} items/sec")
        console.print(f"   ⏱️ Average Step Time: {performance['average_step_time']:.2f} seconds")
        
        # Recommendations
        if risk['recommendations']:
            console.print(f"\n💡 [bold yellow]RECOMMENDATIONS[/bold yellow]")
            for i, rec in enumerate(risk['recommendations'], 1):
                console.print(f"   {i}. {rec}")
        
        console.print("="*80)

    def _get_risk_color(self, risk_level):
        """Get color for risk level display"""
        colors = {
            'LOW': 'green',
            'MEDIUM': 'yellow', 
            'HIGH': 'red',
            'CRITICAL': 'bright_red'
        }
        return colors.get(risk_level, 'white')

    def _generate_multi_target_summary(self, all_results):
        """Generate comprehensive summary for multiple targets"""
        try:
            multi_summary = {
                'scan_overview': {
                    'total_targets': len(all_results),
                    'successful_scans': len([r for r in all_results if r.get('workflow_status') == 'completed']),
                    'failed_scans': len([r for r in all_results if r.get('error')]),
                    'scan_timestamp': datetime.now().isoformat()
                },
                'aggregated_discovery': {
                    'total_subdomains': sum(len(r.get('subdomains', [])) for r in all_results),
                    'total_live_hosts': sum(len(r.get('live_hosts', [])) for r in all_results),
                    'total_urls': sum(len(r.get('urls', [])) for r in all_results),
                    'total_parameterized_urls': sum(len(r.get('parameter_urls', [])) for r in all_results),
                    'total_js_files': sum(len(r.get('js_analysis', {}).get('js_files', [])) for r in all_results),
                    'total_directories': sum(sum(len(dirs) for dirs in r.get('directories', {}).values()) for r in all_results),
                    'unique_technologies': self._aggregate_unique_technologies(all_results),
                    'total_documents': sum(r.get('document_stats', {}).get('total_documents', 0) for r in all_results),
                    'total_sensitive_documents': sum(r.get('document_stats', {}).get('sensitive_documents', 0) for r in all_results)
                },
                'aggregated_security': {
                    'total_vulnerabilities': sum(len(r.get('vulnerabilities', {})) for r in all_results),
                    'total_dast_vulnerabilities': sum(len(r.get('dast_vulnerabilities', {})) for r in all_results),
                    'total_security_issues': sum(len(r.get('security_checks', {})) for r in all_results),
                    'total_sensitive_data': sum(len(r.get('sensitive_data', {})) for r in all_results),
                    'total_sensitive_documents': sum(r.get('document_stats', {}).get('sensitive_documents', 0) for r in all_results),
                    'total_high_risk_documents': sum(r.get('document_stats', {}).get('high_risk_documents', 0) for r in all_results),
                    'risk_distribution': self._calculate_risk_distribution(all_results),
                    'most_vulnerable_targets': self._identify_most_vulnerable_targets(all_results)
                },
                'performance_analysis': {
                    'total_scan_time': sum(r.get('comprehensive_summary', {}).get('scan_overview', {}).get('scan_duration', 0) for r in all_results),
                    'average_scan_time': sum(r.get('comprehensive_summary', {}).get('scan_overview', {}).get('scan_duration', 0) for r in all_results) / len(all_results) if all_results else 0,
                    'fastest_scan': min((r.get('comprehensive_summary', {}).get('scan_overview', {}).get('scan_duration', float('inf')) for r in all_results), default=0),
                    'slowest_scan': max((r.get('comprehensive_summary', {}).get('scan_overview', {}).get('scan_duration', 0) for r in all_results), default=0),
                    'overall_success_rate': sum(r.get('comprehensive_summary', {}).get('scan_overview', {}).get('workflow_efficiency', {}).get('success_rate', 0) for r in all_results) / len(all_results) if all_results else 0
                },
                'target_details': [
                    {
                        'domain': r.get('domain'),
                        'status': r.get('workflow_status', 'unknown'),
                        'scan_duration': r.get('comprehensive_summary', {}).get('scan_overview', {}).get('scan_duration', 0),
                        'risk_level': r.get('comprehensive_summary', {}).get('risk_assessment', {}).get('risk_level', 'UNKNOWN'),
                        'total_findings': r.get('comprehensive_summary', {}).get('security_summary', {}).get('total_security_findings', 0),
                        'subdomains_found': len(r.get('subdomains', [])),
                        'live_hosts_found': len(r.get('live_hosts', []))
                    }
                    for r in all_results
                ]
            }
            
            # Calculate overall risk assessment
            multi_summary['overall_risk_assessment'] = self._calculate_overall_risk_assessment(multi_summary['aggregated_security'])
            
            return multi_summary
            
        except Exception as e:
            console.print(f"⚠️ [yellow]Failed to generate multi-target summary: {e}[/yellow]")
            return {'error': str(e)}

    def _aggregate_unique_technologies(self, all_results):
        """Aggregate unique technologies across all targets"""
        all_technologies = set()
        for result in all_results:
            tech_data = result.get('technology', {}).get('technologies', {})
            for host, techs in tech_data.items():
                if isinstance(techs, list):
                    all_technologies.update(techs)
                elif isinstance(techs, dict):
                    all_technologies.update(techs.keys())
        return list(all_technologies)

    def _calculate_risk_distribution(self, all_results):
        """Calculate risk level distribution across targets"""
        risk_counts = {'LOW': 0, 'MEDIUM': 0, 'HIGH': 0, 'CRITICAL': 0, 'UNKNOWN': 0}
        
        for result in all_results:
            risk_level = result.get('comprehensive_summary', {}).get('risk_assessment', {}).get('risk_level', 'UNKNOWN')
            risk_counts[risk_level] = risk_counts.get(risk_level, 0) + 1
        
        return risk_counts

    def _identify_most_vulnerable_targets(self, all_results):
        """Identify the most vulnerable targets"""
        target_risks = []
        
        for result in all_results:
            domain = result.get('domain')
            total_findings = result.get('comprehensive_summary', {}).get('security_summary', {}).get('total_security_findings', 0)
            risk_level = result.get('comprehensive_summary', {}).get('risk_assessment', {}).get('risk_level', 'UNKNOWN')
            
            target_risks.append({
                'domain': domain,
                'total_findings': total_findings,
                'risk_level': risk_level
            })
        
        # Sort by total findings (descending) and return top 5
        target_risks.sort(key=lambda x: x['total_findings'], reverse=True)
        return target_risks[:5]

    def _calculate_overall_risk_assessment(self, aggregated_security):
        """Calculate overall risk assessment for all targets"""
        total_findings = (
            aggregated_security['total_vulnerabilities'] +
            aggregated_security['total_dast_vulnerabilities'] +
            aggregated_security['total_security_issues'] +
            aggregated_security['total_sensitive_data']
        )
        
        # Determine overall risk level based on total findings and distribution
        risk_distribution = aggregated_security['risk_distribution']
        
        if risk_distribution.get('CRITICAL', 0) > 0:
            overall_risk = 'CRITICAL'
        elif risk_distribution.get('HIGH', 0) > 0:
            overall_risk = 'HIGH'
        elif risk_distribution.get('MEDIUM', 0) > 0:
            overall_risk = 'MEDIUM'
        else:
            overall_risk = 'LOW'
        
        return {
            'overall_risk_level': overall_risk,
            'total_findings': total_findings,
            'high_risk_targets': risk_distribution.get('HIGH', 0) + risk_distribution.get('CRITICAL', 0),
            'recommendations': self._get_multi_target_recommendations(overall_risk, aggregated_security)
        }

    def _get_multi_target_recommendations(self, overall_risk, aggregated_security):
        """Get recommendations for multi-target assessment"""
        recommendations = []
        
        if aggregated_security['total_vulnerabilities'] > 0:
            recommendations.append(f"Address {aggregated_security['total_vulnerabilities']} vulnerabilities across all targets")
        
        if aggregated_security['total_sensitive_data'] > 0:
            recommendations.append(f"Secure {aggregated_security['total_sensitive_data']} sensitive data exposures")
        
        if aggregated_security['most_vulnerable_targets']:
            top_target = aggregated_security['most_vulnerable_targets'][0]
            recommendations.append(f"Prioritize security review for {top_target['domain']} ({top_target['total_findings']} findings)")
        
        if overall_risk in ['HIGH', 'CRITICAL']:
            recommendations.append("Implement organization-wide security improvements")
            recommendations.append("Consider comprehensive security audit for all targets")
        
        return recommendations

    def _display_multi_target_summary(self, multi_summary):
        """Display multi-target summary to user"""
        console.print("\n" + "="*80)
        console.print("🎯 [bold cyan]MULTI-TARGET SCAN SUMMARY[/bold cyan]")
        console.print("="*80)
        
        # Overview
        overview = multi_summary['scan_overview']
        console.print(f"📊 [bold]Total Targets:[/bold] {overview['total_targets']}")
        console.print(f"✅ [bold]Successful Scans:[/bold] {overview['successful_scans']}")
        console.print(f"❌ [bold]Failed Scans:[/bold] {overview['failed_scans']}")
        
        # Aggregated Discovery
        discovery = multi_summary['aggregated_discovery']
        console.print(f"\n🔍 [bold cyan]AGGREGATED DISCOVERY[/bold cyan]")
        console.print(f"   📡 Total Subdomains: {discovery['total_subdomains']}")
        console.print(f"   🌐 Total Live Hosts: {discovery['total_live_hosts']}")
        console.print(f"   🔗 Total URLs: {discovery['total_urls']}")
        console.print(f"   🎯 Total Parameterized URLs: {discovery['total_parameterized_urls']}")
        console.print(f"   📜 Total JavaScript Files: {discovery['total_js_files']}")
        console.print(f"   📁 Total Directories: {discovery['total_directories']}")
        console.print(f"   🔧 Unique Technologies: {len(discovery['unique_technologies'])}")
        console.print(f"   📄 Total Documents: {discovery['total_documents']}")
        console.print(f"   🚨 Total Sensitive Documents: {discovery['total_sensitive_documents']}")
        
        # Aggregated Security
        security = multi_summary['aggregated_security']
        overall_risk = multi_summary['overall_risk_assessment']
        console.print(f"\n🛡️ [bold red]AGGREGATED SECURITY ASSESSMENT[/bold red]")
        console.print(f"   🚨 Overall Risk: [bold {self._get_risk_color(overall_risk['overall_risk_level'])}]{overall_risk['overall_risk_level']}[/bold {self._get_risk_color(overall_risk['overall_risk_level'])}]")
        console.print(f"   🔍 Total Vulnerabilities: {security['total_vulnerabilities']}")
        console.print(f"   🎯 Total DAST Findings: {security['total_dast_vulnerabilities']}")
        console.print(f"   ⚠️ Total Security Issues: {security['total_security_issues']}")
        console.print(f"   📋 Total Sensitive Data: {security['total_sensitive_data']}")
        console.print(f"   📄 Total Sensitive Documents: {security['total_sensitive_documents']}")
        console.print(f"   🚨 Total High Risk Documents: {security['total_high_risk_documents']}")
        console.print(f"   📊 Total Findings: {overall_risk['total_findings']}")
        
        # Performance Analysis
        performance = multi_summary['performance_analysis']
        console.print(f"\n⚡ [bold green]PERFORMANCE ANALYSIS[/bold green]")
        console.print(f"   ⏱️ Total Scan Time: {performance['total_scan_time']:.2f} seconds")
        console.print(f"   📊 Average Scan Time: {performance['average_scan_time']:.2f} seconds")
        console.print(f"   🏃 Overall Success Rate: {performance['overall_success_rate']:.1%}")
        
        # Most Vulnerable Targets
        if security['most_vulnerable_targets']:
            console.print(f"\n🎯 [bold red]MOST VULNERABLE TARGETS[/bold red]")
            for i, target in enumerate(security['most_vulnerable_targets'][:3], 1):
                console.print(f"   {i}. {target['domain']} - {target['total_findings']} findings ({target['risk_level']})")
        
        # Recommendations
        if overall_risk['recommendations']:
            console.print(f"\n💡 [bold yellow]MULTI-TARGET RECOMMENDATIONS[/bold yellow]")
            for i, rec in enumerate(overall_risk['recommendations'], 1):
                console.print(f"   {i}. {rec}")
        
        console.print("="*80)

    def run_scan(self, targets, is_subdomain_input=False):
        """Run scan on multiple targets"""
        if len(targets) > 1:
            console.print(f"📋 [cyan]Multiple Target Mode - Processing {len(targets)} targets[/cyan]")

        all_results = []

        # Use threading if specified
        if self.threads > 1 and len(targets) > 1:
            console.print(f"🧵 [blue]Using {self.threads} threads for parallel processing[/blue]")

            with ThreadPoolExecutor(max_workers=self.threads) as executor:
                future_to_target = {
                    executor.submit(self.scan_single_target, target, is_subdomain_input): target 
                    for target in targets
                }

                for future in as_completed(future_to_target):
                    target = future_to_target[future]
                    try:
                        result = future.result()
                        if result:
                            all_results.append(result)
                        console.print(f"✅ [green]Completed scan for {target}[/green]")
                    except Exception as exc:
                        console.print(f"❌ [red]Error scanning {target}: {exc}[/red]")
        else:
            # Sequential processing
            for target in targets:
                if self.interrupted:
                    console.print("⏭️ [yellow]Skipping remaining targets due to user interrupt[/yellow]")
                    break

                result = self.scan_single_target(target, is_subdomain_input)
                if result:
                    all_results.append(result)

        return all_results

def parse_arguments():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(
        description="HyperRecon Pro v4.0 - Advanced Modular Bug Bounty Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Examples:
  python hyperrecon.py -d example.com
  python hyperrecon.py -d example.com,test.com -t 20
  python hyperrecon.py -l domains.txt --html-reports
  python hyperrecon.py -s subdomain.example.com -o ./out
  python hyperrecon.py -d example.com --no-nuclei --no-gobuster"""
    )

    # Special flags (not mutually exclusive)
    parser.add_argument('--validate-deps', action='store_true', help='Validate tool dependencies')
    parser.add_argument('--version', action='store_true', help='Show version information')
    
    # Mutually exclusive target group
    target_group = parser.add_mutually_exclusive_group(required=False)
    target_group.add_argument('-d', '--domain', help='Target domain(s) (comma-separated)')
    target_group.add_argument('-l', '--list', help='File containing list of domains')
    target_group.add_argument('-s', '--subdomain', help='Target subdomain(s) - skips subdomain enumeration')

    # Basic options
    parser.add_argument('-o', '--output', help='Output directory (default: hyperrecon_results_TIMESTAMP)')
    parser.add_argument('-t', '--threads', type=int, default=10, help='Number of threads (default: 10)')
    parser.add_argument('-hr', '--html-reports', action='store_true', help='Generate HTML reports')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output')
    parser.add_argument('--debug', action='store_true', help='Enable debug mode')

    # Centralized utility disable flags
    parser.add_argument('--no-nuclei', action='store_true', help='Disable nuclei vulnerability scanning')
    parser.add_argument('--no-unfurl', action='store_true', help='Disable unfurl URL analysis')
    parser.add_argument('--no-gobuster', action='store_true', help='Disable gobuster directory bruteforcing')
    parser.add_argument('--no-paramspider', action='store_true', help='Disable paramspider parameter discovery')
    parser.add_argument('--no-gf', action='store_true', help='Disable gf pattern analysis')
    parser.add_argument('--no-js', action='store_true', help='Disable JavaScript analysis')
    parser.add_argument('--no-tech', action='store_true', help='Disable technology detection')
    parser.add_argument('--no-sensitive', action='store_true', help='Disable sensitive data detection')
    parser.add_argument('--no-security', action='store_true', help='Disable security checks')
    parser.add_argument('--no-dast', action='store_true', help='Disable DAST parameter scanning')
    parser.add_argument('--no-wayback', action='store_true', help='Disable wayback URL collection')
    parser.add_argument('--no-gau', action='store_true', help='Disable gau URL collection')
    parser.add_argument('--no-social', action='store_true', help='Disable social media reconnaissance')
    parser.add_argument('--no-documents', action='store_true', help='Disable document analysis')



    return parser.parse_args()

def main():
    """Main function"""
    try:
        args = parse_arguments()

        # Initialize HyperRecon
        hyperrecon = HyperReconPro()
        
        # Display banner
        hyperrecon.display_banner()
        
        # Handle version
        if args.version:
            console.print(f"HyperRecon Pro v{hyperrecon.version}")
            sys.exit(0)
        
        # Handle dependency validation
        if args.validate_deps:
            validation_results = hyperrecon.validate_dependencies()
            if validation_results['all_required_available']:
                console.print("✅ [green]All required dependencies are available![/green]")
                sys.exit(0)
            else:
                console.print("❌ [red]Some required dependencies are missing![/red]")
                sys.exit(1)
        
        # Validate that target is provided if not using special flags
        if not args.domain and not args.list and not args.subdomain:
            console.print("❌ [red]Error: Please specify either -d/--domain, -l/--list, or -s/--subdomain[/red]")
            sys.exit(1)

        # Set configuration
        hyperrecon.args = args
        hyperrecon.verbose = args.verbose
        hyperrecon.debug = args.debug
        hyperrecon.threads = args.threads

        # Apply centralized disable flags to feature flags
        if args.no_nuclei:
            hyperrecon.feature_flags['nuclei'] = False
            console.print("🚫 [yellow]Nuclei vulnerability scanning disabled[/yellow]")
        
        if args.no_unfurl:
            hyperrecon.feature_flags['unfurl'] = False
            hyperrecon.feature_flags['unfurl_analysis'] = False
            console.print("🚫 [yellow]Unfurl URL analysis disabled[/yellow]")
        
        if args.no_gobuster:
            hyperrecon.feature_flags['gobuster'] = False
            console.print("🚫 [yellow]Gobuster directory bruteforcing disabled[/yellow]")
        
        if args.no_paramspider:
            hyperrecon.feature_flags['paramspider'] = False
            console.print("🚫 [yellow]Paramspider parameter discovery disabled[/yellow]")
        
        if args.no_gf:
            hyperrecon.feature_flags['gf'] = False
            hyperrecon.feature_flags['gf_patterns'] = False
            console.print("🚫 [yellow]GF pattern analysis disabled[/yellow]")
        
        if args.no_js:
            hyperrecon.feature_flags['js_analysis'] = False
            console.print("🚫 [yellow]JavaScript analysis disabled[/yellow]")
        
        if args.no_tech:
            hyperrecon.feature_flags['technology_detection'] = False
            hyperrecon.feature_flags['whatweb'] = False
            console.print("🚫 [yellow]Technology detection disabled[/yellow]")
        
        if args.no_sensitive:
            hyperrecon.feature_flags['sensitive_data'] = False
            console.print("🚫 [yellow]Sensitive data detection disabled[/yellow]")
        
        if args.no_security:
            hyperrecon.feature_flags['security_checks'] = False
            console.print("🚫 [yellow]Security checks disabled[/yellow]")
        
        if args.no_dast:
            hyperrecon.feature_flags['dast_scanning'] = False
            console.print("🚫 [yellow]DAST parameter scanning disabled[/yellow]")
        
        if args.no_wayback:
            hyperrecon.feature_flags['waybackurls'] = False
            console.print("🚫 [yellow]Wayback URL collection disabled[/yellow]")
        
        if args.no_gau:
            hyperrecon.feature_flags['gau'] = False
            console.print("🚫 [yellow]GAU URL collection disabled[/yellow]")
        
        if args.no_social:
            hyperrecon.feature_flags['social_media_recon'] = False
            console.print("🚫 [yellow]Social media reconnaissance disabled[/yellow]")
        
        if args.no_documents:
            hyperrecon.feature_flags['document_analysis'] = False
            console.print("🚫 [yellow]Document analysis disabled[/yellow]")

        # Enable HTML reports if requested
        if args.html_reports:
            hyperrecon.feature_flags['html_reports'] = True

        # Set output directory
        if args.output:
            hyperrecon.output_dir = args.output
        else:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            hyperrecon.output_dir = f"hyperrecon_results_{timestamp}"

        # Validate dependencies
        console.print("\n🔍 [cyan]Validating tool dependencies...[/cyan]")
        validation_results = hyperrecon.validate_dependencies()
        
        if not validation_results['all_required_available']:
            console.print("\n⚠️ [yellow]Some critical dependencies missing. Tool will run with limited functionality.[/yellow]")
            console.print("💡 [blue]Install missing tools for full functionality[/blue]")
        else:
            console.print("✅ [green]All required dependencies available[/green]")

        # Get targets and determine input type
        targets = []
        is_subdomain_input = False

        if args.domain:
            targets = [domain.strip() for domain in args.domain.split(',')]
            is_subdomain_input = False
        elif args.subdomain:
            targets = [subdomain.strip() for subdomain in args.subdomain.split(',')]
            is_subdomain_input = True
            console.print("🔄 [cyan]Subdomain input detected - skipping subdomain enumeration[/cyan]")
        elif args.list:
            if not os.path.exists(args.list):
                console.print(f"❌ [red]Error: File '{args.list}' not found[/red]")
                sys.exit(1)
            
            with open(args.list, 'r') as f:
                targets = [line.strip() for line in f if line.strip() and not line.startswith('#')]
            is_subdomain_input = False

        if not targets:
            console.print("❌ [red]Error: No targets specified[/red]")
            sys.exit(1)

        # Start scan
        console.print(f"🚀 [bold green]Starting HyperRecon Pro v{hyperrecon.version}[/bold green]")
        console.print(f"🎯 [cyan]Targets: {len(targets)}[/cyan]")
        console.print(f"🧵 [blue]Threads: {hyperrecon.threads}[/blue]")

        hyperrecon.start_time = datetime.now()

        try:
            results = hyperrecon.run_scan(targets, is_subdomain_input)

            if results:
                console.print(f"✅ [green]Scan completed successfully for {len(results)} target(s)[/green]")
                
                # Generate HTML report if requested
                if args.html_reports:
                    for result in results:
                        domain = result['domain']
                        domain_path = result.get('domain_path', '')
                        if domain_path:
                            report_path = hyperrecon.report_generator.generate_html_report(result, domain_path)
                            if report_path:
                                console.print(f"📄 [blue]HTML report generated: {report_path}[/blue]")
            else:
                console.print("❌ [red]Scan failed or returned no results[/red]")
                sys.exit(1)
        
        except KeyboardInterrupt:
            console.print("\n🛑 [yellow]Scan interrupted by user[/yellow]")
            sys.exit(0)
        except Exception as e:
            console.print(f"❌ [red]Error during scan: {e}[/red]")
            if args.debug:
                raise
            sys.exit(1)
            
    except Exception as e:
        print(f"❌ Critical error in main function: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    try:
        main()
    except SystemExit:
        # Allow normal exits
        pass
    except Exception as e:
        print(f"❌ Critical error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
