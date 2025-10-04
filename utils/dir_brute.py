"""
Enhanced Directory Bruteforcing module with comprehensive security checks integration
Part of HyperRecon Pro v4.0 - Advanced Modular Bug Bounty Scanner
"""

import os
import tempfile
import requests
from typing import List, Tuple, Dict, Any, Optional
from urllib.parse import urljoin, urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from .base_utility import BaseUtility, UtilityResult
from .security_checks import SecurityChecker


class DirBruteforcer(BaseUtility):
    """Enhanced directory bruteforcing utility with integrated security analysis"""
    
    def __init__(self, hyperrecon_instance):
        """Initialize directory bruteforcer with configuration"""
        super().__init__(hyperrecon_instance)
        
        # Configuration
        self.timeout = getattr(hyperrecon_instance, 'timeout', 600)
        self.threads = getattr(hyperrecon_instance, 'threads', 50)
        self.request_timeout = 15  # Per-request timeout
        
        # Directory wordlists to check (prioritized order)
        self.wordlist_paths = [
            '/usr/share/wordlists/seclists/Discovery/Web-Content/common.txt',
            '/usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt',
            '/usr/share/seclists/Discovery/Web-Content/common.txt',
            '/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt',
            '/usr/share/wordlists/dirb/common.txt',
            '/usr/share/dirb/wordlists/common.txt',
            './common.txt',
            '/opt/wordlists/common.txt'
        ]
        
        # Initialize security checker for integrated analysis
        self.security_checker = SecurityChecker(hyperrecon_instance)
        
        # File manager for consistent output
        self.file_manager = getattr(hyperrecon_instance, 'file_manager', None)
        
        # Results storage
        self.directory_wordlist = None
        self.discovered_directories = {}
        self.security_findings = {}

    def execute(self, targets: List[str], domain_path: str) -> UtilityResult:
        """
        Execute comprehensive directory bruteforcing with security analysis
        
        Args:
            targets: List of live hosts to scan
            domain_path: Path to domain output directory
            
        Returns:
            UtilityResult: Directory bruteforcing results with security analysis
        """
        self.start_execution()
        
        if not targets:
            self.log_warning("No targets provided for directory bruteforcing")
            return self.create_result(True, {'directories': {}, 'security_findings': {}}, 0)
        
        # Validate dependencies
        deps_valid, missing_deps = self.validate_dependencies()
        if not deps_valid:
            self.log_warning(f"Some dependencies missing: {', '.join(missing_deps)}")
            # Continue with available tools
        
        try:
            # Find available wordlist
            wordlist = self._find_wordlist()
            if not wordlist:
                self.log_warning("No wordlist found, performing security checks only")
                # Perform security checks without directory bruteforcing
                return self._security_checks_only(targets, domain_path)
            
            # Reset results
            self.discovered_directories = {}
            self.security_findings = {}
            
            total_processed = 0
            
            # Process each target
            for target in targets:
                target_dirs, target_security = self._process_target(target, domain_path, wordlist)
                
                if target_dirs:
                    self.discovered_directories[target] = target_dirs
                
                if target_security:
                    self.security_findings[target] = target_security
                
                total_processed += 1
            
            # Save comprehensive results
            self._save_comprehensive_results(domain_path, total_processed)
            
            total_dirs = sum(len(dirs) for dirs in self.discovered_directories.values())
            total_security = sum(len(findings) for findings in self.security_findings.values())
            
            self.log_info(f"Found {total_dirs} directories and {total_security} security findings across {total_processed} targets")
            
            return self.create_result(
                success=True,
                data={
                    'directories': self.discovered_directories,
                    'security_findings': self.security_findings,
                    'total_directories': total_dirs,
                    'total_security_findings': total_security
                },
                items_processed=total_processed
            )
            
        except Exception as e:
            self.log_error("Directory bruteforcing failed", e)
            return self.create_result(False, {'error': str(e)}, 0)
    
    def _find_wordlist(self) -> Optional[str]:
        """
        Find available directory wordlist
        
        Returns:
            Path to wordlist or None if not found
        """
        for path in self.wordlist_paths:
            if os.path.exists(path):
                self.directory_wordlist = path
                self.log_info(f"Using wordlist: {path}")
                return path
        
        self.log_warning("No directory wordlist found")
        self.log_info("Install SecLists: git clone https://github.com/danielmiessler/SecLists.git")
        return None

    def _process_target(self, target: str, domain_path: str, wordlist: str) -> Tuple[List[str], List[Dict]]:
        """
        Process a single target with directory bruteforcing and security analysis
        
        Args:
            target: Target host URL
            domain_path: Domain output directory
            wordlist: Path to wordlist file
            
        Returns:
            Tuple of (discovered_directories, security_findings)
        """
        directories = []
        security_findings = []
        
        try:
            self.log_info(f"Processing target: {target}")
            
            # Perform gobuster directory bruteforcing
            if self.check_tool_installed('gobuster'):
                directories = self._run_gobuster_scan(target, wordlist)
                if directories:
                    self._save_target_directories(domain_path, target, directories)
            else:
                self.log_warning("Gobuster not available, skipping directory bruteforcing")
            
            # Perform integrated security analysis on discovered directories
            if directories:
                security_findings = self._analyze_discovered_directories(target, directories)
            
            # Always perform basic security path checks
            basic_security = self._perform_security_checks(target)
            security_findings.extend(basic_security)
            
            if security_findings:
                self._save_target_security_findings(domain_path, target, security_findings)
            
        except Exception as e:
            self.log_error(f"Failed to process target {target}", e)
        
        return directories, security_findings
    
    def _run_gobuster_scan(self, target: str, wordlist: str) -> List[str]:
        """
        Run gobuster directory scan with enhanced result parsing
        
        Args:
            target: Target URL
            wordlist: Path to wordlist
            
        Returns:
            List of discovered directories
        """
        try:
            self.log_info(f"Running gobuster scan for {target}")
            
            cmd = [
                'gobuster', 'dir',
                '-u', target,
                '-w', wordlist,
                '-q',  # quiet mode
                '--no-error',
                '-t', str(min(self.threads, 50)),  # Limit threads for stability
                '--timeout', '10s',
                '-k',  # skip SSL verification
                '--status-codes-blacklist', '404,400,401,403,500,502,503',  # Focus on accessible paths
                '--add-slash'  # Add trailing slash to directories
            ]
            
            result = self.run_command(cmd, timeout=self.timeout, 
                                    description=f"Gobuster directory scan for {target}")
            
            if result:
                directories = self._parse_gobuster_output(result, target)
                if directories:
                    self.log_info(f"Found {len(directories)} directories for {target}")
                    return directories
                else:
                    self.log_info(f"No directories found for {target}")
            else:
                self.log_warning(f"No response from gobuster scan for {target}")
            
        except Exception as e:
            self.log_error(f"Gobuster scan failed for {target}", e)
        
        return []

    def _parse_gobuster_output(self, output: str, target: str) -> List[str]:
        """
        Parse gobuster output with enhanced directory extraction
        
        Args:
            output: Raw gobuster output
            target: Target URL
            
        Returns:
            List of discovered directories with metadata
        """
        directories = []
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        for line in output.split('\n'):
            line = line.strip()
            if not line:
                continue
            
            # Enhanced gobuster output parsing
            if '(Status:' in line:
                # Extract path, status code, and size information
                parts = line.split()
                if len(parts) >= 2:
                    path = parts[0]
                    status_info = ' '.join(parts[1:])
                    
                    # Create enhanced directory entry
                    dir_entry = f"[{timestamp}] {target} -> {path} {status_info}"
                    directories.append(dir_entry)
                    
            elif line.startswith('/'):
                # Simple path format
                dir_entry = f"[{timestamp}] {target} -> {line}"
                directories.append(dir_entry)
        
        return directories

    def _analyze_discovered_directories(self, target: str, directories: List[str]) -> List[Dict]:
        """
        Analyze discovered directories for security implications
        
        Args:
            target: Target URL
            directories: List of discovered directories
            
        Returns:
            List of security findings
        """
        security_findings = []
        
        try:
            # Extract directory paths from gobuster results
            dir_paths = []
            for dir_entry in directories:
                # Extract path from formatted entry
                if ' -> ' in dir_entry and '(Status:' in dir_entry:
                    parts = dir_entry.split(' -> ')[1].split(' (Status:')
                    if parts:
                        dir_paths.append(parts[0])
            
            # Analyze each discovered directory
            for dir_path in dir_paths:
                findings = self._analyze_single_directory(target, dir_path)
                security_findings.extend(findings)
            
        except Exception as e:
            self.log_error(f"Failed to analyze directories for {target}", e)
        
        return security_findings
    
    def _analyze_single_directory(self, target: str, dir_path: str) -> List[Dict]:
        """
        Analyze a single directory for security implications
        
        Args:
            target: Target URL
            dir_path: Directory path to analyze
            
        Returns:
            List of security findings for this directory
        """
        findings = []
        
        try:
            full_url = urljoin(target, dir_path)
            
            # Check for sensitive directory patterns
            sensitive_patterns = {
                'admin': 'Administrative interface detected',
                'backup': 'Backup directory detected',
                'config': 'Configuration directory detected',
                'debug': 'Debug directory detected',
                'test': 'Test directory detected',
                'dev': 'Development directory detected',
                'api': 'API endpoint detected',
                'upload': 'Upload directory detected',
                'temp': 'Temporary directory detected',
                'log': 'Log directory detected'
            }
            
            dir_lower = dir_path.lower()
            for pattern, description in sensitive_patterns.items():
                if pattern in dir_lower:
                    finding = {
                        'url': full_url,
                        'type': 'sensitive_directory',
                        'description': description,
                        'severity': self._assess_directory_severity(pattern),
                        'timestamp': datetime.now().isoformat()
                    }
                    findings.append(finding)
            
            # Check for directory listing
            listing_finding = self._check_directory_listing(full_url)
            if listing_finding:
                findings.append(listing_finding)
            
            # Check for common files in directory
            file_findings = self._check_common_files_in_directory(full_url)
            findings.extend(file_findings)
            
        except Exception as e:
            self.log_warning(f"Failed to analyze directory {dir_path}: {e}")
        
        return findings
    
    def _perform_security_checks(self, target: str) -> List[Dict]:
        """
        Perform basic security checks using the integrated security checker
        
        Args:
            target: Target URL
            
        Returns:
            List of security findings
        """
        try:
            # Use the security checker for comprehensive analysis
            security_result = self.security_checker._check_target_security(target, "")
            if security_result and len(security_result) > 0:
                return security_result[0]  # Return vulnerabilities list
        except Exception as e:
            self.log_warning(f"Security checks failed for {target}: {e}")
        
        return []
    
    def _check_directory_listing(self, url: str) -> Optional[Dict]:
        """Check if directory listing is enabled"""
        try:
            response = requests.get(url, timeout=self.request_timeout, verify=False)
            
            if response.status_code == 200:
                content = response.text.lower()
                if any(indicator in content for indicator in ['index of', 'directory listing', 'parent directory']):
                    return {
                        'url': url,
                        'type': 'directory_listing',
                        'description': 'Directory listing enabled',
                        'severity': 'Medium',
                        'timestamp': datetime.now().isoformat()
                    }
        except Exception:
            pass
        return None
    
    def _check_common_files_in_directory(self, base_url: str) -> List[Dict]:
        """Check for common sensitive files in discovered directory"""
        findings = []
        common_files = [
            'index.php', 'config.php', 'database.php', 'db.php',
            'backup.sql', 'dump.sql', '.env', 'config.json',
            'web.config', '.htaccess', 'robots.txt'
        ]
        
        for filename in common_files:
            try:
                file_url = urljoin(base_url.rstrip('/') + '/', filename)
                response = requests.head(file_url, timeout=5, verify=False)
                
                if response.status_code in [200, 403]:  # File exists
                    findings.append({
                        'url': file_url,
                        'type': 'sensitive_file',
                        'description': f'Sensitive file detected: {filename}',
                        'severity': self._assess_file_severity(filename),
                        'timestamp': datetime.now().isoformat()
                    })
            except Exception:
                continue
        
        return findings
    
    def _assess_directory_severity(self, pattern: str) -> str:
        """Assess severity based on directory pattern"""
        high_risk = ['admin', 'backup', 'config', 'debug']
        medium_risk = ['api', 'upload', 'temp', 'log']
        
        if pattern in high_risk:
            return 'High'
        elif pattern in medium_risk:
            return 'Medium'
        else:
            return 'Low'
    
    def _assess_file_severity(self, filename: str) -> str:
        """Assess severity based on file type"""
        high_risk = ['.env', 'config.php', 'database.php', 'backup.sql', 'dump.sql']
        medium_risk = ['web.config', '.htaccess', 'config.json']
        
        if any(risk in filename.lower() for risk in high_risk):
            return 'High'
        elif any(risk in filename.lower() for risk in medium_risk):
            return 'Medium'
        else:
            return 'Low'
    def _security_checks_only(self, targets: List[str], domain_path: str) -> UtilityResult:
        """
        Perform security checks only when no wordlist is available
        
        Args:
            targets: List of targets to check
            domain_path: Domain output directory
            
        Returns:
            UtilityResult with security findings only
        """
        try:
            security_findings = {}
            total_processed = 0
            
            for target in targets:
                findings = self._perform_security_checks(target)
                if findings:
                    security_findings[target] = findings
                    self._save_target_security_findings(domain_path, target, findings)
                total_processed += 1
            
            total_security = sum(len(findings) for findings in security_findings.values())
            
            self.log_info(f"Completed security checks on {total_processed} targets, found {total_security} findings")
            
            return self.create_result(
                success=True,
                data={
                    'directories': {},
                    'security_findings': security_findings,
                    'total_directories': 0,
                    'total_security_findings': total_security
                },
                items_processed=total_processed
            )
            
        except Exception as e:
            self.log_error("Security checks failed", e)
            return self.create_result(False, {'error': str(e)}, 0)
    
    def _save_target_directories(self, domain_path: str, target: str, directories: List[str]) -> None:
        """Save discovered directories for a target"""
        try:
            safe_target = target.replace('://', '_').replace('/', '_').replace(':', '_')
            filename = f'{safe_target}_directories.txt'
            
            if self.file_manager:
                self.file_manager.save_results_realtime(
                    domain_path, 'directories', filename, directories
                )
            else:
                self.save_results(domain_path, 'directories', filename, directories)
                
        except Exception as e:
            self.log_error(f"Failed to save directories for {target}", e)
    
    def _save_target_security_findings(self, domain_path: str, target: str, findings: List[Dict]) -> None:
        """Save security findings for a target"""
        try:
            safe_target = target.replace('://', '_').replace('/', '_').replace(':', '_')
            filename = f'{safe_target}_security_findings.txt'
            
            # Convert findings to text format
            finding_lines = []
            for finding in findings:
                line = f"{finding['url']} -> {finding['description']} (Severity: {finding['severity']})"
                finding_lines.append(line)
            
            if self.file_manager:
                self.file_manager.save_results_realtime(
                    domain_path, 'security_checks', filename, finding_lines
                )
            else:
                self.save_results(domain_path, 'security_checks', filename, finding_lines)
                
        except Exception as e:
            self.log_error(f"Failed to save security findings for {target}", e)
    
    def _save_comprehensive_results(self, domain_path: str, total_processed: int) -> None:
        """
        Save comprehensive directory bruteforcing and security analysis results
        
        Args:
            domain_path: Domain output directory
            total_processed: Number of targets processed
        """
        try:
            # Save directory summary
            if self.discovered_directories:
                dir_summary = self._create_directory_summary(total_processed)
                
                if self.file_manager:
                    self.file_manager.save_results_realtime(
                        domain_path, 'directories', 'directory_summary.txt', dir_summary
                    )
                else:
                    self.save_results(domain_path, 'directories', 'directory_summary.txt', dir_summary)
            
            # Save security summary
            if self.security_findings:
                security_summary = self._create_security_summary(total_processed)
                
                if self.file_manager:
                    self.file_manager.save_results_realtime(
                        domain_path, 'security_checks', 'directory_security_summary.txt', security_summary
                    )
                else:
                    self.save_results(domain_path, 'security_checks', 'directory_security_summary.txt', security_summary)
            
            # Save combined analysis
            combined_analysis = self._create_combined_analysis()
            
            if self.file_manager:
                self.file_manager.save_results_realtime(
                    domain_path, 'directories', 'combined_directory_analysis.txt', combined_analysis
                )
            else:
                self.save_results(domain_path, 'directories', 'combined_directory_analysis.txt', combined_analysis)
            
        except Exception as e:
            self.log_error("Failed to save comprehensive results", e)
    
    def _create_directory_summary(self, total_processed: int) -> List[str]:
        """Create directory discovery summary"""
        summary_lines = [
            f"# Directory Bruteforcing Summary",
            f"# Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            f"# Tool: HyperRecon Directory Bruteforcer",
            f"",
            f"## Statistics",
            f"Targets processed: {total_processed}",
            f"Targets with directories: {len(self.discovered_directories)}",
            f"Total directories found: {sum(len(dirs) for dirs in self.discovered_directories.values())}",
            f"",
            f"## Directory Discoveries by Target",
        ]
        
        for target, directories in self.discovered_directories.items():
            summary_lines.append(f"")
            summary_lines.append(f"### {target} ({len(directories)} directories)")
            for directory in directories[:10]:  # Limit to first 10 per target
                summary_lines.append(f"  - {directory}")
            if len(directories) > 10:
                summary_lines.append(f"  ... and {len(directories) - 10} more")
        
        return summary_lines
    
    def _create_security_summary(self, total_processed: int) -> List[str]:
        """Create security findings summary"""
        summary_lines = [
            f"# Directory Security Analysis Summary",
            f"# Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            f"# Tool: HyperRecon Directory Security Analyzer",
            f"",
            f"## Statistics",
            f"Targets analyzed: {total_processed}",
            f"Targets with security findings: {len(self.security_findings)}",
            f"Total security findings: {sum(len(findings) for findings in self.security_findings.values())}",
            f"",
            f"## Security Findings by Target",
        ]
        
        for target, findings in self.security_findings.items():
            summary_lines.append(f"")
            summary_lines.append(f"### {target} ({len(findings)} findings)")
            
            # Group by severity
            high_severity = [f for f in findings if f.get('severity') == 'High']
            medium_severity = [f for f in findings if f.get('severity') == 'Medium']
            low_severity = [f for f in findings if f.get('severity') == 'Low']
            
            if high_severity:
                summary_lines.append(f"  High Severity ({len(high_severity)}):")
                for finding in high_severity[:5]:
                    summary_lines.append(f"    - {finding['description']}")
            
            if medium_severity:
                summary_lines.append(f"  Medium Severity ({len(medium_severity)}):")
                for finding in medium_severity[:5]:
                    summary_lines.append(f"    - {finding['description']}")
            
            if low_severity:
                summary_lines.append(f"  Low Severity ({len(low_severity)}):")
                for finding in low_severity[:3]:
                    summary_lines.append(f"    - {finding['description']}")
        
        return summary_lines
    
    def _create_combined_analysis(self) -> List[str]:
        """Create combined directory and security analysis"""
        analysis_lines = [
            f"# Combined Directory and Security Analysis",
            f"# Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            f"# Tool: HyperRecon Enhanced Directory Bruteforcer",
            f"",
            f"## Executive Summary",
            f"Directory discoveries: {sum(len(dirs) for dirs in self.discovered_directories.values())}",
            f"Security findings: {sum(len(findings) for findings in self.security_findings.values())}",
            f"",
            f"## Risk Assessment",
        ]
        
        # Calculate risk levels
        high_risk_count = 0
        medium_risk_count = 0
        low_risk_count = 0
        
        for findings in self.security_findings.values():
            for finding in findings:
                severity = finding.get('severity', 'Low')
                if severity == 'High':
                    high_risk_count += 1
                elif severity == 'Medium':
                    medium_risk_count += 1
                else:
                    low_risk_count += 1
        
        analysis_lines.extend([
            f"High Risk Issues: {high_risk_count}",
            f"Medium Risk Issues: {medium_risk_count}",
            f"Low Risk Issues: {low_risk_count}",
            f"",
            f"## Recommendations",
        ])
        
        if high_risk_count > 0:
            analysis_lines.append("- Immediate attention required for high-risk findings")
        if medium_risk_count > 0:
            analysis_lines.append("- Review and address medium-risk findings")
        if len(self.discovered_directories) > 0:
            analysis_lines.append("- Review discovered directories for sensitive content")
        
        analysis_lines.append("- Implement proper access controls and directory restrictions")
        
        return analysis_lines
    
    def validate_dependencies(self) -> Tuple[bool, List[str]]:
        """
        Validate directory bruteforcing tool dependencies
        
        Returns:
            Tuple[bool, List[str]]: (success, missing_dependencies)
        """
        required_tools = ['gobuster']
        optional_tools = ['dirb', 'dirbuster']
        missing_tools = []
        
        # Check required tools
        for tool in required_tools:
            if not self.check_tool_installed(tool):
                missing_tools.append(tool)
        
        # Check optional tools (don't count as failures)
        for tool in optional_tools:
            if not self.check_tool_installed(tool):
                self.log_info(f"Optional tool {tool} not available")
        
        # We can function with basic security checks even without gobuster
        return True, missing_tools


# Legacy compatibility functions for existing code
def bruteforce_directories(hyperrecon_instance, live_hosts, domain_path):
    """
    Legacy compatibility function for existing code
    
    Args:
        hyperrecon_instance: HyperRecon instance
        live_hosts: List of live hosts
        domain_path: Domain output path
        
    Returns:
        Dict of directory results
    """
    bruteforcer = DirBruteforcer(hyperrecon_instance)
    result = bruteforcer.execute(live_hosts, domain_path)
    
    if result.success:
        return result.data.get('directories', {})
    else:
        return {}


def check_common_paths(hyperrecon_instance, live_hosts, domain_path):
    """
    Legacy compatibility function for security checks
    
    Args:
        hyperrecon_instance: HyperRecon instance
        live_hosts: List of live hosts
        domain_path: Domain output path
        
    Returns:
        Dict of security findings
    """
    bruteforcer = DirBruteforcer(hyperrecon_instance)
    result = bruteforcer.execute(live_hosts, domain_path)
    
    if result.success:
        return result.data.get('security_findings', {})
    else:
        return {}