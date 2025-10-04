"""
Security checks module for comprehensive vulnerability detection and misconfiguration analysis
Part of HyperRecon Pro v4.0 - Advanced Modular Bug Bounty Scanner
"""

import os
import tempfile
import json
import requests
from typing import List, Tuple, Dict, Any, Optional
from urllib.parse import urljoin, urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from .base_utility import BaseUtility, UtilityResult


class SecurityChecker(BaseUtility):
    """Security misconfiguration checking utility for comprehensive vulnerability detection"""
    
    def __init__(self, hyperrecon_instance):
        """Initialize security checker with configuration"""
        super().__init__(hyperrecon_instance)
        
        # Security checking configuration
        self.timeout = getattr(hyperrecon_instance, 'timeout', 300)
        self.threads = getattr(hyperrecon_instance, 'threads', 10)
        self.request_timeout = 15  # Per-request timeout
        
        # Load security patterns from config
        self.config_manager = getattr(hyperrecon_instance, 'config_manager', None)
        self.security_paths = self._load_security_paths()
        
        # Vulnerability categories
        self.vulnerability_categories = {
            'exposed_files': [],
            'admin_panels': [],
            'backup_files': [],
            'config_files': [],
            'debug_endpoints': [],
            'api_endpoints': [],
            'sensitive_paths': [],
            'misconfigurations': []
        }
        
        # Status codes that indicate potential vulnerabilities
        self.vulnerable_status_codes = [200, 201, 202, 204, 301, 302, 307, 308]
        self.interesting_status_codes = [401, 403, 405, 500, 502, 503, 504]
        
        # File manager for consistent output
        self.file_manager = getattr(hyperrecon_instance, 'file_manager', None)
    
    def execute(self, targets: List[str], domain_path: str) -> UtilityResult:
        """
        Execute comprehensive security checks on target hosts
        
        Args:
            targets: List of live hosts to check
            domain_path: Path to domain output directory
            
        Returns:
            UtilityResult: Security check results with vulnerabilities found
        """
        self.start_execution()
        
        if not targets:
            self.log_warning("No targets provided for security checks")
            return self.create_result(True, {'vulnerabilities': {}}, 0)
        
        # Validate dependencies
        deps_valid, missing_deps = self.validate_dependencies()
        if not deps_valid:
            self.log_warning(f"Some dependencies missing: {', '.join(missing_deps)}")
            # Continue with basic checks even if some tools are missing
        
        try:
            # Reset vulnerability categories
            for category in self.vulnerability_categories:
                self.vulnerability_categories[category] = []
            
            # Perform security checks
            total_checks = 0
            vulnerabilities_found = 0
            
            # Check each target
            for target in targets:
                target_vulns, target_checks = self._check_target_security(target, domain_path)
                total_checks += target_checks
                vulnerabilities_found += len(target_vulns)
            
            # Save comprehensive results
            self._save_security_results(domain_path, total_checks, vulnerabilities_found)
            
            self.log_info(f"Completed {total_checks} security checks, found {vulnerabilities_found} potential vulnerabilities")
            
            return self.create_result(
                success=True,
                data={
                    'vulnerabilities': self.vulnerability_categories,
                    'total_checks': total_checks,
                    'vulnerabilities_found': vulnerabilities_found
                },
                items_processed=total_checks
            )
            
        except Exception as e:
            self.log_error("Security checks failed", e)
            return self.create_result(False, {'error': str(e)}, 0)
    
    def _load_security_paths(self) -> List[str]:
        """
        Load security paths from configuration
        
        Returns:
            List of security paths to check
        """
        default_paths = [
            '/admin', '/administrator', '/login', '/wp-admin', '/phpmyadmin',
            '/cpanel', '/webmail', '/ftp', '/backup', '/.env', '/.git',
            '/config', '/database', '/api', '/robots.txt', '/sitemap.xml',
            '/debug', '/test', '/dev', '/admin/debug', '/dashboard',
            '/manage', '/panel', '/portal', '/secret', '/token',
            '/account', '/user', '/passwd', '/pwd', '/callback',
            '/oauth', '/saml', '/sso', '/mail', '/mobile', '/number', '/phone'
        ]
        
        if self.config_manager:
            try:
                patterns = self.config_manager.load_patterns()
                if 'security_paths' in patterns:
                    return patterns['security_paths']
            except Exception as e:
                self.log_warning(f"Failed to load security paths from config: {e}")
        
        return default_paths
    
    def _check_target_security(self, target: str, domain_path: str) -> Tuple[List[Dict], int]:
        """
        Perform comprehensive security checks on a single target
        
        Args:
            target: Target host URL
            domain_path: Domain output directory
            
        Returns:
            Tuple of (vulnerabilities_found, total_checks_performed)
        """
        vulnerabilities = []
        total_checks = 0
        
        try:
            # Parse target URL
            parsed_url = urlparse(target)
            base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
            
            self.log_info(f"Checking security for {base_url}")
            
            # Check security paths
            path_vulns, path_checks = self._check_security_paths(base_url)
            vulnerabilities.extend(path_vulns)
            total_checks += path_checks
            
            # Check for common misconfigurations
            config_vulns, config_checks = self._check_misconfigurations(base_url)
            vulnerabilities.extend(config_vulns)
            total_checks += config_checks
            
            # Check for exposed sensitive files
            file_vulns, file_checks = self._check_exposed_files(base_url)
            vulnerabilities.extend(file_vulns)
            total_checks += file_checks
            
            # Check for directory traversal vulnerabilities
            traversal_vulns, traversal_checks = self._check_directory_traversal(base_url)
            vulnerabilities.extend(traversal_vulns)
            total_checks += traversal_checks
            
            # Save target-specific results
            if vulnerabilities:
                self._save_target_vulnerabilities(domain_path, base_url, vulnerabilities)
            
        except Exception as e:
            self.log_error(f"Failed to check security for {target}", e)
        
        return vulnerabilities, total_checks
    
    def _check_security_paths(self, base_url: str) -> Tuple[List[Dict], int]:
        """
        Check common security-sensitive paths
        
        Args:
            base_url: Base URL to check
            
        Returns:
            Tuple of (vulnerabilities_found, checks_performed)
        """
        vulnerabilities = []
        checks_performed = 0
        
        # Use thread pool for concurrent checking
        with ThreadPoolExecutor(max_workers=min(self.threads, 20)) as executor:
            future_to_path = {}
            
            for path in self.security_paths:
                future = executor.submit(self._check_single_path, base_url, path)
                future_to_path[future] = path
                checks_performed += 1
            
            # Collect results
            for future in as_completed(future_to_path, timeout=self.timeout):
                path = future_to_path[future]
                try:
                    result = future.result()
                    if result:
                        vulnerabilities.append(result)
                        self._categorize_vulnerability(result)
                except Exception as e:
                    self.log_warning(f"Failed to check path {path}: {e}")
        
        return vulnerabilities, checks_performed
    
    def _check_single_path(self, base_url: str, path: str) -> Optional[Dict]:
        """
        Check a single security path
        
        Args:
            base_url: Base URL
            path: Path to check
            
        Returns:
            Vulnerability dict if found, None otherwise
        """
        try:
            url = urljoin(base_url, path)
            
            # Make request with proper headers
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.5',
                'Accept-Encoding': 'gzip, deflate',
                'Connection': 'keep-alive'
            }
            
            response = requests.get(
                url, 
                headers=headers,
                timeout=self.request_timeout,
                allow_redirects=True,
                verify=False  # Allow self-signed certificates
            )
            
            # Check if response indicates vulnerability
            if response.status_code in self.vulnerable_status_codes:
                return self._create_vulnerability_entry(
                    url, response, 'accessible_path', 
                    f"Accessible security-sensitive path: {path}"
                )
            elif response.status_code in self.interesting_status_codes:
                return self._create_vulnerability_entry(
                    url, response, 'interesting_path',
                    f"Interesting response for path: {path} (Status: {response.status_code})"
                )
            
        except requests.exceptions.Timeout:
            pass  # Timeout is expected for some paths
        except requests.exceptions.RequestException:
            pass  # Connection errors are expected
        except Exception as e:
            self.log_warning(f"Error checking path {path}: {e}")
        
        return None
    
    def _check_misconfigurations(self, base_url: str) -> Tuple[List[Dict], int]:
        """
        Check for common security misconfigurations
        
        Args:
            base_url: Base URL to check
            
        Returns:
            Tuple of (vulnerabilities_found, checks_performed)
        """
        vulnerabilities = []
        checks_performed = 0
        
        # Check for server information disclosure
        server_vuln = self._check_server_disclosure(base_url)
        if server_vuln:
            vulnerabilities.append(server_vuln)
            self._categorize_vulnerability(server_vuln)
        checks_performed += 1
        
        # Check for directory listing
        dir_listing_vuln = self._check_directory_listing(base_url)
        if dir_listing_vuln:
            vulnerabilities.append(dir_listing_vuln)
            self._categorize_vulnerability(dir_listing_vuln)
        checks_performed += 1
        
        # Check for HTTP methods
        methods_vuln = self._check_http_methods(base_url)
        if methods_vuln:
            vulnerabilities.append(methods_vuln)
            self._categorize_vulnerability(methods_vuln)
        checks_performed += 1
        
        # Check for security headers
        headers_vuln = self._check_security_headers(base_url)
        if headers_vuln:
            vulnerabilities.append(headers_vuln)
            self._categorize_vulnerability(headers_vuln)
        checks_performed += 1
        
        return vulnerabilities, checks_performed
    
    def _check_exposed_files(self, base_url: str) -> Tuple[List[Dict], int]:
        """
        Check for exposed sensitive files
        
        Args:
            base_url: Base URL to check
            
        Returns:
            Tuple of (vulnerabilities_found, checks_performed)
        """
        vulnerabilities = []
        checks_performed = 0
        
        # Common sensitive files
        sensitive_files = [
            '/.env', '/.env.local', '/.env.production', '/.env.backup',
            '/config.php', '/config.json', '/config.xml', '/web.config',
            '/database.yml', '/database.json', '/db.json',
            '/backup.sql', '/dump.sql', '/database.sql',
            '/.git/config', '/.git/HEAD', '/.gitignore',
            '/.svn/entries', '/.hg/hgrc',
            '/composer.json', '/package.json', '/yarn.lock',
            '/.htaccess', '/.htpasswd', '/wp-config.php',
            '/phpinfo.php', '/info.php', '/test.php',
            '/robots.txt', '/sitemap.xml', '/crossdomain.xml',
            '/clientaccesspolicy.xml', '/humans.txt'
        ]
        
        with ThreadPoolExecutor(max_workers=min(self.threads, 15)) as executor:
            future_to_file = {}
            
            for file_path in sensitive_files:
                future = executor.submit(self._check_single_path, base_url, file_path)
                future_to_file[future] = file_path
                checks_performed += 1
            
            # Collect results
            for future in as_completed(future_to_file, timeout=self.timeout):
                file_path = future_to_file[future]
                try:
                    result = future.result()
                    if result:
                        vulnerabilities.append(result)
                        self._categorize_vulnerability(result)
                except Exception as e:
                    self.log_warning(f"Failed to check file {file_path}: {e}")
        
        return vulnerabilities, checks_performed
    
    def _check_directory_traversal(self, base_url: str) -> Tuple[List[Dict], int]:
        """
        Check for directory traversal vulnerabilities
        
        Args:
            base_url: Base URL to check
            
        Returns:
            Tuple of (vulnerabilities_found, checks_performed)
        """
        vulnerabilities = []
        checks_performed = 0
        
        # Directory traversal payloads
        traversal_payloads = [
            '../../../etc/passwd',
            '..\\..\\..\\windows\\system32\\drivers\\etc\\hosts',
            '....//....//....//etc/passwd',
            '%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd',
            '..%252f..%252f..%252fetc%252fpasswd'
        ]
        
        # Common parameters that might be vulnerable
        test_params = ['file', 'path', 'page', 'include', 'doc', 'template']
        
        for param in test_params:
            for payload in traversal_payloads:
                try:
                    test_url = f"{base_url}/?{param}={payload}"
                    
                    response = requests.get(
                        test_url,
                        timeout=self.request_timeout,
                        verify=False
                    )
                    
                    # Check for signs of successful traversal
                    if response.status_code == 200:
                        content = response.text.lower()
                        if any(indicator in content for indicator in ['root:', 'bin/bash', 'localhost', '127.0.0.1']):
                            vuln = self._create_vulnerability_entry(
                                test_url, response, 'directory_traversal',
                                f"Potential directory traversal via {param} parameter"
                            )
                            vulnerabilities.append(vuln)
                            self._categorize_vulnerability(vuln)
                    
                    checks_performed += 1
                    
                except Exception:
                    pass  # Continue with other tests
        
        return vulnerabilities, checks_performed
    
    def _check_server_disclosure(self, base_url: str) -> Optional[Dict]:
        """Check for server information disclosure"""
        try:
            response = requests.head(base_url, timeout=self.request_timeout, verify=False)
            
            # Check for verbose server headers
            server_header = response.headers.get('Server', '')
            if server_header and any(info in server_header.lower() for info in ['apache/', 'nginx/', 'iis/', 'version']):
                return self._create_vulnerability_entry(
                    base_url, response, 'information_disclosure',
                    f"Server information disclosed: {server_header}"
                )
        except Exception:
            pass
        return None
    
    def _check_directory_listing(self, base_url: str) -> Optional[Dict]:
        """Check for directory listing enabled"""
        try:
            response = requests.get(base_url, timeout=self.request_timeout, verify=False)
            
            if response.status_code == 200:
                content = response.text.lower()
                if any(indicator in content for indicator in ['index of', 'directory listing', 'parent directory']):
                    return self._create_vulnerability_entry(
                        base_url, response, 'directory_listing',
                        "Directory listing enabled"
                    )
        except Exception:
            pass
        return None
    
    def _check_http_methods(self, base_url: str) -> Optional[Dict]:
        """Check for dangerous HTTP methods"""
        try:
            response = requests.options(base_url, timeout=self.request_timeout, verify=False)
            
            allowed_methods = response.headers.get('Allow', '').upper()
            dangerous_methods = ['PUT', 'DELETE', 'TRACE', 'CONNECT']
            
            found_dangerous = [method for method in dangerous_methods if method in allowed_methods]
            if found_dangerous:
                return self._create_vulnerability_entry(
                    base_url, response, 'dangerous_methods',
                    f"Dangerous HTTP methods allowed: {', '.join(found_dangerous)}"
                )
        except Exception:
            pass
        return None
    
    def _check_security_headers(self, base_url: str) -> Optional[Dict]:
        """Check for missing security headers"""
        try:
            response = requests.get(base_url, timeout=self.request_timeout, verify=False)
            
            security_headers = [
                'X-Frame-Options', 'X-XSS-Protection', 'X-Content-Type-Options',
                'Strict-Transport-Security', 'Content-Security-Policy'
            ]
            
            missing_headers = [header for header in security_headers if header not in response.headers]
            
            if len(missing_headers) >= 3:  # If most security headers are missing
                return self._create_vulnerability_entry(
                    base_url, response, 'missing_security_headers',
                    f"Missing security headers: {', '.join(missing_headers)}"
                )
        except Exception:
            pass
        return None
    
    def _create_vulnerability_entry(self, url: str, response: requests.Response, 
                                  vuln_type: str, description: str) -> Dict:
        """
        Create a standardized vulnerability entry
        
        Args:
            url: Vulnerable URL
            response: HTTP response
            vuln_type: Type of vulnerability
            description: Vulnerability description
            
        Returns:
            Dict containing vulnerability information
        """
        return {
            'url': url,
            'type': vuln_type,
            'description': description,
            'status_code': response.status_code,
            'response_size': len(response.content) if response.content else 0,
            'headers': dict(response.headers),
            'timestamp': self.start_time,
            'severity': self._assess_severity(vuln_type, response.status_code)
        }
    
    def _assess_severity(self, vuln_type: str, status_code: int) -> str:
        """Assess vulnerability severity"""
        high_severity = ['directory_traversal', 'exposed_files']
        medium_severity = ['accessible_path', 'dangerous_methods', 'directory_listing']
        
        if vuln_type in high_severity:
            return 'High'
        elif vuln_type in medium_severity:
            return 'Medium'
        elif status_code in self.vulnerable_status_codes:
            return 'Medium'
        else:
            return 'Low'
    
    def _categorize_vulnerability(self, vulnerability: Dict) -> None:
        """Categorize vulnerability into appropriate category"""
        vuln_type = vulnerability.get('type', '')
        url = vulnerability.get('url', '')
        
        if 'admin' in url.lower() or 'login' in url.lower():
            self.vulnerability_categories['admin_panels'].append(vulnerability)
        elif 'backup' in url.lower() or vuln_type == 'backup_files':
            self.vulnerability_categories['backup_files'].append(vulnerability)
        elif 'config' in url.lower() or '.env' in url.lower():
            self.vulnerability_categories['config_files'].append(vulnerability)
        elif 'debug' in url.lower() or 'test' in url.lower():
            self.vulnerability_categories['debug_endpoints'].append(vulnerability)
        elif 'api' in url.lower():
            self.vulnerability_categories['api_endpoints'].append(vulnerability)
        elif vuln_type in ['directory_traversal', 'dangerous_methods', 'directory_listing']:
            self.vulnerability_categories['misconfigurations'].append(vulnerability)
        elif vuln_type == 'exposed_files':
            self.vulnerability_categories['exposed_files'].append(vulnerability)
        else:
            self.vulnerability_categories['sensitive_paths'].append(vulnerability)
    
    def _save_security_results(self, domain_path: str, total_checks: int, vulnerabilities_found: int) -> None:
        """
        Save comprehensive security check results
        
        Args:
            domain_path: Domain output directory
            total_checks: Total number of checks performed
            vulnerabilities_found: Number of vulnerabilities found
        """
        try:
            # Save categorized vulnerabilities
            for category, vulns in self.vulnerability_categories.items():
                if vulns:
                    # Save as text file
                    vuln_lines = []
                    for vuln in vulns:
                        vuln_lines.append(f"{vuln['url']} -> {vuln['description']} (Status: {vuln['status_code']}, Severity: {vuln['severity']})")
                    
                    if self.file_manager:
                        self.file_manager.save_results_realtime(
                            domain_path, 'security_checks', f'{category}.txt', vuln_lines
                        )
                    else:
                        self.save_results(domain_path, 'security_checks', f'{category}.txt', vuln_lines)
            
            # Save comprehensive summary
            summary_lines = self._create_security_summary(total_checks, vulnerabilities_found)
            
            if self.file_manager:
                self.file_manager.save_results_realtime(
                    domain_path, 'security_checks', 'security_summary.txt', summary_lines
                )
                
                # Save JSON results for programmatic access
                json_data = {
                    'total_checks': total_checks,
                    'vulnerabilities_found': vulnerabilities_found,
                    'categories': self.vulnerability_categories,
                    'timestamp': self.start_time
                }
                self.file_manager.save_json_results(
                    domain_path, 'security_checks', 'security_results.json', json_data
                )
            else:
                self.save_results(domain_path, 'security_checks', 'security_summary.txt', summary_lines)
            
        except Exception as e:
            self.log_error("Failed to save security check results", e)
    
    def _save_target_vulnerabilities(self, domain_path: str, target: str, vulnerabilities: List[Dict]) -> None:
        """Save vulnerabilities for a specific target"""
        try:
            # Create safe filename from target URL
            safe_target = target.replace('://', '_').replace('/', '_').replace(':', '_')
            filename = f'vulnerabilities_{safe_target}.txt'
            
            vuln_lines = []
            for vuln in vulnerabilities:
                vuln_lines.append(f"{vuln['url']} -> {vuln['description']} (Status: {vuln['status_code']}, Severity: {vuln['severity']})")
            
            if self.file_manager:
                self.file_manager.save_results_realtime(
                    domain_path, 'security_checks', filename, vuln_lines
                )
            else:
                self.save_results(domain_path, 'security_checks', filename, vuln_lines)
                
        except Exception as e:
            self.log_error(f"Failed to save vulnerabilities for {target}", e)
    
    def _create_security_summary(self, total_checks: int, vulnerabilities_found: int) -> List[str]:
        """Create security check summary"""
        from datetime import datetime
        
        summary_lines = [
            f"# Security Checks Summary",
            f"# Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            f"# Tool: HyperRecon Security Checker",
            f"",
            f"## Statistics",
            f"Total security checks performed: {total_checks}",
            f"Potential vulnerabilities found: {vulnerabilities_found}",
            f"",
            f"## Vulnerability Categories",
        ]
        
        for category, vulns in self.vulnerability_categories.items():
            if vulns:
                summary_lines.append(f"")
                summary_lines.append(f"### {category.replace('_', ' ').title()} ({len(vulns)} found)")
                for vuln in vulns[:10]:  # Limit to first 10 per category in summary
                    summary_lines.append(f"  - {vuln['url']} ({vuln['severity']})")
                if len(vulns) > 10:
                    summary_lines.append(f"  ... and {len(vulns) - 10} more")
        
        if vulnerabilities_found == 0:
            summary_lines.append("No significant vulnerabilities found")
        
        return summary_lines
    
    def validate_dependencies(self) -> Tuple[bool, List[str]]:
        """
        Validate security checking tool dependencies
        
        Returns:
            Tuple[bool, List[str]]: (success, missing_dependencies)
        """
        # Security checks primarily use Python requests library
        # which should be available. Optional tools can enhance functionality
        optional_tools = ['curl', 'nmap']
        missing_tools = []
        
        for tool in optional_tools:
            if not self.check_tool_installed(tool):
                missing_tools.append(tool)
        
        # We can function without optional tools
        return True, missing_tools