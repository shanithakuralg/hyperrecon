"""
utils/vuln_scan.py - Enhanced Nuclei Integration with DAST Parameter Scanning
Part of HyperRecon Pro v4.0 - Advanced Modular Bug Bounty Scanner
"""

import os
import subprocess
import tempfile
import json
import re
from datetime import datetime
from .base_utility import BaseUtility

class VulnScanner(BaseUtility):
    def __init__(self, hyperrecon_instance):
        super().__init__(hyperrecon_instance)
        self.nuclei_concurrency = 25
        self.nuclei_retries = 2
        self.nuclei_rate_limit = 150
        self.nuclei_templates = ""

        # Template paths to check
        self.template_paths = [
            '/root/nuclei-templates',
            '/home/nuclei-templates', 
            './nuclei-templates',
            '/usr/share/nuclei-templates',
            os.path.expanduser('~/nuclei-templates'),
            '/opt/nuclei-templates'
        ]

        # Vulnerability categories for enhanced reporting
        self.vulnerability_categories = {
            'critical': ['rce', 'sqli', 'auth-bypass', 'code-injection'],
            'high': ['xss', 'lfi', 'rfi', 'ssrf', 'xxe', 'deserialization'],
            'medium': ['disclosure', 'exposure', 'misconfiguration', 'redirect'],
            'low': ['info-disclosure', 'fingerprint', 'version-detection'],
            'info': ['tech-detection', 'service-detection', 'banner-grab']
        }

    def validate_dependencies(self):
        """Validate nuclei installation and templates"""
        missing_deps = []
        
        if not self.hyperrecon.check_tool_installed('nuclei'):
            missing_deps.append('nuclei')
        
        return len(missing_deps) == 0, missing_deps

    def check_nuclei_installation(self):
        """Check if Nuclei is installed and find templates"""
        if not self.hyperrecon.check_tool_installed('nuclei'):
            try:
                self.hyperrecon.console.print("⚠️ [yellow]Nuclei not installed, skipping vulnerability scan[/yellow]")
            except:
                print("Nuclei not installed, skipping vulnerability scan")
            return False, None

        # Find nuclei templates
        nuclei_templates_path = None
        for path in self.template_paths:
            if os.path.exists(path):
                nuclei_templates_path = path
                break

        return True, nuclei_templates_path

    def categorize_vulnerability(self, vuln_output):
        """Categorize vulnerability based on output and return severity"""
        vuln_lower = vuln_output.lower()
        
        for severity, keywords in self.vulnerability_categories.items():
            for keyword in keywords:
                if keyword in vuln_lower:
                    return severity
        
        # Default categorization based on common patterns
        if any(word in vuln_lower for word in ['critical', 'rce', 'remote code execution']):
            return 'critical'
        elif any(word in vuln_lower for word in ['high', 'sql injection', 'xss']):
            return 'high'
        elif any(word in vuln_lower for word in ['medium', 'lfi', 'ssrf']):
            return 'medium'
        elif any(word in vuln_lower for word in ['low', 'info']):
            return 'low'
        else:
            return 'info'

    def parse_nuclei_output(self, output):
        """Parse nuclei output and extract structured vulnerability information"""
        vulnerabilities = []
        
        for line in output.split('\n'):
            if line.strip():
                # Extract template ID, severity, and description
                vuln_info = {
                    'raw_output': line.strip(),
                    'severity': self.categorize_vulnerability(line),
                    'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                }
                
                # Try to extract template ID
                template_match = re.search(r'\[(.*?)\]', line)
                if template_match:
                    vuln_info['template_id'] = template_match.group(1)
                
                vulnerabilities.append(vuln_info)
        
        return vulnerabilities

    def execute(self, targets, domain_path, scan_type='both'):
        """
        Main execution method for vulnerability scanning
        
        Args:
            targets: List of targets (hosts or URLs)
            domain_path: Path to save results
            scan_type: 'hosts', 'parameters', or 'both'
        """
        if not targets:
            return {'success': False, 'error': 'No targets provided'}

        nuclei_installed, templates_path = self.check_nuclei_installation()
        if not nuclei_installed:
            return {'success': False, 'error': 'Nuclei not installed'}

        results = {
            'success': True,
            'vulnerability_summary': {},
            'detailed_results': {}
        }

        try:
            self.hyperrecon.console.print(f"🛡️ [cyan]Nuclei vulnerability scan on {len(targets)} targets[/cyan]")
        except:
            print(f"Nuclei vulnerability scan on {len(targets)} targets")

        # Determine what to scan based on scan_type and target format
        if scan_type in ['hosts', 'both']:
            # Filter for host-like targets (URLs without parameters)
            host_targets = [t for t in targets if '=' not in t]
            if host_targets:
                subdomain_results = self.scan_subdomains(host_targets, domain_path, templates_path)
                results['detailed_results']['subdomain_vulnerabilities'] = subdomain_results

        if scan_type in ['parameters', 'both']:
            # Filter for parameterized URLs
            param_targets = [t for t in targets if '=' in t]
            if param_targets:
                parameter_results = self.scan_parameters_dast(param_targets, domain_path)
                results['detailed_results']['parameter_vulnerabilities'] = parameter_results

        # Generate comprehensive summary
        results['vulnerability_summary'] = self.generate_vulnerability_summary(results['detailed_results'], domain_path)

        return results

    def scan_vulnerabilities(self, targets, domain_path):
        """Legacy method for backward compatibility"""
        return self.execute(targets, domain_path, 'hosts')

    def scan_subdomains(self, live_hosts, domain_path, templates_path):
        """Scan live hosts for vulnerabilities with enhanced categorization"""
        subdomain_results = {}
        vulnerability_stats = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}

        for host in live_hosts:
            try:
                try:
                    self.hyperrecon.console.print(f"🔧 [blue]Nuclei scan for {host}[/blue]")
                except:
                    print(f"Nuclei scan for {host}")

                # Build nuclei command with tags for domain/subdomain scanning
                cmd = [
                    'nuclei', '-u', host,
                    '-c', str(self.nuclei_concurrency),
                    '-retries', str(self.nuclei_retries), 
                    '-rl', str(self.nuclei_rate_limit),
                    '-silent', '-nc', '-json',
                    '-tags', 'cve,vulnerability,exposure,misconfig,default-login,tech,dns'
                ]

                # Add additional comprehensive tags for domain-level scanning
                if templates_path:
                    # Use specific template directories for better coverage
                    template_dirs = [
                        f'{templates_path}/cves/',
                        f'{templates_path}/vulnerabilities/',
                        f'{templates_path}/exposures/',
                        f'{templates_path}/misconfiguration/',
                        f'{templates_path}/default-logins/',
                        f'{templates_path}/technologies/'
                    ]
                    for template_dir in template_dirs:
                        if os.path.exists(template_dir):
                            cmd.extend(['-t', template_dir])

                result = self.hyperrecon.run_command(cmd, timeout=300, 
                                                   description=f"Nuclei scan for {host}")

                if result and result.strip():
                    # Parse JSON output for better categorization
                    vulnerabilities = []
                    enhanced_vulns = []
                    
                    for line in result.split('\n'):
                        if line.strip():
                            try:
                                # Try to parse as JSON first
                                vuln_data = json.loads(line)
                                severity = vuln_data.get('info', {}).get('severity', 'info').lower()
                                template_id = vuln_data.get('template-id', 'unknown')
                                matched_at = vuln_data.get('matched-at', host)
                                
                                vuln_info = {
                                    'severity': severity,
                                    'template_id': template_id,
                                    'matched_at': matched_at,
                                    'raw_data': vuln_data
                                }
                                vulnerabilities.append(vuln_info)
                                vulnerability_stats[severity] = vulnerability_stats.get(severity, 0) + 1
                                
                                # Create enhanced format for file output
                                enhanced_vulns.append(
                                    f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] "
                                    f"[{severity.upper()}] {host} -> {template_id} -> {matched_at}"
                                )
                                
                            except json.JSONDecodeError:
                                # Fallback to text parsing
                                vuln_info = self.parse_nuclei_output(line)
                                if vuln_info:
                                    vulnerabilities.extend(vuln_info)
                                    enhanced_vulns.append(
                                        f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {host} -> {line.strip()}"
                                    )

                    if vulnerabilities:
                        subdomain_results[host] = vulnerabilities
                        
                        # Save categorized results
                        filename = f"{host.replace('://', '___').replace('/', '_')}_vulns.txt"
                        self.hyperrecon.save_results_realtime(domain_path, 'vulnerabilities', 
                                                            filename, enhanced_vulns)
                        
                        # Save detailed JSON results
                        json_filename = f"{host.replace('://', '___').replace('/', '_')}_vulns.json"
                        self.hyperrecon.save_results_realtime(domain_path, 'vulnerabilities',
                                                            json_filename, [json.dumps(vulnerabilities, indent=2)])
                    else:
                        # Save empty result indicator when result exists but no vulnerabilities parsed
                        filename = f"{host.replace('://', '___').replace('/', '_')}_no_vulns.txt"
                        self.hyperrecon.save_results_realtime(domain_path, 'vulnerabilities',
                                                            filename, [f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] No vulnerabilities found for {host}"])
                else:
                    # Save empty result indicator when no result from nuclei
                    filename = f"{host.replace('://', '___').replace('/', '_')}_no_vulns.txt"
                    self.hyperrecon.save_results_realtime(domain_path, 'vulnerabilities',
                                                        filename, [f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] No vulnerabilities found for {host}"])

            except Exception as e:
                try:
                    self.hyperrecon.console.print(f"⚠️ [yellow]Nuclei scan error for {host}: {e}[/yellow]")
                except:
                    print(f"Nuclei scan error for {host}: {e}")
                continue

        # Enhanced reporting
        total_vulns = sum(len(vulns) for vulns in subdomain_results.values())
        if total_vulns > 0:
            try:
                self.hyperrecon.console.print(f"✅ [green]Found {total_vulns} vulnerabilities across subdomains[/green]")
                self.hyperrecon.console.print(f"📊 [blue]Severity breakdown: Critical: {vulnerability_stats.get('critical', 0)}, High: {vulnerability_stats.get('high', 0)}, Medium: {vulnerability_stats.get('medium', 0)}, Low: {vulnerability_stats.get('low', 0)}, Info: {vulnerability_stats.get('info', 0)}[/blue]")
            except:
                print(f"Found {total_vulns} vulnerabilities across subdomains")
                print(f"Severity breakdown: Critical: {vulnerability_stats.get('critical', 0)}, High: {vulnerability_stats.get('high', 0)}, Medium: {vulnerability_stats.get('medium', 0)}, Low: {vulnerability_stats.get('low', 0)}, Info: {vulnerability_stats.get('info', 0)}")
        else:
            # Save indicator that no vulnerabilities were found
            self.hyperrecon.save_results_realtime(domain_path, 'vulnerabilities',
                                                'no_subdomain_vulnerabilities_found.txt', 
                                                [f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] No subdomain vulnerabilities found"])
            try:
                self.hyperrecon.console.print(f"✅ [green]No vulnerabilities found in subdomain scan[/green]")
            except:
                print("No vulnerabilities found in subdomain scan")

        return subdomain_results

    def scan_parameters_dast(self, param_urls, domain_path):
        """Enhanced DAST scan on parameterized URLs with comprehensive categorization"""
        if not param_urls:
            return {}

        try:
            self.hyperrecon.console.print(f"🎯 [cyan]DAST parameter scan on {len(param_urls)} URLs[/cyan]")
        except:
            print(f"DAST parameter scan on {len(param_urls)} URLs")

        nuclei_installed, templates_path = self.check_nuclei_installation()
        if not nuclei_installed:
            return {}

        parameter_results = {}
        vulnerability_stats = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}

        for param_url in param_urls:
            try:
                # Only scan URLs with parameters
                if '=' not in param_url:
                    continue

                try:
                    self.hyperrecon.console.print(f"🎯 [blue]DAST scan for {param_url[:80]}...[/blue]")
                except:
                    print(f"DAST scan for {param_url[:80]}...")

                # Build DAST nuclei command with original parameter values consideration
                cmd = [
                    'nuclei', '-u', param_url,
                    '-c', str(self.nuclei_concurrency),
                    '-retries', str(self.nuclei_retries), 
                    '-rl', str(self.nuclei_rate_limit),
                    '-silent', '-nc', '-json',
                    '-tags', 'sqli,xss,injection,rce,lfi,ssrf,xxe,ssti,dast'
                ]

                # Add DAST-specific templates that work with original parameter values
                if templates_path:
                    dast_paths = [
                        f'{templates_path}/vulnerabilities/',
                        f'{templates_path}/cves/',
                        f'{templates_path}/fuzzing/',
                        f'{templates_path}/injection/'
                    ]
                    for path in dast_paths:
                        if os.path.exists(path):
                            cmd.extend(['-t', path])
                
                # Add parameter-specific options to preserve original values
                cmd.extend(['-var', 'preserve_original=true'])

                result = self.hyperrecon.run_command(cmd, timeout=600, 
                                                   description=f"DAST scan for parameter URL")

                if result:
                    # Parse JSON output for better categorization
                    vulnerabilities = []
                    enhanced_vulns = []
                    
                    for line in result.split('\n'):
                        if line.strip():
                            try:
                                # Try to parse as JSON first
                                vuln_data = json.loads(line)
                                severity = vuln_data.get('info', {}).get('severity', 'info').lower()
                                template_id = vuln_data.get('template-id', 'unknown')
                                matched_at = vuln_data.get('matched-at', param_url)
                                
                                vuln_info = {
                                    'severity': severity,
                                    'template_id': template_id,
                                    'matched_at': matched_at,
                                    'parameter_url': param_url,
                                    'raw_data': vuln_data
                                }
                                vulnerabilities.append(vuln_info)
                                vulnerability_stats[severity] = vulnerability_stats.get(severity, 0) + 1
                                
                                # Create enhanced format for file output
                                enhanced_vulns.append(
                                    f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] "
                                    f"[{severity.upper()}] {param_url} -> {template_id} -> {matched_at}"
                                )
                                
                            except json.JSONDecodeError:
                                # Fallback to text parsing
                                enhanced_vulns.append(
                                    f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {param_url} -> {line.strip()}"
                                )

                    if vulnerabilities or enhanced_vulns:
                        parameter_results[param_url] = vulnerabilities if vulnerabilities else enhanced_vulns

                        # Save with safe filename
                        safe_url = param_url.replace('://', '___').replace('/', '_').replace('?', '_').replace('&', '_').replace('=', '_')[:100]
                        filename = f"dast_{safe_url}_vulns.txt"
                        self.hyperrecon.save_results_realtime(domain_path, 'vulnerabilities', 
                                                            filename, enhanced_vulns)

                        # Save detailed JSON results if available
                        if vulnerabilities:
                            json_filename = f"dast_{safe_url}_vulns.json"
                            self.hyperrecon.save_results_realtime(domain_path, 'vulnerabilities',
                                                                json_filename, [json.dumps(vulnerabilities, indent=2)])

                        try:
                            self.hyperrecon.console.print(f"🚨 [red]Found {len(enhanced_vulns)} parameter vulnerabilities for {param_url[:50]}...[/red]")
                        except:
                            print(f"Found {len(enhanced_vulns)} parameter vulnerabilities for {param_url[:50]}...")

            except Exception as e:
                try:
                    self.hyperrecon.console.print(f"⚠️ [yellow]DAST scan error for {param_url[:50]}...: {e}[/yellow]")
                except:
                    print(f"DAST scan error for {param_url[:50]}...: {e}")
                continue

        # Enhanced reporting with categorization
        total_param_vulns = sum(len(vulns) for vulns in parameter_results.values())
        if total_param_vulns > 0:
            try:
                self.hyperrecon.console.print(f"✅ [green]Found {total_param_vulns} parameter vulnerabilities via DAST[/green]")
                self.hyperrecon.console.print(f"📊 [blue]DAST Severity breakdown: Critical: {vulnerability_stats.get('critical', 0)}, High: {vulnerability_stats.get('high', 0)}, Medium: {vulnerability_stats.get('medium', 0)}, Low: {vulnerability_stats.get('low', 0)}, Info: {vulnerability_stats.get('info', 0)}[/blue]")
            except:
                print(f"Found {total_param_vulns} parameter vulnerabilities via DAST")
                print(f"DAST Severity breakdown: Critical: {vulnerability_stats.get('critical', 0)}, High: {vulnerability_stats.get('high', 0)}, Medium: {vulnerability_stats.get('medium', 0)}, Low: {vulnerability_stats.get('low', 0)}, Info: {vulnerability_stats.get('info', 0)}")

            # Save comprehensive summary
            summary = [
                f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] DAST Parameter Scan Summary",
                f"Total URLs scanned: {len([url for url in param_urls if '=' in url])}",
                f"Vulnerable URLs found: {len(parameter_results)}",
                f"Total vulnerabilities: {total_param_vulns}",
                "",
                "Severity Breakdown:",
                f"  Critical: {vulnerability_stats.get('critical', 0)}",
                f"  High: {vulnerability_stats.get('high', 0)}",
                f"  Medium: {vulnerability_stats.get('medium', 0)}",
                f"  Low: {vulnerability_stats.get('low', 0)}",
                f"  Info: {vulnerability_stats.get('info', 0)}",
                "",
                "Vulnerable URLs:"
            ]

            for url in parameter_results.keys():
                summary.append(f"  - {url}")

            self.hyperrecon.save_results_realtime(domain_path, 'vulnerabilities',
                                                'dast_parameter_scan_summary.txt', summary)
        else:
            # Save empty result indicator
            self.hyperrecon.save_results_realtime(domain_path, 'vulnerabilities',
                                                'no_parameter_vulnerabilities_found.txt', 
                                                [f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] No parameter vulnerabilities found via DAST"])
            try:
                self.hyperrecon.console.print(f"✅ [green]No vulnerabilities found in DAST parameter scan[/green]")
            except:
                print("No vulnerabilities found in DAST parameter scan")

        return parameter_results

    def generate_vulnerability_summary(self, detailed_results, domain_path):
        """Generate comprehensive vulnerability summary report"""
        summary = {
            'total_vulnerabilities': 0,
            'severity_breakdown': {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0},
            'scan_types': {},
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        }

        # Process subdomain vulnerabilities
        if 'subdomain_vulnerabilities' in detailed_results:
            subdomain_count = 0
            for host, vulns in detailed_results['subdomain_vulnerabilities'].items():
                subdomain_count += len(vulns)
                # Count by severity if structured data available
                for vuln in vulns:
                    if isinstance(vuln, dict) and 'severity' in vuln:
                        severity = vuln['severity']
                        summary['severity_breakdown'][severity] += 1
            
            summary['scan_types']['subdomain_scan'] = {
                'hosts_scanned': len(detailed_results['subdomain_vulnerabilities']),
                'vulnerabilities_found': subdomain_count
            }
            summary['total_vulnerabilities'] += subdomain_count

        # Process parameter vulnerabilities
        if 'parameter_vulnerabilities' in detailed_results:
            param_count = 0
            for url, vulns in detailed_results['parameter_vulnerabilities'].items():
                param_count += len(vulns)
                # Count by severity if structured data available
                for vuln in vulns:
                    if isinstance(vuln, dict) and 'severity' in vuln:
                        severity = vuln['severity']
                        summary['severity_breakdown'][severity] += 1
            
            summary['scan_types']['parameter_scan'] = {
                'urls_scanned': len(detailed_results['parameter_vulnerabilities']),
                'vulnerabilities_found': param_count
            }
            summary['total_vulnerabilities'] += param_count

        # Save comprehensive summary report
        summary_lines = [
            f"[{summary['timestamp']}] Vulnerability Scan Summary Report",
            "=" * 60,
            f"Total Vulnerabilities Found: {summary['total_vulnerabilities']}",
            "",
            "Severity Breakdown:",
            f"  🔴 Critical: {summary['severity_breakdown']['critical']}",
            f"  🟠 High: {summary['severity_breakdown']['high']}",
            f"  🟡 Medium: {summary['severity_breakdown']['medium']}",
            f"  🔵 Low: {summary['severity_breakdown']['low']}",
            f"  ⚪ Info: {summary['severity_breakdown']['info']}",
            "",
            "Scan Type Results:"
        ]

        for scan_type, results in summary['scan_types'].items():
            summary_lines.append(f"  {scan_type.replace('_', ' ').title()}:")
            for key, value in results.items():
                summary_lines.append(f"    {key.replace('_', ' ').title()}: {value}")
            summary_lines.append("")

        self.hyperrecon.save_results_realtime(domain_path, 'vulnerabilities',
                                            'vulnerability_scan_summary.txt', summary_lines)

        return summary

    def get_results_summary(self):
        """Get summary of vulnerability scanning results"""
        return {
            'module': 'VulnScanner',
            'description': 'Enhanced Nuclei vulnerability scanning with DAST parameter testing',
            'features': [
                'Comprehensive vulnerability categorization',
                'DAST parameter scanning',
                'JSON output parsing',
                'Severity-based reporting',
                'Real-time result saving'
            ]
        }
