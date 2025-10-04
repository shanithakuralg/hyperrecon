"""
HTTP probing module for live host detection using httpx
Part of HyperRecon Pro v4.0 - Advanced Modular Bug Bounty Scanner
"""

import os
import tempfile
from typing import List, Tuple, Dict, Any
from .base_utility import BaseUtility, UtilityResult


class HTTPProber(BaseUtility):
    """HTTP probing utility for live host detection using httpx"""
    
    def __init__(self, hyperrecon_instance):
        """Initialize HTTP prober with configuration"""
        super().__init__(hyperrecon_instance)
        
        # HTTP probing configuration
        self.timeout = getattr(hyperrecon_instance, 'timeout', 300)
        self.threads = getattr(hyperrecon_instance, 'threads', 10)
        
        # Status codes to consider as "live"
        self.valid_status_codes = [
            200, 204, 301, 302, 307, 308,  # Success and redirects
            401, 403, 405,                  # Authentication/authorization
            500, 502, 503, 504             # Server errors (still indicate live service)
        ]
        
        # File manager for consistent output
        self.file_manager = getattr(hyperrecon_instance, 'file_manager', None)
    
    def execute(self, targets: List[str], domain_path: str) -> UtilityResult:
        """
        Execute HTTP probing on target hosts
        
        Args:
            targets: List of hosts/subdomains to probe
            domain_path: Path to domain output directory
            
        Returns:
            UtilityResult: Probing results with live hosts
        """
        self.start_execution()
        
        if not targets:
            self.log_warning("No targets provided for HTTP probing")
            return self.create_result(True, {'live_hosts': []}, 0)
        
        # Validate dependencies
        deps_valid, missing_deps = self.validate_dependencies()
        if not deps_valid:
            error_msg = f"Missing dependencies: {', '.join(missing_deps)}"
            self.log_error(error_msg)
            return self.create_result(False, {'error': error_msg}, 0)
        
        try:
            live_hosts = self._probe_hosts(targets, domain_path)
            
            # Save results using file manager
            if live_hosts:
                self._save_results(domain_path, live_hosts, targets)
            
            self.log_info(f"Found {len(live_hosts)} live hosts out of {len(targets)} targets")
            
            return self.create_result(
                success=True,
                data={'live_hosts': live_hosts, 'total_probed': len(targets)},
                items_processed=len(targets)
            )
            
        except Exception as e:
            self.log_error("HTTP probing failed", e)
            return self.create_result(False, {'error': str(e)}, 0)
    
    def _probe_hosts(self, targets: List[str], domain_path: str) -> List[str]:
        """
        Probe hosts using httpx tool with status code categorization
        
        Args:
            targets: List of hosts/domains to probe
            domain_path: Domain output directory
            
        Returns:
            List of live hosts
        """
        live_hosts = []
        status_code_results = {}
        
        # Create temporary file for targets
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as tmp_file:
            tmp_path = tmp_file.name
            
            # Write domains to temporary file (domain-level probing)
            for target in targets:
                # Clean domain format - remove protocols if present
                clean_domain = target.replace('http://', '').replace('https://', '').strip('/')
                tmp_file.write(f"{clean_domain}\n")
        
        try:
            # Build httpx command with status code output
            cmd = [
                'httpx',
                '-l', tmp_path,
                '-silent',
                '-status-code',  # Include status codes in output
                '-timeout', str(self.timeout // 10),
                '-threads', str(self.threads),
                '-follow-redirects',
                '-no-color'
            ]
            
            self.log_info(f"Probing {len(targets)} domains with httpx")
            
            # Execute httpx command
            result = self.run_command(
                cmd, 
                timeout=self.timeout,
                description=f"HTTP probing {len(targets)} domains"
            )
            
            if result:
                # Parse results with status codes
                lines = [line.strip() for line in result.split('\n') if line.strip()]
                
                for line in lines:
                    if '[' in line and ']' in line:
                        # Extract URL and status code
                        try:
                            url_part = line.split('[')[0].strip()
                            status_part = line.split('[')[1].split(']')[0].strip()
                            
                            if status_part.isdigit():
                                status_code = int(status_part)
                                
                                # Add to live hosts
                                live_hosts.append(url_part)
                                
                                # Categorize by status code
                                if status_code not in status_code_results:
                                    status_code_results[status_code] = []
                                status_code_results[status_code].append(url_part)
                        except:
                            # Fallback for lines without status codes
                            live_hosts.append(line)
                    else:
                        # Fallback for simple format
                        live_hosts.append(line)
                
                # Remove duplicates while preserving order
                seen = set()
                unique_live_hosts = []
                for host in live_hosts:
                    if host not in seen:
                        seen.add(host)
                        unique_live_hosts.append(host)
                
                live_hosts = unique_live_hosts
                
                # Save status-code-wise results
                self._save_status_code_results(domain_path, status_code_results)
                
                if self.console:
                    self.console.print(f"✅ [green]Found {len(live_hosts)} live domains[/green]")
                    if status_code_results:
                        for status_code, domains in status_code_results.items():
                            self.console.print(f"   📊 Status {status_code}: {len(domains)} domains")
            else:
                self.log_warning("No output from httpx command")
                
        except Exception as e:
            self.log_error("Failed to execute httpx", e)
        finally:
            # Clean up temporary file
            try:
                os.unlink(tmp_path)
            except:
                pass
        
        return live_hosts
    
    def _save_status_code_results(self, domain_path: str, status_code_results: Dict[int, List[str]]) -> None:
        """
        Save status-code-wise results to separate files
        
        Args:
            domain_path: Domain output directory
            status_code_results: Dictionary mapping status codes to domain lists
        """
        try:
            for status_code, domains in status_code_results.items():
                filename = f"{status_code}_live_domains.txt"
                
                if self.file_manager:
                    self.file_manager.save_results_realtime(
                        domain_path, 'live_hosts', filename, domains
                    )
                else:
                    self.save_results(domain_path, 'live_hosts', filename, domains)
                    
                self.log_info(f"Saved {len(domains)} domains with status code {status_code}")
                
        except Exception as e:
            self.log_error("Failed to save status code results", e)

    def _save_results(self, domain_path: str, live_hosts: List[str], original_targets: List[str]) -> None:
        """
        Save HTTP probing results with proper organization
        
        Args:
            domain_path: Domain output directory
            live_hosts: List of live hosts found
            original_targets: Original target list
        """
        try:
            # Save all live domains
            if self.file_manager:
                self.file_manager.save_results_realtime(
                    domain_path, 'live_hosts', 'live_domains.txt', live_hosts
                )
                
                # Save detailed results with statistics
                detailed_results = self._create_detailed_results(live_hosts, original_targets)
                self.file_manager.save_results_realtime(
                    domain_path, 'live_hosts', 'probing_summary.txt', detailed_results
                )
                
                # Save in JSON format for programmatic access
                json_data = {
                    'live_domains': live_hosts,
                    'total_targets': len(original_targets),
                    'live_count': len(live_hosts),
                    'success_rate': f"{(len(live_hosts)/len(original_targets)*100):.1f}%" if original_targets else "0%",
                    'timestamp': self.start_time,
                    'probing_type': 'domain_level'
                }
                self.file_manager.save_json_results(
                    domain_path, 'live_hosts', 'probing_results.json', json_data
                )
            else:
                # Fallback to base utility save method
                self.save_results(domain_path, 'live_hosts', 'live_domains.txt', live_hosts)
                
        except Exception as e:
            self.log_error("Failed to save HTTP probing results", e)
    
    def _create_detailed_results(self, live_hosts: List[str], original_targets: List[str]) -> List[str]:
        """
        Create detailed results summary
        
        Args:
            live_hosts: List of live hosts
            original_targets: Original targets
            
        Returns:
            List of summary lines
        """
        from datetime import datetime
        
        summary_lines = [
            f"# HTTP Probing Results Summary",
            f"# Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            f"# Tool: httpx",
            f"",
            f"## Statistics",
            f"Total targets probed: {len(original_targets)}",
            f"Live hosts found: {len(live_hosts)}",
            f"Success rate: {(len(live_hosts)/len(original_targets)*100):.1f}%" if original_targets else "0%",
            f"Status codes checked: {', '.join(map(str, self.valid_status_codes))}",
            f"",
            f"## Live Hosts",
        ]
        
        # Add live hosts with numbering
        for i, host in enumerate(live_hosts, 1):
            summary_lines.append(f"{i:3d}. {host}")
        
        if not live_hosts:
            summary_lines.append("No live hosts found")
        
        return summary_lines
    
    def validate_dependencies(self) -> Tuple[bool, List[str]]:
        """
        Validate HTTP probing tool dependencies
        
        Returns:
            Tuple[bool, List[str]]: (success, missing_dependencies)
        """
        required_tools = ['httpx']
        missing_tools = []
        
        for tool in required_tools:
            if not self.check_tool_installed(tool):
                missing_tools.append(tool)
        
        if missing_tools:
            self.log_warning(f"Missing HTTP probing tools: {', '.join(missing_tools)}")
            
            # Provide installation instructions
            for tool in missing_tools:
                if tool == 'httpx':
                    self.log_info("Install httpx: go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest")
        
        return len(missing_tools) == 0, missing_tools
    
    def get_live_host_statistics(self, live_hosts: List[str]) -> Dict[str, Any]:
        """
        Generate statistics about live hosts
        
        Args:
            live_hosts: List of live hosts
            
        Returns:
            Dict containing statistics
        """
        stats = {
            'total_count': len(live_hosts),
            'http_count': 0,
            'https_count': 0,
            'unique_domains': set(),
            'port_distribution': {}
        }
        
        for host in live_hosts:
            # Count protocol types
            if host.startswith('https://'):
                stats['https_count'] += 1
            elif host.startswith('http://'):
                stats['http_count'] += 1
            
            # Extract domain for uniqueness
            try:
                from urllib.parse import urlparse
                parsed = urlparse(host)
                if parsed.netloc:
                    stats['unique_domains'].add(parsed.netloc.split(':')[0])
                    
                    # Track port distribution
                    port = parsed.port or (443 if parsed.scheme == 'https' else 80)
                    stats['port_distribution'][port] = stats['port_distribution'].get(port, 0) + 1
            except:
                pass
        
        # Convert set to count
        stats['unique_domains'] = len(stats['unique_domains'])
        
        return stats
    
    def probe_single_host(self, host: str, timeout: int = 10) -> Dict[str, Any]:
        """
        Probe a single host for detailed information
        
        Args:
            host: Host to probe
            timeout: Request timeout
            
        Returns:
            Dict containing probe results
        """
        result = {
            'host': host,
            'is_live': False,
            'status_code': None,
            'response_time': None,
            'server': None,
            'title': None,
            'error': None
        }
        
        try:
            # Build command for single host probing with more details
            cmd = [
                'httpx',
                '-u', host,
                '-silent',
                '-mc', ','.join(map(str, self.valid_status_codes)),
                '-timeout', str(timeout),
                '-status-code',
                '-response-time',
                '-server',
                '-title',
                '-no-color'
            ]
            
            output = self.run_command(cmd, timeout=timeout + 5)
            
            if output:
                # Parse httpx output (format: URL [STATUS_CODE] [RESPONSE_TIME] [SERVER] [TITLE])
                parts = output.strip().split()
                if len(parts) >= 2:
                    result['is_live'] = True
                    
                    # Extract status code
                    for part in parts:
                        if part.startswith('[') and part.endswith(']') and part[1:-1].isdigit():
                            result['status_code'] = int(part[1:-1])
                            break
                    
                    # Additional parsing could be added here for server, title, etc.
            
        except Exception as e:
            result['error'] = str(e)
            self.log_error(f"Failed to probe single host {host}", e)
        
        return result