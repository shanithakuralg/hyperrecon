"""
Enhanced technology detection module with categorization and comprehensive reporting
Part of HyperRecon Pro v4.0 - Advanced Modular Bug Bounty Scanner
"""

import re
import requests
from datetime import datetime
from typing import List, Tuple, Dict, Any, Set
from .base_utility import BaseUtility, UtilityResult
from .config import ConfigManager


class TechDetector(BaseUtility):
    """
    Enhanced technology detection utility with categorization and comprehensive reporting
    Eliminates code duplication from main file and provides modular tech detection
    """
    
    def __init__(self, hyperrecon_instance):
        """Initialize technology detector with configuration"""
        super().__init__(hyperrecon_instance)
        self.config_manager = ConfigManager()
        self.tech_patterns = self.config_manager.get_technology_patterns()
        self.tech_results = {}
        self.tech_categories = {}
        
        # Initialize technology categories
        self._initialize_tech_categories()
    
    def _initialize_tech_categories(self):
        """Initialize technology categorization structure"""
        self.tech_categories = {
            'php': [], 'asp': [], 'java': [], 'nodejs': [], 'python': [], 'ruby': [],
            'react': [], 'angular': [], 'vue': [], 'wordpress': [], 'drupal': [], 
            'joomla': [], 'nginx': [], 'apache': [], 'iis': [], 'cdn': [], 'cms': [],
            'framework': [], 'database': [], 'server': [], 'language': [], 'other': []
        }
    
    def execute(self, targets: List[str], domain_path: str) -> UtilityResult:
        """
        Execute enhanced technology detection with categorization
        
        Args:
            targets: List of live hosts to scan
            domain_path: Path to domain output directory
            
        Returns:
            UtilityResult: Detection results with categorized technologies
        """
        self.start_execution()
        
        if not targets:
            self.log_warning("No live hosts provided for technology detection")
            return self.create_result(False, {}, 0)
        
        self.log_info(f"Starting technology detection on {len(targets)} hosts")
        
        # Reset results for this execution
        self.tech_results = {}
        self._initialize_tech_categories()
        
        processed_count = 0
        
        for host in targets:
            try:
                host_results = self._detect_host_technologies(host)
                if host_results:
                    self.tech_results[host] = host_results
                    self._categorize_host_technologies(host, host_results)
                processed_count += 1
                
            except Exception as e:
                self.log_error(f"Technology detection failed for {host}", e)
        
        # Generate categorized output files
        self._generate_categorized_files(domain_path)
        
        # Generate comprehensive summary
        self._generate_technology_summary(domain_path, targets)
        
        self.log_info(f"Technology detection completed for {processed_count} hosts")
        
        return self.create_result(
            success=True,
            data=self.tech_results,
            items_processed=processed_count
        )
    
    def _detect_host_technologies(self, host: str) -> Dict[str, Any]:
        """
        Detect technologies for a single host using multiple methods
        
        Args:
            host: Target host URL
            
        Returns:
            Dict containing detected technologies and metadata
        """
        host_results = {
            'whatweb': {},
            'headers': {},
            'content': {},
            'technologies': set(),
            'server_info': {},
            'detected_patterns': []
        }
        
        try:
            # Method 1: Whatweb detection (if available)
            if self.check_tool_installed('whatweb'):
                whatweb_result = self._run_whatweb_detection(host)
                if whatweb_result:
                    host_results['whatweb'] = whatweb_result
                    host_results['technologies'].update(self._extract_whatweb_technologies(whatweb_result))
            
            # Method 2: HTTP headers analysis
            headers_result = self._analyze_http_headers(host)
            if headers_result:
                host_results['headers'] = headers_result
                host_results['technologies'].update(headers_result.get('detected_technologies', set()))
                host_results['server_info'].update(headers_result.get('server_info', {}))
            
            # Method 3: Content pattern matching
            content_result = self._analyze_page_content(host)
            if content_result:
                host_results['content'] = content_result
                host_results['technologies'].update(content_result.get('detected_technologies', set()))
                host_results['detected_patterns'].extend(content_result.get('matched_patterns', []))
            
            # Convert set to list for JSON serialization
            host_results['technologies'] = list(host_results['technologies'])
            
        except Exception as e:
            self.log_error(f"Technology detection error for {host}", e)
        
        return host_results
    
    def _run_whatweb_detection(self, host: str) -> Dict[str, Any]:
        """
        Run whatweb tool for technology detection
        
        Args:
            host: Target host
            
        Returns:
            Dict containing whatweb results
        """
        try:
            cmd = ['whatweb', host, '--no-errors', '-q', '--log-brief']
            result = self.run_command(cmd, timeout=30, description=f"Whatweb scan for {host}")
            
            if result:
                return {
                    'raw_output': result,
                    'timestamp': datetime.now().isoformat(),
                    'technologies': self._parse_whatweb_output(result)
                }
        except Exception as e:
            self.log_warning(f"Whatweb detection failed for {host}: {e}")
        
        return {}
    
    def _parse_whatweb_output(self, output: str) -> List[str]:
        """
        Parse whatweb output to extract technology names
        
        Args:
            output: Raw whatweb output
            
        Returns:
            List of detected technologies
        """
        technologies = []
        
        try:
            # Parse whatweb output format: URL [status_code] [technologies]
            lines = output.strip().split('\n')
            for line in lines:
                if '[' in line and ']' in line:
                    # Extract content between brackets
                    parts = re.findall(r'\[([^\]]+)\]', line)
                    for part in parts[1:]:  # Skip status code (first bracket)
                        # Split by comma and clean up
                        techs = [tech.strip() for tech in part.split(',')]
                        technologies.extend(techs)
        except Exception as e:
            self.log_warning(f"Failed to parse whatweb output: {e}")
        
        return technologies
    
    def _extract_whatweb_technologies(self, whatweb_result: Dict[str, Any]) -> Set[str]:
        """Extract technology names from whatweb results"""
        technologies = set()
        
        if 'technologies' in whatweb_result:
            for tech in whatweb_result['technologies']:
                # Clean and normalize technology names
                clean_tech = re.sub(r'[^\w\s-]', '', tech.lower().strip())
                if clean_tech and len(clean_tech) > 1:
                    technologies.add(clean_tech)
        
        return technologies
    
    def _analyze_http_headers(self, host: str) -> Dict[str, Any]:
        """
        Analyze HTTP headers for technology indicators
        
        Args:
            host: Target host
            
        Returns:
            Dict containing header analysis results
        """
        headers_result = {
            'detected_technologies': set(),
            'server_info': {},
            'headers': {},
            'security_headers': {}
        }
        
        try:
            # Ensure proper URL format
            if not host.startswith(('http://', 'https://')):
                host = f"https://{host}"
            
            response = requests.get(host, timeout=10, verify=False, allow_redirects=True)
            headers = response.headers
            headers_result['headers'] = dict(headers)
            
            # Analyze server header
            server = headers.get('Server', '').lower()
            if server:
                headers_result['server_info']['server'] = server
                headers_result['detected_technologies'].update(self._extract_server_technologies(server))
            
            # Analyze X-Powered-By header
            powered_by = headers.get('X-Powered-By', '').lower()
            if powered_by:
                headers_result['server_info']['powered_by'] = powered_by
                headers_result['detected_technologies'].update(self._extract_powered_by_technologies(powered_by))
            
            # Check for framework-specific headers
            framework_headers = {
                'X-AspNet-Version': 'asp.net',
                'X-AspNetMvc-Version': 'asp.net mvc',
                'X-Drupal-Cache': 'drupal',
                'X-Generator': 'generator',
                'X-Pingback': 'wordpress'
            }
            
            for header_name, tech in framework_headers.items():
                if header_name in headers:
                    headers_result['detected_technologies'].add(tech)
                    headers_result['server_info'][header_name.lower()] = headers[header_name]
            
            # Analyze security headers
            security_headers = ['X-Frame-Options', 'X-XSS-Protection', 'X-Content-Type-Options', 
                              'Strict-Transport-Security', 'Content-Security-Policy']
            
            for sec_header in security_headers:
                if sec_header in headers:
                    headers_result['security_headers'][sec_header] = headers[sec_header]
            
        except Exception as e:
            self.log_warning(f"HTTP headers analysis failed for {host}: {e}")
        
        return headers_result
    
    def _extract_server_technologies(self, server_header: str) -> Set[str]:
        """Extract technologies from Server header"""
        technologies = set()
        server_lower = server_header.lower()
        
        server_patterns = {
            'nginx': ['nginx'],
            'apache': ['apache'],
            'iis': ['microsoft-iis', 'iis'],
            'cloudflare': ['cloudflare'],
            'nodejs': ['node.js', 'express'],
            'php': ['php'],
            'python': ['python', 'gunicorn', 'uwsgi'],
            'ruby': ['passenger', 'puma', 'unicorn']
        }
        
        for tech, patterns in server_patterns.items():
            if any(pattern in server_lower for pattern in patterns):
                technologies.add(tech)
        
        return technologies
    
    def _extract_powered_by_technologies(self, powered_by_header: str) -> Set[str]:
        """Extract technologies from X-Powered-By header"""
        technologies = set()
        powered_by_lower = powered_by_header.lower()
        
        powered_by_patterns = {
            'php': ['php'],
            'asp': ['asp.net', 'asp'],
            'nodejs': ['express', 'node.js'],
            'python': ['django', 'flask'],
            'ruby': ['rails', 'rack']
        }
        
        for tech, patterns in powered_by_patterns.items():
            if any(pattern in powered_by_lower for pattern in patterns):
                technologies.add(tech)
        
        return technologies
    
    def _analyze_page_content(self, host: str) -> Dict[str, Any]:
        """
        Analyze page content for technology patterns
        
        Args:
            host: Target host
            
        Returns:
            Dict containing content analysis results
        """
        content_result = {
            'detected_technologies': set(),
            'matched_patterns': [],
            'meta_tags': {},
            'scripts': [],
            'stylesheets': []
        }
        
        try:
            # Ensure proper URL format
            if not host.startswith(('http://', 'https://')):
                host = f"https://{host}"
            
            response = requests.get(host, timeout=10, verify=False, allow_redirects=True)
            content = response.text.lower()
            
            # Pattern matching against configured technology patterns
            for tech_name, patterns in self.tech_patterns.items():
                for pattern in patterns:
                    if pattern.lower() in content:
                        content_result['detected_technologies'].add(tech_name)
                        content_result['matched_patterns'].append({
                            'technology': tech_name,
                            'pattern': pattern,
                            'context': self._extract_pattern_context(content, pattern.lower())
                        })
            
            # Extract meta generator tags
            generator_match = re.search(r'<meta[^>]*name=["\']generator["\'][^>]*content=["\']([^"\']+)["\']', content)
            if generator_match:
                generator = generator_match.group(1)
                content_result['meta_tags']['generator'] = generator
                content_result['detected_technologies'].update(self._analyze_generator_tag(generator))
            
            # Extract script sources for framework detection
            script_matches = re.findall(r'<script[^>]*src=["\']([^"\']+)["\']', content)
            content_result['scripts'] = script_matches[:10]  # Limit to first 10
            
            for script in script_matches:
                content_result['detected_technologies'].update(self._analyze_script_source(script))
            
            # Extract stylesheet links
            css_matches = re.findall(r'<link[^>]*href=["\']([^"\']+\.css[^"\']*)["\']', content)
            content_result['stylesheets'] = css_matches[:10]  # Limit to first 10
            
        except Exception as e:
            self.log_warning(f"Content analysis failed for {host}: {e}")
        
        return content_result
    
    def _extract_pattern_context(self, content: str, pattern: str, context_length: int = 50) -> str:
        """Extract context around a matched pattern"""
        try:
            index = content.find(pattern)
            if index != -1:
                start = max(0, index - context_length)
                end = min(len(content), index + len(pattern) + context_length)
                return content[start:end].strip()
        except:
            pass
        return ""
    
    def _analyze_generator_tag(self, generator: str) -> Set[str]:
        """Analyze meta generator tag for technology detection"""
        technologies = set()
        generator_lower = generator.lower()
        
        generator_patterns = {
            'wordpress': ['wordpress'],
            'drupal': ['drupal'],
            'joomla': ['joomla'],
            'magento': ['magento'],
            'shopify': ['shopify'],
            'wix': ['wix'],
            'squarespace': ['squarespace']
        }
        
        for tech, patterns in generator_patterns.items():
            if any(pattern in generator_lower for pattern in patterns):
                technologies.add(tech)
        
        return technologies
    
    def _analyze_script_source(self, script_src: str) -> Set[str]:
        """Analyze script sources for framework detection"""
        technologies = set()
        script_lower = script_src.lower()
        
        script_patterns = {
            'react': ['react', 'react-dom'],
            'angular': ['angular', 'angularjs'],
            'vue': ['vue.js', 'vue.min.js', 'vuejs'],
            'jquery': ['jquery'],
            'bootstrap': ['bootstrap'],
            'nodejs': ['socket.io'],
            'webpack': ['webpack', 'bundle.js']
        }
        
        for tech, patterns in script_patterns.items():
            if any(pattern in script_lower for pattern in patterns):
                technologies.add(tech)
        
        return technologies
    
    def _categorize_host_technologies(self, host: str, host_results: Dict[str, Any]):
        """
        Categorize detected technologies for a host
        
        Args:
            host: Target host
            host_results: Detection results for the host
        """
        detected_techs = host_results.get('technologies', [])
        
        # Technology categorization mapping
        category_mapping = {
            'php': ['php', 'phpsessid', 'laravel', 'symfony', 'codeigniter'],
            'asp': ['asp', 'asp.net', 'aspsessionid', 'microsoft-iis'],
            'java': ['java', 'jsp', 'jsessionid', 'tomcat', 'spring'],
            'nodejs': ['node', 'nodejs', 'express', 'socket.io'],
            'python': ['python', 'django', 'flask', 'gunicorn', 'uwsgi'],
            'ruby': ['ruby', 'rails', 'rack', 'passenger', 'puma'],
            'react': ['react', 'react-dom', '_next', 'webpack'],
            'angular': ['angular', 'angularjs', 'ng-'],
            'vue': ['vue', 'vuejs', 'nuxt'],
            'wordpress': ['wordpress', 'wp-content', 'wp-admin', 'wp-includes'],
            'drupal': ['drupal', '/sites/default/', '/modules/', '/themes/'],
            'joomla': ['joomla', 'administrator', 'components', 'modules'],
            'nginx': ['nginx'],
            'apache': ['apache', 'httpd'],
            'iis': ['microsoft-iis', 'iis']
        }
        
        for tech in detected_techs:
            tech_lower = tech.lower()
            categorized = False
            
            for category, patterns in category_mapping.items():
                if any(pattern in tech_lower for pattern in patterns):
                    if host not in self.tech_categories[category]:
                        self.tech_categories[category].append(host)
                    categorized = True
                    break
            
            # If not categorized, add to 'other'
            if not categorized and tech_lower not in ['', 'unknown']:
                if host not in self.tech_categories['other']:
                    self.tech_categories['other'].append(host)
    
    def _generate_categorized_files(self, domain_path: str):
        """
        Generate categorized technology files
        
        Args:
            domain_path: Domain output directory path
        """
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        for tech_name, hosts in self.tech_categories.items():
            if hosts:
                # Remove duplicates and sort
                unique_hosts = sorted(list(set(hosts)))
                
                # Format hosts with timestamp and technology info
                formatted_hosts = []
                for host in unique_hosts:
                    host_tech_info = self.tech_results.get(host, {})
                    detected_techs = host_tech_info.get('technologies', [])
                    
                    # Filter technologies relevant to this category
                    relevant_techs = [tech for tech in detected_techs 
                                    if any(pattern in tech.lower() 
                                          for pattern in self._get_category_patterns(tech_name))]
                    
                    tech_info = f"Uses {tech_name.replace('_', ' ').title()}"
                    if relevant_techs:
                        tech_info += f" ({', '.join(relevant_techs[:3])})"
                    
                    formatted_hosts.append(f"[{timestamp}] {host} -> {tech_info}")
                
                # Save categorized file
                filename = f'{tech_name}_hosts.txt'
                self.save_results(domain_path, 'technology_detection', filename, formatted_hosts)
                
                self.log_info(f"Found {len(unique_hosts)} hosts using {tech_name.replace('_', ' ').title()}")
    
    def _get_category_patterns(self, category: str) -> List[str]:
        """Get patterns for a specific technology category"""
        category_patterns = {
            'php': ['php', 'phpsessid', 'laravel', 'symfony'],
            'asp': ['asp', 'aspsessionid', 'microsoft-iis'],
            'java': ['java', 'jsp', 'jsessionid', 'tomcat'],
            'nodejs': ['node', 'express', 'socket.io'],
            'python': ['python', 'django', 'flask'],
            'ruby': ['ruby', 'rails', 'rack'],
            'react': ['react', '_next', 'webpack'],
            'angular': ['angular', 'ng-'],
            'vue': ['vue', 'nuxt'],
            'wordpress': ['wordpress', 'wp-'],
            'drupal': ['drupal'],
            'joomla': ['joomla'],
            'nginx': ['nginx'],
            'apache': ['apache'],
            'iis': ['iis']
        }
        
        return category_patterns.get(category, [category])
    
    def _generate_technology_summary(self, domain_path: str, total_hosts: List[str]):
        """
        Generate comprehensive technology summary
        
        Args:
            domain_path: Domain output directory path
            total_hosts: List of all scanned hosts
        """
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        summary = [
            f"[{timestamp}] Technology Detection Summary",
            f"Total hosts scanned: {len(total_hosts)}",
            f"Hosts with detected technologies: {len(self.tech_results)}",
            "",
            "Technology Distribution:"
        ]
        
        # Add category statistics
        total_categorized = 0
        for tech_name, hosts in self.tech_categories.items():
            if hosts:
                unique_hosts = list(set(hosts))
                summary.append(f"  {tech_name.replace('_', ' ').title()}: {len(unique_hosts)} hosts")
                total_categorized += len(unique_hosts)
        
        summary.extend([
            "",
            f"Total categorized detections: {total_categorized}",
            "",
            "Detection Methods Used:"
        ])
        
        # Add detection method statistics
        whatweb_count = sum(1 for result in self.tech_results.values() if result.get('whatweb'))
        headers_count = sum(1 for result in self.tech_results.values() if result.get('headers'))
        content_count = sum(1 for result in self.tech_results.values() if result.get('content'))
        
        summary.extend([
            f"  Whatweb detection: {whatweb_count} hosts",
            f"  HTTP headers analysis: {headers_count} hosts", 
            f"  Content pattern matching: {content_count} hosts"
        ])
        
        # Save summary
        self.save_results(domain_path, 'technology_detection', 'technology_summary.txt', summary)
        
        # Save detailed results as JSON for further analysis
        detailed_results = {
            'timestamp': timestamp,
            'total_hosts': len(total_hosts),
            'detected_hosts': len(self.tech_results),
            'categories': {k: list(set(v)) for k, v in self.tech_categories.items() if v},
            'detailed_results': self.tech_results
        }
        
        import json
        detailed_json = json.dumps(detailed_results, indent=2, default=str)
        self.save_results(domain_path, 'technology_detection', 'detailed_results.json', detailed_json)
        
        self.log_info("Technology detection summary generated")
    
    def validate_dependencies(self) -> Tuple[bool, List[str]]:
        """
        Validate technology detection tool dependencies
        
        Returns:
            Tuple[bool, List[str]]: (success, missing_dependencies)
        """
        required_tools = []
        optional_tools = ['whatweb']
        missing_tools = []
        
        # Check optional tools
        for tool in optional_tools:
            if not self.check_tool_installed(tool):
                missing_tools.append(tool)
                self.log_warning(f"Optional tool '{tool}' not found - some detection methods will be unavailable")
        
        # Technology detection can work without external tools using HTTP analysis
        # So we always return success, but report missing optional tools
        return True, missing_tools