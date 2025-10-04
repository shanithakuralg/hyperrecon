"""
Enhanced sensitive data detection module with comprehensive pattern matching
Part of HyperRecon Pro v4.0 - Advanced Modular Bug Bounty Scanner
"""

import re
import os
import requests
from datetime import datetime
from typing import List, Tuple, Dict, Any, Set
from urllib.parse import urlparse, parse_qs
from .base_utility import BaseUtility, UtilityResult
from .config import ConfigManager


class SensitiveDataDetector(BaseUtility):
    """
    Enhanced sensitive data detection utility with comprehensive pattern matching
    Detects sensitive information in URLs, responses, and file paths
    """
    
    def __init__(self, hyperrecon_instance):
        """Initialize sensitive data detector with patterns"""
        super().__init__(hyperrecon_instance)
        self.config_manager = ConfigManager()
        self.sensitive_patterns = self.config_manager.get_sensitive_patterns()
        self.compiled_patterns = {}
        self.detection_results = {}
        
        # Compile regex patterns for better performance
        self._compile_patterns()
        
        # Initialize detection categories
        self._initialize_categories()
    
    def _compile_patterns(self):
        """Compile regex patterns for efficient matching"""
        try:
            for pattern_name, pattern in self.sensitive_patterns.items():
                try:
                    self.compiled_patterns[pattern_name] = re.compile(pattern, re.IGNORECASE)
                except re.error as e:
                    self.log_warning(f"Invalid regex pattern for {pattern_name}: {e}")
        except Exception as e:
            self.log_error("Failed to compile sensitive data patterns", e)
    
    def _initialize_categories(self):
        """Initialize detection result categories"""
        self.detection_results = {
            'credentials': [],
            'tokens_keys': [],
            'config_files': [],
            'backup_files': [],
            'sensitive_paths': [],
            'personal_data': [],
            'api_endpoints': [],
            'database_files': [],
            'log_files': [],
            'development_files': [],
            'other_sensitive': []
        }
    
    def execute(self, targets: List[str], domain_path: str) -> UtilityResult:
        """
        Execute comprehensive sensitive data detection
        
        Args:
            targets: List of URLs to analyze for sensitive data
            domain_path: Path to domain output directory
            
        Returns:
            UtilityResult: Detection results with categorized findings
        """
        self.start_execution()
        
        if not targets:
            self.log_warning("No targets provided for sensitive data detection")
            return self.create_result(True, self.detection_results, 0)
        
        self.log_info(f"Starting sensitive data detection on {len(targets)} URLs")
        
        processed_count = 0
        
        try:
            # Process each URL for sensitive data patterns
            for url in targets:
                if url.strip():
                    self._analyze_url(url.strip())
                    processed_count += 1
            
            # Save categorized results
            self._save_detection_results(domain_path)
            
            # Generate summary report
            summary = self._generate_summary()
            
            self.log_info(f"Sensitive data detection completed. Found {summary['total_findings']} potential issues")
            
            return self.create_result(True, {
                'detection_results': self.detection_results,
                'summary': summary
            }, processed_count)
            
        except Exception as e:
            self.log_error("Sensitive data detection failed", e)
            return self.create_result(False, self.detection_results, processed_count)
    
    def _analyze_url(self, url: str):
        """
        Analyze a single URL for sensitive data patterns
        
        Args:
            url: URL to analyze
        """
        try:
            # Parse URL components
            parsed_url = urlparse(url)
            
            # Check URL path for sensitive patterns
            self._check_url_path(url, parsed_url.path)
            
            # Check query parameters
            if parsed_url.query:
                self._check_query_parameters(url, parsed_url.query)
            
            # Check file extensions and names
            self._check_file_patterns(url, parsed_url.path)
            
            # Attempt to fetch and analyze response content (if enabled)
            if hasattr(self.hyperrecon, 'enable_content_analysis') and self.hyperrecon.enable_content_analysis:
                self._analyze_response_content(url)
                
        except Exception as e:
            self.log_warning(f"Failed to analyze URL {url}: {e}")
    
    def _check_url_path(self, url: str, path: str):
        """Check URL path for sensitive patterns"""
        for pattern_name, compiled_pattern in self.compiled_patterns.items():
            if compiled_pattern.search(path):
                self._add_detection(pattern_name, url, f"Path contains {pattern_name}")
    
    def _check_query_parameters(self, url: str, query_string: str):
        """Check query parameters for sensitive data"""
        try:
            params = parse_qs(query_string)
            
            for param_name, param_values in params.items():
                # Check parameter names
                for pattern_name, compiled_pattern in self.compiled_patterns.items():
                    if compiled_pattern.search(param_name):
                        self._add_detection(pattern_name, url, f"Parameter name '{param_name}' matches {pattern_name}")
                
                # Check parameter values
                for value in param_values:
                    for pattern_name, compiled_pattern in self.compiled_patterns.items():
                        if compiled_pattern.search(value):
                            self._add_detection(pattern_name, url, f"Parameter value matches {pattern_name}")
                            
        except Exception as e:
            self.log_warning(f"Failed to parse query parameters for {url}: {e}")
    
    def _check_file_patterns(self, url: str, path: str):
        """Check for sensitive file types and patterns"""
        # Extract filename and extension
        filename = os.path.basename(path)
        
        # Define file type categories
        config_extensions = ['.env', '.yaml', '.yml', '.json', '.xml', '.ini', '.conf', '.config']
        backup_extensions = ['.bak', '.backup', '.old', '.swp', '.tmp', '.orig', '.save']
        database_extensions = ['.sql', '.db', '.dbf', '.sqlite', '.mdb']
        log_extensions = ['.log', '.logs']
        development_extensions = ['.git', '.svn', '.DS_Store', '.htaccess', '.htpasswd']
        
        # Check for config files
        if any(filename.lower().endswith(ext) for ext in config_extensions):
            self._add_detection('config_files', url, f"Config file detected: {filename}")
        
        # Check for backup files
        if any(filename.lower().endswith(ext) for ext in backup_extensions):
            self._add_detection('backup_files', url, f"Backup file detected: {filename}")
        
        # Check for database files
        if any(filename.lower().endswith(ext) for ext in database_extensions):
            self._add_detection('database_files', url, f"Database file detected: {filename}")
        
        # Check for log files
        if any(filename.lower().endswith(ext) for ext in log_extensions):
            self._add_detection('log_files', url, f"Log file detected: {filename}")
        
        # Check for development files
        if any(filename.lower().endswith(ext) or ext in path.lower() for ext in development_extensions):
            self._add_detection('development_files', url, f"Development file detected: {filename}")
    
    def _analyze_response_content(self, url: str):
        """
        Analyze response content for sensitive data (optional feature)
        
        Args:
            url: URL to fetch and analyze
        """
        try:
            # Make a HEAD request first to check content type
            head_response = requests.head(url, timeout=10, allow_redirects=True)
            content_type = head_response.headers.get('content-type', '').lower()
            
            # Only analyze text-based content
            if 'text' in content_type or 'json' in content_type or 'xml' in content_type:
                response = requests.get(url, timeout=15, allow_redirects=True)
                
                if response.status_code == 200:
                    content = response.text[:50000]  # Limit content size
                    
                    # Check content for sensitive patterns
                    for pattern_name, compiled_pattern in self.compiled_patterns.items():
                        matches = compiled_pattern.findall(content)
                        if matches:
                            for match in matches[:5]:  # Limit matches per pattern
                                self._add_detection(pattern_name, url, f"Content contains {pattern_name}: {match[:50]}...")
                                
        except requests.RequestException:
            # Silently ignore network errors for content analysis
            pass
        except Exception as e:
            self.log_warning(f"Content analysis failed for {url}: {e}")
    
    def _add_detection(self, pattern_name: str, url: str, description: str):
        """
        Add a detection result to the appropriate category
        
        Args:
            pattern_name: Name of the detected pattern
            url: URL where pattern was found
            description: Description of the finding
        """
        detection_entry = {
            'url': url,
            'pattern': pattern_name,
            'description': description,
            'timestamp': datetime.now().isoformat()
        }
        
        # Categorize the detection
        category = self._categorize_pattern(pattern_name)
        self.detection_results[category].append(detection_entry)
    
    def _categorize_pattern(self, pattern_name: str) -> str:
        """
        Categorize a pattern into appropriate detection category
        
        Args:
            pattern_name: Name of the pattern
            
        Returns:
            str: Category name
        """
        credential_patterns = ['session_id', 'jwt_token', 'private_ips']
        token_patterns = ['api_keys_tokens', 'aws_keys', 'google_api_keys', 'github_tokens']
        personal_patterns = ['email_addresses', 'phone_numbers', 'credit_card_numbers']
        path_patterns = ['sensitive_paths', 'exposed_files']
        
        if pattern_name in credential_patterns:
            return 'credentials'
        elif pattern_name in token_patterns:
            return 'tokens_keys'
        elif pattern_name in personal_patterns:
            return 'personal_data'
        elif pattern_name in path_patterns:
            return 'sensitive_paths'
        elif 'config' in pattern_name:
            return 'config_files'
        elif 'backup' in pattern_name:
            return 'backup_files'
        elif 'api' in pattern_name or 'parametrized' in pattern_name:
            return 'api_endpoints'
        else:
            return 'other_sensitive'
    
    def _save_detection_results(self, domain_path: str):
        """
        Save detection results in enhanced URL -> Pattern format
        
        Args:
            domain_path: Domain output directory path
        """
        try:
            # Save overall summary
            summary_data = []
            total_findings = 0
            
            for category, detections in self.detection_results.items():
                if detections:
                    summary_data.append(f"\n=== {category.upper().replace('_', ' ')} ===")
                    
                    for detection in detections:
                        summary_data.append(f"{detection['url']} -> {detection['pattern']} ({detection['description']})")
                        total_findings += 1
            
            if summary_data:
                summary_data.insert(0, f"Sensitive Data Detection Results - {total_findings} findings")
                summary_data.insert(1, f"Scan completed: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
                
                self.save_results(domain_path, "sensitive_data", "sensitive_data_summary.txt", 
                                "\n".join(summary_data))
            
            # Save category-specific files
            for category, detections in self.detection_results.items():
                if detections:
                    category_data = []
                    for detection in detections:
                        category_data.append(f"{detection['url']} -> {detection['pattern']}")
                    
                    self.save_results(domain_path, "sensitive_data", f"{category}.txt", 
                                    category_data)
            
            # Save detailed JSON report
            detailed_report = {
                'scan_info': {
                    'timestamp': datetime.now().isoformat(),
                    'total_findings': total_findings,
                    'categories_found': len([c for c in self.detection_results.values() if c])
                },
                'results': self.detection_results
            }
            
            self.save_results(domain_path, "sensitive_data", "detailed_report.json", 
                            detailed_report)
            
        except Exception as e:
            self.log_error("Failed to save sensitive data detection results", e)
    
    def _generate_summary(self) -> Dict[str, Any]:
        """
        Generate summary statistics for the detection results
        
        Returns:
            Dict containing summary statistics
        """
        total_findings = sum(len(detections) for detections in self.detection_results.values())
        categories_with_findings = [cat for cat, detections in self.detection_results.items() if detections]
        
        pattern_counts = {}
        for detections in self.detection_results.values():
            for detection in detections:
                pattern = detection['pattern']
                pattern_counts[pattern] = pattern_counts.get(pattern, 0) + 1
        
        return {
            'total_findings': total_findings,
            'categories_found': len(categories_with_findings),
            'categories_with_findings': categories_with_findings,
            'pattern_counts': pattern_counts,
            'most_common_patterns': sorted(pattern_counts.items(), key=lambda x: x[1], reverse=True)[:5]
        }
    
    def validate_dependencies(self) -> Tuple[bool, List[str]]:
        """
        Validate sensitive data detection dependencies
        
        Returns:
            Tuple[bool, List[str]]: (success, missing_dependencies)
        """
        # Sensitive data detection only requires Python standard library
        # and the requests library which should be available
        missing_deps = []
        
        try:
            import requests
        except ImportError:
            missing_deps.append("requests")
        
        try:
            import re
        except ImportError:
            missing_deps.append("re")
        
        return len(missing_deps) == 0, missing_deps