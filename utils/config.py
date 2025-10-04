"""
Centralized configuration management system for patterns and tool settings
Part of HyperRecon Pro v4.0 - Advanced Modular Bug Bounty Scanner
"""

import os
import json
import yaml
from typing import Dict, List, Any, Optional
from pathlib import Path


class ConfigManager:
    """
    Centralized configuration management for HyperRecon Pro
    Handles patterns, tool settings, and dependency management
    """
    
    def __init__(self, config_dir: str = "config"):
        """
        Initialize configuration manager
        
        Args:
            config_dir: Directory containing configuration files
        """
        self.config_dir = Path(config_dir)
        self.config_dir.mkdir(exist_ok=True)
        
        # Configuration cache
        self._patterns_cache = None
        self._tool_config_cache = None
        self._wordlists_cache = None
        
        # Default configurations
        self._default_patterns = self._get_default_patterns()
        self._default_tool_config = self._get_default_tool_config()
        
        # Initialize configuration files if they don't exist
        self._initialize_config_files()
    
    def _initialize_config_files(self):
        """Create default configuration files if they don't exist"""
        patterns_file = self.config_dir / "patterns.yaml"
        if not patterns_file.exists():
            self._save_patterns(self._default_patterns)
        
        tool_config_file = self.config_dir / "tool_config.yaml"
        if not tool_config_file.exists():
            self._save_tool_config(self._default_tool_config)
    
    def load_patterns(self) -> Dict[str, Any]:
        """
        Load sensitive data patterns from configuration
        
        Returns:
            Dict containing all pattern configurations
        """
        if self._patterns_cache is not None:
            return self._patterns_cache
        
        patterns_file = self.config_dir / "patterns.yaml"
        
        try:
            if patterns_file.exists():
                with open(patterns_file, 'r', encoding='utf-8') as f:
                    self._patterns_cache = yaml.safe_load(f)
            else:
                self._patterns_cache = self._default_patterns
                
        except Exception as e:
            print(f"Warning: Failed to load patterns config: {e}")
            self._patterns_cache = self._default_patterns
        
        return self._patterns_cache
    
    def get_sensitive_patterns(self) -> Dict[str, str]:
        """Get sensitive data detection patterns"""
        patterns = self.load_patterns()
        return patterns.get('sensitive_data', {})
    
    def get_technology_patterns(self) -> Dict[str, List[str]]:
        """Get technology detection patterns"""
        patterns = self.load_patterns()
        return patterns.get('technology_detection', {})
    
    def get_security_paths(self) -> List[str]:
        """Get common security paths for checking"""
        patterns = self.load_patterns()
        return patterns.get('security_paths', [])
    
    def load_tool_config(self) -> Dict[str, Any]:
        """
        Load tool configuration settings
        
        Returns:
            Dict containing tool configurations
        """
        if self._tool_config_cache is not None:
            return self._tool_config_cache
        
        config_file = self.config_dir / "tool_config.yaml"
        
        try:
            if config_file.exists():
                with open(config_file, 'r', encoding='utf-8') as f:
                    self._tool_config_cache = yaml.safe_load(f)
            else:
                self._tool_config_cache = self._default_tool_config
                
        except Exception as e:
            print(f"Warning: Failed to load tool config: {e}")
            self._tool_config_cache = self._default_tool_config
        
        return self._tool_config_cache
    
    def get_tool_paths(self) -> Dict[str, str]:
        """Get configured tool paths"""
        config = self.load_tool_config()
        return config.get('tool_paths', {})
    
    def get_tool_settings(self, tool_name: str) -> Dict[str, Any]:
        """
        Get settings for a specific tool
        
        Args:
            tool_name: Name of the tool
            
        Returns:
            Dict containing tool-specific settings
        """
        config = self.load_tool_config()
        return config.get('tools', {}).get(tool_name, {})
    
    def get_wordlist_paths(self) -> List[str]:
        """
        Get configured wordlist paths
        
        Returns:
            List of wordlist file paths
        """
        if self._wordlists_cache is not None:
            return self._wordlists_cache
        
        config = self.load_tool_config()
        wordlist_paths = config.get('wordlists', {}).get('paths', [])
        
        # Filter to only existing paths
        existing_paths = []
        for path in wordlist_paths:
            if os.path.exists(path):
                existing_paths.append(path)
        
        self._wordlists_cache = existing_paths
        return existing_paths
    
    def validate_dependencies(self) -> Dict[str, Any]:
        """
        Validate all tool dependencies
        
        Returns:
            Dict containing validation results
        """
        config = self.load_tool_config()
        required_tools = config.get('required_tools', [])
        optional_tools = config.get('optional_tools', [])
        
        validation_results = {
            'required_missing': [],
            'optional_missing': [],
            'available_tools': [],
            'all_required_available': True
        }
        
        # Check required tools
        for tool in required_tools:
            if self._check_tool_available(tool):
                validation_results['available_tools'].append(tool)
            else:
                validation_results['required_missing'].append(tool)
                validation_results['all_required_available'] = False
        
        # Check optional tools
        for tool in optional_tools:
            if self._check_tool_available(tool):
                validation_results['available_tools'].append(tool)
            else:
                validation_results['optional_missing'].append(tool)
        
        return validation_results
    
    def _check_tool_available(self, tool_name: str) -> bool:
        """Check if a tool is available in the system"""
        try:
            import subprocess
            result = subprocess.run(['which', tool_name], capture_output=True, timeout=5)
            return result.returncode == 0
        except:
            return False
    
    def update_pattern(self, category: str, pattern_name: str, pattern_value: str):
        """
        Update a specific pattern
        
        Args:
            category: Pattern category (e.g., 'sensitive_data')
            pattern_name: Name of the pattern
            pattern_value: Pattern regex or value
        """
        patterns = self.load_patterns()
        
        if category not in patterns:
            patterns[category] = {}
        
        patterns[category][pattern_name] = pattern_value
        self._save_patterns(patterns)
        self._patterns_cache = None  # Clear cache
    
    def add_security_path(self, path: str):
        """
        Add a new security path to check
        
        Args:
            path: Security path to add
        """
        patterns = self.load_patterns()
        
        if 'security_paths' not in patterns:
            patterns['security_paths'] = []
        
        if path not in patterns['security_paths']:
            patterns['security_paths'].append(path)
            self._save_patterns(patterns)
            self._patterns_cache = None  # Clear cache
    
    def _save_patterns(self, patterns: Dict[str, Any]):
        """Save patterns to configuration file"""
        patterns_file = self.config_dir / "patterns.yaml"
        
        try:
            with open(patterns_file, 'w', encoding='utf-8') as f:
                yaml.dump(patterns, f, default_flow_style=False, indent=2)
        except Exception as e:
            print(f"Error saving patterns config: {e}")
    
    def _save_tool_config(self, config: Dict[str, Any]):
        """Save tool configuration to file"""
        config_file = self.config_dir / "tool_config.yaml"
        
        try:
            with open(config_file, 'w', encoding='utf-8') as f:
                yaml.dump(config, f, default_flow_style=False, indent=2)
        except Exception as e:
            print(f"Error saving tool config: {e}")
    
    def _get_default_patterns(self) -> Dict[str, Any]:
        """Get default pattern configurations"""
        return {
            'sensitive_data': {
                'session_id': r'[Ss]essionid|sid|JSESSIONID|PHPSESSID',
                'jwt_token': r'eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+',
                'uuid': r'[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}',
                'credit_card_numbers': r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|6(?:011|5[0-9]{2})[0-9]{12}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|(?:2131|1800|35\d{3})\d{11})\b',
                'private_ips': r'\b(10\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)|172\.(1[6-9]|2[0-9]|3[0-1])\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)|192\.168\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))\b',
                'api_keys_tokens': r'api[-_]?key|access[-_]?token|secret|code|auth|oauth_token',
                'exposed_files': r'\.(env|yaml|yml|json|xml|log|sql|ini|bak|conf|config|db|dbf|tar|gz|backup|swp|old|key|pem|crt|pfx|pdf|xlsx|xls|ppt|pptx|zip|rar|7z)',
                'sensitive_paths': r'/(admin|login|password|secret|token|account|user|passwd|pwd|callback|oauth|saml|sso|mail|mobile|number|phone|dashboard|manage|panel|portal)',
                'aws_keys': r'AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16}',
                'google_api_keys': r'AIza[0-9A-Za-z_-]{35}',
                'firebase_db_url': r'https:\/\/[a-zA-Z0-9_-]+\.firebaseio\.com',
                'github_tokens': r'ghp_[0-9a-zA-Z]{36}|gho_[0-9a-zA-Z]{36}|ghu_[0-9a-zA-Z]{36}|ghs_[0-9a-zA-Z]{36}|ghr_[0-9a-zA-Z]{36}',
                'email_addresses': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
                'phone_numbers': r'\b(?:\+?1[-.\s]?)?\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}\b',
                'parametrized_urls': r'\?.*='
            },
            'technology_detection': {
                'wordpress': ['wp-content', 'wp-admin', 'wp-includes', 'wordpress'],
                'drupal': ['drupal', '/sites/default/', '/modules/', '/themes/'],
                'joomla': ['joomla', 'administrator', 'components', 'modules'],
                'php': ['.php', 'php', 'PHPSESSID'],
                'asp': ['.asp', '.aspx', 'ASPSESSIONID'],
                'java': ['.jsp', 'jsessionid', 'java'],
                'nodejs': ['node', 'express', 'socket.io'],
                'python': ['django', 'flask', 'python'],
                'ruby': ['rails', 'ruby', 'rack'],
                'react': ['react', '_next', 'webpack'],
                'angular': ['angular', 'ng-'],
                'vue': ['vue', 'nuxt'],
                'nginx': ['nginx'],
                'apache': ['apache'],
                'iis': ['microsoft-iis', 'iis']
            },
            'security_paths': [
                '/admin', '/administrator', '/login', '/wp-admin', '/phpmyadmin',
                '/cpanel', '/webmail', '/ftp', '/backup', '/.env', '/.git',
                '/config', '/database', '/api', '/robots.txt', '/sitemap.xml',
                '/debug', '/test', '/dev', '/admin/debug', '/dashboard',
                '/manage', '/panel', '/portal', '/secret', '/token', '/account',
                '/user', '/passwd', '/pwd', '/callback', '/oauth', '/saml',
                '/sso', '/mail', '/mobile', '/number', '/phone'
            ]
        }
    
    def _get_default_tool_config(self) -> Dict[str, Any]:
        """Get default tool configurations"""
        return {
            'required_tools': [
                'subfinder', 'httpx', 'nuclei'
            ],
            'optional_tools': [
                'assetfinder', 'gau', 'waybackurls', 'gobuster', 'whatweb',
                'unfurl', 'gf', 'uro', 'paramspider'
            ],
            'tool_paths': {
                'nuclei_templates': '/root/nuclei-templates',
                'wordlists_dir': '/usr/share/wordlists'
            },
            'tools': {
                'subfinder': {
                    'timeout': 300,
                    'threads': 10,
                    'silent': True
                },
                'httpx': {
                    'timeout': 10,
                    'threads': 50,
                    'status_codes': [200, 204, 301, 302, 401, 403, 405, 500, 502, 503, 504]
                },
                'nuclei': {
                    'concurrency': 25,
                    'retries': 2,
                    'rate_limit': 150,
                    'timeout': 300
                },
                'gobuster': {
                    'threads': 50,
                    'timeout': 600,
                    'extensions': ['php', 'html', 'txt', 'js']
                },
                'paramspider': {
                    'exclude_extensions': ['css', 'js', 'png', 'jpg', 'gif', 'svg', 'ico', 'woff', 'woff2', 'ttf', 'otf', 'mp4', 'pdf', 'doc', 'docx', 'zip', 'rar']
                }
            },
            'wordlists': {
                'paths': [
                    '/usr/share/wordlists/seclists/Discovery/Web-Content/common.txt',
                    '/usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt',
                    '/usr/share/seclists/Discovery/Web-Content/common.txt',
                    '/usr/share/wordlists/dirb/common.txt',
                    '/usr/share/dirb/wordlists/common.txt'
                ]
            }
        }