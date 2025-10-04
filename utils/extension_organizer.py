"""
Extension Organizer Utility for HyperRecon Pro v4.0
Advanced URL extension-based organization and analysis

This module provides comprehensive URL organization capabilities including:
- Extension-based URL filtering and categorization
- Important file type identification (PHP, JSP, ASP, SQL, etc.)
- Security-focused extension analysis
- Organized file structure creation
- Extension-based vulnerability assessment
"""

import os
import re
import json
from urllib.parse import urlparse, parse_qs
from typing import Dict, List, Set, Tuple, Any, Optional
from dataclasses import dataclass, field
from datetime import datetime
from collections import defaultdict

from .base_utility import BaseUtility, UtilityResult
from .error_handler import ErrorCategory


@dataclass
class ExtensionInfo:
    """Information about a specific file extension"""
    extension: str
    category: str
    risk_level: str
    description: str
    urls: List[str] = field(default_factory=list)
    count: int = 0
    security_notes: List[str] = field(default_factory=list)


class ExtensionOrganizer(BaseUtility):
    """
    Advanced extension-based URL organizer for security-focused reconnaissance
    Categorizes and organizes URLs based on file extensions with security analysis
    """

    def __init__(self, hyperrecon_instance):
        """Initialize Extension Organizer with comprehensive extension mappings"""
        super().__init__(hyperrecon_instance)
        
        # Important extensions with security implications
        self.extension_categories = {
            # Web Application Files (High Priority)
            'web_apps': {
                'extensions': ['.php', '.asp', '.aspx', '.jsp', '.jspx', '.cfm', '.cgi', '.pl', '.py', '.rb'],
                'risk_level': 'HIGH',
                'description': 'Server-side web application files',
                'security_notes': [
                    'May contain source code and logic vulnerabilities',
                    'Potential for code injection attacks',
                    'Could expose application architecture',
                    'May contain hardcoded credentials'
                ]
            },
            
            # Database Files (Critical Priority)
            'database': {
                'extensions': ['.sql', '.db', '.sqlite', '.sqlite3', '.mdb', '.accdb', '.dbf', '.frm', '.myd', '.myi'],
                'risk_level': 'CRITICAL',
                'description': 'Database files and SQL scripts',
                'security_notes': [
                    'May contain sensitive data',
                    'Could expose database structure',
                    'Potential data breach risk',
                    'May contain user credentials'
                ]
            },
            
            # Configuration Files (Critical Priority)
            'config': {
                'extensions': ['.conf', '.cfg', '.ini', '.yaml', '.yml', '.json', '.xml', '.properties', '.env', '.config'],
                'risk_level': 'CRITICAL',
                'description': 'Configuration and settings files',
                'security_notes': [
                    'Often contain sensitive configuration data',
                    'May expose API keys and passwords',
                    'Could reveal system architecture',
                    'Potential for privilege escalation'
                ]
            },
            
            # Backup Files (High Priority)
            'backup': {
                'extensions': ['.bak', '.backup', '.old', '.orig', '.save', '.tmp', '.temp', '.swp', '.swo', '.~'],
                'risk_level': 'HIGH',
                'description': 'Backup and temporary files',
                'security_notes': [
                    'May contain outdated but sensitive information',
                    'Could expose previous versions of files',
                    'Often forgotten and left accessible',
                    'May contain development artifacts'
                ]
            },
            
            # Source Code Files (Medium-High Priority)
            'source_code': {
                'extensions': ['.java', '.c', '.cpp', '.h', '.cs', '.vb', '.go', '.rs', '.swift', '.kt', '.scala'],
                'risk_level': 'MEDIUM',
                'description': 'Source code files',
                'security_notes': [
                    'May expose application logic',
                    'Could contain hardcoded secrets',
                    'Reveals programming patterns',
                    'Potential intellectual property exposure'
                ]
            },
            
            # Script Files (Medium Priority)
            'scripts': {
                'extensions': ['.sh', '.bat', '.cmd', '.ps1', '.vbs', '.js', '.ts', '.coffee', '.lua'],
                'risk_level': 'MEDIUM',
                'description': 'Script and automation files',
                'security_notes': [
                    'May contain automation logic',
                    'Could expose system commands',
                    'Potential for command injection',
                    'May reveal deployment processes'
                ]
            },
            
            # Archive Files (Medium Priority)
            'archives': {
                'extensions': ['.zip', '.rar', '.7z', '.tar', '.gz', '.bz2', '.xz', '.war', '.jar', '.ear'],
                'risk_level': 'MEDIUM',
                'description': 'Archive and compressed files',
                'security_notes': [
                    'May contain multiple sensitive files',
                    'Could expose entire application structure',
                    'Potential for zip bomb attacks',
                    'May contain source code or data'
                ]
            },
            
            # Log Files (Low-Medium Priority)
            'logs': {
                'extensions': ['.log', '.logs', '.out', '.err', '.trace', '.debug'],
                'risk_level': 'LOW',
                'description': 'Log and debug files',
                'security_notes': [
                    'May contain error messages with sensitive info',
                    'Could expose system paths and structure',
                    'May reveal user activities',
                    'Potential information disclosure'
                ]
            },
            
            # Certificate Files (High Priority)
            'certificates': {
                'extensions': ['.pem', '.crt', '.cer', '.p12', '.pfx', '.key', '.pub', '.csr'],
                'risk_level': 'HIGH',
                'description': 'Certificate and key files',
                'security_notes': [
                    'May contain private keys',
                    'Could compromise SSL/TLS security',
                    'Potential for man-in-the-middle attacks',
                    'Critical for secure communications'
                ]
            },
            
            # Document Files (Low Priority)
            'documents': {
                'extensions': ['.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx', '.odt', '.ods', '.odp'],
                'risk_level': 'LOW',
                'description': 'Document files',
                'security_notes': [
                    'May contain sensitive business information',
                    'Could expose organizational structure',
                    'Potential metadata leakage',
                    'May contain embedded objects'
                ]
            },
            
            # Media Files (Very Low Priority)
            'media': {
                'extensions': ['.jpg', '.jpeg', '.png', '.gif', '.bmp', '.svg', '.ico', '.mp3', '.mp4', '.avi', '.mov'],
                'risk_level': 'VERY_LOW',
                'description': 'Media and image files',
                'security_notes': [
                    'May contain EXIF metadata',
                    'Could expose location information',
                    'Potential for steganography',
                    'Generally low security risk'
                ]
            },
            
            # System Files (High Priority)
            'system': {
                'extensions': ['.htaccess', '.htpasswd', '.passwd', '.shadow', '.hosts', '.bashrc', '.profile'],
                'risk_level': 'HIGH',
                'description': 'System and access control files',
                'security_notes': [
                    'Critical system configuration files',
                    'May contain authentication data',
                    'Could expose access control rules',
                    'High security impact if compromised'
                ]
            }
        }
        
        # Create reverse mapping for quick lookup
        self.extension_to_category = {}
        self.extension_info = {}
        
        for category, info in self.extension_categories.items():
            for ext in info['extensions']:
                self.extension_to_category[ext] = category
                self.extension_info[ext] = ExtensionInfo(
                    extension=ext,
                    category=category,
                    risk_level=info['risk_level'],
                    description=info['description'],
                    security_notes=info['security_notes'].copy()
                )
        
        # Priority order for processing (highest risk first)
        self.priority_order = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'VERY_LOW']

    def execute(self, urls: List[str], domain_path: str) -> UtilityResult:
        """
        Execute extension-based URL organization
        
        Args:
            urls: List of URLs to organize by extension
            domain_path: Path to domain-specific output directory
            
        Returns:
            UtilityResult with organized extension data
        """
        self.start_execution()
        self.set_operation("extension_organization")
        
        try:
            if not urls:
                self.log_warning("No URLs provided for extension organization")
                return self.create_result(True, {'extensions': {}, 'summary': {}}, 0)
            
            self.log_info(f"Starting extension organization on {len(urls)} URLs")
            
            # Organize URLs by extension
            organized_data = self._organize_urls_by_extension(urls)
            
            # Generate security analysis
            security_analysis = self._analyze_extension_security(organized_data)
            
            # Create comprehensive summary
            summary = self._generate_extension_summary(organized_data, security_analysis)
            
            # Save organized results
            self._save_extension_results(domain_path, organized_data, security_analysis, summary)
            
            result_data = {
                'extensions': organized_data,
                'security_analysis': security_analysis,
                'summary': summary,
                'total_urls': len(urls),
                'organized_urls': sum(len(data['urls']) for data in organized_data.values()),
                'categories_found': len(organized_data)
            }
            
            self.log_info(f"Extension organization completed: {len(organized_data)} extensions found, {result_data['organized_urls']} URLs organized")
            
            return self.create_result(True, result_data, len(urls))
            
        except Exception as e:
            self.log_error("Extension organization failed", e, ErrorCategory.PROCESSING_ERROR)
            return self.create_result(False, {'error': str(e)}, 0)

    def _organize_urls_by_extension(self, urls: List[str]) -> Dict[str, Dict[str, Any]]:
        """Organize URLs by their file extensions"""
        organized = defaultdict(lambda: {
            'urls': [],
            'count': 0,
            'category': 'unknown',
            'risk_level': 'UNKNOWN',
            'description': 'Unknown file type',
            'security_notes': [],
            'parameters': [],
            'unique_paths': set(),
            'domains': set()
        })
        
        for url in urls:
            try:
                parsed_url = urlparse(url)
                path = parsed_url.path.lower()
                
                # Extract extension
                if '.' in path:
                    extension = '.' + path.split('.')[-1]
                    
                    # Skip if extension is too long (likely not a real extension)
                    if len(extension) > 10:
                        continue
                    
                    # Get extension info
                    if extension in self.extension_info:
                        ext_info = self.extension_info[extension]
                        organized[extension].update({
                            'category': ext_info.category,
                            'risk_level': ext_info.risk_level,
                            'description': ext_info.description,
                            'security_notes': ext_info.security_notes
                        })
                    else:
                        # Unknown extension
                        organized[extension].update({
                            'category': 'unknown',
                            'risk_level': 'UNKNOWN',
                            'description': f'Unknown file type: {extension}',
                            'security_notes': ['Unknown file type - requires manual analysis']
                        })
                    
                    # Add URL data
                    organized[extension]['urls'].append(url)
                    organized[extension]['count'] += 1
                    organized[extension]['unique_paths'].add(parsed_url.path)
                    organized[extension]['domains'].add(parsed_url.netloc)
                    
                    # Extract parameters if present
                    if parsed_url.query:
                        params = parse_qs(parsed_url.query)
                        for param in params.keys():
                            if param not in organized[extension]['parameters']:
                                organized[extension]['parameters'].append(param)
                
            except Exception as e:
                self.log_warning(f"Failed to process URL {url}: {str(e)}")
                continue
        
        # Convert sets to lists for JSON serialization
        for ext_data in organized.values():
            ext_data['unique_paths'] = list(ext_data['unique_paths'])
            ext_data['domains'] = list(ext_data['domains'])
        
        return dict(organized)

    def _analyze_extension_security(self, organized_data: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze security implications of found extensions"""
        analysis = {
            'risk_distribution': defaultdict(int),
            'category_distribution': defaultdict(int),
            'high_risk_extensions': [],
            'critical_findings': [],
            'security_recommendations': [],
            'attack_vectors': [],
            'priority_targets': []
        }
        
        for extension, data in organized_data.items():
            risk_level = data['risk_level']
            category = data['category']
            count = data['count']
            
            # Update distributions
            analysis['risk_distribution'][risk_level] += count
            analysis['category_distribution'][category] += count
            
            # Identify high-risk extensions
            if risk_level in ['CRITICAL', 'HIGH']:
                analysis['high_risk_extensions'].append({
                    'extension': extension,
                    'risk_level': risk_level,
                    'count': count,
                    'category': category,
                    'urls': data['urls'][:5]  # First 5 URLs as examples
                })
            
            # Generate critical findings
            if risk_level == 'CRITICAL':
                analysis['critical_findings'].append({
                    'extension': extension,
                    'count': count,
                    'description': data['description'],
                    'security_impact': f"Found {count} {extension} files - {data['description']}",
                    'urls': data['urls']
                })
            
            # Identify potential attack vectors
            if category in ['web_apps', 'database', 'config']:
                analysis['attack_vectors'].append({
                    'extension': extension,
                    'category': category,
                    'attack_types': self._get_attack_vectors_for_category(category),
                    'count': count
                })
        
        # Generate security recommendations
        analysis['security_recommendations'] = self._generate_security_recommendations(organized_data)
        
        # Identify priority targets (highest risk + highest count)
        priority_targets = []
        for extension, data in organized_data.items():
            if data['risk_level'] in ['CRITICAL', 'HIGH']:
                priority_score = self._calculate_priority_score(data['risk_level'], data['count'])
                priority_targets.append({
                    'extension': extension,
                    'priority_score': priority_score,
                    'risk_level': data['risk_level'],
                    'count': data['count'],
                    'category': data['category']
                })
        
        # Sort by priority score
        analysis['priority_targets'] = sorted(priority_targets, key=lambda x: x['priority_score'], reverse=True)[:10]
        
        return analysis

    def _get_attack_vectors_for_category(self, category: str) -> List[str]:
        """Get potential attack vectors for a file category"""
        attack_vectors = {
            'web_apps': [
                'Code Injection', 'SQL Injection', 'XSS', 'Remote Code Execution',
                'Path Traversal', 'Authentication Bypass'
            ],
            'database': [
                'Data Breach', 'SQL Injection', 'Privilege Escalation',
                'Information Disclosure', 'Database Enumeration'
            ],
            'config': [
                'Configuration Disclosure', 'Credential Exposure', 'API Key Leakage',
                'System Information Disclosure', 'Privilege Escalation'
            ],
            'backup': [
                'Information Disclosure', 'Source Code Exposure', 'Data Breach',
                'Historical Data Access'
            ],
            'certificates': [
                'Man-in-the-Middle', 'SSL/TLS Compromise', 'Certificate Theft',
                'Cryptographic Attacks'
            ]
        }
        
        return attack_vectors.get(category, ['Information Disclosure', 'Unauthorized Access'])

    def _calculate_priority_score(self, risk_level: str, count: int) -> int:
        """Calculate priority score based on risk level and count"""
        risk_multipliers = {
            'CRITICAL': 100,
            'HIGH': 50,
            'MEDIUM': 25,
            'LOW': 10,
            'VERY_LOW': 5,
            'UNKNOWN': 1
        }
        
        base_score = risk_multipliers.get(risk_level, 1)
        count_bonus = min(count * 5, 50)  # Max 50 bonus points for count
        
        return base_score + count_bonus

    def _generate_security_recommendations(self, organized_data: Dict[str, Dict[str, Any]]) -> List[str]:
        """Generate security recommendations based on found extensions"""
        recommendations = []
        
        # Check for critical extensions
        critical_extensions = [ext for ext, data in organized_data.items() if data['risk_level'] == 'CRITICAL']
        if critical_extensions:
            recommendations.append(f"URGENT: Secure or remove {len(critical_extensions)} critical file types: {', '.join(critical_extensions[:5])}")
        
        # Check for web application files
        web_app_extensions = [ext for ext, data in organized_data.items() if data['category'] == 'web_apps']
        if web_app_extensions:
            recommendations.append(f"Review {len(web_app_extensions)} web application files for vulnerabilities")
        
        # Check for database files
        db_extensions = [ext for ext, data in organized_data.items() if data['category'] == 'database']
        if db_extensions:
            recommendations.append(f"Immediately secure {len(db_extensions)} database file types from public access")
        
        # Check for configuration files
        config_extensions = [ext for ext, data in organized_data.items() if data['category'] == 'config']
        if config_extensions:
            recommendations.append(f"Audit {len(config_extensions)} configuration file types for sensitive data")
        
        # Check for backup files
        backup_extensions = [ext for ext, data in organized_data.items() if data['category'] == 'backup']
        if backup_extensions:
            recommendations.append(f"Remove or secure {len(backup_extensions)} backup file types")
        
        # General recommendations
        high_risk_count = sum(1 for data in organized_data.values() if data['risk_level'] in ['CRITICAL', 'HIGH'])
        if high_risk_count > 5:
            recommendations.append("Implement comprehensive file access controls")
            recommendations.append("Conduct security audit of exposed file types")
        
        if not recommendations:
            recommendations.append("Continue monitoring for sensitive file exposures")
        
        return recommendations

    def _generate_extension_summary(self, organized_data: Dict[str, Dict[str, Any]], 
                                  security_analysis: Dict[str, Any]) -> Dict[str, Any]:
        """Generate comprehensive extension organization summary"""
        
        total_urls = sum(data['count'] for data in organized_data.values())
        total_extensions = len(organized_data)
        
        # Calculate statistics
        risk_stats = dict(security_analysis['risk_distribution'])
        category_stats = dict(security_analysis['category_distribution'])
        
        # Top extensions by count
        top_extensions = sorted(
            [(ext, data['count'], data['risk_level']) for ext, data in organized_data.items()],
            key=lambda x: x[1], reverse=True
        )[:10]
        
        # High-risk summary
        high_risk_count = risk_stats.get('CRITICAL', 0) + risk_stats.get('HIGH', 0)
        critical_count = risk_stats.get('CRITICAL', 0)
        
        return {
            'total_urls_organized': total_urls,
            'total_extensions_found': total_extensions,
            'risk_distribution': risk_stats,
            'category_distribution': category_stats,
            'top_extensions': top_extensions,
            'high_risk_files': high_risk_count,
            'critical_files': critical_count,
            'security_score': self._calculate_security_score(risk_stats),
            'organization_timestamp': datetime.now().isoformat(),
            'recommendations_count': len(security_analysis['security_recommendations']),
            'priority_targets_count': len(security_analysis['priority_targets']),
            'attack_vectors_identified': len(security_analysis['attack_vectors'])
        }

    def _calculate_security_score(self, risk_stats: Dict[str, int]) -> Dict[str, Any]:
        """Calculate overall security score based on risk distribution"""
        total_files = sum(risk_stats.values())
        if total_files == 0:
            return {'score': 100, 'level': 'EXCELLENT', 'description': 'No files found'}
        
        # Weight different risk levels (negative impact on score)
        weights = {'CRITICAL': -50, 'HIGH': -25, 'MEDIUM': -10, 'LOW': -2, 'VERY_LOW': -1, 'UNKNOWN': -5}
        
        weighted_score = sum(risk_stats.get(risk, 0) * weight for risk, weight in weights.items())
        base_score = 100
        # Normalize the weighted score
        normalized_penalty = weighted_score / total_files if total_files > 0 else 0
        final_score = max(0, min(100, base_score + normalized_penalty))
        
        # Determine security level
        if final_score >= 90:
            level = 'EXCELLENT'
        elif final_score >= 75:
            level = 'GOOD'
        elif final_score >= 50:
            level = 'MODERATE'
        elif final_score >= 25:
            level = 'POOR'
        else:
            level = 'CRITICAL'
        
        return {
            'score': round(final_score, 1),
            'level': level,
            'description': f'Security score based on {total_files} files analyzed'
        }

    def _save_extension_results(self, domain_path: str, organized_data: Dict[str, Dict[str, Any]],
                              security_analysis: Dict[str, Any], summary: Dict[str, Any]):
        """Save extension organization results to files"""
        try:
            # Create extensions directory
            extensions_dir = os.path.join(domain_path, 'extensions')
            
            # Save organized data by extension
            for extension, data in organized_data.items():
                # Clean extension name for filename
                clean_ext = extension.replace('.', '').replace('/', '_')
                
                # Create category subdirectory
                category_dir = os.path.join(extensions_dir, data['category'])
                
                # Save URLs for this extension
                urls_content = []
                urls_content.append(f"# {extension.upper()} Files ({data['count']} found)")
                urls_content.append(f"# Category: {data['category']}")
                urls_content.append(f"# Risk Level: {data['risk_level']}")
                urls_content.append(f"# Description: {data['description']}")
                urls_content.append("")
                
                if data['security_notes']:
                    urls_content.append("# Security Notes:")
                    for note in data['security_notes']:
                        urls_content.append(f"# - {note}")
                    urls_content.append("")
                
                urls_content.append("# URLs:")
                urls_content.extend(data['urls'])
                
                if data['parameters']:
                    urls_content.append("")
                    urls_content.append("# Common Parameters:")
                    urls_content.extend([f"# - {param}" for param in data['parameters']])
                
                self.save_results(domain_path, f'extensions/{data["category"]}', 
                                f'{clean_ext}_urls.txt', '\n'.join(urls_content))
            
            # Save comprehensive summary
            self.save_results(domain_path, 'extensions', 'extension_summary.json',
                            json.dumps(summary, indent=2))
            
            # Save security analysis
            # Convert defaultdict to regular dict for JSON serialization
            security_analysis_clean = {}
            for key, value in security_analysis.items():
                if isinstance(value, defaultdict):
                    security_analysis_clean[key] = dict(value)
                else:
                    security_analysis_clean[key] = value
            
            self.save_results(domain_path, 'extensions', 'security_analysis.json',
                            json.dumps(security_analysis_clean, indent=2))
            
            # Save high-risk extensions report
            if security_analysis['high_risk_extensions']:
                high_risk_report = []
                high_risk_report.append("HIGH-RISK EXTENSIONS FOUND")
                high_risk_report.append("=" * 40)
                
                for ext_info in security_analysis['high_risk_extensions']:
                    high_risk_report.append(f"\nExtension: {ext_info['extension']}")
                    high_risk_report.append(f"Risk Level: {ext_info['risk_level']}")
                    high_risk_report.append(f"Category: {ext_info['category']}")
                    high_risk_report.append(f"Count: {ext_info['count']}")
                    high_risk_report.append("Sample URLs:")
                    for url in ext_info['urls']:
                        high_risk_report.append(f"  - {url}")
                    high_risk_report.append("-" * 30)
                
                self.save_results(domain_path, 'extensions', 'high_risk_extensions.txt',
                                '\n'.join(high_risk_report))
            
            # Save all extensions overview
            overview = []
            overview.append("EXTENSION ORGANIZATION OVERVIEW")
            overview.append("=" * 50)
            overview.append(f"Total URLs Organized: {summary['total_urls_organized']}")
            overview.append(f"Total Extensions Found: {summary['total_extensions_found']}")
            overview.append(f"High-Risk Files: {summary['high_risk_files']}")
            overview.append(f"Critical Files: {summary['critical_files']}")
            overview.append(f"Security Score: {summary['security_score']['score']}/100 ({summary['security_score']['level']})")
            overview.append("")
            
            overview.append("TOP EXTENSIONS BY COUNT:")
            for ext, count, risk in summary['top_extensions']:
                overview.append(f"  {ext}: {count} files (Risk: {risk})")
            
            overview.append("")
            overview.append("SECURITY RECOMMENDATIONS:")
            for i, rec in enumerate(security_analysis['security_recommendations'], 1):
                overview.append(f"  {i}. {rec}")
            
            self.save_results(domain_path, 'extensions', 'overview.txt', '\n'.join(overview))
            
            self.log_info(f"Extension organization results saved to {domain_path}/extensions/")
            
        except Exception as e:
            self.log_error("Failed to save extension results", e, ErrorCategory.FILE_ERROR)

    def validate_dependencies(self) -> Tuple[bool, List[str]]:
        """Validate dependencies for extension organization"""
        # Extension organizer uses only built-in libraries
        missing_deps = []
        
        try:
            import json
            import re
            from urllib.parse import urlparse, parse_qs
            from collections import defaultdict
        except ImportError as e:
            missing_deps.append(str(e))
        
        return len(missing_deps) == 0, missing_deps

    def get_supported_extensions(self) -> Dict[str, List[str]]:
        """Get all supported extensions by category"""
        return {category: info['extensions'] for category, info in self.extension_categories.items()}

    def get_extension_info(self, extension: str) -> Optional[ExtensionInfo]:
        """Get information about a specific extension"""
        return self.extension_info.get(extension)

    def add_custom_extension(self, extension: str, category: str, risk_level: str, 
                           description: str, security_notes: List[str] = None):
        """Add custom extension mapping"""
        if security_notes is None:
            security_notes = []
        
        # Add to category if exists, otherwise create new
        if category not in self.extension_categories:
            self.extension_categories[category] = {
                'extensions': [],
                'risk_level': risk_level,
                'description': f'Custom category: {category}',
                'security_notes': []
            }
        
        self.extension_categories[category]['extensions'].append(extension)
        
        # Update mappings
        self.extension_to_category[extension] = category
        self.extension_info[extension] = ExtensionInfo(
            extension=extension,
            category=category,
            risk_level=risk_level,
            description=description,
            security_notes=security_notes
        )
        
        self.log_info(f"Added custom extension: {extension} to category {category}")

    def get_extension_statistics(self, organized_data: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
        """Get detailed statistics about organized extensions"""
        stats = {
            'total_extensions': len(organized_data),
            'total_urls': sum(data['count'] for data in organized_data.values()),
            'by_category': defaultdict(int),
            'by_risk_level': defaultdict(int),
            'top_domains': defaultdict(int),
            'most_common_parameters': defaultdict(int)
        }
        
        for data in organized_data.values():
            stats['by_category'][data['category']] += data['count']
            stats['by_risk_level'][data['risk_level']] += data['count']
            
            for domain in data['domains']:
                stats['top_domains'][domain] += data['count']
            
            for param in data['parameters']:
                stats['most_common_parameters'][param] += 1
        
        # Convert to regular dicts and get top items
        stats['by_category'] = dict(stats['by_category'])
        stats['by_risk_level'] = dict(stats['by_risk_level'])
        stats['top_domains'] = dict(sorted(stats['top_domains'].items(), key=lambda x: x[1], reverse=True)[:10])
        stats['most_common_parameters'] = dict(sorted(stats['most_common_parameters'].items(), key=lambda x: x[1], reverse=True)[:10])
        
        return stats