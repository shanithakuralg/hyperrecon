"""
Document Analyzer Utility for HyperRecon Pro v4.0
Advanced document filtering and sensitive data detection

This module provides comprehensive document analysis capabilities including:
- Document type filtering (PDF, DOC, XLS, etc.)
- Sensitive data pattern detection
- Content analysis and metadata extraction
- Security-focused document assessment
"""

import os
import re
import json
import requests
from urllib.parse import urlparse, urljoin
from typing import Dict, List, Set, Tuple, Any, Optional
from dataclasses import dataclass
from datetime import datetime

from .base_utility import BaseUtility, UtilityResult
from .error_handler import ErrorCategory


@dataclass
class DocumentInfo:
    """Information about a discovered document"""
    url: str
    filename: str
    extension: str
    size: Optional[int] = None
    content_type: Optional[str] = None
    last_modified: Optional[str] = None
    sensitive_patterns: List[str] = None
    risk_level: str = "LOW"
    metadata: Dict[str, Any] = None

    def __post_init__(self):
        if self.sensitive_patterns is None:
            self.sensitive_patterns = []
        if self.metadata is None:
            self.metadata = {}


class DocumentAnalyzer(BaseUtility):
    """
    Advanced document analyzer for filtering and analyzing documents
    Focuses on security-relevant document discovery and sensitive data detection
    """

    def __init__(self, hyperrecon_instance):
        """Initialize Document Analyzer with enhanced patterns and filters"""
        super().__init__(hyperrecon_instance)
        
        # Document extensions to analyze
        self.document_extensions = {
            # Office Documents
            'office': ['.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx', '.odt', '.ods', '.odp'],
            # PDF Documents
            'pdf': ['.pdf'],
            # Text Documents
            'text': ['.txt', '.rtf', '.csv', '.tsv'],
            # Archive Files
            'archive': ['.zip', '.rar', '.7z', '.tar', '.gz', '.bz2'],
            # Configuration Files
            'config': ['.conf', '.cfg', '.ini', '.yaml', '.yml', '.json', '.xml'],
            # Database Files
            'database': ['.sql', '.db', '.sqlite', '.mdb', '.accdb'],
            # Backup Files
            'backup': ['.bak', '.backup', '.old', '.orig', '.save'],
            # Log Files
            'logs': ['.log', '.logs'],
            # Source Code (potentially sensitive)
            'source': ['.php', '.asp', '.aspx', '.jsp', '.py', '.rb', '.pl', '.sh', '.bat'],
            # Certificate Files
            'certificates': ['.pem', '.crt', '.cer', '.p12', '.pfx', '.key'],
            # Other Sensitive
            'sensitive': ['.env', '.htaccess', '.htpasswd', '.passwd', '.shadow']
        }
        
        # Sensitive data patterns
        self.sensitive_patterns = {
            'credentials': {
                'password': [
                    r'password\s*[:=]\s*["\']?([^"\'\s]+)["\']?',
                    r'pwd\s*[:=]\s*["\']?([^"\'\s]+)["\']?',
                    r'pass\s*[:=]\s*["\']?([^"\'\s]+)["\']?',
                    r'secret\s*[:=]\s*["\']?([^"\'\s]+)["\']?'
                ],
                'username': [
                    r'username\s*[:=]\s*["\']?([^"\'\s]+)["\']?',
                    r'user\s*[:=]\s*["\']?([^"\'\s]+)["\']?',
                    r'login\s*[:=]\s*["\']?([^"\'\s]+)["\']?'
                ],
                'api_key': [
                    r'api[_-]?key\s*[:=]\s*["\']?([a-zA-Z0-9_-]{20,})["\']?',
                    r'apikey\s*[:=]\s*["\']?([a-zA-Z0-9_-]{20,})["\']?',
                    r'access[_-]?token\s*[:=]\s*["\']?([a-zA-Z0-9_-]{20,})["\']?'
                ]
            },
            'database': {
                'connection_string': [
                    r'server\s*=\s*["\']?([^"\'\s;]+)["\']?',
                    r'database\s*=\s*["\']?([^"\'\s;]+)["\']?',
                    r'host\s*[:=]\s*["\']?([^"\'\s]+)["\']?',
                    r'port\s*[:=]\s*["\']?(\d+)["\']?'
                ],
                'sql_queries': [
                    r'SELECT\s+.*\s+FROM\s+\w+',
                    r'INSERT\s+INTO\s+\w+',
                    r'UPDATE\s+\w+\s+SET',
                    r'DELETE\s+FROM\s+\w+'
                ]
            },
            'personal_info': {
                'email': [
                    r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
                ],
                'phone': [
                    r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b',
                    r'\b\+\d{1,3}[-.\s]?\d{3,4}[-.\s]?\d{3,4}[-.\s]?\d{3,4}\b'
                ],
                'ssn': [
                    r'\b\d{3}-\d{2}-\d{4}\b',
                    r'\b\d{9}\b'
                ],
                'credit_card': [
                    r'\b4\d{3}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b',  # Visa
                    r'\b5[1-5]\d{2}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b',  # MasterCard
                    r'\b3[47]\d{2}[-\s]?\d{6}[-\s]?\d{5}\b'  # American Express
                ]
            },
            'security': {
                'private_key': [
                    r'-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----',
                    r'-----BEGIN\s+ENCRYPTED\s+PRIVATE\s+KEY-----'
                ],
                'certificate': [
                    r'-----BEGIN\s+CERTIFICATE-----'
                ],
                'hash': [
                    r'\b[a-fA-F0-9]{32}\b',  # MD5
                    r'\b[a-fA-F0-9]{40}\b',  # SHA1
                    r'\b[a-fA-F0-9]{64}\b'   # SHA256
                ]
            },
            'cloud_services': {
                'aws': [
                    r'AKIA[0-9A-Z]{16}',  # AWS Access Key
                    r'aws_access_key_id\s*[:=]\s*["\']?([^"\'\s]+)["\']?',
                    r'aws_secret_access_key\s*[:=]\s*["\']?([^"\'\s]+)["\']?'
                ],
                'google': [
                    r'AIza[0-9A-Za-z_-]{35}',  # Google API Key
                    r'ya29\.[0-9A-Za-z_-]+',  # Google OAuth
                ],
                'github': [
                    r'ghp_[0-9A-Za-z]{36}',  # GitHub Personal Access Token
                    r'github_pat_[0-9A-Za-z_]{82}'  # GitHub Fine-grained PAT
                ]
            },
            'internal_info': {
                'internal_ip': [
                    r'\b10\.(?:[0-9]{1,3}\.){2}[0-9]{1,3}\b',
                    r'\b172\.(?:1[6-9]|2[0-9]|3[01])\.(?:[0-9]{1,3}\.)[0-9]{1,3}\b',
                    r'\b192\.168\.(?:[0-9]{1,3}\.)[0-9]{1,3}\b'
                ],
                'internal_domain': [
                    r'\b\w+\.local\b',
                    r'\b\w+\.internal\b',
                    r'\b\w+\.corp\b'
                ],
                'file_paths': [
                    r'[C-Z]:\\(?:[^\\/:*?"<>|\r\n]+\\)*[^\\/:*?"<>|\r\n]*',  # Windows paths
                    r'/(?:home|root|etc|var|usr|opt)/[^\s]*',  # Linux paths
                ]
            }
        }
        
        # Risk assessment criteria
        self.risk_criteria = {
            'CRITICAL': ['private_key', 'certificate', 'aws', 'github', 'api_key'],
            'HIGH': ['password', 'connection_string', 'credit_card', 'ssn'],
            'MEDIUM': ['username', 'email', 'phone', 'internal_ip', 'hash'],
            'LOW': ['sql_queries', 'internal_domain', 'file_paths']
        }
        
        # Session for HTTP requests
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })

    def execute(self, urls: List[str], domain_path: str) -> UtilityResult:
        """
        Execute document analysis on provided URLs
        
        Args:
            urls: List of URLs to analyze for documents
            domain_path: Path to domain-specific output directory
            
        Returns:
            UtilityResult with document analysis results
        """
        self.start_execution()
        self.set_operation("document_analysis")
        
        try:
            if not urls:
                self.log_warning("No URLs provided for document analysis")
                return self.create_result(True, {'documents': {}, 'summary': {}}, 0)
            
            self.log_info(f"Starting document analysis on {len(urls)} URLs")
            
            # Filter URLs for potential documents
            document_urls = self._filter_document_urls(urls)
            self.log_info(f"Found {len(document_urls)} potential document URLs")
            
            # Analyze each document URL
            analyzed_documents = {}
            sensitive_findings = {}
            
            for url in document_urls:
                try:
                    doc_info = self._analyze_document_url(url)
                    if doc_info:
                        analyzed_documents[url] = doc_info
                        
                        # Collect sensitive findings
                        if doc_info.sensitive_patterns:
                            sensitive_findings[url] = {
                                'filename': doc_info.filename,
                                'patterns': doc_info.sensitive_patterns,
                                'risk_level': doc_info.risk_level,
                                'extension': doc_info.extension
                            }
                            
                except Exception as e:
                    self.log_warning(f"Failed to analyze document {url}: {str(e)}")
                    continue
            
            # Generate comprehensive summary
            summary = self._generate_document_summary(analyzed_documents, sensitive_findings)
            
            # Save results
            self._save_document_results(domain_path, analyzed_documents, sensitive_findings, summary)
            
            result_data = {
                'documents': analyzed_documents,
                'sensitive_findings': sensitive_findings,
                'summary': summary,
                'total_documents': len(analyzed_documents),
                'sensitive_documents': len(sensitive_findings)
            }
            
            self.log_info(f"Document analysis completed: {len(analyzed_documents)} documents analyzed, {len(sensitive_findings)} with sensitive data")
            
            return self.create_result(True, result_data, len(analyzed_documents))
            
        except Exception as e:
            self.log_error("Document analysis failed", e, ErrorCategory.PROCESSING_ERROR)
            return self.create_result(False, {'error': str(e)}, 0)

    def _filter_document_urls(self, urls: List[str]) -> List[str]:
        """Filter URLs that likely point to documents"""
        document_urls = []
        
        # Get all extensions we're interested in
        all_extensions = []
        for ext_list in self.document_extensions.values():
            all_extensions.extend(ext_list)
        
        for url in urls:
            try:
                parsed_url = urlparse(url)
                path = parsed_url.path.lower()
                
                # Check if URL ends with document extension
                for ext in all_extensions:
                    if path.endswith(ext):
                        document_urls.append(url)
                        break
                else:
                    # Check for common document patterns in URL
                    if any(pattern in path for pattern in [
                        'download', 'file', 'doc', 'pdf', 'upload', 'attachment',
                        'document', 'report', 'manual', 'guide', 'backup'
                    ]):
                        document_urls.append(url)
                        
            except Exception as e:
                self.log_warning(f"Failed to parse URL {url}: {str(e)}")
                continue
        
        return list(set(document_urls))  # Remove duplicates

    def _analyze_document_url(self, url: str) -> Optional[DocumentInfo]:
        """Analyze a single document URL"""
        try:
            # Get document metadata via HEAD request
            response = self.session.head(url, timeout=10, allow_redirects=True)
            
            if response.status_code not in [200, 206]:
                return None
            
            # Extract basic information
            parsed_url = urlparse(url)
            filename = os.path.basename(parsed_url.path) or 'unknown'
            extension = os.path.splitext(filename)[1].lower()
            
            # Get metadata from headers
            content_type = response.headers.get('content-type', '')
            content_length = response.headers.get('content-length')
            last_modified = response.headers.get('last-modified')
            
            size = int(content_length) if content_length and content_length.isdigit() else None
            
            # Create document info
            doc_info = DocumentInfo(
                url=url,
                filename=filename,
                extension=extension,
                size=size,
                content_type=content_type,
                last_modified=last_modified,
                metadata={
                    'headers': dict(response.headers),
                    'status_code': response.status_code,
                    'final_url': response.url
                }
            )
            
            # Attempt to analyze content for sensitive data (for small files)
            if size and size < 1024 * 1024:  # Only analyze files < 1MB
                try:
                    content_response = self.session.get(url, timeout=15, stream=True)
                    if content_response.status_code == 200:
                        # Read first chunk of content
                        content_chunk = content_response.raw.read(8192).decode('utf-8', errors='ignore')
                        sensitive_patterns = self._detect_sensitive_patterns(content_chunk)
                        doc_info.sensitive_patterns = sensitive_patterns
                        doc_info.risk_level = self._calculate_risk_level(sensitive_patterns)
                except Exception as e:
                    self.log_warning(f"Failed to analyze content of {url}: {str(e)}")
            
            # Determine document category
            doc_category = self._categorize_document(extension)
            doc_info.metadata['category'] = doc_category
            
            return doc_info
            
        except Exception as e:
            self.log_warning(f"Failed to analyze document URL {url}: {str(e)}")
            return None

    def _detect_sensitive_patterns(self, content: str) -> List[str]:
        """Detect sensitive data patterns in content"""
        found_patterns = []
        
        for category, patterns in self.sensitive_patterns.items():
            for pattern_type, pattern_list in patterns.items():
                for pattern in pattern_list:
                    try:
                        if re.search(pattern, content, re.IGNORECASE | re.MULTILINE):
                            pattern_name = f"{category}.{pattern_type}"
                            if pattern_name not in found_patterns:
                                found_patterns.append(pattern_name)
                    except re.error as e:
                        self.log_warning(f"Invalid regex pattern {pattern}: {str(e)}")
                        continue
        
        return found_patterns

    def _calculate_risk_level(self, sensitive_patterns: List[str]) -> str:
        """Calculate risk level based on found sensitive patterns"""
        if not sensitive_patterns:
            return "LOW"
        
        # Check for critical patterns
        for pattern in sensitive_patterns:
            for risk_level, critical_patterns in self.risk_criteria.items():
                if any(critical_pattern in pattern for critical_pattern in critical_patterns):
                    return risk_level
        
        return "LOW"

    def _categorize_document(self, extension: str) -> str:
        """Categorize document based on extension"""
        for category, extensions in self.document_extensions.items():
            if extension in extensions:
                return category
        return "unknown"

    def _generate_document_summary(self, documents: Dict[str, DocumentInfo], 
                                 sensitive_findings: Dict[str, Any]) -> Dict[str, Any]:
        """Generate comprehensive document analysis summary"""
        
        # Category distribution
        category_counts = {}
        extension_counts = {}
        risk_distribution = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        
        total_size = 0
        
        for doc_info in documents.values():
            # Count categories
            category = doc_info.metadata.get('category', 'unknown')
            category_counts[category] = category_counts.get(category, 0) + 1
            
            # Count extensions
            ext = doc_info.extension or 'unknown'
            extension_counts[ext] = extension_counts.get(ext, 0) + 1
            
            # Count risk levels
            risk_distribution[doc_info.risk_level] += 1
            
            # Sum sizes
            if doc_info.size:
                total_size += doc_info.size
        
        # Sensitive pattern analysis
        pattern_frequency = {}
        for finding in sensitive_findings.values():
            for pattern in finding['patterns']:
                pattern_frequency[pattern] = pattern_frequency.get(pattern, 0) + 1
        
        # Most common sensitive patterns
        top_patterns = sorted(pattern_frequency.items(), key=lambda x: x[1], reverse=True)[:10]
        
        # High-risk documents
        high_risk_docs = [
            {
                'url': url,
                'filename': finding['filename'],
                'risk_level': finding['risk_level'],
                'patterns': finding['patterns']
            }
            for url, finding in sensitive_findings.items()
            if finding['risk_level'] in ['CRITICAL', 'HIGH']
        ]
        
        return {
            'total_documents': len(documents),
            'sensitive_documents': len(sensitive_findings),
            'total_size_bytes': total_size,
            'total_size_mb': round(total_size / (1024 * 1024), 2) if total_size > 0 else 0,
            'category_distribution': category_counts,
            'extension_distribution': extension_counts,
            'risk_distribution': risk_distribution,
            'pattern_frequency': pattern_frequency,
            'top_sensitive_patterns': top_patterns,
            'high_risk_documents': high_risk_docs,
            'analysis_timestamp': datetime.now().isoformat(),
            'recommendations': self._generate_recommendations(documents, sensitive_findings)
        }

    def _generate_recommendations(self, documents: Dict[str, DocumentInfo], 
                                sensitive_findings: Dict[str, Any]) -> List[str]:
        """Generate security recommendations based on findings"""
        recommendations = []
        
        if sensitive_findings:
            recommendations.append(f"Review {len(sensitive_findings)} documents containing sensitive data")
        
        # Check for critical findings
        critical_docs = [f for f in sensitive_findings.values() if f['risk_level'] == 'CRITICAL']
        if critical_docs:
            recommendations.append(f"URGENT: {len(critical_docs)} documents contain critical sensitive data (API keys, private keys)")
        
        # Check for high-risk findings
        high_risk_docs = [f for f in sensitive_findings.values() if f['risk_level'] == 'HIGH']
        if high_risk_docs:
            recommendations.append(f"HIGH PRIORITY: {len(high_risk_docs)} documents contain high-risk data (passwords, credentials)")
        
        # Check for backup files
        backup_docs = [d for d in documents.values() if d.metadata.get('category') == 'backup']
        if backup_docs:
            recommendations.append(f"Secure or remove {len(backup_docs)} backup files from public access")
        
        # Check for config files
        config_docs = [d for d in documents.values() if d.metadata.get('category') == 'config']
        if config_docs:
            recommendations.append(f"Review {len(config_docs)} configuration files for sensitive information")
        
        # Check for database files
        db_docs = [d for d in documents.values() if d.metadata.get('category') == 'database']
        if db_docs:
            recommendations.append(f"Secure {len(db_docs)} database files immediately")
        
        if not recommendations:
            recommendations.append("No immediate security concerns found in document analysis")
        
        return recommendations

    def _save_document_results(self, domain_path: str, documents: Dict[str, DocumentInfo],
                             sensitive_findings: Dict[str, Any], summary: Dict[str, Any]):
        """Save document analysis results to files"""
        try:
            # Save all documents list
            documents_list = []
            for url, doc_info in documents.items():
                documents_list.append({
                    'url': url,
                    'filename': doc_info.filename,
                    'extension': doc_info.extension,
                    'size': doc_info.size,
                    'content_type': doc_info.content_type,
                    'last_modified': doc_info.last_modified,
                    'category': doc_info.metadata.get('category', 'unknown'),
                    'risk_level': doc_info.risk_level,
                    'sensitive_patterns': doc_info.sensitive_patterns
                })
            
            self.save_results(domain_path, 'documents', 'all_documents.json', 
                            json.dumps(documents_list, indent=2))
            
            # Save sensitive findings separately
            if sensitive_findings:
                self.save_results(domain_path, 'documents', 'sensitive_documents.json',
                                json.dumps(sensitive_findings, indent=2))
                
                # Save sensitive findings as text for easy review
                sensitive_text = []
                sensitive_text.append("SENSITIVE DOCUMENTS FOUND")
                sensitive_text.append("=" * 50)
                
                for url, finding in sensitive_findings.items():
                    sensitive_text.append(f"\nURL: {url}")
                    sensitive_text.append(f"File: {finding['filename']}")
                    sensitive_text.append(f"Risk Level: {finding['risk_level']}")
                    sensitive_text.append(f"Extension: {finding['extension']}")
                    sensitive_text.append("Sensitive Patterns Found:")
                    for pattern in finding['patterns']:
                        sensitive_text.append(f"  - {pattern}")
                    sensitive_text.append("-" * 30)
                
                self.save_results(domain_path, 'documents', 'sensitive_documents.txt',
                                '\n'.join(sensitive_text))
            
            # Save summary
            self.save_results(domain_path, 'documents', 'document_summary.json',
                            json.dumps(summary, indent=2))
            
            # Save URLs only for easy processing
            document_urls = list(documents.keys())
            self.save_results(domain_path, 'documents', 'document_urls.txt',
                            '\n'.join(document_urls))
            
            self.log_info(f"Document analysis results saved to {domain_path}/documents/")
            
        except Exception as e:
            self.log_error("Failed to save document results", e, ErrorCategory.FILE_ERROR)

    def validate_dependencies(self) -> Tuple[bool, List[str]]:
        """Validate dependencies for document analysis"""
        # Document analyzer primarily uses built-in libraries
        # Only requires requests which should already be available
        missing_deps = []
        
        try:
            import requests
        except ImportError:
            missing_deps.append('requests')
        
        try:
            import re
        except ImportError:
            missing_deps.append('re')  # This should never happen as it's built-in
        
        return len(missing_deps) == 0, missing_deps

    def get_supported_extensions(self) -> Dict[str, List[str]]:
        """Get all supported document extensions by category"""
        return self.document_extensions.copy()

    def get_sensitive_patterns(self) -> Dict[str, Any]:
        """Get all sensitive data patterns"""
        return self.sensitive_patterns.copy()

    def add_custom_pattern(self, category: str, pattern_type: str, pattern: str):
        """Add custom sensitive data pattern"""
        if category not in self.sensitive_patterns:
            self.sensitive_patterns[category] = {}
        
        if pattern_type not in self.sensitive_patterns[category]:
            self.sensitive_patterns[category][pattern_type] = []
        
        self.sensitive_patterns[category][pattern_type].append(pattern)
        self.log_info(f"Added custom pattern: {category}.{pattern_type}")

    def add_custom_extension(self, category: str, extension: str):
        """Add custom document extension"""
        if category not in self.document_extensions:
            self.document_extensions[category] = []
        
        if extension not in self.document_extensions[category]:
            self.document_extensions[category].append(extension)
            self.log_info(f"Added custom extension: {extension} to {category}")