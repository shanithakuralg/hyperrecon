"""
utils/param_scan.py - Enhanced ParamSpider Wrapper and Parameter Discovery
Part of HyperRecon Pro v4.0 - Advanced Modular Bug Bounty Scanner
"""

import os
import tempfile
import re
import requests
from datetime import datetime
from urllib.parse import urlparse, parse_qs, urlencode
from .base_utility import BaseUtility

class ParamScanner(BaseUtility):
    def __init__(self, hyperrecon_instance):
        super().__init__(hyperrecon_instance)
        self.tool_name = 'ParamSpider'

        # Sensitive data patterns from your original tool (enhanced)
        self.sensitive_patterns = {
            'session_id': r'[Ss]essionid|sid|JSESSIONID|PHPSESSID',
            'jwt_token': r'eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+',
            'uuid': r'[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}',
            'credit_card_numbers': r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|6(?:011|5[0-9]{2})[0-9]{12}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|(?:2131|1800|35\d{3})\d{11})\b',
            'private_ips': r'\b(10\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)|172\.(1[6-9]|2[0-9]|3[0-1])\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)|192\.168\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))\b',
            'api_keys_tokens': r'api[-_]?key|access[-_]?token|secret|code|auth|oauth_token',
            'exposed_files': r'\.(env|yaml|yml|json|xml|log|sql|ini|bak|conf|config|db|dbf|tar|gz|backup|swp|old|key|pem|crt|pfx|pdf|xlsx|xls|ppt|pptx|zip|rar|7z)',
            'sensitive_paths': r'/(admin|login|password|secret|token|account|user|passwd|pwd|callback|oauth|saml|sso|mail|mobile|number|phone|dashboard|manage|panel|portal)',
            'payment_info_keywords': r'payment|invoice|transaction|order|orderid|payid|checkout|billing|creditcard',
            'api_endpoints': r'/api/v[0-9]+|/api/|/graphql|/rest/',
            'social_security_numbers': r'\b[0-9]{3}-[0-9]{2}-[0-9]{4}\b',
            'potential_session_ids': r'[a-zA-Z0-9]{25,}|sessid|session',
            'parametrized_urls': r'\?.*=',
            'aws_keys': r'AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16}',
            'google_api_keys': r'AIza[0-9A-Za-z_-]{35}',
            'firebase_db_url': r'https:\/\/[a-zA-Z0-9_-]+\.firebaseio\.com',
            'azure_sas_token': r'sig=[a-zA-Z0-9%]+&se=[0-9T:-Z]+&sp=[a-zA-Z]+&sv=[0-9.-]+&sr=[a-zA-Z]+&si=[a-zA-Z0-9%]+',
            'slack_webhook_urls': r'https:\/\/hooks\.slack\.com\/services\/T[a-zA-Z0-9]+\/B[a-zA-Z0-9]+\/[a-zA-Z0-9]+',
            'github_tokens': r'ghp_[0-9a-zA-Z]{36}|gho_[0-9a-zA-Z]{36}|ghu_[0-9a-zA-Z]{36}|ghs_[0-9a-zA-Z]{36}|ghr_[0-9a-zA-Z]{36}',
            'email_addresses': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
            'phone_numbers': r'\b(?:\+?1[-.\s]?)?\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}\b',
            'database_credentials': r'(database|db)_(user|pass|host|name)',
            'internal_ips': r'\b(192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.|10\.|127\.0\.0\.1)',
            'debug_endpoints': r'(/debug|/test|/dev|/admin/debug)',
            'backup_files': r'\.(bak|backup|old|orig|save|tmp|temp)',
            'api_keys': r'(?i)(api[_-]?key|access[_-]?token|secret[_-]?key)[\s:=]*[\'"]?[A-Za-z0-9_\-]{16,}[\'"]?',
            'webhook_urls': r'(webhook|callback)_url',
            'payment_gateways': r'(paypal|stripe|braintree|square)_',
            'authentication_tokens': r'(auth|bearer|token)[\s:=]*[A-Za-z0-9\-_\.]{20,}'
        }

        # ParamSpider paths to check
        self.paramspider_paths = [
            'ParamSpider/paramspider.py',
            './ParamSpider/paramspider.py', 
            'paramspider.py',
            './paramspider.py',
            os.path.expanduser('~/tools/ParamSpider/paramspider.py'),
            os.path.expanduser('~/ParamSpider/paramspider.py'),
            '/opt/ParamSpider/paramspider.py',
            '/usr/local/bin/ParamSpider/paramspider.py',
            '/root/ParamSpider/paramspider.py'
        ]

    def find_paramspider(self):
        """Find ParamSpider installation"""
        for path in self.paramspider_paths:
            if os.path.exists(path):
                try:
                    self.hyperrecon.console.print(f"✅ [green]Found ParamSpider at: {path}[/green]")
                except:
                    print(f"Found ParamSpider at: {path}")
                return path
        return None

    def extract_parameterized_urls_from_collection(self, urls, domain_path):
        """Extract parameterized URLs from URL collection using regex pattern with proper URO integration"""
        if not urls:
            return []

        self.log_info(f"Extracting parameterized URLs from {len(urls)} collected URLs")

        # Use the parametrized_urls pattern from sensitive_patterns
        parametrized_pattern = self.sensitive_patterns['parametrized_urls']  # r'\?.*='
        
        parameterized_urls = []
        
        for url in urls:
            # Check if URL matches the parameterized pattern
            if re.search(parametrized_pattern, url, re.IGNORECASE):
                parameterized_urls.append(url)

        # Apply URO filtering using the centralized URO filter
        if parameterized_urls:
            # Use the hyperrecon's URO filter for consistent filtering
            parameterized_urls = self.hyperrecon.uro_filter.filter_parameterized_urls(parameterized_urls)

        # Log results
        if parameterized_urls:
            self.log_info(f"Found {len(parameterized_urls)} parameterized URLs from URL collection")
        else:
            self.log_info("No parameterized URLs found in URL collection")

        return parameterized_urls

    def discover_parameters(self, domain, domain_path):
        """Discover parameters using ParamSpider with proper URO integration and error handling"""
        self.log_info(f"Parameter discovery for {domain}")

        paramspider_script = self.find_paramspider()

        if not paramspider_script:
            self.log_error("ParamSpider not found!")
            self.log_info("Install: git clone https://github.com/0xKayala/ParamSpider.git")

            # Save empty result indicator
            self.save_results(domain_path, 'parameters', 'paramspider_not_found.txt', 
                            ["ParamSpider not found", 
                             "Install: git clone https://github.com/0xKayala/ParamSpider.git"])
            return []

        # Use ParamSpider with temporary output file
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as tmp_file:
            temp_output = tmp_file.name

        cmd = [
            'python3', paramspider_script,
            '--domain', domain,
            '--exclude', 'css,js,png,jpg,gif,svg,ico,woff,woff2,ttf,otf,mp4,pdf,doc,docx,zip,rar',
            '--output', temp_output,
            '--quiet'
        ]

        result = self.run_command(cmd, timeout=300, description="Running ParamSpider")

        # Check if file was created successfully and apply URO filtering
        if os.path.exists(temp_output):
            try:
                with open(temp_output, 'r', encoding='utf-8') as f:
                    urls = [url.strip() for url in f.readlines() if url.strip()]
                
                # Clean up temporary file
                try:
                    os.unlink(temp_output)
                except:
                    pass
                
                if urls:
                    # Apply URO filtering to ParamSpider results
                    filtered_urls = self.hyperrecon.uro_filter.filter_parameterized_urls(urls)
                    
                    self.log_info(f"ParamSpider found {len(urls)} URLs, filtered to {len(filtered_urls)}")
                    return filtered_urls
                else:
                    self.log_info("ParamSpider found no URLs")
                    return []
                    
            except Exception as e:
                self.log_error(f"Error reading ParamSpider output: {e}")
                # Clean up temporary file
                try:
                    os.unlink(temp_output)
                except:
                    pass
                return []
        else:
            self.log_info("ParamSpider found no parameters")

        return []

    def apply_uro_filter(self, urls_list):
        """Apply URO filtering to clean URLs - DEPRECATED: Use hyperrecon.uro_filter instead"""
        # This method is deprecated - use the centralized URO filter
        return self.hyperrecon.uro_filter.filter_urls(urls_list)

    def extract_gf_patterns(self, urls, domain_path):
        """Extract URLs using GF patterns with proper URO integration"""
        if not urls:
            return {}

        self.log_info(f"Applying GF patterns to {len(urls)} URLs")

        # GF patterns to check
        gf_patterns = [
            'xss', 'sqli', 'redirect', 'idor', 'ssrf', 'ssti', 'lfi', 'rce', 
            'jsvar', 'interestingEXT', 'img-traversal', 'debug_logic', 
            'interestingparams', 'interestingsubs', 'upload', 'callback'
        ]

        gf_results = {}

        # Create temp file with URLs
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as tmp:
            tmp.write('\n'.join(urls))
            tmp_path = tmp.name

        try:
            for pattern in gf_patterns:
                if self.check_tool_installed('gf'):
                    # Read file content and pass as input
                    with open(tmp_path, 'r') as f:
                        urls_content = f.read()

                    result = self.run_command(['gf', pattern], input_data=urls_content, 
                                            description=f"GF pattern {pattern}")

                    if result:
                        pattern_urls = [url.strip() for url in result.split('\n') if url.strip()]
                        if pattern_urls:
                            # Apply FUZZ replacement and URO filtering
                            fuzzed_urls = []
                            for url in pattern_urls:
                                fuzzed_url = re.sub(r'([?&][^=]+)=([^&]*)', r'\1=FUZZ', url)
                                fuzzed_urls.append(fuzzed_url)

                            # Apply URO filtering to both using centralized filter
                            pattern_urls = self.hyperrecon.uro_filter.apply_consistent_filtering(
                                pattern_urls, f"GF {pattern} original")
                            fuzzed_urls = self.hyperrecon.uro_filter.apply_consistent_filtering(
                                fuzzed_urls, f"GF {pattern} fuzzed")

                            gf_results[pattern] = {
                                'original_urls': pattern_urls,
                                'fuzzed_urls': fuzzed_urls
                            }

                            # Save both versions
                            self.save_results(domain_path, 'gf_patterns', f'{pattern}_original.txt', pattern_urls)
                            self.save_results(domain_path, 'gf_patterns', f'{pattern}_fuzzed.txt', fuzzed_urls)

                            self.log_info(f"Found {len(pattern_urls)} URLs for {pattern}")
                else:
                    self.log_warning("GF tool not installed, skipping pattern extraction")
                    break
        finally:
            try:
                os.unlink(tmp_path)
            except:
                pass

        return gf_results

    def filter_by_extensions(self, urls, domain_path):
        """Filter URLs by file extensions - Enhanced to include all document types"""
        if not urls:
            return {}

        try:
            self.hyperrecon.console.print("📁 [cyan]Filtering URLs by extensions[/cyan]")
        except:
            print("Filtering URLs by extensions")

        # Enhanced extensions list including all document types from your original tool
        extensions = [
            'php', 'asp', 'aspx', 'jsp', 'js', 'json', 'xml', 'txt', 'csv',
            'pdf', 'doc', 'docx', 'ppt', 'pptx', 'xls', 'xlsx',
            'env', 'yaml', 'yml', 'log', 'sql', 'ini', 'bak', 'conf', 'config', 
            'db', 'dbf', 'tar', 'gz', 'backup', 'swp', 'old', 'key', 'pem', 
            'crt', 'pfx', 'zip', 'rar', '7z'
        ]

        extension_results = {}

        for ext in extensions:
            filtered = []
            for url in urls:
                if url.lower().endswith(f'.{ext}') or f'.{ext}?' in url.lower():
                    filtered.append(url)

            if filtered:
                extension_results[ext] = filtered
                self.hyperrecon.save_results_realtime(domain_path, 'extensions',
                                                    f'{ext}_files.txt', filtered)
                try:
                    self.hyperrecon.console.print(f"✅ [green]Found {len(filtered)} {ext.upper()} files[/green]")
                except:
                    print(f"Found {len(filtered)} {ext.upper()} files")

        return extension_results

    def analyze_documents(self, extension_results, domain_path):
        """Analyze PDF, DOC, and PPT files for sensitive information"""
        doc_results = {}
        sensitive_keywords = ['password', 'credential', 'secret', 'admin', 'config', 'backup',
                            'login', 'auth', 'private', 'confidential', 'internal', 'restricted']

        # PDF Analysis
        pdf_urls = extension_results.get('pdf', [])
        if pdf_urls:
            try:
                self.hyperrecon.console.print(f"📄 [cyan]Analyzing {len(pdf_urls)} PDF files[/cyan]")
            except:
                print(f"Analyzing {len(pdf_urls)} PDF files")

            doc_results['pdf_analysis'] = {
                'total_pdfs': len(pdf_urls),
                'sensitive_pdfs': [],
                'all_pdfs': pdf_urls
            }

            for pdf_url in pdf_urls:
                if any(keyword in pdf_url.lower() for keyword in sensitive_keywords):
                    doc_results['pdf_analysis']['sensitive_pdfs'].append(pdf_url)

            self.hyperrecon.save_results_realtime(domain_path, 'documents',
                                                'all_pdf_files.txt', pdf_urls)
            if doc_results['pdf_analysis']['sensitive_pdfs']:
                self.hyperrecon.save_results_realtime(domain_path, 'documents',
                                                    'sensitive_pdf_files.txt',
                                                    doc_results['pdf_analysis']['sensitive_pdfs'])

        # PPT Analysis  
        ppt_urls = extension_results.get('ppt', []) + extension_results.get('pptx', [])
        if ppt_urls:
            try:
                self.hyperrecon.console.print(f"📊 [cyan]Analyzing {len(ppt_urls)} PowerPoint files[/cyan]")
            except:
                print(f"Analyzing {len(ppt_urls)} PowerPoint files")

            doc_results['ppt_analysis'] = {
                'total_ppts': len(ppt_urls),
                'sensitive_ppts': [],
                'all_ppts': ppt_urls
            }

            for ppt_url in ppt_urls:
                if any(keyword in ppt_url.lower() for keyword in sensitive_keywords):
                    doc_results['ppt_analysis']['sensitive_ppts'].append(ppt_url)

            self.hyperrecon.save_results_realtime(domain_path, 'documents',
                                                'all_ppt_files.txt', ppt_urls)
            if doc_results['ppt_analysis']['sensitive_ppts']:
                self.hyperrecon.save_results_realtime(domain_path, 'documents',
                                                    'sensitive_ppt_files.txt',
                                                    doc_results['ppt_analysis']['sensitive_ppts'])

        # DOC Analysis
        doc_urls = extension_results.get('doc', []) + extension_results.get('docx', [])
        if doc_urls:
            try:
                self.hyperrecon.console.print(f"📝 [cyan]Analyzing {len(doc_urls)} Word documents[/cyan]")
            except:
                print(f"Analyzing {len(doc_urls)} Word documents")

            doc_results['doc_analysis'] = {
                'total_docs': len(doc_urls),
                'sensitive_docs': [],
                'all_docs': doc_urls
            }

            for doc_url in doc_urls:
                if any(keyword in doc_url.lower() for keyword in sensitive_keywords):
                    doc_results['doc_analysis']['sensitive_docs'].append(doc_url)

            self.hyperrecon.save_results_realtime(domain_path, 'documents',
                                                'all_doc_files.txt', doc_urls)
            if doc_results['doc_analysis']['sensitive_docs']:
                self.hyperrecon.save_results_realtime(domain_path, 'documents',
                                                    'sensitive_doc_files.txt',
                                                    doc_results['doc_analysis']['sensitive_docs'])

        # XLS Analysis  
        xls_urls = extension_results.get('xls', []) + extension_results.get('xlsx', [])
        if xls_urls:
            try:
                self.hyperrecon.console.print(f"📊 [cyan]Analyzing {len(xls_urls)} Excel files[/cyan]")
            except:
                print(f"Analyzing {len(xls_urls)} Excel files")

            doc_results['xls_analysis'] = {
                'total_xls': len(xls_urls),
                'sensitive_xls': [],
                'all_xls': xls_urls
            }

            for xls_url in xls_urls:
                if any(keyword in xls_url.lower() for keyword in sensitive_keywords):
                    doc_results['xls_analysis']['sensitive_xls'].append(xls_url)

            self.hyperrecon.save_results_realtime(domain_path, 'documents',
                                                'all_xls_files.txt', xls_urls)
            if doc_results['xls_analysis']['sensitive_xls']:
                self.hyperrecon.save_results_realtime(domain_path, 'documents',
                                                    'sensitive_xls_files.txt',
                                                    doc_results['xls_analysis']['sensitive_xls'])

        return doc_results

    def extract_sensitive_data(self, urls, domain_path):
        """Extract sensitive data patterns from URLs - Enhanced format with URL mapping and proper logging"""
        if not urls:
            return {}

        self.log_info(f"Extracting sensitive data patterns from {len(urls)} URLs")

        sensitive_results = {}

        for pattern_name, pattern in self.sensitive_patterns.items():
            matching_data = []

            for url in urls:
                matches = re.findall(pattern, url, re.IGNORECASE)
                if matches:
                    # Enhanced format: URL -> Found Pattern with timestamp
                    for match in matches:
                        if isinstance(match, tuple):
                            match_str = ' '.join(str(m) for m in match if m)
                        else:
                            match_str = str(match)

                        matching_data.append(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {url} -> {match_str}")

            if matching_data:
                sensitive_results[pattern_name] = matching_data

                # Save with enhanced format
                self.save_results(domain_path, 'sensitive_data', f'{pattern_name}.txt', matching_data)
                self.log_warning(f"Found {len(matching_data)} {pattern_name.replace('_', ' ')}")

        return sensitive_results

    def unfurl_urls(self, urls, domain_path):
        """Process URLs with unfurl - Enhanced with proper command structure and URO integration"""
        if not urls:
            return {}
        
        if not self.check_tool_installed('unfurl'):
            self.log_warning("Unfurl tool not installed, skipping URL processing")
            return {}

        self.log_info(f"Processing {len(urls)} URLs with unfurl")

        unfurl_results = {}
        urls_input = '\n'.join(urls)

        # Enhanced unfurl modes with -unique flag to prevent duplicates
        unfurl_commands = {
            'domains': ['unfurl', '--unique', 'domains'],
            'apex_domains': ['unfurl', '--unique', 'apexes'], 
            'paths': ['unfurl', '--unique', 'paths'],
            'query_keys': ['unfurl', '--unique', 'keys'],
            'query_values': ['unfurl', '--unique', 'values'],
            'scheme_domain_path': ['unfurl', '--unique', 'format', '%s://%d%p'],
            'query_keypairs': ['unfurl', '--unique', 'keypairs']
        }

        for mode, cmd in unfurl_commands.items():
            result = self.run_command(cmd, input_data=urls_input, description=f"Unfurl {mode}")
            if result:
                items = [item.strip() for item in result.split('\n') if item.strip()]
                if items:
                    # Apply URO filtering to remove duplicates using centralized filter
                    items = self.hyperrecon.uro_filter.apply_consistent_filtering(items, f"Unfurl {mode}")
                    unfurl_results[mode] = items

                    filename = f'unique_{mode}.txt'
                    self.save_results(domain_path, 'unfurl_results', filename, items)
                    self.log_info(f"Found {len(items)} unique {mode.replace('_', ' ')}")

        return unfurl_results

    def execute(self, targets, domain_path):
        """
        Execute comprehensive parameter scanning workflow
        
        Args:
            targets: Dictionary containing domain and collected URLs
            domain_path: Path to domain output directory
            
        Returns:
            UtilityResult: Parameter scanning results
        """
        self.start_execution()
        
        try:
            domain = targets.get('domain')
            collected_urls = targets.get('urls', [])
            
            if not domain:
                return self.create_result(False, {}, 0, ["Domain not provided"])
            
            self.log_info(f"Starting parameter scanning for {domain}")
            
            results = {}
            
            # 1. Extract parameterized URLs from URL collection
            if collected_urls:
                collection_param_urls = self.extract_parameterized_urls_from_collection(collected_urls, domain_path)
                results['collection_parameterized_urls'] = collection_param_urls
            else:
                results['collection_parameterized_urls'] = []
            
            # 2. Run ParamSpider for additional parameter discovery
            paramspider_urls = self.discover_parameters(domain, domain_path)
            results['paramspider_urls'] = paramspider_urls
            
            # 3. Combine both sources and apply final URO filtering
            all_param_urls = results['collection_parameterized_urls'] + paramspider_urls
            if all_param_urls:
                # Remove duplicates using URO
                final_param_urls = self.hyperrecon.uro_filter.filter_urls(all_param_urls)
                
                # Save the main file: all_parameterized_urls.txt
                self.save_results(domain_path, 'parameters', 'all_parameterized_urls.txt', final_param_urls)
                
                # Create original_value_param_urls.txt by filtering from urls.txt if it exists
                urls_file = os.path.join(domain_path, 'urls', 'all_urls.txt')
                if os.path.exists(urls_file):
                    try:
                        with open(urls_file, 'r') as f:
                            all_urls = [line.strip() for line in f if line.strip()]
                        
                        # Extract parameterized URLs from all_urls.txt
                        param_from_urls = []
                        for url in all_urls:
                            if '?' in url and '=' in url:
                                param_from_urls.append(url)
                        
                        # Apply URO filtering and save as original_value_param_urls.txt
                        if param_from_urls:
                            filtered_original = self.hyperrecon.uro_filter.filter_urls(param_from_urls)
                            self.save_results(domain_path, 'parameters', 'original_value_param_urls.txt', filtered_original)
                        else:
                            self.save_results(domain_path, 'parameters', 'original_value_param_urls.txt', 
                                            ["No parameterized URLs found in collected URLs"])
                    except Exception as e:
                        self.log_error(f"Error processing original URLs: {e}")
                        self.save_results(domain_path, 'parameters', 'original_value_param_urls.txt', 
                                        ["Error processing original URLs"])
                else:
                    self.save_results(domain_path, 'parameters', 'original_value_param_urls.txt', 
                                    ["No URLs file found"])
                
                # Save statistics
                stats = [
                    f"Parameter URL Statistics - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
                    f"Collection URLs: {len(results['collection_parameterized_urls'])}",
                    f"ParamSpider URLs: {len(paramspider_urls)}",
                    f"Combined URLs: {len(all_param_urls)}",
                    f"Final Filtered URLs: {len(final_param_urls)}",
                    f"Duplicates Removed: {len(all_param_urls) - len(final_param_urls)}"
                ]
                self.save_results(domain_path, 'parameters', 'all_parameterized_urls_stats.txt', stats)
                
                results['all_parameterized_urls'] = final_param_urls
            else:
                results['all_parameterized_urls'] = []
                # Create empty files
                self.save_results(domain_path, 'parameters', 'all_parameterized_urls.txt', 
                                ["No parameterized URLs found"])
                self.save_results(domain_path, 'parameters', 'original_value_param_urls.txt', 
                                ["No parameterized URLs found"])
            
            # 4. Extract GF patterns if URLs available
            if collected_urls:
                gf_results = self.extract_gf_patterns(collected_urls, domain_path)
                results['gf_patterns'] = gf_results
            
            # 5. Extract sensitive data patterns
            if collected_urls:
                sensitive_results = self.extract_sensitive_data(collected_urls, domain_path)
                results['sensitive_data'] = sensitive_results
            
            # 6. Process URLs with unfurl
            if collected_urls:
                unfurl_results = self.unfurl_urls(collected_urls, domain_path)
                results['unfurl_results'] = unfurl_results
            
            # 7. Filter by extensions
            if collected_urls:
                extension_results = self.filter_by_extensions(collected_urls, domain_path)
                results['extension_filtering'] = extension_results
                
                # 8. Analyze documents
                if extension_results:
                    doc_results = self.analyze_documents(extension_results, domain_path)
                    results['document_analysis'] = doc_results
            
            total_items = len(results.get('all_parameterized_urls', []))
            
            self.log_info(f"Parameter scanning completed for {domain}")
            return self.create_result(True, results, total_items)
            
        except Exception as e:
            self.log_error("Parameter scanning execution failed", e)
            return self.create_result(False, {}, 0, [str(e)])

    def validate_dependencies(self):
        """
        Validate parameter scanning tool dependencies
        
        Returns:
            Tuple[bool, List[str]]: (all_available, missing_tools)
        """
        missing_tools = []
        
        # Check ParamSpider
        if not self.find_paramspider():
            missing_tools.append('ParamSpider')
        
        # Check optional tools
        optional_tools = ['gf', 'unfurl']
        for tool in optional_tools:
            if not self.check_tool_installed(tool):
                missing_tools.append(f'{tool} (optional)')
        
        return len(missing_tools) == 0, missing_tools

    def get_results_summary(self):
        """
        Get summary of parameter scanning results
        
        Returns:
            Dict: Summary of results
        """
        if not hasattr(self, 'last_result') or not self.last_result:
            return {}
        
        results = self.last_result.data
        
        summary = {
            'parameterized_urls_found': len(results.get('all_parameterized_urls', [])),
            'collection_params': len(results.get('collection_parameterized_urls', [])),
            'paramspider_params': len(results.get('paramspider_urls', [])),
            'gf_patterns_found': len(results.get('gf_patterns', {})),
            'sensitive_patterns_found': len(results.get('sensitive_data', {})),
            'unfurl_modes_processed': len(results.get('unfurl_results', {})),
            'extensions_found': len(results.get('extension_filtering', {})),
            'documents_analyzed': len(results.get('document_analysis', {}))
        }
        
        return summary
