#!/usr/bin/env python3
"""
HyperRecon Pro v4.0 - Advanced Usage Examples
Demonstrates advanced features, integrations, and customizations
"""

import os
import sys
import json
import time
import threading
import queue
from datetime import datetime, timedelta
from concurrent.futures import ThreadPoolExecutor, as_completed

# Add the parent directory to the path to import hyperrecon
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from hyperrecon import HyperReconPro

class CustomReconWorkflow:
    """Custom reconnaissance workflow with advanced features"""
    
    def __init__(self):
        self.hyperrecon = HyperReconPro()
        self.results_queue = queue.Queue()
        self.progress_callback = None
        
    def set_progress_callback(self, callback):
        """Set callback function for progress updates"""
        self.progress_callback = callback
        
    def custom_scan_workflow(self, targets, custom_config=None):
        """Run custom scan workflow with advanced features"""
        if custom_config:
            self._apply_custom_config(custom_config)
        
        all_results = []
        
        for i, target in enumerate(targets):
            if self.progress_callback:
                self.progress_callback(f"Processing {target} ({i+1}/{len(targets)})")
            
            # Custom workflow steps
            result = self._execute_custom_workflow(target)
            all_results.append(result)
            
            # Add to results queue for real-time processing
            self.results_queue.put(result)
        
        return all_results
    
    def _apply_custom_config(self, config):
        """Apply custom configuration"""
        for key, value in config.items():
            if hasattr(self.hyperrecon, key):
                setattr(self.hyperrecon, key, value)
            elif key == 'feature_flags':
                self.hyperrecon.feature_flags.update(value)
    
    def _execute_custom_workflow(self, target):
        """Execute custom workflow for a single target"""
        domain_path = self.hyperrecon.create_output_structure(target)
        
        result = {
            'domain': target,
            'scan_start': datetime.now().isoformat(),
            'domain_path': domain_path,
            'custom_workflow': True
        }
        
        # Custom step 1: Enhanced subdomain enumeration
        subdomain_result = self._enhanced_subdomain_enumeration(target, domain_path)
        result['enhanced_subdomains'] = subdomain_result
        
        # Custom step 2: Intelligent URL collection
        url_result = self._intelligent_url_collection(target, domain_path, subdomain_result)
        result['intelligent_urls'] = url_result
        
        # Custom step 3: Targeted vulnerability assessment
        vuln_result = self._targeted_vulnerability_assessment(target, domain_path, url_result)
        result['targeted_vulnerabilities'] = vuln_result
        
        result['scan_end'] = datetime.now().isoformat()
        return result
    
    def _enhanced_subdomain_enumeration(self, target, domain_path):
        """Enhanced subdomain enumeration with multiple sources"""
        print(f"   🔍 Enhanced subdomain enumeration for {target}")
        
        # Use multiple enumeration techniques
        subdomain_result = self.hyperrecon.subdomain_enumerator.execute(target, domain_path)
        
        if subdomain_result.success:
            subdomains = subdomain_result.data.get('subdomains', [])
            
            # Additional processing: categorize subdomains
            categorized = {
                'production': [],
                'staging': [],
                'development': [],
                'api': [],
                'admin': [],
                'other': []
            }
            
            for subdomain in subdomains:
                if any(keyword in subdomain.lower() for keyword in ['prod', 'www', 'mail']):
                    categorized['production'].append(subdomain)
                elif any(keyword in subdomain.lower() for keyword in ['staging', 'stage', 'test']):
                    categorized['staging'].append(subdomain)
                elif any(keyword in subdomain.lower() for keyword in ['dev', 'development']):
                    categorized['development'].append(subdomain)
                elif any(keyword in subdomain.lower() for keyword in ['api', 'rest', 'graphql']):
                    categorized['api'].append(subdomain)
                elif any(keyword in subdomain.lower() for keyword in ['admin', 'manage', 'control']):
                    categorized['admin'].append(subdomain)
                else:
                    categorized['other'].append(subdomain)
            
            return {
                'total_subdomains': len(subdomains),
                'categorized': categorized,
                'high_value_targets': categorized['admin'] + categorized['api']
            }
        
        return {'total_subdomains': 0, 'categorized': {}, 'high_value_targets': []}
    
    def _intelligent_url_collection(self, target, domain_path, subdomain_result):
        """Intelligent URL collection with prioritization"""
        print(f"   🌐 Intelligent URL collection for {target}")
        
        # Focus on high-value targets first
        high_value_targets = subdomain_result.get('high_value_targets', [])
        
        if high_value_targets:
            # Prioritize high-value targets
            url_result = self.hyperrecon.url_collector.execute(high_value_targets[0], domain_path)
        else:
            url_result = self.hyperrecon.url_collector.execute(target, domain_path)
        
        if url_result.success:
            urls = url_result.data.get('filtered_urls', [])
            
            # Categorize URLs by potential value
            categorized_urls = {
                'authentication': [],
                'api_endpoints': [],
                'admin_panels': [],
                'file_uploads': [],
                'search_forms': [],
                'other': []
            }
            
            for url in urls:
                url_lower = url.lower()
                if any(keyword in url_lower for keyword in ['login', 'auth', 'signin', 'oauth']):
                    categorized_urls['authentication'].append(url)
                elif any(keyword in url_lower for keyword in ['api', 'rest', 'graphql', 'json']):
                    categorized_urls['api_endpoints'].append(url)
                elif any(keyword in url_lower for keyword in ['admin', 'manage', 'control', 'dashboard']):
                    categorized_urls['admin_panels'].append(url)
                elif any(keyword in url_lower for keyword in ['upload', 'file', 'attach']):
                    categorized_urls['file_uploads'].append(url)
                elif any(keyword in url_lower for keyword in ['search', 'query', 'find']):
                    categorized_urls['search_forms'].append(url)
                else:
                    categorized_urls['other'].append(url)
            
            return {
                'total_urls': len(urls),
                'categorized': categorized_urls,
                'priority_targets': (
                    categorized_urls['authentication'] + 
                    categorized_urls['admin_panels'] + 
                    categorized_urls['api_endpoints']
                )
            }
        
        return {'total_urls': 0, 'categorized': {}, 'priority_targets': []}
    
    def _targeted_vulnerability_assessment(self, target, domain_path, url_result):
        """Targeted vulnerability assessment based on discovered assets"""
        print(f"   🛡️ Targeted vulnerability assessment for {target}")
        
        priority_targets = url_result.get('priority_targets', [])
        
        if priority_targets:
            # Focus vulnerability scanning on priority targets
            vuln_result = self.hyperrecon.vuln_scanner.execute(priority_targets[:10], domain_path, 'urls')
            
            if vuln_result.get('success'):
                vulnerabilities = vuln_result.get('detailed_results', {})
                
                # Categorize vulnerabilities by severity
                severity_breakdown = {
                    'critical': [],
                    'high': [],
                    'medium': [],
                    'low': [],
                    'info': []
                }
                
                for vuln_type, vuln_data in vulnerabilities.items():
                    for target_url, vulns in vuln_data.items():
                        for vuln in vulns:
                            severity = vuln.get('severity', 'info').lower()
                            if severity in severity_breakdown:
                                severity_breakdown[severity].append({
                                    'type': vuln_type,
                                    'url': target_url,
                                    'details': vuln
                                })
                
                return {
                    'total_vulnerabilities': sum(len(v) for v in severity_breakdown.values()),
                    'severity_breakdown': severity_breakdown,
                    'critical_findings': severity_breakdown['critical'] + severity_breakdown['high']
                }
        
        return {'total_vulnerabilities': 0, 'severity_breakdown': {}, 'critical_findings': []}

def example_custom_workflow():
    """Example: Custom reconnaissance workflow"""
    print("🎯 Example 1: Custom Reconnaissance Workflow")
    print("-" * 50)
    
    # Initialize custom workflow
    workflow = CustomReconWorkflow()
    
    # Set progress callback
    def progress_callback(message):
        print(f"   📊 Progress: {message}")
    
    workflow.set_progress_callback(progress_callback)
    
    # Custom configuration
    custom_config = {
        'verbose': True,
        'threads': 8,
        'output_dir': 'examples/output/custom_workflow',
        'feature_flags': {
            'subfinder': True,
            'httpx': True,
            'nuclei': True,
            'social_media_recon': False,  # Disable for focused scan
            'directory_bruteforce': False  # Disable for speed
        }
    }
    
    # Target domains
    targets = ["example.com"]
    
    print(f"Running custom workflow on {len(targets)} target(s)")
    
    # Execute custom workflow
    results = workflow.custom_scan_workflow(targets, custom_config)
    
    # Process results
    for result in results:
        domain = result['domain']
        print(f"\n✅ Custom workflow completed for {domain}")
        
        # Enhanced subdomain results
        enhanced_subs = result.get('enhanced_subdomains', {})
        print(f"   • Total subdomains: {enhanced_subs.get('total_subdomains', 0)}")
        print(f"   • High-value targets: {len(enhanced_subs.get('high_value_targets', []))}")
        
        # Intelligent URL results
        intelligent_urls = result.get('intelligent_urls', {})
        print(f"   • Total URLs: {intelligent_urls.get('total_urls', 0)}")
        print(f"   • Priority targets: {len(intelligent_urls.get('priority_targets', []))}")
        
        # Targeted vulnerability results
        targeted_vulns = result.get('targeted_vulnerabilities', {})
        print(f"   • Total vulnerabilities: {targeted_vulns.get('total_vulnerabilities', 0)}")
        print(f"   • Critical findings: {len(targeted_vulns.get('critical_findings', []))}")

def example_batch_processing():
    """Example: Batch processing with queue management"""
    print("\n🎯 Example 2: Batch Processing with Queue Management")
    print("-" * 50)
    
    # Initialize HyperRecon Pro
    hyperrecon = HyperReconPro()
    hyperrecon.verbose = False
    hyperrecon.output_dir = "examples/output/batch_processing"
    
    # Create a batch of targets
    batch_targets = [
        "example.com",
        "test.com", 
        "demo.com",
        "sample.com"
    ]
    
    print(f"Processing batch of {len(batch_targets)} targets")
    
    # Results queue for real-time processing
    results_queue = queue.Queue()
    completed_scans = []
    
    def process_results():
        """Process results as they come in"""
        while True:
            try:
                result = results_queue.get(timeout=5)
                if result is None:  # Sentinel value to stop
                    break
                
                domain = result.get('domain', 'Unknown')
                print(f"   ✅ Processed result for {domain}")
                completed_scans.append(result)
                results_queue.task_done()
                
            except queue.Empty:
                continue
    
    # Start result processing thread
    result_processor = threading.Thread(target=process_results)
    result_processor.start()
    
    # Process targets in batches
    batch_size = 2
    for i in range(0, len(batch_targets), batch_size):
        batch = batch_targets[i:i+batch_size]
        print(f"\n   📦 Processing batch {i//batch_size + 1}: {batch}")
        
        # Process batch
        batch_results = hyperrecon.run_scan(batch)
        
        # Add results to queue
        for result in batch_results:
            results_queue.put(result)
    
    # Signal completion
    results_queue.put(None)
    result_processor.join()
    
    print(f"\n✅ Batch processing completed")
    print(f"   • Total targets processed: {len(completed_scans)}")
    print(f"   • Success rate: {len(completed_scans)/len(batch_targets)*100:.1f}%")

def example_continuous_monitoring():
    """Example: Continuous monitoring setup"""
    print("\n🎯 Example 3: Continuous Monitoring Setup")
    print("-" * 50)
    
    class ContinuousMonitor:
        def __init__(self, targets, interval_hours=24):
            self.targets = targets
            self.interval_hours = interval_hours
            self.hyperrecon = HyperReconPro()
            self.hyperrecon.verbose = False
            self.hyperrecon.output_dir = "examples/output/continuous_monitoring"
            self.last_results = {}
            self.running = False
        
        def start_monitoring(self, duration_hours=1):  # Short duration for demo
            """Start continuous monitoring"""
            self.running = True
            end_time = datetime.now() + timedelta(hours=duration_hours)
            
            print(f"   🔄 Starting continuous monitoring for {duration_hours} hour(s)")
            print(f"   📊 Monitoring {len(self.targets)} targets every {self.interval_hours} hours")
            
            scan_count = 0
            while self.running and datetime.now() < end_time:
                scan_count += 1
                print(f"\n   📅 Scan #{scan_count} at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
                
                # Run scans
                current_results = self.hyperrecon.run_scan(self.targets)
                
                # Compare with previous results
                changes = self._detect_changes(current_results)
                
                if changes:
                    print(f"   🚨 Changes detected:")
                    for domain, change_list in changes.items():
                        print(f"     • {domain}: {len(change_list)} changes")
                        for change in change_list[:3]:  # Show first 3 changes
                            print(f"       - {change}")
                else:
                    print(f"   ✅ No significant changes detected")
                
                # Update last results
                self.last_results = {r['domain']: r for r in current_results}
                
                # For demo, break after first scan
                break
            
            print(f"   ⏹️ Monitoring stopped after {scan_count} scan(s)")
        
        def _detect_changes(self, current_results):
            """Detect changes between scans"""
            changes = {}
            
            for result in current_results:
                domain = result['domain']
                
                if domain not in self.last_results:
                    changes[domain] = ["First scan - baseline established"]
                    continue
                
                last_result = self.last_results[domain]
                domain_changes = []
                
                # Check for new subdomains
                current_subs = set(result.get('subdomains', []))
                last_subs = set(last_result.get('subdomains', []))
                new_subs = current_subs - last_subs
                
                if new_subs:
                    domain_changes.append(f"New subdomains: {len(new_subs)}")
                
                # Check for new vulnerabilities
                current_vulns = len(result.get('vulnerabilities', {}))
                last_vulns = len(last_result.get('vulnerabilities', {}))
                
                if current_vulns > last_vulns:
                    domain_changes.append(f"New vulnerabilities: {current_vulns - last_vulns}")
                
                # Check for new technologies
                current_techs = set(str(result.get('technologies', {})))
                last_techs = set(str(last_result.get('technologies', {})))
                
                if current_techs != last_techs:
                    domain_changes.append("Technology stack changes detected")
                
                if domain_changes:
                    changes[domain] = domain_changes
            
            return changes
        
        def stop_monitoring(self):
            """Stop continuous monitoring"""
            self.running = False
    
    # Demo continuous monitoring
    monitor_targets = ["example.com"]
    monitor = ContinuousMonitor(monitor_targets, interval_hours=1)
    
    # Start monitoring (short duration for demo)
    monitor.start_monitoring(duration_hours=0.1)  # 6 minutes for demo

def example_integration_with_external_tools():
    """Example: Integration with external tools and APIs"""
    print("\n🎯 Example 4: Integration with External Tools")
    print("-" * 50)
    
    class ExternalToolIntegration:
        def __init__(self):
            self.hyperrecon = HyperReconPro()
            self.hyperrecon.verbose = True
            self.hyperrecon.output_dir = "examples/output/external_integration"
        
        def integrate_with_shodan(self, target):
            """Simulate Shodan integration"""
            print(f"   🔍 Simulating Shodan integration for {target}")
            
            # In a real implementation, you would use the Shodan API
            # For demo, we'll simulate the data
            simulated_shodan_data = {
                'open_ports': [80, 443, 22, 21],
                'services': ['HTTP', 'HTTPS', 'SSH', 'FTP'],
                'vulnerabilities': ['CVE-2021-44228', 'CVE-2021-45046'],
                'location': 'US',
                'organization': 'Example Corp'
            }
            
            print(f"     • Open ports: {simulated_shodan_data['open_ports']}")
            print(f"     • Services: {simulated_shodan_data['services']}")
            print(f"     • Known vulnerabilities: {len(simulated_shodan_data['vulnerabilities'])}")
            
            return simulated_shodan_data
        
        def integrate_with_virustotal(self, target):
            """Simulate VirusTotal integration"""
            print(f"   🦠 Simulating VirusTotal integration for {target}")
            
            # Simulated VirusTotal data
            simulated_vt_data = {
                'malicious_detections': 0,
                'suspicious_detections': 1,
                'reputation_score': 85,
                'categories': ['business', 'technology'],
                'last_analysis_date': datetime.now().isoformat()
            }
            
            print(f"     • Reputation score: {simulated_vt_data['reputation_score']}/100")
            print(f"     • Malicious detections: {simulated_vt_data['malicious_detections']}")
            print(f"     • Categories: {simulated_vt_data['categories']}")
            
            return simulated_vt_data
        
        def integrate_with_certificate_transparency(self, target):
            """Simulate Certificate Transparency integration"""
            print(f"   📜 Simulating Certificate Transparency integration for {target}")
            
            # Simulated CT data
            simulated_ct_data = {
                'certificates_found': 15,
                'subdomains_from_certs': [
                    f'www.{target}',
                    f'api.{target}',
                    f'admin.{target}',
                    f'staging.{target}'
                ],
                'certificate_authorities': ['Let\'s Encrypt', 'DigiCert'],
                'expired_certificates': 3
            }
            
            print(f"     • Certificates found: {simulated_ct_data['certificates_found']}")
            print(f"     • Subdomains from certs: {len(simulated_ct_data['subdomains_from_certs'])}")
            print(f"     • Expired certificates: {simulated_ct_data['expired_certificates']}")
            
            return simulated_ct_data
        
        def comprehensive_external_scan(self, target):
            """Run comprehensive scan with external tool integration"""
            print(f"   🌐 Comprehensive external scan for {target}")
            
            # Run standard HyperRecon scan
            standard_results = self.hyperrecon.run_scan([target])
            
            if not standard_results:
                return None
            
            result = standard_results[0]
            
            # Integrate external tool data
            result['external_integrations'] = {
                'shodan': self.integrate_with_shodan(target),
                'virustotal': self.integrate_with_virustotal(target),
                'certificate_transparency': self.integrate_with_certificate_transparency(target)
            }
            
            # Correlate data
            result['correlation_analysis'] = self._correlate_external_data(result)
            
            return result
        
        def _correlate_external_data(self, result):
            """Correlate data from different sources"""
            correlations = []
            
            # Get external data
            external = result.get('external_integrations', {})
            shodan_data = external.get('shodan', {})
            vt_data = external.get('virustotal', {})
            ct_data = external.get('certificate_transparency', {})
            
            # Correlate subdomains
            hyperrecon_subs = set(result.get('subdomains', []))
            ct_subs = set(ct_data.get('subdomains_from_certs', []))
            
            new_from_ct = ct_subs - hyperrecon_subs
            if new_from_ct:
                correlations.append(f"Certificate Transparency revealed {len(new_from_ct)} additional subdomains")
            
            # Correlate vulnerabilities
            shodan_vulns = shodan_data.get('vulnerabilities', [])
            if shodan_vulns:
                correlations.append(f"Shodan identified {len(shodan_vulns)} known vulnerabilities")
            
            # Correlate reputation
            vt_score = vt_data.get('reputation_score', 0)
            if vt_score < 50:
                correlations.append(f"VirusTotal reputation score is low ({vt_score}/100)")
            
            return correlations
    
    # Demo external tool integration
    integration = ExternalToolIntegration()
    target = "example.com"
    
    print(f"Running comprehensive external integration scan for {target}")
    
    result = integration.comprehensive_external_scan(target)
    
    if result:
        print(f"\n✅ External integration scan completed for {target}")
        
        correlations = result.get('correlation_analysis', [])
        if correlations:
            print(f"   🔗 Correlation analysis:")
            for correlation in correlations:
                print(f"     • {correlation}")
        else:
            print(f"   ℹ️ No significant correlations found")

def example_custom_reporting():
    """Example: Custom reporting and data visualization"""
    print("\n🎯 Example 5: Custom Reporting and Visualization")
    print("-" * 50)
    
    class CustomReporter:
        def __init__(self):
            self.hyperrecon = HyperReconPro()
            self.hyperrecon.verbose = False
            self.hyperrecon.output_dir = "examples/output/custom_reporting"
        
        def generate_executive_summary(self, results):
            """Generate executive summary report"""
            print("   📊 Generating executive summary...")
            
            summary = {
                'scan_overview': {
                    'total_domains': len(results),
                    'scan_date': datetime.now().isoformat(),
                    'total_scan_time': 0
                },
                'key_findings': {
                    'total_subdomains': 0,
                    'total_urls': 0,
                    'total_live_hosts': 0,
                    'total_vulnerabilities': 0,
                    'critical_vulnerabilities': 0
                },
                'risk_assessment': {
                    'overall_risk_score': 0,
                    'risk_factors': []
                },
                'recommendations': []
            }
            
            # Aggregate data
            for result in results:
                summary['key_findings']['total_subdomains'] += len(result.get('subdomains', []))
                summary['key_findings']['total_urls'] += len(result.get('all_urls', []))
                summary['key_findings']['total_live_hosts'] += len(result.get('live_hosts', []))
                
                vulns = result.get('vulnerabilities', {})
                for vuln_type, vuln_data in vulns.items():
                    for target, vuln_list in vuln_data.items():
                        summary['key_findings']['total_vulnerabilities'] += len(vuln_list)
                        
                        # Count critical vulnerabilities
                        for vuln in vuln_list:
                            if vuln.get('severity', '').lower() in ['critical', 'high']:
                                summary['key_findings']['critical_vulnerabilities'] += 1
            
            # Calculate risk score
            risk_score = min(100, (
                summary['key_findings']['critical_vulnerabilities'] * 20 +
                summary['key_findings']['total_vulnerabilities'] * 5 +
                summary['key_findings']['total_live_hosts'] * 2
            ))
            summary['risk_assessment']['overall_risk_score'] = risk_score
            
            # Generate recommendations
            if summary['key_findings']['critical_vulnerabilities'] > 0:
                summary['recommendations'].append("Immediately address critical vulnerabilities")
            
            if summary['key_findings']['total_live_hosts'] > 50:
                summary['recommendations'].append("Review and minimize exposed services")
            
            if risk_score > 70:
                summary['risk_assessment']['risk_factors'].append("High number of vulnerabilities detected")
            
            return summary
        
        def generate_technical_report(self, results):
            """Generate detailed technical report"""
            print("   🔧 Generating technical report...")
            
            technical_report = {
                'methodology': {
                    'tools_used': ['subfinder', 'httpx', 'nuclei', 'gobuster'],
                    'scan_techniques': ['subdomain enumeration', 'port scanning', 'vulnerability assessment'],
                    'scan_parameters': {
                        'threads': self.hyperrecon.threads,
                        'timeout': 300,
                        'scope': 'comprehensive'
                    }
                },
                'detailed_findings': {},
                'technical_recommendations': [],
                'appendices': {
                    'raw_data_locations': [],
                    'tool_outputs': []
                }
            }
            
            # Process each domain
            for result in results:
                domain = result['domain']
                technical_report['detailed_findings'][domain] = {
                    'infrastructure': {
                        'subdomains': result.get('subdomains', []),
                        'live_hosts': result.get('live_hosts', []),
                        'technologies': result.get('technologies', {})
                    },
                    'security_findings': result.get('vulnerabilities', {}),
                    'attack_surface': {
                        'total_endpoints': len(result.get('all_urls', [])),
                        'parameter_endpoints': len(result.get('parameter_urls', [])),
                        'js_files': len(result.get('javascript_analysis', {}).get('js_files', []))
                    }
                }
                
                # Add raw data locations
                domain_path = result.get('domain_path', '')
                if domain_path:
                    technical_report['appendices']['raw_data_locations'].append(domain_path)
            
            return technical_report
        
        def create_comparison_report(self, current_results, previous_results=None):
            """Create comparison report between scans"""
            print("   📈 Generating comparison report...")
            
            if not previous_results:
                # Simulate previous results for demo
                previous_results = []
                for result in current_results:
                    prev_result = result.copy()
                    # Simulate fewer findings in previous scan
                    prev_result['subdomains'] = result.get('subdomains', [])[:len(result.get('subdomains', []))//2]
                    prev_result['vulnerabilities'] = {}
                    previous_results.append(prev_result)
            
            comparison = {
                'scan_comparison': {
                    'current_scan_date': datetime.now().isoformat(),
                    'previous_scan_date': (datetime.now() - timedelta(days=7)).isoformat(),
                    'domains_compared': len(current_results)
                },
                'changes_detected': {},
                'trend_analysis': {},
                'alerts': []
            }
            
            # Compare results
            for i, current in enumerate(current_results):
                domain = current['domain']
                previous = previous_results[i] if i < len(previous_results) else {}
                
                domain_changes = {
                    'new_subdomains': [],
                    'new_vulnerabilities': 0,
                    'resolved_vulnerabilities': 0,
                    'infrastructure_changes': []
                }
                
                # Compare subdomains
                current_subs = set(current.get('subdomains', []))
                previous_subs = set(previous.get('subdomains', []))
                new_subs = current_subs - previous_subs
                domain_changes['new_subdomains'] = list(new_subs)
                
                # Compare vulnerabilities
                current_vuln_count = sum(len(v) for vuln_type in current.get('vulnerabilities', {}).values() for v in vuln_type.values())
                previous_vuln_count = sum(len(v) for vuln_type in previous.get('vulnerabilities', {}).values() for v in vuln_type.values())
                
                if current_vuln_count > previous_vuln_count:
                    domain_changes['new_vulnerabilities'] = current_vuln_count - previous_vuln_count
                    comparison['alerts'].append(f"New vulnerabilities detected in {domain}")
                elif current_vuln_count < previous_vuln_count:
                    domain_changes['resolved_vulnerabilities'] = previous_vuln_count - current_vuln_count
                
                comparison['changes_detected'][domain] = domain_changes
            
            return comparison
        
        def export_to_formats(self, report_data, formats=['json', 'html']):
            """Export reports to multiple formats"""
            print(f"   💾 Exporting reports to formats: {formats}")
            
            output_files = []
            base_path = self.hyperrecon.output_dir
            
            for format_type in formats:
                if format_type == 'json':
                    json_file = os.path.join(base_path, 'custom_report.json')
                    with open(json_file, 'w') as f:
                        json.dump(report_data, f, indent=2)
                    output_files.append(json_file)
                    print(f"     • JSON report: {json_file}")
                
                elif format_type == 'html':
                    html_file = os.path.join(base_path, 'custom_report.html')
                    html_content = self._generate_html_report(report_data)
                    with open(html_file, 'w') as f:
                        f.write(html_content)
                    output_files.append(html_file)
                    print(f"     • HTML report: {html_file}")
                
                elif format_type == 'csv':
                    csv_file = os.path.join(base_path, 'custom_report.csv')
                    self._generate_csv_report(report_data, csv_file)
                    output_files.append(csv_file)
                    print(f"     • CSV report: {csv_file}")
            
            return output_files
        
        def _generate_html_report(self, report_data):
            """Generate HTML report content"""
            html_template = """
            <!DOCTYPE html>
            <html>
            <head>
                <title>Custom HyperRecon Report</title>
                <style>
                    body { font-family: Arial, sans-serif; margin: 20px; }
                    .header { background: #2c3e50; color: white; padding: 20px; }
                    .section { margin: 20px 0; padding: 15px; border: 1px solid #ddd; }
                    .metric { display: inline-block; margin: 10px; padding: 10px; background: #f8f9fa; }
                    .alert { background: #f8d7da; color: #721c24; padding: 10px; margin: 10px 0; }
                </style>
            </head>
            <body>
                <div class="header">
                    <h1>HyperRecon Pro Custom Report</h1>
                    <p>Generated: {timestamp}</p>
                </div>
                
                <div class="section">
                    <h2>Executive Summary</h2>
                    <div class="metric">Risk Score: {risk_score}/100</div>
                    <div class="metric">Total Domains: {total_domains}</div>
                    <div class="metric">Total Vulnerabilities: {total_vulns}</div>
                </div>
                
                <div class="section">
                    <h2>Key Findings</h2>
                    <p>Detailed findings would be displayed here...</p>
                </div>
                
                <div class="section">
                    <h2>Recommendations</h2>
                    <ul>
                        <li>Review and address identified vulnerabilities</li>
                        <li>Implement security monitoring</li>
                        <li>Regular security assessments</li>
                    </ul>
                </div>
            </body>
            </html>
            """.format(
                timestamp=datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                risk_score=report_data.get('risk_assessment', {}).get('overall_risk_score', 0),
                total_domains=report_data.get('scan_overview', {}).get('total_domains', 0),
                total_vulns=report_data.get('key_findings', {}).get('total_vulnerabilities', 0)
            )
            
            return html_template
        
        def _generate_csv_report(self, report_data, csv_file):
            """Generate CSV report"""
            import csv
            
            with open(csv_file, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(['Metric', 'Value'])
                
                # Write key metrics
                key_findings = report_data.get('key_findings', {})
                for metric, value in key_findings.items():
                    writer.writerow([metric.replace('_', ' ').title(), value])
    
    # Demo custom reporting
    reporter = CustomReporter()
    
    # Run a scan to get data
    target = "example.com"
    print(f"Running scan for custom reporting demo: {target}")
    
    scan_results = reporter.hyperrecon.run_scan([target])
    
    if scan_results:
        print(f"\n📊 Generating custom reports...")
        
        # Generate different report types
        executive_summary = reporter.generate_executive_summary(scan_results)
        technical_report = reporter.generate_technical_report(scan_results)
        comparison_report = reporter.create_comparison_report(scan_results)
        
        # Combine reports
        combined_report = {
            'executive_summary': executive_summary,
            'technical_report': technical_report,
            'comparison_report': comparison_report
        }
        
        # Export to multiple formats
        output_files = reporter.export_to_formats(combined_report, ['json', 'html'])
        
        print(f"\n✅ Custom reporting completed")
        print(f"   • Executive summary generated")
        print(f"   • Technical report generated")
        print(f"   • Comparison report generated")
        print(f"   • Reports exported to: {output_files}")

def main():
    """Run all advanced usage examples"""
    print("🚀 HyperRecon Pro v4.0 - Advanced Usage Examples")
    print("=" * 70)
    
    # Create output directory
    os.makedirs("examples/output", exist_ok=True)
    
    try:
        # Run advanced examples
        example_custom_workflow()
        example_batch_processing()
        example_continuous_monitoring()
        example_integration_with_external_tools()
        example_custom_reporting()
        
        print("\n" + "=" * 70)
        print("✅ All advanced usage examples completed successfully!")
        print("\n📁 Check the following directories for results:")
        print("   • examples/output/custom_workflow/")
        print("   • examples/output/batch_processing/")
        print("   • examples/output/continuous_monitoring/")
        print("   • examples/output/external_integration/")
        print("   • examples/output/custom_reporting/")
        
        print("\n🎯 Advanced Features Demonstrated:")
        print("   • Custom reconnaissance workflows")
        print("   • Batch processing with queue management")
        print("   • Continuous monitoring capabilities")
        print("   • External tool integrations")
        print("   • Custom reporting and visualization")
        
    except KeyboardInterrupt:
        print("\n⏹️ Advanced examples interrupted by user")
    except Exception as e:
        print(f"\n❌ Error running advanced examples: {e}")
        if "--debug" in sys.argv:
            raise

if __name__ == "__main__":
    main()