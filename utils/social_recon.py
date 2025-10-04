"""
utils/social_recon.py - Enhanced Social Media Reconnaissance with Direct URLs
Part of HyperRecon Pro v4.0 - Advanced Modular Bug Bounty Scanner
"""

import time
import requests
from datetime import datetime

class SocialRecon:
    def __init__(self, hyperrecon_instance):
        self.hyperrecon = hyperrecon_instance

        # Social media platforms to check
        self.platforms = [
            'github', 'twitter', 'linkedin', 'instagram', 'facebook', 
            'youtube', 'discord', 'reddit', 'tiktok', 'telegram',
            'pinterest', 'snapchat', 'whatsapp', 'twitch', 'medium', 
            'stackoverflow'
        ]
    
    def execute(self, target, domain_path):
        """Execute social media reconnaissance - wrapper for comprehensive_recon"""
        try:
            results = self.comprehensive_recon(target, domain_path)
            
            # Create a proper result object with success attribute
            class SocialReconResult:
                def __init__(self, success, data, errors=None):
                    self.success = success
                    self.data = data
                    self.errors = errors or []
                    self.execution_time = 0  # Add missing attribute
            
            return SocialReconResult(True, results, [])
            
        except Exception as e:
            class SocialReconResult:
                def __init__(self, success, data, errors=None):
                    self.success = success
                    self.data = data
                    self.errors = errors or []
                    self.execution_time = 0  # Add missing attribute
            
            return SocialReconResult(False, {}, [str(e)])

    def comprehensive_recon(self, target, domain_path):
        """Search for mentions of targets on all major social media platforms"""
        try:
            self.hyperrecon.console.print(f"🔎 [cyan]Social media reconnaissance for {target}[/cyan]")
        except:
            print(f"Social media reconnaissance for {target}")

        social_results = {}
        successful_platforms = 0
        failed_platforms = 0

        try:
            for platform in self.platforms:
                try:
                    try:
                        self.hyperrecon.console.print(f"🔍 [blue]Searching {platform.title()} for {target}[/blue]")
                    except:
                        print(f"Searching {platform.title()} for {target}")

                    # Get platform-specific search function
                    search_func = getattr(self, f'search_{platform}', None)
                    if search_func:
                        try:
                            platform_results = search_func(target)
                            if platform_results and isinstance(platform_results, dict):
                                # Validate that the result has the expected structure
                                if ('direct_urls' in platform_results or 
                                    'queries' in platform_results or 
                                    'profiles_to_check' in platform_results):
                                    
                                    social_results[platform] = platform_results
                                    successful_platforms += 1

                                    # Real-time save platform results with direct URLs
                                    filename = f"{platform}_results.txt"
                                    self.save_platform_results(domain_path, filename, platform_results, target)
                                else:
                                    try:
                                        self.hyperrecon.console.print(f"⚠️ [yellow]{platform.title()}: Invalid result structure[/yellow]")
                                    except:
                                        print(f"{platform.title()}: Invalid result structure")
                                    failed_platforms += 1
                            else:
                                try:
                                    self.hyperrecon.console.print(f"⚠️ [yellow]{platform.title()}: No valid results returned[/yellow]")
                                except:
                                    print(f"{platform.title()}: No valid results returned")
                                failed_platforms += 1

                            time.sleep(0.2)  # Rate limiting

                        except Exception as e:
                            try:
                                self.hyperrecon.console.print(f"⚠️ [yellow]{platform.title()} search error: {e}[/yellow]")
                            except:
                                print(f"{platform.title()} search error: {e}")
                            failed_platforms += 1
                            continue
                    else:
                        try:
                            self.hyperrecon.console.print(f"⚠️ [yellow]{platform.title()}: No search function available[/yellow]")
                        except:
                            print(f"{platform.title()}: No search function available")
                        failed_platforms += 1

                except Exception as e:
                    try:
                        self.hyperrecon.console.print(f"❌ [red]{platform.title()} processing error: {e}[/red]")
                    except:
                        print(f"{platform.title()} processing error: {e}")
                    failed_platforms += 1
                    continue

            # Report results
            if social_results:
                try:
                    self.hyperrecon.console.print(f"✅ [green]Social media recon completed for {target}[/green]")
                    self.hyperrecon.console.print(f"📊 [blue]Found results on {successful_platforms} platforms[/blue]")
                    if failed_platforms > 0:
                        self.hyperrecon.console.print(f"⚠️ [yellow]{failed_platforms} platforms had issues[/yellow]")
                except:
                    print(f"Found results on {successful_platforms} platforms")
                    if failed_platforms > 0:
                        print(f"{failed_platforms} platforms had issues")

                # Create comprehensive summary
                self.create_social_media_summary(social_results, domain_path, target)
            else:
                try:
                    self.hyperrecon.console.print(f"❌ [red]No social media results found for {target}[/red]")
                    if failed_platforms > 0:
                        self.hyperrecon.console.print(f"⚠️ [yellow]{failed_platforms} platforms had errors[/yellow]")
                except:
                    print(f"No social media results found for {target}")
                    if failed_platforms > 0:
                        print(f"{failed_platforms} platforms had errors")

                # Save "no results" indicator
                no_results_content = [
                    f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] No social media results found for {target}",
                    f"Platforms checked: {len(self.platforms)}",
                    f"Successful searches: {successful_platforms}",
                    f"Failed searches: {failed_platforms}",
                    "",
                    "This could mean:",
                    "- Target has no social media presence with this name",
                    "- Target uses different usernames on social platforms", 
                    "- Some platforms may have been temporarily unavailable",
                    "",
                    "Consider trying variations of the target name or manual searches."
                ]
                
                self.hyperrecon.save_results_realtime(domain_path, 'social_media_recon',
                                                    'no_social_media_results.txt', no_results_content)

        except Exception as e:
            try:
                self.hyperrecon.console.print(f"❌ [red]Social media recon error: {e}[/red]")
            except:
                print(f"Social media recon error: {e}")

        return social_results

    def save_platform_results(self, domain_path, filename, results, target):
        """Save platform-specific results with direct URLs"""
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        content = [
            f"[{timestamp}] Social Media Search Results for {target}",
            "=" * 60
        ]

        if isinstance(results, dict):
            if 'type' in results and results['type'] == 'search_suggestions':
                platform_name = results.get('platform', 'Unknown')
                content.extend([
                    f"Platform: {platform_name}",
                    f"Target: {target}",
                    f"Scan Time: {timestamp}",
                    ""
                ])

                # Add platform note/description
                if 'note' in results:
                    content.extend([
                        f"Description: {results['note']}",
                        ""
                    ])

                # Add direct URLs first (most important)
                if 'direct_urls' in results and results['direct_urls']:
                    content.extend([
                        "🔗 DIRECT URLS TO CHECK:",
                        "-" * 30
                    ])
                    for i, url in enumerate(results['direct_urls'], 1):
                        content.append(f"  {i}. {url}")
                    content.append("")

                # Add profile links if different from direct URLs
                if 'profiles_to_check' in results and results['profiles_to_check']:
                    content.extend([
                        "👤 PROFILE LINKS:",
                        "-" * 20
                    ])
                    for i, link in enumerate(results['profiles_to_check'], 1):
                        content.append(f"  {i}. {link}")
                    content.append("")

                # Add search queries for manual investigation
                if 'queries' in results and results['queries']:
                    content.extend([
                        "🔍 GOOGLE SEARCH QUERIES:",
                        "-" * 30,
                        "Copy and paste these into Google for manual investigation:"
                    ])
                    for i, query in enumerate(results['queries'], 1):
                        content.append(f"  {i}. {query}")
                    content.append("")

                # Add usage instructions
                content.extend([
                    "💡 HOW TO USE:",
                    "-" * 15,
                    "1. Click on direct URLs to check if profiles exist",
                    "2. Use Google search queries for broader investigation",
                    "3. Look for variations of the target name",
                    "4. Check for related accounts or mentions",
                    ""
                ])

            elif 'direct_results' in results:
                content.extend([
                    "✅ DIRECT RESULTS FOUND:",
                    "-" * 25
                ])
                for i, result in enumerate(results['direct_results'], 1):
                    content.append(f"  {i}. {result}")
                content.append("")
            else:
                content.extend([
                    "📄 RAW RESULTS:",
                    "-" * 15,
                    str(results)
                ])
        elif isinstance(results, list):
            content.extend([
                "📋 RESULTS LIST:",
                "-" * 15
            ])
            content.extend(results)
        else:
            content.extend([
                "📄 RESULT DATA:",
                "-" * 15,
                str(results)
            ])

        # Add footer with timestamp
        content.extend([
            "",
            "=" * 60,
            f"Report generated: {timestamp}",
            f"Target: {target}",
            "=" * 60
        ])

        self.hyperrecon.save_results_realtime(domain_path, 'social_media_recon', filename, content)

    def create_social_media_summary(self, social_results, domain_path, target):
        """Create comprehensive social media summary"""
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        summary = [
            f"[{timestamp}] Social Media Reconnaissance Summary for {target}",
            f"Platforms with results: {len(social_results)}/{len(self.platforms)}",
            f"Scan completed: {timestamp}",
            "",
            "=" * 60,
            "🔗 DIRECT ACCESS URLS",
            "=" * 60
        ]

        # Add all direct URLs organized by platform
        total_urls = 0
        for platform, results in social_results.items():
            if isinstance(results, dict):
                platform_urls = []
                
                # Collect URLs from different sources
                if 'direct_urls' in results:
                    platform_urls.extend(results['direct_urls'])
                if 'profiles_to_check' in results:
                    platform_urls.extend(results['profiles_to_check'])
                
                if platform_urls:
                    summary.append(f"\n📱 {platform.upper()}:")
                    for url in platform_urls:
                        summary.append(f"   {url}")
                    total_urls += len(platform_urls)

        summary.extend([
            "",
            "=" * 60,
            "🔍 GOOGLE SEARCH QUERIES",
            "=" * 60
        ])

        # Add search queries for manual investigation
        for platform, results in social_results.items():
            if isinstance(results, dict) and 'queries' in results:
                summary.append(f"\n🔎 {platform.upper()} Queries:")
                for query in results['queries']:
                    summary.append(f"   {query}")

        summary.extend([
            "",
            "=" * 60,
            "📊 PLATFORM COVERAGE REPORT", 
            "=" * 60
        ])

        # Detailed platform status
        successful_platforms = []
        failed_platforms = []
        
        for platform in self.platforms:
            if platform in social_results:
                successful_platforms.append(platform)
                summary.append(f"  ✅ {platform.title()}: Results found")
            else:
                failed_platforms.append(platform)
                summary.append(f"  ❌ {platform.title()}: No results")

        summary.extend([
            "",
            "=" * 60,
            "📈 SUMMARY STATISTICS",
            "=" * 60,
            f"Total platforms checked: {len(self.platforms)}",
            f"Platforms with results: {len(successful_platforms)}",
            f"Platforms without results: {len(failed_platforms)}",
            f"Total direct URLs found: {total_urls}",
            f"Success rate: {(len(successful_platforms)/len(self.platforms)*100):.1f}%",
            "",
            "💡 NEXT STEPS:",
            "1. Visit the direct URLs above to check for valid profiles",
            "2. Use the Google search queries for additional investigation", 
            "3. Try variations of the target name for better coverage",
            "4. Check individual platform result files for detailed information"
        ])

        self.hyperrecon.save_results_realtime(domain_path, 'social_media_recon',
                                            'social_media_summary.txt', summary)

    def search_github(self, target):
        """Search GitHub with direct URLs"""
        try:
            direct_urls = [
                f'https://github.com/{target}',
                f'https://github.com/search?q={target}',
                f'https://github.com/search?q="{target}"&type=repositories',
                f'https://github.com/search?q="{target}"&type=code',
                f'https://github.com/search?q="{target}"&type=users'
            ]

            search_queries = [
                f'site:github.com "{target}"',
                f'site:github.com {target}',
                f'"{target}" github.com',
                f'inurl:github.com "{target}"'
            ]

            return {
                'type': 'search_suggestions',
                'platform': 'GitHub',
                'direct_urls': direct_urls,
                'queries': search_queries,
                'note': 'GitHub repositories, users, and code search'
            }
        except Exception:
            return None

    def search_twitter(self, target):
        """Enhanced Twitter/X search with direct URLs"""
        try:
            direct_urls = [
                f'https://twitter.com/{target}',
                f'https://x.com/{target}',
                f'https://twitter.com/search?q={target}',
                f'https://x.com/search?q={target}',
                f'https://twitter.com/search?q="{target}"',
                f'https://x.com/search?q="{target}"'
            ]

            search_queries = [
                f'site:twitter.com "{target}"',
                f'site:x.com "{target}"',
                f'"{target}" twitter.com',
                f'@{target} site:twitter.com'
            ]

            return {
                'type': 'search_suggestions',
                'platform': 'Twitter/X',
                'direct_urls': direct_urls,
                'queries': search_queries,
                'note': 'Twitter/X profiles and mentions'
            }
        except Exception:
            return None

    def search_linkedin(self, target):
        """LinkedIn search with direct URLs"""
        try:
            direct_urls = [
                f'https://linkedin.com/in/{target}',
                f'https://linkedin.com/company/{target}',
                f'https://linkedin.com/search/results/people/?keywords={target}',
                f'https://linkedin.com/search/results/companies/?keywords={target}'
            ]

            search_queries = [
                f'site:linkedin.com "{target}"',
                f'"{target}" linkedin.com',
                f'site:linkedin.com/in/ "{target}"',
                f'site:linkedin.com/company/ "{target}"'
            ]

            return {
                'type': 'search_suggestions',
                'platform': 'LinkedIn',
                'direct_urls': direct_urls,
                'queries': search_queries,
                'note': 'LinkedIn profiles and company pages'
            }
        except Exception:
            return None

    def search_instagram(self, target):
        """Instagram search with direct URLs"""
        try:
            direct_urls = [
                f'https://instagram.com/{target}',
                f'https://instagram.com/explore/tags/{target}/',
                f'https://instagram.com/search/top/?q={target}'
            ]

            return {
                'type': 'search_suggestions',
                'platform': 'Instagram',
                'direct_urls': direct_urls,
                'queries': [f'site:instagram.com "{target}"'],
                'note': 'Instagram profiles and hashtags'
            }
        except:
            return None

    def search_facebook(self, target):
        """Facebook search with direct URLs"""
        try:
            direct_urls = [
                f'https://facebook.com/{target}',
                f'https://facebook.com/search/top/?q={target}',
                f'https://facebook.com/pages/search/?q={target}'
            ]

            return {
                'type': 'search_suggestions',
                'platform': 'Facebook',
                'direct_urls': direct_urls,
                'queries': [f'site:facebook.com "{target}"'],
                'note': 'Facebook pages and profiles'
            }
        except:
            return None

    # Add remaining 11 platforms with direct URLs...
    def search_youtube(self, target):
        try:
            direct_urls = [
                f'https://youtube.com/c/{target}',
                f'https://youtube.com/user/{target}',
                f'https://youtube.com/results?search_query={target}',
                f'https://youtube.com/@{target}',
                f'https://youtube.com/channel/{target}'
            ]
            
            search_queries = [
                f'site:youtube.com "{target}"',
                f'"{target}" youtube.com',
                f'site:youtube.com/c/ "{target}"',
                f'site:youtube.com/user/ "{target}"'
            ]
            
            return {
                'type': 'search_suggestions', 
                'platform': 'YouTube', 
                'direct_urls': direct_urls,
                'queries': search_queries,
                'note': 'YouTube channels and video content'
            }
        except: 
            return None

    def search_discord(self, target):
        try:
            direct_urls = [
                f'https://discord.gg/{target}',
                f'https://disboard.org/search?keyword={target}',
                f'https://discord.me/servers/search?term={target}'
            ]
            
            search_queries = [
                f'site:discord.gg "{target}"',
                f'"{target}" discord server',
                f'"{target}" discord.gg',
                f'site:disboard.org "{target}"'
            ]
            
            return {
                'type': 'search_suggestions', 
                'platform': 'Discord', 
                'direct_urls': direct_urls,
                'queries': search_queries,
                'note': 'Discord servers and communities'
            }
        except: 
            return None

    def search_reddit(self, target):
        try:
            direct_urls = [
                f'https://reddit.com/r/{target}',
                f'https://reddit.com/user/{target}',
                f'https://reddit.com/search/?q={target}',
                f'https://www.reddit.com/u/{target}'
            ]
            
            search_queries = [
                f'site:reddit.com "{target}"',
                f'site:reddit.com/r/ "{target}"',
                f'site:reddit.com/user/ "{target}"',
                f'"{target}" reddit.com'
            ]
            
            return {
                'type': 'search_suggestions', 
                'platform': 'Reddit', 
                'direct_urls': direct_urls,
                'queries': search_queries,
                'note': 'Reddit communities and user profiles'
            }
        except: 
            return None

    def search_tiktok(self, target):
        try:
            direct_urls = [
                f'https://tiktok.com/@{target}',
                f'https://tiktok.com/search?q={target}',
                f'https://www.tiktok.com/@{target}'
            ]
            
            search_queries = [
                f'site:tiktok.com "{target}"',
                f'"{target}" tiktok.com',
                f'site:tiktok.com/@{target}'
            ]
            
            return {
                'type': 'search_suggestions', 
                'platform': 'TikTok', 
                'direct_urls': direct_urls,
                'queries': search_queries,
                'note': 'TikTok profiles and content'
            }
        except: 
            return None

    def search_telegram(self, target):
        try:
            direct_urls = [
                f'https://t.me/{target}',
                f'https://t.me/s/{target}',
                f'https://telegram.me/{target}'
            ]
            
            search_queries = [
                f'site:t.me "{target}"',
                f'"{target}" telegram',
                f'"{target}" t.me',
                f'site:telegram.me "{target}"'
            ]
            
            return {
                'type': 'search_suggestions', 
                'platform': 'Telegram', 
                'direct_urls': direct_urls,
                'queries': search_queries,
                'note': 'Telegram channels and groups'
            }
        except: 
            return None

    def search_pinterest(self, target):
        try:
            direct_urls = [
                f'https://pinterest.com/{target}',
                f'https://pinterest.com/search/pins/?q={target}',
                f'https://www.pinterest.com/{target}'
            ]
            
            search_queries = [
                f'site:pinterest.com "{target}"',
                f'"{target}" pinterest.com',
                f'site:pinterest.com/{target}'
            ]
            
            return {
                'type': 'search_suggestions', 
                'platform': 'Pinterest', 
                'direct_urls': direct_urls,
                'queries': search_queries,
                'note': 'Pinterest profiles and boards'
            }
        except: 
            return None

    def search_snapchat(self, target):
        try:
            direct_urls = [
                f'https://snapchat.com/add/{target}',
                f'https://www.snapchat.com/add/{target}'
            ]
            
            search_queries = [
                f'site:snapchat.com "{target}"',
                f'"{target}" snapchat',
                f'"{target}" snapchat.com/add'
            ]
            
            return {
                'type': 'search_suggestions', 
                'platform': 'Snapchat', 
                'direct_urls': direct_urls,
                'queries': search_queries,
                'note': 'Snapchat user profiles'
            }
        except: 
            return None

    def search_whatsapp(self, target):
        try:
            # WhatsApp Business and group search suggestions
            search_queries = [
                f'site:chat.whatsapp.com "{target}"',
                f'"{target}" WhatsApp Business',
                f'"{target}" WhatsApp group',
                f'inurl:wa.me "{target}"'
            ]
            
            direct_urls = [
                f'https://wa.me/{target}',  # If target is a phone number
                f'https://chat.whatsapp.com/{target}'  # If target is a group invite
            ]
            
            return {
                'type': 'search_suggestions', 
                'platform': 'WhatsApp', 
                'direct_urls': direct_urls,
                'queries': search_queries,
                'note': 'WhatsApp Business profiles and group searches'
            }
        except: 
            return None

    def search_twitch(self, target):
        try:
            direct_urls = [
                f'https://twitch.tv/{target}',
                f'https://twitch.tv/search?term={target}',
                f'https://www.twitch.tv/{target}'
            ]
            
            search_queries = [
                f'site:twitch.tv "{target}"',
                f'"{target}" twitch.tv',
                f'"{target}" twitch streamer'
            ]
            
            return {
                'type': 'search_suggestions', 
                'platform': 'Twitch', 
                'direct_urls': direct_urls,
                'queries': search_queries,
                'note': 'Twitch streaming profiles'
            }
        except: 
            return None

    def search_medium(self, target):
        try:
            direct_urls = [
                f'https://medium.com/@{target}',
                f'https://medium.com/search?q={target}',
                f'https://{target}.medium.com'
            ]
            
            search_queries = [
                f'site:medium.com "{target}"',
                f'site:medium.com/@{target}',
                f'"{target}" medium.com',
                f'site:{target}.medium.com'
            ]
            
            return {
                'type': 'search_suggestions', 
                'platform': 'Medium', 
                'direct_urls': direct_urls,
                'queries': search_queries,
                'note': 'Medium blog profiles and publications'
            }
        except: 
            return None

    def search_stackoverflow(self, target):
        try:
            direct_urls = [
                f'https://stackoverflow.com/search?q={target}',
                f'https://stackoverflow.com/users?tab=Reputation&filter=all&search={target}',
                f'https://stackexchange.com/search?q={target}'
            ]
            
            search_queries = [
                f'site:stackoverflow.com "{target}"',
                f'site:stackexchange.com "{target}"',
                f'"{target}" stackoverflow.com',
                f'site:stackoverflow.com/users "{target}"'
            ]
            
            return {
                'type': 'search_suggestions', 
                'platform': 'Stack Overflow', 
                'direct_urls': direct_urls,
                'queries': search_queries,
                'note': 'Stack Overflow and Stack Exchange profiles'
            }
        except: 
            return None
