"""
Network Analyzer
Extracts network artifacts and browser data
"""

import os
import json
import sqlite3
import psutil
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Any, Optional

from ..utils.logger import get_logger
from ..utils.timezone_utils import get_current_utc_isoformat
from ..utils.hashing import calculate_file_hash


class NetworkAnalyzer:
    """Network analyzer for forensic analysis"""
    
    def __init__(self):
        self.logger = get_logger(__name__)
        
        # Browser data locations
        self.browser_locations = {
            'chrome': {
                'history': os.path.expanduser("~\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\History"),
                'cookies': os.path.expanduser("~\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Cookies"),
                'downloads': os.path.expanduser("~\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Downloads"),
                'login_data': os.path.expanduser("~\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Login Data")
            },
            'firefox': {
                'profile_dir': os.path.expanduser("~\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles"),
                'places': 'places.sqlite',
                'cookies': 'cookies.sqlite',
                'downloads': 'downloads.sqlite',
                'formhistory': 'formhistory.sqlite'
            },
            'edge': {
                'history': os.path.expanduser("~\\AppData\\Local\\Microsoft\\Edge\\User Data\\Default\\History"),
                'cookies': os.path.expanduser("~\\AppData\\Local\\Microsoft\\Edge\\User Data\\Default\\Cookies"),
                'downloads': os.path.expanduser("~\\AppData\\Local\\Microsoft\\Edge\\User Data\\Default\\Downloads"),
                'login_data': os.path.expanduser("~\\AppData\\Local\\Microsoft\\Edge\\User Data\\Default\\Login Data")
            }
        }
    
    def extract_network_artifacts(self, output_dir: Path) -> Dict[str, Any]:
        """Extract network artifacts"""
        self.logger.info("Extracting network artifacts")
        
        network_artifacts = {
            'extraction_time': get_current_utc_isoformat(),
            'artifacts': {}
        }
        
        try:
            # Extract network configuration
            network_config = self.extract_network_configuration(output_dir)
            network_artifacts['artifacts']['network_config'] = network_config
            
            # Extract browser history
            browser_history = self.extract_browser_history(output_dir)
            network_artifacts['artifacts']['browser_history'] = browser_history
            
            # Extract browser cookies
            browser_cookies = self.extract_browser_cookies(output_dir)
            network_artifacts['artifacts']['browser_cookies'] = browser_cookies
            
            # Extract browser downloads
            browser_downloads = self.extract_browser_downloads(output_dir)
            network_artifacts['artifacts']['browser_downloads'] = browser_downloads
            
            # Extract DNS cache
            dns_cache = self.extract_dns_cache(output_dir)
            network_artifacts['artifacts']['dns_cache'] = dns_cache
            
            # Extract ARP cache
            arp_cache = self.extract_arp_cache(output_dir)
            network_artifacts['artifacts']['arp_cache'] = arp_cache
            
            # Save to files
            self._save_network_artifacts(output_dir, network_artifacts)
            
            return network_artifacts
            
        except Exception as e:
            self.logger.error(f"Error extracting network artifacts: {str(e)}")
            raise
    
    def extract_network_configuration(self, output_dir: Path) -> Dict[str, Any]:
        """Extract network configuration"""
        self.logger.info("Extracting network configuration")
        
        network_config_dir = output_dir / "network_config"
        network_config_dir.mkdir(exist_ok=True)
        
        network_config_data = {
            'extraction_time': get_current_utc_isoformat(),
            'network_config': {}
        }
        
        try:
            # Get network interfaces
            network_interfaces = psutil.net_if_addrs()
            network_config_data['network_config']['interfaces'] = {}
            
            for interface, addresses in network_interfaces.items():
                interface_data = []
                for addr in addresses:
                    addr_data = {
                        'family': str(addr.family),
                        'address': addr.address,
                        'netmask': addr.netmask,
                        'broadcast': addr.broadcast,
                        'ptp': addr.ptp
                    }
                    interface_data.append(addr_data)
                network_config_data['network_config']['interfaces'][interface] = interface_data
            
            # Get network statistics
            network_stats = psutil.net_io_counters(pernic=True)
            network_config_data['network_config']['statistics'] = {}
            
            for interface, stats in network_stats.items():
                stats_data = {
                    'bytes_sent': stats.bytes_sent,
                    'bytes_recv': stats.bytes_recv,
                    'packets_sent': stats.packets_sent,
                    'packets_recv': stats.packets_recv,
                    'errin': stats.errin,
                    'errout': stats.errout,
                    'dropin': stats.dropin,
                    'dropout': stats.dropout
                }
                network_config_data['network_config']['statistics'][interface] = stats_data
            
        except Exception as e:
            self.logger.error(f"Error extracting network configuration: {str(e)}")
        
        # Save network configuration
        with open(network_config_dir / "network_config.json", 'w', encoding='utf-8') as f:
            json.dump(network_config_data, f, indent=2, default=str, ensure_ascii=False)
        
        return network_config_data
    
    def extract_browser_history(self, output_dir: Path) -> Dict[str, Any]:
        """Extract browser history"""
        self.logger.info("Extracting browser history")
        
        browser_history_dir = output_dir / "browser_history"
        browser_history_dir.mkdir(exist_ok=True)
        
        browser_history_data = {
            'extraction_time': get_current_utc_isoformat(),
            'browsers': {}
        }
        
        # Extract Chrome history
        try:
            chrome_history = self._extract_chrome_history()
            browser_history_data['browsers']['chrome'] = chrome_history
        except Exception as e:
            self.logger.warning(f"Error extracting Chrome history: {str(e)}")
            browser_history_data['browsers']['chrome'] = {'error': str(e)}
        
        # Extract Firefox history
        try:
            firefox_history = self._extract_firefox_history()
            browser_history_data['browsers']['firefox'] = firefox_history
        except Exception as e:
            self.logger.warning(f"Error extracting Firefox history: {str(e)}")
            browser_history_data['browsers']['firefox'] = {'error': str(e)}
        
        # Extract Edge history
        try:
            edge_history = self._extract_edge_history()
            browser_history_data['browsers']['edge'] = edge_history
        except Exception as e:
            self.logger.warning(f"Error extracting Edge history: {str(e)}")
            browser_history_data['browsers']['edge'] = {'error': str(e)}
        
        # Save browser history
        with open(browser_history_dir / "browser_history.json", 'w', encoding='utf-8') as f:
            json.dump(browser_history_data, f, indent=2, default=str, ensure_ascii=False)
        
        return browser_history_data
    
    def extract_browser_cookies(self, output_dir: Path) -> Dict[str, Any]:
        """Extract browser cookies"""
        self.logger.info("Extracting browser cookies")
        
        browser_cookies_dir = output_dir / "browser_cookies"
        browser_cookies_dir.mkdir(exist_ok=True)
        
        browser_cookies_data = {
            'extraction_time': get_current_utc_isoformat(),
            'browsers': {}
        }
        
        # Extract Chrome cookies
        try:
            chrome_cookies = self._extract_chrome_cookies()
            browser_cookies_data['browsers']['chrome'] = chrome_cookies
        except Exception as e:
            self.logger.warning(f"Error extracting Chrome cookies: {str(e)}")
            browser_cookies_data['browsers']['chrome'] = {'error': str(e)}
        
        # Extract Firefox cookies
        try:
            firefox_cookies = self._extract_firefox_cookies()
            browser_cookies_data['browsers']['firefox'] = firefox_cookies
        except Exception as e:
            self.logger.warning(f"Error extracting Firefox cookies: {str(e)}")
            browser_cookies_data['browsers']['firefox'] = {'error': str(e)}
        
        # Extract Edge cookies
        try:
            edge_cookies = self._extract_edge_cookies()
            browser_cookies_data['browsers']['edge'] = edge_cookies
        except Exception as e:
            self.logger.warning(f"Error extracting Edge cookies: {str(e)}")
            browser_cookies_data['browsers']['edge'] = {'error': str(e)}
        
        # Save browser cookies
        with open(browser_cookies_dir / "browser_cookies.json", 'w', encoding='utf-8') as f:
            json.dump(browser_cookies_data, f, indent=2, default=str, ensure_ascii=False)
        
        return browser_cookies_data
    
    def extract_browser_downloads(self, output_dir: Path) -> Dict[str, Any]:
        """Extract browser downloads"""
        self.logger.info("Extracting browser downloads")
        
        browser_downloads_dir = output_dir / "browser_downloads"
        browser_downloads_dir.mkdir(exist_ok=True)
        
        browser_downloads_data = {
            'extraction_time': get_current_utc_isoformat(),
            'browsers': {}
        }
        
        # Extract Chrome downloads
        try:
            chrome_downloads = self._extract_chrome_downloads()
            browser_downloads_data['browsers']['chrome'] = chrome_downloads
        except Exception as e:
            self.logger.warning(f"Error extracting Chrome downloads: {str(e)}")
            browser_downloads_data['browsers']['chrome'] = {'error': str(e)}
        
        # Extract Firefox downloads
        try:
            firefox_downloads = self._extract_firefox_downloads()
            browser_downloads_data['browsers']['firefox'] = firefox_downloads
        except Exception as e:
            self.logger.warning(f"Error extracting Firefox downloads: {str(e)}")
            browser_downloads_data['browsers']['firefox'] = {'error': str(e)}
        
        # Extract Edge downloads
        try:
            edge_downloads = self._extract_edge_downloads()
            browser_downloads_data['browsers']['edge'] = edge_downloads
        except Exception as e:
            self.logger.warning(f"Error extracting Edge downloads: {str(e)}")
            browser_downloads_data['browsers']['edge'] = {'error': str(e)}
        
        # Save browser downloads
        with open(browser_downloads_dir / "browser_downloads.json", 'w', encoding='utf-8') as f:
            json.dump(browser_downloads_data, f, indent=2, default=str, ensure_ascii=False)
        
        return browser_downloads_data
    
    def extract_dns_cache(self, output_dir: Path) -> Dict[str, Any]:
        """Extract DNS cache"""
        self.logger.info("Extracting DNS cache")
        
        dns_cache_dir = output_dir / "dns_cache"
        dns_cache_dir.mkdir(exist_ok=True)
        
        dns_cache_data = {
            'extraction_time': get_current_utc_isoformat(),
            'dns_cache': []
        }
        
        try:
            # Execute ipconfig /displaydns command
            import subprocess
            
            result = subprocess.run(['ipconfig', '/displaydns'], 
                                  capture_output=True, text=True, shell=True)
            
            if result.returncode == 0:
                dns_cache_data['dns_cache'] = result.stdout
            else:
                dns_cache_data['error'] = result.stderr
                
        except Exception as e:
            self.logger.error(f"Error extracting DNS cache: {str(e)}")
            dns_cache_data['error'] = str(e)
        
        # Save DNS cache
        with open(dns_cache_dir / "dns_cache.txt", 'w') as f:
            f.write(dns_cache_data.get('dns_cache', ''))
        
        with open(dns_cache_dir / "dns_cache.json", 'w', encoding='utf-8') as f:
            json.dump(dns_cache_data, f, indent=2, default=str, ensure_ascii=False)
        
        return dns_cache_data
    
    def extract_arp_cache(self, output_dir: Path) -> Dict[str, Any]:
        """Extract ARP cache"""
        self.logger.info("Extracting ARP cache")
        
        arp_cache_dir = output_dir / "arp_cache"
        arp_cache_dir.mkdir(exist_ok=True)
        
        arp_cache_data = {
            'extraction_time': get_current_utc_isoformat(),
            'arp_cache': []
        }
        
        try:
            # Execute arp -a command
            import subprocess
            
            result = subprocess.run(['arp', '-a'], 
                                  capture_output=True, text=True, shell=True)
            
            if result.returncode == 0:
                arp_cache_data['arp_cache'] = result.stdout
            else:
                arp_cache_data['error'] = result.stderr
                
        except Exception as e:
            self.logger.error(f"Error extracting ARP cache: {str(e)}")
            arp_cache_data['error'] = str(e)
        
        # Save ARP cache
        with open(arp_cache_dir / "arp_cache.txt", 'w') as f:
            f.write(arp_cache_data.get('arp_cache', ''))
        
        with open(arp_cache_dir / "arp_cache.json", 'w', encoding='utf-8') as f:
            json.dump(arp_cache_data, f, indent=2, default=str, ensure_ascii=False)
        
        return arp_cache_data
    
    def _extract_chrome_history(self) -> Dict[str, Any]:
        """Extract Chrome browser history"""
        chrome_history = {
            'extraction_time': get_current_utc_isoformat(),
            'history': []
        }
        
        history_file = self.browser_locations['chrome']['history']
        
        if os.path.exists(history_file):
            try:
                # Copy the history file to avoid database lock issues
                import shutil
                temp_history = history_file + '.temp'
                shutil.copy2(history_file, temp_history)
                
                conn = sqlite3.connect(temp_history)
                cursor = conn.cursor()
                
                cursor.execute("""
                    SELECT url, title, visit_count, last_visit_time, typed_count
                    FROM urls
                    ORDER BY last_visit_time DESC
                    LIMIT 1000
                """)
                
                for row in cursor.fetchall():
                    history_entry = {
                        'url': row[0],
                        'title': row[1],
                        'visit_count': row[2],
                        'last_visit_time': row[3],
                        'typed_count': row[4]
                    }
                    chrome_history['history'].append(history_entry)
                
                conn.close()
                os.remove(temp_history)
                
            except Exception as e:
                chrome_history['error'] = str(e)
        else:
            chrome_history['error'] = 'History file not found'
        
        return chrome_history
    
    def _extract_firefox_history(self) -> Dict[str, Any]:
        """Extract Firefox browser history"""
        firefox_history = {
            'extraction_time': get_current_utc_isoformat(),
            'history': []
        }
        
        profile_dir = self.browser_locations['firefox']['profile_dir']
        
        if os.path.exists(profile_dir):
            try:
                # Find the default profile
                profiles = [d for d in os.listdir(profile_dir) if d.endswith('.default')]
                if profiles:
                    profile_path = os.path.join(profile_dir, profiles[0])
                    places_file = os.path.join(profile_path, self.browser_locations['firefox']['places'])
                    
                    if os.path.exists(places_file):
                        import shutil
                        temp_places = places_file + '.temp'
                        shutil.copy2(places_file, temp_places)
                        
                        conn = sqlite3.connect(temp_places)
                        cursor = conn.cursor()
                        
                        cursor.execute("""
                            SELECT url, title, visit_count, last_visit_date, typed
                            FROM moz_places
                            WHERE url IS NOT NULL
                            ORDER BY last_visit_date DESC
                            LIMIT 1000
                        """)
                        
                        for row in cursor.fetchall():
                            history_entry = {
                                'url': row[0],
                                'title': row[1],
                                'visit_count': row[2],
                                'last_visit_date': row[3],
                                'typed': row[4]
                            }
                            firefox_history['history'].append(history_entry)
                        
                        conn.close()
                        os.remove(temp_places)
                    else:
                        firefox_history['error'] = 'Places file not found'
                else:
                    firefox_history['error'] = 'No default profile found'
            except Exception as e:
                firefox_history['error'] = str(e)
        else:
            firefox_history['error'] = 'Firefox profile directory not found'
        
        return firefox_history
    
    def _extract_edge_history(self) -> Dict[str, Any]:
        """Extract Edge browser history"""
        edge_history = {
            'extraction_time': get_current_utc_isoformat(),
            'history': []
        }
        
        history_file = self.browser_locations['edge']['history']
        
        if os.path.exists(history_file):
            try:
                # Copy the history file to avoid database lock issues
                import shutil
                temp_history = history_file + '.temp'
                shutil.copy2(history_file, temp_history)
                
                conn = sqlite3.connect(temp_history)
                cursor = conn.cursor()
                
                cursor.execute("""
                    SELECT url, title, visit_count, last_visit_time, typed_count
                    FROM urls
                    ORDER BY last_visit_time DESC
                    LIMIT 1000
                """)
                
                for row in cursor.fetchall():
                    history_entry = {
                        'url': row[0],
                        'title': row[1],
                        'visit_count': row[2],
                        'last_visit_time': row[3],
                        'typed_count': row[4]
                    }
                    edge_history['history'].append(history_entry)
                
                conn.close()
                os.remove(temp_history)
                
            except Exception as e:
                edge_history['error'] = str(e)
        else:
            edge_history['error'] = 'History file not found'
        
        return edge_history
    
    def _extract_chrome_cookies(self) -> Dict[str, Any]:
        """Extract Chrome cookies"""
        chrome_cookies = {
            'extraction_time': get_current_utc_isoformat(),
            'cookies': []
        }
        
        cookies_file = self.browser_locations['chrome']['cookies']
        
        if os.path.exists(cookies_file):
            try:
                import shutil
                temp_cookies = cookies_file + '.temp'
                shutil.copy2(cookies_file, temp_cookies)
                
                conn = sqlite3.connect(temp_cookies)
                cursor = conn.cursor()
                
                cursor.execute("""
                    SELECT host_key, name, value, path, expires_utc, is_secure, is_httponly
                    FROM cookies
                    ORDER BY expires_utc DESC
                    LIMIT 1000
                """)
                
                for row in cursor.fetchall():
                    cookie_entry = {
                        'host_key': row[0],
                        'name': row[1],
                        'value': row[2],
                        'path': row[3],
                        'expires_utc': row[4],
                        'is_secure': row[5],
                        'is_httponly': row[6]
                    }
                    chrome_cookies['cookies'].append(cookie_entry)
                
                conn.close()
                os.remove(temp_cookies)
                
            except Exception as e:
                chrome_cookies['error'] = str(e)
        else:
            chrome_cookies['error'] = 'Cookies file not found'
        
        return chrome_cookies
    
    def _extract_firefox_cookies(self) -> Dict[str, Any]:
        """Extract Firefox cookies"""
        firefox_cookies = {
            'extraction_time': get_current_utc_isoformat(),
            'cookies': []
        }
        
        profile_dir = self.browser_locations['firefox']['profile_dir']
        
        if os.path.exists(profile_dir):
            try:
                profiles = [d for d in os.listdir(profile_dir) if d.endswith('.default')]
                if profiles:
                    profile_path = os.path.join(profile_dir, profiles[0])
                    cookies_file = os.path.join(profile_path, self.browser_locations['firefox']['cookies'])
                    
                    if os.path.exists(cookies_file):
                        import shutil
                        temp_cookies = cookies_file + '.temp'
                        shutil.copy2(cookies_file, temp_cookies)
                        
                        conn = sqlite3.connect(temp_cookies)
                        cursor = conn.cursor()
                        
                        cursor.execute("""
                            SELECT host, name, value, path, expiry, isSecure, isHttpOnly
                            FROM moz_cookies
                            ORDER BY expiry DESC
                            LIMIT 1000
                        """)
                        
                        for row in cursor.fetchall():
                            cookie_entry = {
                                'host': row[0],
                                'name': row[1],
                                'value': row[2],
                                'path': row[3],
                                'expiry': row[4],
                                'isSecure': row[5],
                                'isHttpOnly': row[6]
                            }
                            firefox_cookies['cookies'].append(cookie_entry)
                        
                        conn.close()
                        os.remove(temp_cookies)
                    else:
                        firefox_cookies['error'] = 'Cookies file not found'
                else:
                    firefox_cookies['error'] = 'No default profile found'
            except Exception as e:
                firefox_cookies['error'] = str(e)
        else:
            firefox_cookies['error'] = 'Firefox profile directory not found'
        
        return firefox_cookies
    
    def _extract_edge_cookies(self) -> Dict[str, Any]:
        """Extract Edge cookies"""
        edge_cookies = {
            'extraction_time': get_current_utc_isoformat(),
            'cookies': []
        }
        
        cookies_file = self.browser_locations['edge']['cookies']
        
        if os.path.exists(cookies_file):
            try:
                import shutil
                temp_cookies = cookies_file + '.temp'
                shutil.copy2(cookies_file, temp_cookies)
                
                conn = sqlite3.connect(temp_cookies)
                cursor = conn.cursor()
                
                cursor.execute("""
                    SELECT host_key, name, value, path, expires_utc, is_secure, is_httponly
                    FROM cookies
                    ORDER BY expires_utc DESC
                    LIMIT 1000
                """)
                
                for row in cursor.fetchall():
                    cookie_entry = {
                        'host_key': row[0],
                        'name': row[1],
                        'value': row[2],
                        'path': row[3],
                        'expires_utc': row[4],
                        'is_secure': row[5],
                        'is_httponly': row[6]
                    }
                    edge_cookies['cookies'].append(cookie_entry)
                
                conn.close()
                os.remove(temp_cookies)
                
            except Exception as e:
                edge_cookies['error'] = str(e)
        else:
            edge_cookies['error'] = 'Cookies file not found'
        
        return edge_cookies
    
    def _extract_chrome_downloads(self) -> Dict[str, Any]:
        """Extract Chrome downloads"""
        chrome_downloads = {
            'extraction_time': get_current_utc_isoformat(),
            'downloads': []
        }
        
        downloads_file = self.browser_locations['chrome']['downloads']
        
        if os.path.exists(downloads_file):
            try:
                import shutil
                temp_downloads = downloads_file + '.temp'
                shutil.copy2(downloads_file, temp_downloads)
                
                conn = sqlite3.connect(temp_downloads)
                cursor = conn.cursor()
                
                cursor.execute("""
                    SELECT target_path, tab_url, start_time, end_time, received_bytes, total_bytes
                    FROM downloads
                    ORDER BY start_time DESC
                    LIMIT 1000
                """)
                
                for row in cursor.fetchall():
                    download_entry = {
                        'target_path': row[0],
                        'tab_url': row[1],
                        'start_time': row[2],
                        'end_time': row[3],
                        'received_bytes': row[4],
                        'total_bytes': row[5]
                    }
                    chrome_downloads['downloads'].append(download_entry)
                
                conn.close()
                os.remove(temp_downloads)
                
            except Exception as e:
                chrome_downloads['error'] = str(e)
        else:
            chrome_downloads['error'] = 'Downloads file not found'
        
        return chrome_downloads
    
    def _extract_firefox_downloads(self) -> Dict[str, Any]:
        """Extract Firefox downloads"""
        firefox_downloads = {
            'extraction_time': get_current_utc_isoformat(),
            'downloads': []
        }
        
        profile_dir = self.browser_locations['firefox']['profile_dir']
        
        if os.path.exists(profile_dir):
            try:
                profiles = [d for d in os.listdir(profile_dir) if d.endswith('.default')]
                if profiles:
                    profile_path = os.path.join(profile_dir, profiles[0])
                    downloads_file = os.path.join(profile_path, self.browser_locations['firefox']['downloads'])
                    
                    if os.path.exists(downloads_file):
                        import shutil
                        temp_downloads = downloads_file + '.temp'
                        shutil.copy2(downloads_file, temp_downloads)
                        
                        conn = sqlite3.connect(temp_downloads)
                        cursor = conn.cursor()
                        
                        cursor.execute("""
                            SELECT target, source, startTime, endTime, currBytes, maxBytes
                            FROM moz_downloads
                            ORDER BY startTime DESC
                            LIMIT 1000
                        """)
                        
                        for row in cursor.fetchall():
                            download_entry = {
                                'target': row[0],
                                'source': row[1],
                                'startTime': row[2],
                                'endTime': row[3],
                                'currBytes': row[4],
                                'maxBytes': row[5]
                            }
                            firefox_downloads['downloads'].append(download_entry)
                        
                        conn.close()
                        os.remove(temp_downloads)
                    else:
                        firefox_downloads['error'] = 'Downloads file not found'
                else:
                    firefox_downloads['error'] = 'No default profile found'
            except Exception as e:
                firefox_downloads['error'] = str(e)
        else:
            firefox_downloads['error'] = 'Firefox profile directory not found'
        
        return firefox_downloads
    
    def _extract_edge_downloads(self) -> Dict[str, Any]:
        """Extract Edge downloads"""
        edge_downloads = {
            'extraction_time': get_current_utc_isoformat(),
            'downloads': []
        }
        
        downloads_file = self.browser_locations['edge']['downloads']
        
        if os.path.exists(downloads_file):
            try:
                import shutil
                temp_downloads = downloads_file + '.temp'
                shutil.copy2(downloads_file, temp_downloads)
                
                conn = sqlite3.connect(temp_downloads)
                cursor = conn.cursor()
                
                cursor.execute("""
                    SELECT target_path, tab_url, start_time, end_time, received_bytes, total_bytes
                    FROM downloads
                    ORDER BY start_time DESC
                    LIMIT 1000
                """)
                
                for row in cursor.fetchall():
                    download_entry = {
                        'target_path': row[0],
                        'tab_url': row[1],
                        'start_time': row[2],
                        'end_time': row[3],
                        'received_bytes': row[4],
                        'total_bytes': row[5]
                    }
                    edge_downloads['downloads'].append(download_entry)
                
                conn.close()
                os.remove(temp_downloads)
                
            except Exception as e:
                edge_downloads['error'] = str(e)
        else:
            edge_downloads['error'] = 'Downloads file not found'
        
        return edge_downloads
    
    def _save_network_artifacts(self, output_dir: Path, artifacts: Dict[str, Any]):
        """Save network artifacts to files"""
        try:
            # Save main network artifacts
            with open(output_dir / "network_artifacts.json", 'w', encoding='utf-8') as f:
                json.dump(artifacts, f, indent=2, default=str, ensure_ascii=False)
            
            # Save individual artifact files
            for artifact_type, data in artifacts['artifacts'].items():
                artifact_file = output_dir / f"{artifact_type}.json"
                with open(artifact_file, 'w', encoding='utf-8') as f:
                    json.dump(data, f, indent=2, default=str, ensure_ascii=False)
            
            self.logger.info(f"Network artifacts saved to: {output_dir}")
            
        except Exception as e:
            self.logger.error(f"Error saving network artifacts: {str(e)}")
            raise
