"""
Windows Registry Parser
Extracts forensic artifacts from Windows Registry
"""

import os
import json
import winreg
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Any, Optional

from ..utils.logger import get_logger
from ..utils.timezone_utils import get_current_utc_isoformat


class RegistryParser:
    """Windows Registry parser for forensic analysis"""
    
    def __init__(self):
        self.logger = get_logger(__name__)
        
        # Important registry keys for forensic analysis
        self.forensic_keys = {
            'run_keys': [
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices",
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunServicesOnce",
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run",
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run32",
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\StartupFolder"
            ],
            'user_run_keys': [
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices",
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunServicesOnce"
            ],
            'uninstall_keys': [
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
                r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
            ],
            'network_keys': [
                r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces",
                r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Hosts",
                r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\PersistentRoutes"
            ],
            'system_keys': [
                r"SYSTEM\CurrentControlSet\Control\TimeZoneInformation",
                r"SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName",
                r"SYSTEM\CurrentControlSet\Control\Session Manager\Environment"
            ]
        }
    
    def extract_all_registry_artifacts(self, output_dir: Path) -> Dict[str, Any]:
        """Extract all registry artifacts"""
        self.logger.info("Extracting all registry artifacts")
        
        registry_artifacts = {
            'extraction_time': get_current_utc_isoformat(),
            'artifacts': {}
        }
        
        try:
            # Extract run keys
            run_keys = self.extract_run_keys()
            registry_artifacts['artifacts']['run_keys'] = run_keys
            
            # Extract uninstall information
            uninstall_info = self.extract_uninstall_info()
            registry_artifacts['artifacts']['uninstall_info'] = uninstall_info
            
            # Extract network configuration
            network_config = self.extract_network_config()
            registry_artifacts['artifacts']['network_config'] = network_config
            
            # Extract system information
            system_info = self.extract_system_info()
            registry_artifacts['artifacts']['system_info'] = system_info
            
            # Extract user activity
            user_activity = self.extract_user_activity()
            registry_artifacts['artifacts']['user_activity'] = user_activity
            
            # Extract browser information
            browser_info = self.extract_browser_info()
            registry_artifacts['artifacts']['browser_info'] = browser_info
            
            # Save to files
            self._save_registry_artifacts(output_dir, registry_artifacts)
            
            return registry_artifacts
            
        except Exception as e:
            self.logger.error(f"Error extracting registry artifacts: {str(e)}")
            raise
    
    def extract_run_keys(self) -> Dict[str, Any]:
        """Extract run keys from registry"""
        self.logger.info("Extracting run keys")
        
        run_keys_data = {
            'extraction_time': get_current_utc_isoformat(),
            'run_keys': {}
        }
        
        for key_path in self.forensic_keys['run_keys']:
            try:
                key_data = self._read_registry_key(winreg.HKEY_LOCAL_MACHINE, key_path)
                if key_data:
                    run_keys_data['run_keys'][key_path] = key_data
            except Exception as e:
                self.logger.warning(f"Error reading run key {key_path}: {str(e)}")
        
        # Extract user-specific run keys
        try:
            user_run_keys = self._extract_user_run_keys()
            run_keys_data['user_run_keys'] = user_run_keys
        except Exception as e:
            self.logger.warning(f"Error extracting user run keys: {str(e)}")
        
        return run_keys_data
    
    def extract_uninstall_info(self) -> Dict[str, Any]:
        """Extract uninstall information"""
        self.logger.info("Extracting uninstall information")
        
        uninstall_data = {
            'extraction_time': get_current_utc_isoformat(),
            'installed_programs': {}
        }
        
        for key_path in self.forensic_keys['uninstall_keys']:
            try:
                programs = self._read_registry_subkeys(winreg.HKEY_LOCAL_MACHINE, key_path)
                uninstall_data['installed_programs'][key_path] = programs
            except Exception as e:
                self.logger.warning(f"Error reading uninstall key {key_path}: {str(e)}")
        
        return uninstall_data
    
    def extract_network_config(self) -> Dict[str, Any]:
        """Extract network configuration"""
        self.logger.info("Extracting network configuration")
        
        network_data = {
            'extraction_time': get_current_utc_isoformat(),
            'network_config': {}
        }
        
        for key_path in self.forensic_keys['network_keys']:
            try:
                config = self._read_registry_key(winreg.HKEY_LOCAL_MACHINE, key_path)
                if config:
                    network_data['network_config'][key_path] = config
            except Exception as e:
                self.logger.warning(f"Error reading network key {key_path}: {str(e)}")
        
        return network_data
    
    def extract_system_info(self) -> Dict[str, Any]:
        """Extract system information"""
        self.logger.info("Extracting system information")
        
        system_data = {
            'extraction_time': get_current_utc_isoformat(),
            'system_info': {}
        }
        
        for key_path in self.forensic_keys['system_keys']:
            try:
                info = self._read_registry_key(winreg.HKEY_LOCAL_MACHINE, key_path)
                if info:
                    system_data['system_info'][key_path] = info
            except Exception as e:
                self.logger.warning(f"Error reading system key {key_path}: {str(e)}")
        
        return system_data
    
    def extract_user_activity(self) -> Dict[str, Any]:
        """Extract user activity from registry"""
        self.logger.info("Extracting user activity")
        
        user_activity_data = {
            'extraction_time': get_current_utc_isoformat(),
            'user_activity': {}
        }
        
        # Extract recent documents
        try:
            recent_docs = self._extract_recent_documents()
            user_activity_data['user_activity']['recent_documents'] = recent_docs
        except Exception as e:
            self.logger.warning(f"Error extracting recent documents: {str(e)}")
        
        # Extract typed paths
        try:
            typed_paths = self._extract_typed_paths()
            user_activity_data['user_activity']['typed_paths'] = typed_paths
        except Exception as e:
            self.logger.warning(f"Error extracting typed paths: {str(e)}")
        
        # Extract last visited
        try:
            last_visited = self._extract_last_visited()
            user_activity_data['user_activity']['last_visited'] = last_visited
        except Exception as e:
            self.logger.warning(f"Error extracting last visited: {str(e)}")
        
        return user_activity_data
    
    def extract_browser_info(self) -> Dict[str, Any]:
        """Extract browser information"""
        self.logger.info("Extracting browser information")
        
        browser_data = {
            'extraction_time': get_current_utc_isoformat(),
            'browsers': {}
        }
        
        # Internet Explorer
        try:
            ie_info = self._extract_ie_info()
            browser_data['browsers']['internet_explorer'] = ie_info
        except Exception as e:
            self.logger.warning(f"Error extracting IE info: {str(e)}")
        
        # Chrome
        try:
            chrome_info = self._extract_chrome_info()
            browser_data['browsers']['chrome'] = chrome_info
        except Exception as e:
            self.logger.warning(f"Error extracting Chrome info: {str(e)}")
        
        # Firefox
        try:
            firefox_info = self._extract_firefox_info()
            browser_data['browsers']['firefox'] = firefox_info
        except Exception as e:
            self.logger.warning(f"Error extracting Firefox info: {str(e)}")
        
        return browser_data
    
    def extract_run_history(self) -> Dict[str, Any]:
        """Extract run history specifically"""
        return self.extract_run_keys()
    
    def _read_registry_key(self, hkey, key_path: str) -> Dict[str, Any]:
        """Read registry key values"""
        try:
            with winreg.OpenKey(hkey, key_path) as key:
                values = {}
                i = 0
                while True:
                    try:
                        name, value, type_ = winreg.EnumValue(key, i)
                        
                        # Handle binary data for JSON serialization
                        if isinstance(value, bytes):
                            # Convert bytes to hex string for JSON compatibility
                            value_str = value.hex()
                            value_info = {
                                'value': value_str,
                                'type': type_,
                                'data_type': 'binary',
                                'size': len(value)
                            }
                        else:
                            value_info = {
                                'value': value,
                                'type': type_,
                                'data_type': 'text'
                            }
                        
                        values[name] = value_info
                        i += 1
                    except WindowsError:
                        break
                return values
        except Exception as e:
            self.logger.warning(f"Error reading registry key {key_path}: {str(e)}")
            return {}
    
    def _read_registry_subkeys(self, hkey, key_path: str) -> Dict[str, Any]:
        """Read registry subkeys"""
        try:
            with winreg.OpenKey(hkey, key_path) as key:
                subkeys = {}
                i = 0
                while True:
                    try:
                        subkey_name = winreg.EnumKey(key, i)
                        with winreg.OpenKey(key, subkey_name) as subkey:
                            subkey_data = self._read_registry_key(hkey, f"{key_path}\\{subkey_name}")
                            subkeys[subkey_name] = subkey_data
                        i += 1
                    except WindowsError:
                        break
                return subkeys
        except Exception as e:
            self.logger.warning(f"Error reading registry subkeys {key_path}: {str(e)}")
            return {}
    
    def _extract_user_run_keys(self) -> Dict[str, Any]:
        """Extract user-specific run keys"""
        user_run_keys = {}
        
        try:
            # Get current user SID
            import win32api
            import win32security
            
            username = win32api.GetUserName()
            user_sid = win32security.LookupAccountName(None, username)[0]
            user_sid_str = win32security.ConvertSidToStringSid(user_sid)
            
            # Extract user run keys
            for key_path in self.forensic_keys['user_run_keys']:
                try:
                    full_path = f"USERS\\{user_sid_str}\\{key_path}"
                    key_data = self._read_registry_key(winreg.HKEY_USERS, full_path)
                    if key_data:
                        user_run_keys[full_path] = key_data
                except Exception as e:
                    self.logger.warning(f"Error reading user run key {key_path}: {str(e)}")
        
        except Exception as e:
            self.logger.warning(f"Error extracting user run keys: {str(e)}")
        
        return user_run_keys
    
    def _extract_recent_documents(self) -> Dict[str, Any]:
        """Extract recent documents from registry"""
        recent_docs = {}
        
        try:
            # Get current user SID
            import win32api
            import win32security
            
            username = win32api.GetUserName()
            user_sid = win32security.LookupAccountName(None, username)[0]
            user_sid_str = win32security.ConvertSidToStringSid(user_sid)
            
            # Recent documents key
            recent_key = f"USERS\\{user_sid_str}\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RecentDocs"
            recent_docs['recent_docs'] = self._read_registry_key(winreg.HKEY_USERS, recent_key)
            
        except Exception as e:
            self.logger.warning(f"Error extracting recent documents: {str(e)}")
        
        return recent_docs
    
    def _extract_typed_paths(self) -> Dict[str, Any]:
        """Extract typed paths from registry"""
        typed_paths = {}
        
        try:
            # Get current user SID
            import win32api
            import win32security
            
            username = win32api.GetUserName()
            user_sid = win32security.LookupAccountName(None, username)[0]
            user_sid_str = win32security.ConvertSidToStringSid(user_sid)
            
            # Typed paths key
            typed_key = f"USERS\\{user_sid_str}\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\TypedPaths"
            typed_paths['typed_paths'] = self._read_registry_key(winreg.HKEY_USERS, typed_key)
            
        except Exception as e:
            self.logger.warning(f"Error extracting typed paths: {str(e)}")
        
        return typed_paths
    
    def _extract_last_visited(self) -> Dict[str, Any]:
        """Extract last visited information"""
        last_visited = {}
        
        try:
            # Get current user SID
            import win32api
            import win32security
            
            username = win32api.GetUserName()
            user_sid = win32security.LookupAccountName(None, username)[0]
            user_sid_str = win32security.ConvertSidToStringSid(user_sid)
            
            # Last visited key
            last_key = f"USERS\\{user_sid_str}\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ComDlg32\\LastVisitedPidlMRU"
            last_visited['last_visited'] = self._read_registry_key(winreg.HKEY_USERS, last_key)
            
        except Exception as e:
            self.logger.warning(f"Error extracting last visited: {str(e)}")
        
        return last_visited
    
    def _extract_ie_info(self) -> Dict[str, Any]:
        """Extract Internet Explorer information"""
        ie_info = {}
        
        try:
            # IE settings
            ie_key = r"SOFTWARE\Microsoft\Internet Explorer"
            ie_info['settings'] = self._read_registry_key(winreg.HKEY_LOCAL_MACHINE, ie_key)
            
        except Exception as e:
            self.logger.warning(f"Error extracting IE info: {str(e)}")
        
        return ie_info
    
    def _extract_chrome_info(self) -> Dict[str, Any]:
        """Extract Chrome information"""
        chrome_info = {}
        
        try:
            # Chrome settings
            chrome_key = r"SOFTWARE\Google\Chrome"
            chrome_info['settings'] = self._read_registry_key(winreg.HKEY_LOCAL_MACHINE, chrome_key)
            
        except Exception as e:
            self.logger.warning(f"Error extracting Chrome info: {str(e)}")
        
        return chrome_info
    
    def _extract_firefox_info(self) -> Dict[str, Any]:
        """Extract Firefox information"""
        firefox_info = {}
        
        try:
            # Firefox settings
            firefox_key = r"SOFTWARE\Mozilla\Mozilla Firefox"
            firefox_info['settings'] = self._read_registry_key(winreg.HKEY_LOCAL_MACHINE, firefox_key)
            
        except Exception as e:
            self.logger.warning(f"Error extracting Firefox info: {str(e)}")
        
        return firefox_info
    
    def _save_registry_artifacts(self, output_dir: Path, artifacts: Dict[str, Any]):
        """Save registry artifacts to files"""
        try:
            # Custom JSON encoder to handle non-serializable types
            class RegistryJSONEncoder(json.JSONEncoder):
                def default(self, obj):
                    if isinstance(obj, bytes):
                        return obj.hex()
                    elif hasattr(obj, '__dict__'):
                        return str(obj)
                    else:
                        return str(obj)
            
            # Save main registry artifacts
            with open(output_dir / "registry_artifacts.json", 'w', encoding='utf-8') as f:
                json.dump(artifacts, f, indent=2, cls=RegistryJSONEncoder, ensure_ascii=False)
            
            # Save individual artifact files
            for artifact_type, data in artifacts['artifacts'].items():
                artifact_file = output_dir / f"{artifact_type}.json"
                with open(artifact_file, 'w', encoding='utf-8') as f:
                    json.dump(data, f, indent=2, cls=RegistryJSONEncoder, ensure_ascii=False)
            
            self.logger.info(f"Registry artifacts saved to: {output_dir}")
            
        except Exception as e:
            self.logger.error(f"Error saving registry artifacts: {str(e)}")
            raise
