"""
CSV Export utilities for forensic analysis
Converts JSON data to CSV format for better analyst readability
"""

import csv
import json
from pathlib import Path
from typing import Dict, List, Any, Union
import logging
from datetime import datetime

from .timezone_utils import get_current_utc_isoformat

logger = logging.getLogger(__name__)

class CSVExporter:
    """CSV export utility for forensic artifacts"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
    
    def export_to_csv(self, data: Union[Dict, List], output_path: Path, 
                     filename: str, flatten_nested: bool = True) -> bool:
        """
        Export data to CSV format
        
        Args:
            data: Data to export (dict or list)
            output_path: Output directory path
            filename: CSV filename
            flatten_nested: Whether to flatten nested dictionaries
            
        Returns:
            True if successful, False otherwise
        """
        try:
            csv_path = output_path / f"{filename}.csv"
            
            if isinstance(data, dict):
                if flatten_nested:
                    flattened_data = self._flatten_dict(data)
                    # Convert flattened dict to list of single dict for CSV writing
                    list_data = [flattened_data]
                    self._write_csv(list_data, csv_path)
                else:
                    # Convert dict to list of key-value pairs
                    list_data = [{"key": k, "value": str(v)} for k, v in data.items()]
                    self._write_csv(list_data, csv_path)
                    
            elif isinstance(data, list):
                if data and isinstance(data[0], dict):
                    if flatten_nested:
                        flattened_data = [self._flatten_dict(item) for item in data]
                        self._write_csv(flattened_data, csv_path)
                    else:
                        self._write_csv(data, csv_path)
                else:
                    # Simple list, convert to dict with index
                    list_data = [{"index": i, "value": str(item)} for i, item in enumerate(data)]
                    self._write_csv(list_data, csv_path)
            else:
                # Single value
                list_data = [{"value": str(data)}]
                self._write_csv(list_data, csv_path)
            
            self.logger.info(f"CSV exported successfully: {csv_path}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error exporting to CSV: {e}")
            return False
    
    def _flatten_dict(self, data: Dict, parent_key: str = '', sep: str = '_') -> Dict:
        """
        Flatten nested dictionary
        
        Args:
            data: Dictionary to flatten
            parent_key: Parent key for nested items
            sep: Separator for nested keys
            
        Returns:
            Flattened dictionary
        """
        items = []
        for k, v in data.items():
            new_key = f"{parent_key}{sep}{k}" if parent_key else k
            
            if isinstance(v, dict):
                items.extend(self._flatten_dict(v, new_key, sep=sep).items())
            elif isinstance(v, list):
                # Convert list to string representation
                items.append((new_key, str(v)))
            else:
                items.append((new_key, v))
        
        return dict(items)
    
    def _write_csv(self, data: List[Dict], csv_path: Path) -> None:
        """
        Write data to CSV file
        
        Args:
            data: List of dictionaries to write
            csv_path: Path to CSV file
        """
        if not data:
            return
        
        # Get all unique keys from all dictionaries
        all_keys = set()
        for item in data:
            all_keys.update(item.keys())
        
        # Sort keys for consistent column order
        fieldnames = sorted(all_keys)
        
        with open(csv_path, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            
            for row in data:
                # Fill missing values with empty string
                for key in fieldnames:
                    if key not in row:
                        row[key] = ''
                writer.writerow(row)
    
    def export_registry_artifacts(self, registry_data: Dict, output_path: Path) -> bool:
        """
        Export registry artifacts to CSV
        
        Args:
            registry_data: Registry artifacts data
            output_path: Output directory path
            
        Returns:
            True if successful, False otherwise
        """
        try:
            # Handle nested structure where artifacts are under 'artifacts' key
            artifacts_data = registry_data.get('artifacts', registry_data)
            
            # Export run keys
            if 'run_keys' in artifacts_data:
                self.export_to_csv(artifacts_data['run_keys'], output_path, 'registry_run_keys')
            
            # Export system info
            if 'system_info' in artifacts_data:
                self.export_to_csv(artifacts_data['system_info'], output_path, 'registry_system_info')
            
            # Export user activity
            if 'user_activity' in artifacts_data:
                self.export_to_csv(artifacts_data['user_activity'], output_path, 'registry_user_activity')
            
            # Export browser info
            if 'browser_info' in artifacts_data:
                self.export_to_csv(artifacts_data['browser_info'], output_path, 'registry_browser_info')
            
            # Export network config
            if 'network_config' in artifacts_data:
                self.export_to_csv(artifacts_data['network_config'], output_path, 'registry_network_config')
            
            # Export uninstall info
            if 'uninstall_info' in artifacts_data:
                self.export_to_csv(artifacts_data['uninstall_info'], output_path, 'registry_uninstall_info')
            
            return True
            
        except Exception as e:
            self.logger.error(f"Error exporting registry artifacts to CSV: {e}")
            return False
    
    def export_filesystem_artifacts(self, filesystem_data: Dict, output_path: Path) -> bool:
        """
        Export filesystem artifacts to CSV
        
        Args:
            filesystem_data: Filesystem artifacts data
            output_path: Output directory path
            
        Returns:
            True if successful, False otherwise
        """
        try:
            # Export file timeline
            if 'file_timeline' in filesystem_data:
                self.export_to_csv(filesystem_data['file_timeline'], output_path, 'filesystem_timeline')
            
            # Export recent files
            if 'recent_files' in filesystem_data:
                self.export_to_csv(filesystem_data['recent_files'], output_path, 'filesystem_recent_files')
            
            # Export startup files
            if 'startup_files' in filesystem_data:
                self.export_to_csv(filesystem_data['startup_files'], output_path, 'filesystem_startup_files')
            
            # Export temp files
            if 'temp_files' in filesystem_data:
                self.export_to_csv(filesystem_data['temp_files'], output_path, 'filesystem_temp_files')
            
            return True
            
        except Exception as e:
            self.logger.error(f"Error exporting filesystem artifacts to CSV: {e}")
            return False
    
    def export_memory_artifacts(self, memory_data: Dict, output_path: Path) -> bool:
        """
        Export memory artifacts to CSV
        
        Args:
            memory_data: Memory artifacts data
            output_path: Output directory path
            
        Returns:
            True if successful, False otherwise
        """
        try:
            # Export process information
            if 'processes' in memory_data:
                self.export_to_csv(memory_data['processes'], output_path, 'memory_processes')
            
            # Export network connections
            if 'network_connections' in memory_data:
                self.export_to_csv(memory_data['network_connections'], output_path, 'memory_network_connections')
            
            # Export loaded modules
            if 'loaded_modules' in memory_data:
                self.export_to_csv(memory_data['loaded_modules'], output_path, 'memory_loaded_modules')
            
            return True
            
        except Exception as e:
            self.logger.error(f"Error exporting memory artifacts to CSV: {e}")
            return False
    
    def export_network_artifacts(self, network_data: Dict, output_path: Path) -> bool:
        """
        Export network artifacts to CSV
        
        Args:
            network_data: Network artifacts data
            output_path: Output directory path
            
        Returns:
            True if successful, False otherwise
        """
        try:
            # Export browser history
            if 'browser_history' in network_data:
                self.export_to_csv(network_data['browser_history'], output_path, 'network_browser_history')
            
            # Export browser cookies
            if 'browser_cookies' in network_data:
                self.export_to_csv(network_data['browser_cookies'], output_path, 'network_browser_cookies')
            
            # Export browser downloads
            if 'browser_downloads' in network_data:
                self.export_to_csv(network_data['browser_downloads'], output_path, 'network_browser_downloads')
            
            # Export DNS cache
            if 'dns_cache' in network_data:
                self.export_to_csv(network_data['dns_cache'], output_path, 'network_dns_cache')
            
            # Export ARP cache
            if 'arp_cache' in network_data:
                self.export_to_csv(network_data['arp_cache'], output_path, 'network_arp_cache')
            
            return True
            
        except Exception as e:
            self.logger.error(f"Error exporting network artifacts to CSV: {e}")
            return False
    
    def export_evtx_artifacts(self, evtx_data: Dict, output_path: Path) -> bool:
        """
        Export EVTX artifacts to CSV
        
        Args:
            evtx_data: EVTX artifacts data
            output_path: Output directory path
            
        Returns:
            True if successful, False otherwise
        """
        try:
            # Export security events
            if 'security_events' in evtx_data:
                self.export_to_csv(evtx_data['security_events'], output_path, 'evtx_security_events')
            
            # Export system events
            if 'system_events' in evtx_data:
                self.export_to_csv(evtx_data['system_events'], output_path, 'evtx_system_events')
            
            # Export application events
            if 'application_events' in evtx_data:
                self.export_to_csv(evtx_data['application_events'], output_path, 'evtx_application_events')
            
            # Export analysis results
            if 'analysis_results' in evtx_data:
                self.export_to_csv(evtx_data['analysis_results'], output_path, 'evtx_analysis_results')
            
            return True
            
        except Exception as e:
            self.logger.error(f"Error exporting EVTX artifacts to CSV: {e}")
            return False
    
    def export_all_artifacts(self, artifacts_data: Dict, output_path: Path) -> bool:
        """
        Export all artifacts to CSV format
        
        Args:
            artifacts_data: All artifacts data
            output_path: Output directory path
            
        Returns:
            True if successful, False otherwise
        """
        try:
            csv_dir = output_path / "csv_exports"
            csv_dir.mkdir(exist_ok=True)
            
            success = True
            
            # Export each artifact type
            if 'registry' in artifacts_data:
                success &= self.export_registry_artifacts(artifacts_data['registry'], csv_dir)
            
            if 'filesystem' in artifacts_data:
                success &= self.export_filesystem_artifacts(artifacts_data['filesystem'], csv_dir)
            
            if 'memory' in artifacts_data:
                success &= self.export_memory_artifacts(artifacts_data['memory'], csv_dir)
            
            if 'network' in artifacts_data:
                success &= self.export_network_artifacts(artifacts_data['network'], csv_dir)
            
            if 'evtx' in artifacts_data:
                success &= self.export_evtx_artifacts(artifacts_data['evtx'], csv_dir)
            
            # Create export summary
            summary = {
                'export_time': get_current_utc_isoformat(),
                'export_format': 'CSV',
                'artifacts_exported': list(artifacts_data.keys()),
                'export_directory': str(csv_dir)
            }
            
            self.export_to_csv(summary, csv_dir, 'export_summary')
            
            return success
            
        except Exception as e:
            self.logger.error(f"Error exporting all artifacts to CSV: {e}")
            return False
