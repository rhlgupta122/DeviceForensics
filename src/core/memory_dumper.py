"""
Memory Dumper
Extracts memory artifacts and performs RAM analysis
"""

import os
import json
import psutil
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Any, Optional

from ..utils.logger import get_logger
from ..utils.timezone_utils import get_current_utc_isoformat
from ..utils.hashing import calculate_file_hash


class MemoryDumper:
    """Memory dumper for forensic analysis"""
    
    def __init__(self):
        self.logger = get_logger(__name__)
    
    def extract_memory_artifacts(self, output_dir: Path) -> Dict[str, Any]:
        """Extract memory artifacts"""
        self.logger.info("Extracting memory artifacts")
        
        memory_artifacts = {
            'extraction_time': get_current_utc_isoformat(),
            'artifacts': {}
        }
        
        try:
            # Extract memory information
            memory_info = self.extract_memory_information(output_dir)
            memory_artifacts['artifacts']['memory_info'] = memory_info
            
            # Extract process information
            process_info = self.extract_process_information(output_dir)
            memory_artifacts['artifacts']['process_info'] = process_info
            
            # Extract network connections
            network_connections = self.extract_network_connections(output_dir)
            memory_artifacts['artifacts']['network_connections'] = network_connections
            
            # Extract loaded modules
            loaded_modules = self.extract_loaded_modules(output_dir)
            memory_artifacts['artifacts']['loaded_modules'] = loaded_modules
            
            # Extract memory dump (if possible)
            memory_dump = self.extract_memory_dump(output_dir)
            memory_artifacts['artifacts']['memory_dump'] = memory_dump
            
            # Save to files
            self._save_memory_artifacts(output_dir, memory_artifacts)
            
            return memory_artifacts
            
        except Exception as e:
            self.logger.error(f"Error extracting memory artifacts: {str(e)}")
            raise
    
    def extract_memory_information(self, output_dir: Path) -> Dict[str, Any]:
        """Extract memory information"""
        self.logger.info("Extracting memory information")
        
        memory_info_dir = output_dir / "memory_info"
        memory_info_dir.mkdir(exist_ok=True)
        
        memory_info_data = {
            'extraction_time': get_current_utc_isoformat(),
            'memory_info': {}
        }
        
        try:
            # Get virtual memory information
            virtual_memory = psutil.virtual_memory()
            memory_info_data['memory_info']['virtual_memory'] = {
                'total': virtual_memory.total,
                'available': virtual_memory.available,
                'percent': virtual_memory.percent,
                'used': virtual_memory.used,
                'free': virtual_memory.free,
                'active': getattr(virtual_memory, 'active', None),
                'inactive': getattr(virtual_memory, 'inactive', None),
                'wired': getattr(virtual_memory, 'wired', None)
            }
            
            # Get swap memory information
            swap_memory = psutil.swap_memory()
            memory_info_data['memory_info']['swap_memory'] = {
                'total': swap_memory.total,
                'used': swap_memory.used,
                'free': swap_memory.free,
                'percent': swap_memory.percent,
                'sin': swap_memory.sin,
                'sout': swap_memory.sout
            }
            
        except Exception as e:
            self.logger.error(f"Error extracting memory information: {str(e)}")
        
        # Save memory information
        with open(memory_info_dir / "memory_info.json", 'w', encoding='utf-8') as f:
            json.dump(memory_info_data, f, indent=2, default=str, ensure_ascii=False)
        
        return memory_info_data
    
    def extract_process_information(self, output_dir: Path) -> Dict[str, Any]:
        """Extract process information"""
        self.logger.info("Extracting process information")
        
        process_info_dir = output_dir / "process_info"
        process_info_dir.mkdir(exist_ok=True)
        
        process_info_data = {
            'extraction_time': get_current_utc_isoformat(),
            'processes': []
        }
        
        try:
            for proc in psutil.process_iter(['pid', 'name', 'exe', 'cmdline', 'create_time', 'memory_info', 'cpu_percent']):
                try:
                    proc_info = proc.info
                    process_data = {
                        'pid': proc_info['pid'],
                        'name': proc_info['name'],
                        'exe': proc_info['exe'],
                        'cmdline': proc_info['cmdline'],
                        'create_time': datetime.fromtimestamp(proc_info['create_time']).isoformat() if proc_info['create_time'] else None,
                        'memory_info': {
                            'rss': proc_info['memory_info'].rss if proc_info['memory_info'] else None,
                            'vms': proc_info['memory_info'].vms if proc_info['memory_info'] else None,
                            'percent': proc_info['memory_info'].percent if proc_info['memory_info'] else None
                        },
                        'cpu_percent': proc_info['cpu_percent']
                    }
                    process_info_data['processes'].append(process_data)
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    continue
        
        except Exception as e:
            self.logger.error(f"Error extracting process information: {str(e)}")
        
        # Save process information
        with open(process_info_dir / "process_info.json", 'w', encoding='utf-8') as f:
            json.dump(process_info_data, f, indent=2, default=str, ensure_ascii=False)
        
        return process_info_data
    
    def extract_network_connections(self, output_dir: Path) -> Dict[str, Any]:
        """Extract network connections from memory"""
        self.logger.info("Extracting network connections")
        
        network_connections_dir = output_dir / "network_connections"
        network_connections_dir.mkdir(exist_ok=True)
        
        network_connections_data = {
            'extraction_time': get_current_utc_isoformat(),
            'connections': []
        }
        
        try:
            for conn in psutil.net_connections(kind='inet'):
                try:
                    connection_data = {
                        'fd': conn.fd,
                        'family': conn.family,
                        'type': conn.type,
                        'laddr': {
                            'ip': conn.laddr.ip if conn.laddr else None,
                            'port': conn.laddr.port if conn.laddr else None
                        },
                        'raddr': {
                            'ip': conn.raddr.ip if conn.raddr else None,
                            'port': conn.raddr.port if conn.raddr else None
                        },
                        'status': conn.status,
                        'pid': conn.pid
                    }
                    network_connections_data['connections'].append(connection_data)
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
        
        except Exception as e:
            self.logger.error(f"Error extracting network connections: {str(e)}")
        
        # Save network connections
        with open(network_connections_dir / "network_connections.json", 'w', encoding='utf-8') as f:
            json.dump(network_connections_data, f, indent=2, default=str, ensure_ascii=False)
        
        return network_connections_data
    
    def extract_loaded_modules(self, output_dir: Path) -> Dict[str, Any]:
        """Extract loaded modules information"""
        self.logger.info("Extracting loaded modules")
        
        loaded_modules_dir = output_dir / "loaded_modules"
        loaded_modules_dir.mkdir(exist_ok=True)
        
        loaded_modules_data = {
            'extraction_time': get_current_utc_isoformat(),
            'modules': []
        }
        
        try:
            for proc in psutil.process_iter(['pid', 'name']):
                try:
                    proc_info = proc.info
                    modules = []
                    
                    # Try to get loaded modules for the process
                    try:
                        if hasattr(proc, 'memory_maps'):
                            for mmap in proc.memory_maps():
                                module_info = {
                                    'path': mmap.path,
                                    'rss': mmap.rss,
                                    'size': mmap.size,
                                    'pss': mmap.pss,
                                    'shared_clean': mmap.shared_clean,
                                    'shared_dirty': mmap.shared_dirty,
                                    'private_clean': mmap.private_clean,
                                    'private_dirty': mmap.private_dirty,
                                    'referenced': mmap.referenced,
                                    'anonymous': mmap.anonymous,
                                    'swap': mmap.swap
                                }
                                modules.append(module_info)
                    except (psutil.AccessDenied, psutil.NoSuchProcess):
                        pass
                    
                    if modules:
                        process_modules = {
                            'pid': proc_info['pid'],
                            'name': proc_info['name'],
                            'modules': modules
                        }
                        loaded_modules_data['modules'].append(process_modules)
                        
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    continue
        
        except Exception as e:
            self.logger.error(f"Error extracting loaded modules: {str(e)}")
        
        # Save loaded modules
        with open(loaded_modules_dir / "loaded_modules.json", 'w') as f:
            json.dump(loaded_modules_data, f, indent=2)
        
        return loaded_modules_data
    
    def extract_memory_dump(self, output_dir: Path) -> Dict[str, Any]:
        """Extract memory dump (if possible)"""
        self.logger.info("Attempting memory dump extraction")
        
        memory_dump_dir = output_dir / "memory_dump"
        memory_dump_dir.mkdir(exist_ok=True)
        
        memory_dump_data = {
            'extraction_time': get_current_utc_isoformat(),
            'dump_status': 'not_attempted',
            'dump_file': None,
            'dump_size': None,
            'error': None
        }
        
        try:
            # Note: Full memory dumps require elevated privileges and specialized tools
            # This is a simplified approach that may not work on all systems
            
            self.logger.warning("Full memory dump requires elevated privileges and specialized tools")
            memory_dump_data['dump_status'] = 'requires_elevated_privileges'
            memory_dump_data['error'] = 'Full memory dump requires elevated privileges and specialized tools'
            
            # Alternative: Extract process memory for specific processes
            process_memory_dumps = self._extract_process_memory_dumps(memory_dump_dir)
            memory_dump_data['process_dumps'] = process_memory_dumps
            
        except Exception as e:
            self.logger.error(f"Error during memory dump extraction: {str(e)}")
            memory_dump_data['dump_status'] = 'failed'
            memory_dump_data['error'] = str(e)
        
        # Save memory dump information
        with open(memory_dump_dir / "memory_dump_info.json", 'w', encoding='utf-8') as f:
            json.dump(memory_dump_data, f, indent=2, default=str, ensure_ascii=False)
        
        return memory_dump_data
    
    def _extract_process_memory_dumps(self, output_dir: Path) -> Dict[str, Any]:
        """Extract memory dumps for specific processes"""
        process_dumps_data = {
            'extraction_time': get_current_utc_isoformat(),
            'process_dumps': {}
        }
        
        # Focus on important processes for forensic analysis
        important_processes = [
            'explorer.exe',
            'svchost.exe',
            'winlogon.exe',
            'lsass.exe',
            'csrss.exe',
            'wininit.exe'
        ]
        
        for proc in psutil.process_iter(['pid', 'name']):
            try:
                proc_info = proc.info
                if proc_info['name'].lower() in important_processes:
                    process_dump_info = {
                        'pid': proc_info['pid'],
                        'name': proc_info['name'],
                        'dump_status': 'not_attempted',
                        'dump_file': None,
                        'error': None
                    }
                    
                    try:
                        # Try to get process memory information
                        memory_info = proc.memory_info()
                        process_dump_info['memory_info'] = {
                            'rss': memory_info.rss,
                            'vms': memory_info.vms,
                            'percent': memory_info.percent
                        }
                        process_dump_info['dump_status'] = 'memory_info_extracted'
                        
                    except (psutil.AccessDenied, psutil.NoSuchProcess):
                        process_dump_info['dump_status'] = 'access_denied'
                        process_dump_info['error'] = 'Access denied to process memory'
                    
                    process_dumps_data['process_dumps'][f"{proc_info['name']}_{proc_info['pid']}"] = process_dump_info
                    
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
        
        return process_dumps_data
    
    def _save_memory_artifacts(self, output_dir: Path, artifacts: Dict[str, Any]):
        """Save memory artifacts to files"""
        try:
            # Save main memory artifacts
            with open(output_dir / "memory_artifacts.json", 'w', encoding='utf-8') as f:
                json.dump(artifacts, f, indent=2, default=str, ensure_ascii=False)
            
            # Save individual artifact files
            for artifact_type, data in artifacts['artifacts'].items():
                artifact_file = output_dir / f"{artifact_type}.json"
                with open(artifact_file, 'w', encoding='utf-8') as f:
                    json.dump(data, f, indent=2, default=str, ensure_ascii=False)
            
            self.logger.info(f"Memory artifacts saved to: {output_dir}")
            
        except Exception as e:
            self.logger.error(f"Error saving memory artifacts: {str(e)}")
            raise
