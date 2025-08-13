"""
File System Analyzer
Extracts forensic artifacts from Windows file system
"""

import os
import json
import shutil
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Any, Optional

from ..utils.logger import get_logger
from ..utils.hashing import calculate_file_hash, create_hash_manifest
from ..utils.timezone_utils import get_current_utc_isoformat, convert_file_timestamps_to_utc


class FileSystemAnalyzer:
    """File system analyzer for forensic analysis"""
    
    def __init__(self):
        self.logger = get_logger(__name__)
        
        # Important file system locations for forensic analysis
        self.forensic_locations = {
            'system_files': [
                r"C:\Windows\System32",
                r"C:\Windows\SysWOW64",
                r"C:\Windows\System32\drivers",
                r"C:\Windows\System32\config"
            ],
            'user_profiles': [
                os.path.expanduser("~\\AppData\\Local"),
                os.path.expanduser("~\\AppData\\Roaming"),
                os.path.expanduser("~\\Documents"),
                os.path.expanduser("~\\Desktop"),
                os.path.expanduser("~\\Downloads"),
                os.path.expanduser("~\\Pictures"),
                os.path.expanduser("~\\Videos")
            ],
            'temp_locations': [
                os.environ.get('TEMP', r"C:\Windows\Temp"),
                os.environ.get('TMP', r"C:\Windows\Temp"),
                os.path.expanduser("~\\AppData\\Local\\Temp")
            ],
            'recent_files': [
                os.path.expanduser("~\\AppData\\Roaming\\Microsoft\\Windows\\Recent"),
                os.path.expanduser("~\\AppData\\Local\\Microsoft\\Windows\\History")
            ],
            'startup_locations': [
                r"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup",
                os.path.expanduser("~\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup")
            ]
        }
    
    def extract_filesystem_artifacts(self, output_dir: Path) -> Dict[str, Any]:
        """Extract file system artifacts"""
        self.logger.info("Extracting file system artifacts")
        
        filesystem_artifacts = {
            'extraction_time': get_current_utc_isoformat(),
            'artifacts': {}
        }
        
        try:
            # Extract file timeline
            file_timeline = self.extract_file_timeline(output_dir)
            filesystem_artifacts['artifacts']['file_timeline'] = file_timeline
            
            # Extract recent files
            recent_files = self.extract_recent_files(output_dir)
            filesystem_artifacts['artifacts']['recent_files'] = recent_files
            
            # Extract startup files
            startup_files = self.extract_startup_files(output_dir)
            filesystem_artifacts['artifacts']['startup_files'] = startup_files
            
            # Extract temp files
            temp_files = self.extract_temp_files(output_dir)
            filesystem_artifacts['artifacts']['temp_files'] = temp_files
            
            # Extract user documents
            user_documents = self.extract_user_documents(output_dir)
            filesystem_artifacts['artifacts']['user_documents'] = user_documents
            
            # Extract system information
            system_info = self.extract_system_information(output_dir)
            filesystem_artifacts['artifacts']['system_info'] = system_info
            
            # Save to files
            self._save_filesystem_artifacts(output_dir, filesystem_artifacts)
            
            return filesystem_artifacts
            
        except Exception as e:
            self.logger.error(f"Error extracting file system artifacts: {str(e)}")
            raise
    
    def extract_file_timeline(self, output_dir: Path) -> Dict[str, Any]:
        """Extract file timeline information"""
        self.logger.info("Extracting file timeline")
        
        timeline_dir = output_dir / "file_timeline"
        timeline_dir.mkdir(exist_ok=True)
        
        timeline_data = {
            'extraction_time': get_current_utc_isoformat(),
            'timeline_entries': []
        }
        
        # Focus on important directories for timeline analysis
        timeline_directories = [
            os.path.expanduser("~\\Desktop"),
            os.path.expanduser("~\\Documents"),
            os.path.expanduser("~\\Downloads"),
            os.path.expanduser("~\\AppData\\Local\\Temp"),
            os.path.expanduser("~\\AppData\\Roaming\\Microsoft\\Windows\\Recent")
        ]
        
        for directory in timeline_directories:
            if os.path.exists(directory):
                try:
                    dir_timeline = self._extract_directory_timeline(Path(directory))
                    timeline_data['timeline_entries'].extend(dir_timeline)
                except Exception as e:
                    self.logger.warning(f"Error extracting timeline for {directory}: {str(e)}")
        
        # Sort timeline entries by modification time
        timeline_data['timeline_entries'].sort(key=lambda x: x.get('modified_time', ''))
        
        # Save timeline data
        with open(timeline_dir / "file_timeline.json", 'w', encoding='utf-8') as f:
            json.dump(timeline_data, f, indent=2, default=str, ensure_ascii=False)
        
        return timeline_data
    
    def extract_recent_files(self, output_dir: Path) -> Dict[str, Any]:
        """Extract recent files information"""
        self.logger.info("Extracting recent files")
        
        recent_files_dir = output_dir / "recent_files"
        recent_files_dir.mkdir(exist_ok=True)
        
        recent_files_data = {
            'extraction_time': get_current_utc_isoformat(),
            'recent_files': {}
        }
        
        for location in self.forensic_locations['recent_files']:
            if os.path.exists(location):
                try:
                    location_data = self._extract_location_files(Path(location))
                    recent_files_data['recent_files'][location] = location_data
                except Exception as e:
                    self.logger.warning(f"Error extracting recent files from {location}: {str(e)}")
        
        # Save recent files data
        with open(recent_files_dir / "recent_files.json", 'w', encoding='utf-8') as f:
            json.dump(recent_files_data, f, indent=2, default=str, ensure_ascii=False)
        
        return recent_files_data
    
    def extract_startup_files(self, output_dir: Path) -> Dict[str, Any]:
        """Extract startup files information"""
        self.logger.info("Extracting startup files")
        
        startup_files_dir = output_dir / "startup_files"
        startup_files_dir.mkdir(exist_ok=True)
        
        startup_files_data = {
            'extraction_time': get_current_utc_isoformat(),
            'startup_files': {}
        }
        
        for location in self.forensic_locations['startup_locations']:
            if os.path.exists(location):
                try:
                    location_data = self._extract_location_files(Path(location))
                    startup_files_data['startup_files'][location] = location_data
                except Exception as e:
                    self.logger.warning(f"Error extracting startup files from {location}: {str(e)}")
        
        # Save startup files data
        with open(startup_files_dir / "startup_files.json", 'w', encoding='utf-8') as f:
            json.dump(startup_files_data, f, indent=2, default=str, ensure_ascii=False)
        
        return startup_files_data
    
    def extract_temp_files(self, output_dir: Path) -> Dict[str, Any]:
        """Extract temporary files information"""
        self.logger.info("Extracting temporary files")
        
        temp_files_dir = output_dir / "temp_files"
        temp_files_dir.mkdir(exist_ok=True)
        
        temp_files_data = {
            'extraction_time': get_current_utc_isoformat(),
            'temp_files': {}
        }
        
        for location in self.forensic_locations['temp_locations']:
            if os.path.exists(location):
                try:
                    location_data = self._extract_location_files(Path(location))
                    temp_files_data['temp_files'][location] = location_data
                except Exception as e:
                    self.logger.warning(f"Error extracting temp files from {location}: {str(e)}")
        
        # Save temp files data
        with open(temp_files_dir / "temp_files.json", 'w', encoding='utf-8') as f:
            json.dump(temp_files_data, f, indent=2, default=str, ensure_ascii=False)
        
        return temp_files_data
    
    def extract_user_documents(self, output_dir: Path) -> Dict[str, Any]:
        """Extract user documents information"""
        self.logger.info("Extracting user documents")
        
        user_documents_dir = output_dir / "user_documents"
        user_documents_dir.mkdir(exist_ok=True)
        
        user_documents_data = {
            'extraction_time': get_current_utc_isoformat(),
            'user_documents': {}
        }
        
        for location in self.forensic_locations['user_profiles']:
            if os.path.exists(location):
                try:
                    location_data = self._extract_location_files(Path(location))
                    user_documents_data['user_documents'][location] = location_data
                except Exception as e:
                    self.logger.warning(f"Error extracting user documents from {location}: {str(e)}")
        
        # Save user documents data
        with open(user_documents_dir / "user_documents.json", 'w') as f:
            json.dump(user_documents_data, f, indent=2)
        
        return user_documents_data
    
    def extract_system_information(self, output_dir: Path) -> Dict[str, Any]:
        """Extract system information"""
        self.logger.info("Extracting system information")
        
        system_info_dir = output_dir / "system_info"
        system_info_dir.mkdir(exist_ok=True)
        
        system_info_data = {
            'extraction_time': get_current_utc_isoformat(),
            'system_info': {}
        }
        
        try:
            # Get disk information
            disk_info = self._get_disk_information()
            system_info_data['system_info']['disk_info'] = disk_info
            
            # Get volume information
            volume_info = self._get_volume_information()
            system_info_data['system_info']['volume_info'] = volume_info
            
            # Get file system information
            filesystem_info = self._get_filesystem_information()
            system_info_data['system_info']['filesystem_info'] = filesystem_info
            
        except Exception as e:
            self.logger.error(f"Error extracting system information: {str(e)}")
        
        # Save system information
        with open(system_info_dir / "system_info.json", 'w', encoding='utf-8') as f:
            json.dump(system_info_data, f, indent=2, default=str, ensure_ascii=False)
        
        return system_info_data
    
    def _extract_directory_timeline(self, directory: Path) -> List[Dict[str, Any]]:
        """Extract timeline for a specific directory"""
        timeline_entries = []
        
        try:
            # Limit the number of files processed to avoid hanging
            file_count = 0
            max_files = 1000  # Limit to prevent hanging
            
            for file_path in directory.rglob("*"):
                if file_count >= max_files:
                    self.logger.warning(f"Reached maximum file limit ({max_files}) for {directory}")
                    break
                    
                if file_path.is_file():
                    try:
                        # Skip temporary files that are likely to cause permission issues
                        if any(temp_pattern in str(file_path).lower() for temp_pattern in 
                              ['.tmp', 'temp', 'cache', 'log', 'lock']):
                            continue
                            
                        stat = file_path.stat()
                        # Get UTC timestamps
                        timestamps = convert_file_timestamps_to_utc(stat)
                        entry = {
                            'file_path': str(file_path),
                            'file_name': file_path.name,
                            'file_size': stat.st_size,
                            'created_time_utc': timestamps['created_time_utc'],
                            'modified_time_utc': timestamps['modified_time_utc'],
                            'accessed_time_utc': timestamps['accessed_time_utc'],
                            'created_time_local': timestamps['created_time_local'],
                            'modified_time_local': timestamps['modified_time_local'],
                            'accessed_time_local': timestamps['accessed_time_local'],
                            'file_hash': calculate_file_hash(file_path)
                        }
                        timeline_entries.append(entry)
                        file_count += 1
                    except (PermissionError, OSError) as e:
                        # Skip files with permission issues
                        continue
                    except Exception as e:
                        self.logger.warning(f"Error processing file {file_path}: {str(e)}")
                        continue
        
        except Exception as e:
            self.logger.warning(f"Error extracting timeline for {directory}: {str(e)}")
        
        return timeline_entries
    
    def _extract_location_files(self, location: Path) -> Dict[str, Any]:
        """Extract file information from a specific location"""
        location_data = {
            'location': str(location),
            'files': []
        }
        
        try:
            # Limit the number of files processed to avoid hanging
            file_count = 0
            max_files = 500  # Limit to prevent hanging
            
            for file_path in location.rglob("*"):
                if file_count >= max_files:
                    self.logger.warning(f"Reached maximum file limit ({max_files}) for {location}")
                    break
                    
                if file_path.is_file():
                    try:
                        # Skip temporary files that are likely to cause permission issues
                        if any(temp_pattern in str(file_path).lower() for temp_pattern in 
                              ['.tmp', 'temp', 'cache', 'log', 'lock']):
                            continue
                            
                        stat = file_path.stat()
                        # Get UTC timestamps
                        timestamps = convert_file_timestamps_to_utc(stat)
                        file_info = {
                            'name': file_path.name,
                            'path': str(file_path),
                            'size': stat.st_size,
                            'created_utc': timestamps['created_time_utc'],
                            'modified_utc': timestamps['modified_time_utc'],
                            'accessed_utc': timestamps['accessed_time_utc'],
                            'created_local': timestamps['created_time_local'],
                            'modified_local': timestamps['modified_time_local'],
                            'accessed_local': timestamps['accessed_time_local'],
                            'hash': calculate_file_hash(file_path)
                        }
                        location_data['files'].append(file_info)
                        file_count += 1
                    except (PermissionError, OSError) as e:
                        # Skip files with permission issues
                        continue
                    except Exception as e:
                        self.logger.warning(f"Error processing file {file_path}: {str(e)}")
                        continue
        
        except Exception as e:
            self.logger.warning(f"Error extracting files from {location}: {str(e)}")
        
        return location_data
    
    def _get_disk_information(self) -> Dict[str, Any]:
        """Get disk information"""
        disk_info = {}
        
        try:
            import psutil
            
            for partition in psutil.disk_partitions():
                try:
                    partition_info = {
                        'device': partition.device,
                        'mountpoint': partition.mountpoint,
                        'fstype': partition.fstype,
                        'opts': partition.opts
                    }
                    
                    # Get disk usage
                    usage = psutil.disk_usage(partition.mountpoint)
                    partition_info['usage'] = {
                        'total': usage.total,
                        'used': usage.used,
                        'free': usage.free,
                        'percent': usage.percent
                    }
                    
                    disk_info[partition.device] = partition_info
                    
                except Exception as e:
                    self.logger.warning(f"Error getting disk info for {partition.device}: {str(e)}")
        
        except Exception as e:
            self.logger.error(f"Error getting disk information: {str(e)}")
        
        return disk_info
    
    def _get_volume_information(self) -> Dict[str, Any]:
        """Get volume information"""
        volume_info = {}
        
        try:
            import win32api
            import win32file
            
            drives = win32api.GetLogicalDriveStrings().split('\000')[:-1]
            
            for drive in drives:
                try:
                    volume_name = win32api.GetVolumeInformation(drive)[0]
                    volume_info[drive] = {
                        'volume_name': volume_name,
                        'drive_type': win32file.GetDriveType(drive)
                    }
                except Exception as e:
                    self.logger.warning(f"Error getting volume info for {drive}: {str(e)}")
        
        except Exception as e:
            self.logger.error(f"Error getting volume information: {str(e)}")
        
        return volume_info
    
    def _get_filesystem_information(self) -> Dict[str, Any]:
        """Get file system information"""
        filesystem_info = {}
        
        try:
            import platform
            import psutil
            
            filesystem_info['os_info'] = {
                'system': platform.system(),
                'release': platform.release(),
                'version': platform.version(),
                'machine': platform.machine(),
                'processor': platform.processor()
            }
            
            filesystem_info['memory_info'] = {
                'total': psutil.virtual_memory().total,
                'available': psutil.virtual_memory().available,
                'percent': psutil.virtual_memory().percent
            }
            
        except Exception as e:
            self.logger.error(f"Error getting filesystem information: {str(e)}")
        
        return filesystem_info
    
    def _save_filesystem_artifacts(self, output_dir: Path, artifacts: Dict[str, Any]):
        """Save file system artifacts to files"""
        try:
            # Save main filesystem artifacts
            with open(output_dir / "filesystem_artifacts.json", 'w', encoding='utf-8') as f:
                json.dump(artifacts, f, indent=2, default=str, ensure_ascii=False)
            
            # Save individual artifact files
            for artifact_type, data in artifacts['artifacts'].items():
                artifact_file = output_dir / f"{artifact_type}.json"
                with open(artifact_file, 'w', encoding='utf-8') as f:
                    json.dump(data, f, indent=2, default=str, ensure_ascii=False)
            
            self.logger.info(f"File system artifacts saved to: {output_dir}")
            
        except Exception as e:
            self.logger.error(f"Error saving filesystem artifacts: {str(e)}")
            raise
