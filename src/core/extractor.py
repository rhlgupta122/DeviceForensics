"""
Main Forensic Extractor Class
Orchestrates the extraction of all forensic artifacts
"""

import os
import json
import hashlib
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Any, Optional

from .registry_parser import RegistryParser
from .filesystem_analyzer import FileSystemAnalyzer
from .memory_dumper import MemoryDumper
from .network_analyzer import NetworkAnalyzer
from .evtx_analyzer import EVTXAnalyzer
from ..utils.logger import get_logger
from ..utils.hashing import calculate_file_hash
from ..utils.timezone_utils import get_current_utc_isoformat
from ..utils.csv_exporter import CSVExporter
from ..reports.report_generator import ReportGenerator


class ForensicExtractor:
    """Main forensic extraction orchestrator"""
    
    def __init__(self):
        self.logger = get_logger(__name__)
        self.registry_parser = RegistryParser()
        self.filesystem_analyzer = FileSystemAnalyzer()
        self.memory_dumper = MemoryDumper()
        self.network_analyzer = NetworkAnalyzer()
        self.evtx_analyzer = EVTXAnalyzer()
        self.report_generator = ReportGenerator()
        self.csv_exporter = CSVExporter()
        
        # Extraction results
        self.extraction_results = {
            'metadata': {
                'extraction_time': get_current_utc_isoformat(),
                'extractor_version': '1.0.0',
                'target_system': self._get_system_info()
            },
            'artifacts': {}
        }
    
    def extract_all_artifacts(self, output_dir: Path) -> Dict[str, Any]:
        """Extract all available forensic artifacts"""
        self.logger.info("Starting comprehensive forensic extraction")
        
        try:
            # Extract registry artifacts
            self.extract_registry_artifacts(output_dir)
            
            # Extract file system artifacts
            self.extract_filesystem_artifacts(output_dir)
            
            # Extract memory artifacts
            self.extract_memory_artifacts(output_dir)
            
            # Extract network artifacts
            self.extract_network_artifacts(output_dir)
            
            # Extract user activity artifacts
            self.extract_user_activity_artifacts(output_dir)
            
            # Extract EVTX artifacts
            self.extract_evtx_artifacts(output_dir)
            
            # Save extraction metadata
            self._save_extraction_metadata(output_dir)
            
            # Export artifacts to CSV for analyst readability
            self.export_artifacts_to_csv(output_dir)
            
            self.logger.info("Comprehensive forensic extraction completed")
            return self.extraction_results
            
        except Exception as e:
            self.logger.error(f"Error during comprehensive extraction: {str(e)}")
            raise
    
    def extract_registry_artifacts(self, output_dir: Path) -> Dict[str, Any]:
        """Extract Windows Registry artifacts"""
        self.logger.info("Extracting registry artifacts")
        
        registry_dir = output_dir / "registry"
        registry_dir.mkdir(exist_ok=True)
        
        try:
            registry_artifacts = self.registry_parser.extract_all_registry_artifacts(registry_dir)
            self.extraction_results['artifacts']['registry'] = registry_artifacts
            
            self.logger.info(f"Registry artifacts extracted to: {registry_dir}")
            return registry_artifacts
            
        except Exception as e:
            self.logger.error(f"Error extracting registry artifacts: {str(e)}")
            raise
    
    def extract_filesystem_artifacts(self, output_dir: Path) -> Dict[str, Any]:
        """Extract file system artifacts"""
        self.logger.info("Extracting file system artifacts")
        
        filesystem_dir = output_dir / "filesystem"
        filesystem_dir.mkdir(exist_ok=True)
        
        try:
            filesystem_artifacts = self.filesystem_analyzer.extract_filesystem_artifacts(filesystem_dir)
            self.extraction_results['artifacts']['filesystem'] = filesystem_artifacts
            
            self.logger.info(f"File system artifacts extracted to: {filesystem_dir}")
            return filesystem_artifacts
            
        except Exception as e:
            self.logger.error(f"Error extracting file system artifacts: {str(e)}")
            raise
    
    def extract_memory_artifacts(self, output_dir: Path) -> Dict[str, Any]:
        """Extract memory artifacts"""
        self.logger.info("Extracting memory artifacts")
        
        memory_dir = output_dir / "memory"
        memory_dir.mkdir(exist_ok=True)
        
        try:
            memory_artifacts = self.memory_dumper.extract_memory_artifacts(memory_dir)
            self.extraction_results['artifacts']['memory'] = memory_artifacts
            
            self.logger.info(f"Memory artifacts extracted to: {memory_dir}")
            return memory_artifacts
            
        except Exception as e:
            self.logger.error(f"Error extracting memory artifacts: {str(e)}")
            raise
    
    def extract_network_artifacts(self, output_dir: Path) -> Dict[str, Any]:
        """Extract network artifacts"""
        self.logger.info("Extracting network artifacts")
        
        network_dir = output_dir / "network"
        network_dir.mkdir(exist_ok=True)
        
        try:
            network_artifacts = self.network_analyzer.extract_network_artifacts(network_dir)
            self.extraction_results['artifacts']['network'] = network_artifacts
            
            self.logger.info(f"Network artifacts extracted to: {network_dir}")
            return network_artifacts
            
        except Exception as e:
            self.logger.error(f"Error extracting network artifacts: {str(e)}")
            raise
    
    def extract_user_activity_artifacts(self, output_dir: Path) -> Dict[str, Any]:
        """Extract user activity artifacts"""
        self.logger.info("Extracting user activity artifacts")
        
        user_activity_dir = output_dir / "user_activity"
        user_activity_dir.mkdir(exist_ok=True)
        
        try:
            # Extract recent files
            recent_files = self._extract_recent_files(user_activity_dir)
            
            # Extract run history
            run_history = self._extract_run_history(user_activity_dir)
            
            # Extract user profiles
            user_profiles = self._extract_user_profiles(user_activity_dir)
            
            user_activity_artifacts = {
                'recent_files': recent_files,
                'run_history': run_history,
                'user_profiles': user_profiles
            }
            
            self.extraction_results['artifacts']['user_activity'] = user_activity_artifacts
            
            self.logger.info(f"User activity artifacts extracted to: {user_activity_dir}")
            return user_activity_artifacts
            
        except Exception as e:
            self.logger.error(f"Error extracting user activity artifacts: {str(e)}")
            raise
    
    def extract_evtx_artifacts(self, output_dir: Path) -> Dict[str, Any]:
        """Extract and analyze Windows Event Log (EVTX) artifacts"""
        self.logger.info("Extracting EVTX artifacts")
        
        evtx_dir = output_dir / "evtx"
        evtx_dir.mkdir(exist_ok=True)
        
        try:
            # Find EVTX files in common locations
            evtx_locations = [
                Path("C:\\Windows\\System32\\winevt\\Logs"),
                Path("C:\\Windows\\System32\\config"),
                Path("C:\\Windows\\System32\\winevt\\Logs\\Archive")
            ]
            
            evtx_files = []
            for location in evtx_locations:
                if location.exists():
                    evtx_files.extend(list(location.glob("*.evtx")))
            
            if not evtx_files:
                self.logger.warning("No EVTX files found in standard locations")
                return {}
            
            self.logger.info(f"Found {len(evtx_files)} EVTX files")
            
            # Copy EVTX files to output directory
            copied_files = []
            for evtx_file in evtx_files:
                try:
                    dest_path = evtx_dir / evtx_file.name
                    if not dest_path.exists():
                        import shutil
                        shutil.copy2(evtx_file, dest_path)
                        copied_files.append(str(dest_path))
                        self.logger.info(f"Copied EVTX file: {evtx_file.name}")
                except Exception as e:
                    self.logger.warning(f"Error copying EVTX file {evtx_file}: {str(e)}")
            
            # Analyze EVTX files
            evtx_analysis = self.evtx_analyzer.analyze_evtx_directory(evtx_dir, output_dir)
            
            # Generate security investigation report
            if evtx_analysis:
                security_report = self.evtx_analyzer.generate_security_report(evtx_analysis, output_dir)
                evtx_analysis['security_report_path'] = security_report
            
            evtx_artifacts = {
                'extraction_time': get_current_utc_isoformat(),
                'evtx_files_found': len(evtx_files),
                'evtx_files_copied': len(copied_files),
                'evtx_file_paths': copied_files,
                'analysis_results': evtx_analysis
            }
            
            self.extraction_results['artifacts']['evtx'] = evtx_artifacts
            
            self.logger.info(f"EVTX artifacts extracted and analyzed to: {evtx_dir}")
            return evtx_artifacts
            
        except Exception as e:
            self.logger.error(f"Error extracting EVTX artifacts: {str(e)}")
            raise
    
    def generate_report(self, artifacts_dir: Path, output_report: str) -> str:
        """Generate forensic report from extracted artifacts"""
        self.logger.info(f"Generating forensic report: {output_report}")
        
        try:
            report_path = self.report_generator.generate_report(
                artifacts_dir=artifacts_dir,
                output_path=output_report,
                extraction_results=self.extraction_results
            )
            
            self.logger.info(f"Forensic report generated: {report_path}")
            return report_path
            
        except Exception as e:
            self.logger.error(f"Error generating report: {str(e)}")
            raise
    
    def _extract_recent_files(self, output_dir: Path) -> Dict[str, Any]:
        """Extract recent files information"""
        recent_files_dir = output_dir / "recent_files"
        recent_files_dir.mkdir(exist_ok=True)
        
        recent_files_data = {
            'extraction_time': get_current_utc_isoformat(),
            'recent_files': []
        }
        
        # Extract from various recent files locations
        recent_locations = [
            os.path.expanduser("~\\AppData\\Roaming\\Microsoft\\Windows\\Recent"),
            os.path.expanduser("~\\AppData\\Local\\Microsoft\\Windows\\History"),
            os.path.expanduser("~\\AppData\\Local\\Microsoft\\Windows\\Explorer")
        ]
        
        for location in recent_locations:
            if os.path.exists(location):
                location_data = {
                    'location': location,
                    'files': []
                }
                
                for file_path in Path(location).rglob("*"):
                    if file_path.is_file():
                        try:
                            file_info = {
                                'name': file_path.name,
                                'path': str(file_path),
                                'size': file_path.stat().st_size,
                                'modified': datetime.fromtimestamp(file_path.stat().st_mtime).isoformat(),
                                'hash': calculate_file_hash(file_path)
                            }
                            location_data['files'].append(file_info)
                        except Exception as e:
                            self.logger.warning(f"Error processing file {file_path}: {str(e)}")
                
                recent_files_data['recent_files'].append(location_data)
        
        # Save to file
        with open(recent_files_dir / "recent_files.json", 'w', encoding='utf-8') as f:
            json.dump(recent_files_data, f, indent=2, default=str, ensure_ascii=False)
        
        return recent_files_data
    
    def _extract_run_history(self, output_dir: Path) -> Dict[str, Any]:
        """Extract run history from registry"""
        run_history_dir = output_dir / "run_history"
        run_history_dir.mkdir(exist_ok=True)
        
        try:
            run_history = self.registry_parser.extract_run_history()
            
            with open(run_history_dir / "run_history.json", 'w', encoding='utf-8') as f:
                json.dump(run_history, f, indent=2, default=str, ensure_ascii=False)
            
            return run_history
            
        except Exception as e:
            self.logger.error(f"Error extracting run history: {str(e)}")
            return {'error': str(e)}
    
    def _extract_user_profiles(self, output_dir: Path) -> Dict[str, Any]:
        """Extract user profile information"""
        user_profiles_dir = output_dir / "user_profiles"
        user_profiles_dir.mkdir(exist_ok=True)
        
        user_profiles_data = {
            'extraction_time': get_current_utc_isoformat(),
            'profiles': []
        }
        
        try:
            import winreg
            
            # Get user profiles from registry
            key_path = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList"
            
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path) as key:
                i = 0
                while True:
                    try:
                        subkey_name = winreg.EnumKey(key, i)
                        with winreg.OpenKey(key, subkey_name) as subkey:
                            try:
                                profile_path = winreg.QueryValueEx(subkey, "ProfileImagePath")[0]
                                profile_info = {
                                    'sid': subkey_name,
                                    'profile_path': profile_path,
                                    'username': os.path.basename(profile_path)
                                }
                                user_profiles_data['profiles'].append(profile_info)
                            except FileNotFoundError:
                                pass
                        i += 1
                    except WindowsError:
                        break
            
            with open(user_profiles_dir / "user_profiles.json", 'w', encoding='utf-8') as f:
                json.dump(user_profiles_data, f, indent=2, default=str, ensure_ascii=False)
            
            return user_profiles_data
            
        except Exception as e:
            self.logger.error(f"Error extracting user profiles: {str(e)}")
            return {'error': str(e)}
    
    def _get_system_info(self) -> Dict[str, str]:
        """Get basic system information"""
        try:
            import platform
            import psutil
            
            system_info = {
                'hostname': platform.node(),
                'os': platform.system(),
                'os_version': platform.version(),
                'architecture': platform.machine(),
                'processor': platform.processor(),
                'total_memory': f"{psutil.virtual_memory().total / (1024**3):.2f} GB"
            }
            
            return system_info
            
        except Exception as e:
            self.logger.error(f"Error getting system info: {str(e)}")
            return {'error': str(e)}
    
    def _save_extraction_metadata(self, output_dir: Path):
        """Save extraction metadata"""
        metadata_file = output_dir / "extraction_metadata.json"
        
        with open(metadata_file, 'w', encoding='utf-8') as f:
            json.dump(self.extraction_results, f, indent=2, default=str, ensure_ascii=False)
        
        self.logger.info(f"Extraction metadata saved to: {metadata_file}")
    
    def export_artifacts_to_csv(self, output_dir: Path) -> bool:
        """Export all extracted artifacts to CSV format for analyst readability"""
        self.logger.info("Exporting artifacts to CSV format")
        
        try:
            success = self.csv_exporter.export_all_artifacts(
                self.extraction_results['artifacts'], 
                output_dir
            )
            
            if success:
                self.logger.info("CSV export completed successfully")
            else:
                self.logger.warning("Some CSV exports failed")
                
            return success
            
        except Exception as e:
            self.logger.error(f"Error exporting artifacts to CSV: {str(e)}")
            return False
