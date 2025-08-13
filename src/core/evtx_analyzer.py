"""
Windows Event Log (EVTX) Analyzer Module

This module provides functionality to analyze Windows Event Log files (.evtx)
and extract important event IDs for security investigation purposes.
"""

import os
import json
import xml.etree.ElementTree as ET
from pathlib import Path
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple
from collections import defaultdict, Counter
import logging

# EVTX library import - try multiple sources
evtx = None
PyEvtxParser = None

try:
    import evtx
    from evtx import PyEvtxParser
except ImportError:
    try:
        import python_evtx as evtx
        from python_evtx import PyEvtxParser
    except ImportError:
        try:
            # Try alternative import
            from evtx import PyEvtxParser
            import evtx
        except ImportError:
            # Fallback - no EVTX library available
            evtx = None
            PyEvtxParser = None

from ..utils.logger import get_logger
from ..utils.hashing import calculate_file_hash
from ..utils.timezone_utils import get_current_utc_isoformat


class EVTXAnalyzer:
    """
    Analyzer for Windows Event Log (EVTX) files.
    
    Extracts and classifies important event IDs for security investigation.
    """
    
    # Important Event IDs for security investigation
    SECURITY_EVENT_IDS = {
        # Authentication Events
        4624: "Successful logon",
        4625: "Failed logon",
        4634: "Account logoff",
        4647: "User initiated logoff",
        4648: "Explicit credential logon",
        4778: "Session reconnected",
        4779: "Session disconnected",
        
        # Account Management
        4720: "Account created",
        4722: "Account enabled",
        4723: "Account disabled",
        4724: "Password change attempt",
        4725: "Account locked out",
        4726: "Account deleted",
        4728: "Member added to security group",
        4729: "Member removed from security group",
        4732: "Member added to security group",
        4733: "Member removed from security group",
        4738: "User account changed",
        4740: "User account locked out",
        4767: "User account unlocked",
        
        # Process and Service Events
        4688: "Process creation",
        4697: "Service installation",
        4698: "Scheduled task created",
        4699: "Scheduled task deleted",
        4700: "Scheduled task enabled",
        4701: "Scheduled task disabled",
        4702: "Scheduled task updated",
        
        # File and Object Access
        4656: "Object access requested",
        4657: "Registry value modified",
        4658: "Object access denied",
        4660: "Object deleted",
        4663: "Object access attempt",
        4670: "Object permissions changed",
        4673: "Privileged service called",
        4674: "Sensitive privileges assigned",
        
        # Network and Firewall
        5152: "Windows Filtering Platform blocked a packet",
        5153: "Windows Filtering Platform blocked a connection",
        5154: "Windows Filtering Platform permitted an application or service to listen on a port",
        5155: "Windows Filtering Platform blocked an application or service from listening on a port",
        5156: "Windows Filtering Platform allowed a connection",
        5157: "Windows Filtering Platform blocked a connection",
        5158: "Windows Filtering Platform permitted a bind to a local port",
        5159: "Windows Filtering Platform blocked a bind to a local port",
        
        # System Events
        6005: "Event log service was started",
        6006: "Event log service was stopped",
        6008: "Previous system shutdown was unexpected",
        6013: "System shutdown was initiated",
        1074: "System was shut down",
        1076: "System was restarted",
        
        # Application Events
        1000: "Application error",
        1001: "Application hang",
        1002: "Application crash",
        1003: "Application recovery",
        1004: "Application unresponsive",
        1005: "Application error reporting",
        
        # PowerShell Events
        4103: "PowerShell command executed",
        4104: "PowerShell script executed",
        4105: "PowerShell script block executed",
        4106: "PowerShell script block logged",
        4107: "PowerShell script block execution started",
        4108: "PowerShell script block execution finished",
        
        # Windows Defender Events
        1116: "Windows Defender threat detected",
        1117: "Windows Defender threat quarantined",
        1118: "Windows Defender threat removed",
        1119: "Windows Defender threat restored",
        1120: "Windows Defender threat allowed",
        1121: "Windows Defender threat blocked",
        
        # RDP Events
        4778: "Session reconnected",
        4779: "Session disconnected",
        4800: "Workstation locked",
        4801: "Workstation unlocked",
        4802: "Screen saver invoked",
        4803: "Screen saver dismissed",
        
        # USB and Device Events
        6416: "New external device recognized",
        6417: "Device setup completed",
        6418: "Device setup failed",
        6419: "Device removed",
        6420: "Device disabled",
        6421: "Device enabled",
        6422: "Device installation attempted",
        6423: "Device installation completed",
        6424: "Device installation failed"
    }
    
    # Event severity levels
    SEVERITY_LEVELS = {
        0: "Success",
        1: "Informational", 
        2: "Warning",
        3: "Error",
        4: "Critical"
    }
    
    def __init__(self):
        """Initialize the EVTX analyzer."""
        self.logger = get_logger(__name__)
        self.analysis_results = {
            'metadata': {
                'analysis_time': get_current_utc_isoformat(),
                'analyzer_version': '1.0.0'
            },
            'summary': {},
            'events': {},
            'statistics': {},
            'security_events': {},
            'timeline': [],
            'anomalies': []
        }
        
        if not evtx:
            self.logger.warning("EVTX library not available. Install with: pip install evtx")
    
    def analyze_evtx_file(self, evtx_path: Path) -> Dict[str, Any]:
        """
        Analyze a single EVTX file.
        
        Args:
            evtx_path: Path to the EVTX file
            
        Returns:
            Dictionary containing analysis results
        """
        if not evtx_path.exists():
            self.logger.error(f"EVTX file not found: {evtx_path}")
            return {}
            
        self.logger.info(f"Analyzing EVTX file: {evtx_path}")
        
        file_results = {
            'file_info': {
                'path': str(evtx_path),
                'size': evtx_path.stat().st_size,
                'hash': calculate_file_hash(evtx_path, 'sha256'),
                'modified_time': datetime.fromtimestamp(evtx_path.stat().st_mtime).isoformat()
            },
            'events': [],
            'event_counts': defaultdict(int),
            'security_events': [],
            'timeline': [],
            'anomalies': []
        }
        
        try:
            if not evtx:
                self.logger.warning("EVTX library not available. Using fallback implementation.")
                return self._analyze_evtx_file_fallback(evtx_path)
                
            with open(evtx_path, 'rb') as f:
                parser = PyEvtxParser(f)
                
                for record in parser.records():
                    try:
                        event_data = self._parse_event_record(record)
                        if event_data:
                            file_results['events'].append(event_data)
                            file_results['event_counts'][event_data['event_id']] += 1
                            
                            # Add to timeline
                            if 'timestamp' in event_data:
                                file_results['timeline'].append({
                                    'timestamp': event_data['timestamp'],
                                    'event_id': event_data['event_id'],
                                    'description': event_data.get('description', ''),
                                    'source': event_data.get('source', ''),
                                    'level': event_data.get('level', '')
                                })
                            
                            # Check for security events
                            if event_data['event_id'] in self.SECURITY_EVENT_IDS:
                                file_results['security_events'].append(event_data)
                                
                    except Exception as e:
                        self.logger.warning(f"Error parsing event record: {e}")
                        continue
                        
        except Exception as e:
            self.logger.error(f"Error analyzing EVTX file {evtx_path}: {e}")
            
        # Sort timeline by timestamp
        file_results['timeline'].sort(key=lambda x: x['timestamp'])
        
        # Analyze for anomalies
        file_results['anomalies'] = self._detect_anomalies(file_results['events'])
        
        return file_results
    
    def _parse_event_record(self, record) -> Optional[Dict[str, Any]]:
        """
        Parse a single event record.
        
        Args:
            record: EVTX record object
            
        Returns:
            Parsed event data dictionary
        """
        try:
            # Get basic record information
            event_data = {
                'event_id': record.event_id(),
                'timestamp': record.timestamp().isoformat(),
                'source': record.source_name(),
                'level': record.event_level(),
                'level_description': self.SEVEREITY_LEVELS.get(record.event_level(), 'Unknown'),
                'description': self.SECURITY_EVENT_IDS.get(record.event_id(), 'Unknown event'),
                'computer_name': record.computer_name(),
                'user_sid': record.user_sid(),
                'event_data': {}
            }
            
            # Parse XML data if available
            try:
                xml_data = record.xml()
                if xml_data:
                    root = ET.fromstring(xml_data)
                    event_data['event_data'] = self._extract_xml_data(root)
            except Exception as e:
                self.logger.debug(f"Error parsing XML data: {e}")
                
            return event_data
            
        except Exception as e:
            self.logger.debug(f"Error parsing event record: {e}")
            return None
    
    def _extract_xml_data(self, root: ET.Element) -> Dict[str, Any]:
        """
        Extract relevant data from event XML.
        
        Args:
            root: XML root element
            
        Returns:
            Extracted data dictionary
        """
        data = {}
        
        try:
            # Extract EventData
            event_data = root.find('.//EventData')
            if event_data is not None:
                for data_item in event_data.findall('Data'):
                    name = data_item.get('Name', '')
                    value = data_item.text or ''
                    if name and value:
                        data[name] = value
            
            # Extract UserData
            user_data = root.find('.//UserData')
            if user_data is not None:
                for child in user_data:
                    data[child.tag] = child.text or ''
                    
        except Exception as e:
            self.logger.debug(f"Error extracting XML data: {e}")
            
        return data
    
    def _detect_anomalies(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Detect anomalies in event data.
        
        Args:
            events: List of parsed events
            
        Returns:
            List of detected anomalies
        """
        anomalies = []
        
        if not events:
            return anomalies
            
        # Group events by time windows
        time_windows = defaultdict(list)
        for event in events:
            if 'timestamp' in event:
                try:
                    timestamp = datetime.fromisoformat(event['timestamp'].replace('Z', '+00:00'))
                    window_key = timestamp.replace(minute=0, second=0, microsecond=0)
                    time_windows[window_key].append(event)
                except:
                    continue
        
        # Detect high-frequency events
        for window, window_events in time_windows.items():
            if len(window_events) > 100:  # Threshold for high frequency
                anomalies.append({
                    'type': 'high_frequency_events',
                    'timestamp': window.isoformat(),
                    'count': len(window_events),
                    'description': f"High frequency of events ({len(window_events)}) in one hour"
                })
        
        # Detect failed logon attempts
        failed_logons = [e for e in events if e.get('event_id') == 4625]
        if len(failed_logons) > 10:
            anomalies.append({
                'type': 'multiple_failed_logons',
                'count': len(failed_logons),
                'description': f"Multiple failed logon attempts ({len(failed_logons)}) detected"
            })
        
        # Detect unusual process creation
        process_events = [e for e in events if e.get('event_id') == 4688]
        if process_events:
            process_names = [e.get('event_data', {}).get('NewProcessName', '') for e in process_events]
            process_counter = Counter(process_names)
            
            for process, count in process_counter.most_common(5):
                if count > 50:  # Threshold for unusual process creation
                    anomalies.append({
                        'type': 'unusual_process_creation',
                        'process': process,
                        'count': count,
                        'description': f"Unusual number of process creations for {process} ({count})"
                    })
        
        return anomalies
    
    def analyze_evtx_directory(self, evtx_dir: Path, output_dir: Path) -> Dict[str, Any]:
        """
        Analyze all EVTX files in a directory.
        
        Args:
            evtx_dir: Directory containing EVTX files
            output_dir: Output directory for analysis results
            
        Returns:
            Combined analysis results
        """
        self.logger.info(f"Analyzing EVTX files in directory: {evtx_dir}")
        
        # Create analysis output directory
        analysis_dir = output_dir / "Analysis"
        analysis_dir.mkdir(parents=True, exist_ok=True)
        
        # Find all EVTX files
        evtx_files = list(evtx_dir.glob("*.evtx"))
        if not evtx_files:
            self.logger.warning(f"No EVTX files found in {evtx_dir}")
            return {}
        
        self.logger.info(f"Found {len(evtx_files)} EVTX files")
        
        # Analyze each file
        all_results = {
            'metadata': {
                'analysis_time': get_current_utc_isoformat(),
                'analyzer_version': '1.0.0',
                'total_files': len(evtx_files)
            },
            'files': {},
            'summary': {
                'total_events': 0,
                'security_events': 0,
                'event_types': defaultdict(int),
                'anomalies': 0
            },
            'timeline': [],
            'security_events': [],
            'anomalies': []
        }
        
        for evtx_file in evtx_files:
            file_results = self.analyze_evtx_file(evtx_file)
            if file_results:
                all_results['files'][evtx_file.name] = file_results
                
                # Update summary
                all_results['summary']['total_events'] += len(file_results['events'])
                all_results['summary']['security_events'] += len(file_results['security_events'])
                all_results['summary']['anomalies'] += len(file_results['anomalies'])
                
                # Update event type counts
                for event_id, count in file_results['event_counts'].items():
                    all_results['summary']['event_types'][event_id] += count
                
                # Add to global timeline
                all_results['timeline'].extend(file_results['timeline'])
                all_results['security_events'].extend(file_results['security_events'])
                all_results['anomalies'].extend(file_results['anomalies'])
        
        # Sort global timeline
        all_results['timeline'].sort(key=lambda x: x['timestamp'])
        
        # Save detailed results
        self._save_analysis_results(all_results, analysis_dir)
        
        return all_results
    
    def _save_analysis_results(self, results: Dict[str, Any], output_dir: Path):
        """
        Save analysis results to files.
        
        Args:
            results: Analysis results
            output_dir: Output directory
        """
        # Save main analysis results
        with open(output_dir / "evtx_analysis.json", 'w') as f:
            json.dump(results, f, indent=2, default=str)
        
        # Save security events summary
        security_summary = {
            'total_security_events': len(results['security_events']),
            'security_events_by_type': defaultdict(int),
            'critical_events': [],
            'recent_events': []
        }
        
        for event in results['security_events']:
            event_id = event['event_id']
            security_summary['security_events_by_type'][event_id] += 1
            
            # Identify critical events
            if event_id in [4625, 4720, 4728, 4688, 5152, 5153]:  # Failed logon, account creation, etc.
                security_summary['critical_events'].append(event)
            
            # Get recent events (last 24 hours)
            try:
                event_time = datetime.fromisoformat(event['timestamp'].replace('Z', '+00:00'))
                if event_time > datetime.now() - timedelta(days=1):
                    security_summary['recent_events'].append(event)
            except:
                pass
        
        with open(output_dir / "security_summary.json", 'w') as f:
            json.dump(security_summary, f, indent=2, default=str)
        
        # Save timeline
        with open(output_dir / "event_timeline.json", 'w') as f:
            json.dump(results['timeline'], f, indent=2, default=str)
        
        # Save anomalies
        with open(output_dir / "anomalies.json", 'w') as f:
            json.dump(results['anomalies'], f, indent=2, default=str)
        
        self.logger.info(f"Analysis results saved to {output_dir}")
    
    def generate_security_report(self, analysis_results: Dict[str, Any], output_dir: Path) -> str:
        """
        Generate a security-focused report from EVTX analysis.
        
        Args:
            analysis_results: Results from EVTX analysis
            output_dir: Output directory
            
        Returns:
            Path to generated report
        """
        report_path = output_dir / "security_investigation_report.html"
        
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Security Investigation Report - EVTX Analysis</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                .header {{ background-color: #f0f0f0; padding: 20px; border-radius: 5px; }}
                .section {{ margin: 20px 0; padding: 15px; border: 1px solid #ddd; border-radius: 5px; }}
                .critical {{ background-color: #ffe6e6; border-color: #ff9999; }}
                .warning {{ background-color: #fff3cd; border-color: #ffeaa7; }}
                .info {{ background-color: #e7f3ff; border-color: #74b9ff; }}
                table {{ width: 100%; border-collapse: collapse; margin: 10px 0; }}
                th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
                th {{ background-color: #f2f2f2; }}
                .event-count {{ font-weight: bold; color: #e74c3c; }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>Security Investigation Report</h1>
                <p><strong>Generated:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
                <p><strong>Analysis Period:</strong> {analysis_results['metadata']['analysis_time']}</p>
            </div>
            
            <div class="section info">
                <h2>Executive Summary</h2>
                <p>Analysis of {analysis_results['summary']['total_events']} events from {analysis_results['metadata']['total_files']} EVTX files.</p>
                <p><span class="event-count">{analysis_results['summary']['security_events']}</span> security-relevant events identified.</p>
                <p><span class="event-count">{analysis_results['summary']['anomalies']}</span> anomalies detected.</p>
            </div>
            
            <div class="section warning">
                <h2>Critical Security Events</h2>
                <table>
                    <tr><th>Event ID</th><th>Description</th><th>Count</th><th>Risk Level</th></tr>
        """
        
        # Add critical events
        critical_events = {
            4625: "Failed Logon",
            4720: "Account Created", 
            4728: "Member Added to Security Group",
            4688: "Process Creation",
            5152: "WFP Blocked Packet",
            5153: "WFP Blocked Connection"
        }
        
        for event_id, description in critical_events.items():
            count = analysis_results['summary']['event_types'].get(event_id, 0)
            if count > 0:
                risk_level = "HIGH" if count > 10 else "MEDIUM" if count > 5 else "LOW"
                html_content += f"""
                    <tr>
                        <td>{event_id}</td>
                        <td>{description}</td>
                        <td>{count}</td>
                        <td>{risk_level}</td>
                    </tr>
                """
        
        html_content += """
                </table>
            </div>
            
            <div class="section critical">
                <h2>Detected Anomalies</h2>
        """
        
        if analysis_results['anomalies']:
            for anomaly in analysis_results['anomalies'][:10]:  # Show top 10
                html_content += f"""
                    <div style="margin: 10px 0; padding: 10px; background-color: #ffe6e6; border-left: 4px solid #e74c3c;">
                        <strong>{anomaly.get('type', 'Unknown')}</strong><br>
                        {anomaly.get('description', 'No description')}<br>
                        <small>Count: {anomaly.get('count', 'N/A')}</small>
                    </div>
                """
        else:
            html_content += "<p>No anomalies detected.</p>"
        
        html_content += """
            </div>
            
            <div class="section info">
                <h2>Recent Security Events (Last 24 Hours)</h2>
        """
        
        recent_events = [e for e in analysis_results['security_events'] 
                        if datetime.fromisoformat(e['timestamp'].replace('Z', '+00:00')) > datetime.now() - timedelta(days=1)]
        
        if recent_events:
            html_content += """
                <table>
                    <tr><th>Timestamp</th><th>Event ID</th><th>Description</th><th>Source</th></tr>
            """
            for event in recent_events[:20]:  # Show last 20
                html_content += f"""
                    <tr>
                        <td>{event['timestamp']}</td>
                        <td>{event['event_id']}</td>
                        <td>{event['description']}</td>
                        <td>{event['source']}</td>
                    </tr>
                """
            html_content += "</table>"
        else:
            html_content += "<p>No recent security events found.</p>"
        
        html_content += """
            </div>
            
            <div class="section">
                <h2>Investigation Recommendations</h2>
                <ul>
                    <li>Review all failed logon attempts (Event ID 4625) for potential brute force attacks</li>
                    <li>Investigate any account creation events (Event ID 4720) for unauthorized access</li>
                    <li>Check process creation events (Event ID 4688) for suspicious activity</li>
                    <li>Review network blocking events (Event ID 5152/5153) for potential threats</li>
                    <li>Analyze timeline for patterns of suspicious activity</li>
                </ul>
            </div>
        </body>
        </html>
        """
        
        with open(report_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        self.logger.info(f"Security investigation report generated: {report_path}")
        return str(report_path)
    
    def _analyze_evtx_file_fallback(self, evtx_path: Path) -> Dict[str, Any]:
        """
        Fallback EVTX analysis when library is not available
        """
        try:
            # Basic file analysis without parsing
            file_info = {
                'file_path': str(evtx_path),
                'file_size': evtx_path.stat().st_size,
                'modified_time': datetime.fromtimestamp(evtx_path.stat().st_mtime).isoformat(),
                'hash': calculate_file_hash(evtx_path),
                'analysis_method': 'fallback_basic'
            }
            
            # Try to extract basic information using alternative methods
            try:
                import xml.etree.ElementTree as ET
                import gzip
                
                # Try to read as gzipped XML
                with gzip.open(evtx_path, 'rt', encoding='utf-8') as f:
                    content = f.read()
                    # Basic XML parsing to extract event information
                    root = ET.fromstring(content)
                    
                    # Extract basic event information
                    events = []
                    for event in root.findall('.//Event'):
                        event_data = {
                            'event_id': event.get('EventID', 'Unknown'),
                            'system_time': event.get('SystemTime', 'Unknown'),
                            'source': event.get('Source', 'Unknown')
                        }
                        events.append(event_data)
                    
                    file_info['total_events'] = len(events)
                    file_info['events'] = events[:100]  # Limit to first 100 events
                    
            except Exception as xml_error:
                self.logger.warning(f"Could not parse EVTX as XML: {str(xml_error)}")
                file_info['total_events'] = 0
                file_info['events'] = []
            
            return file_info
            
        except Exception as e:
            self.logger.error(f"Error in fallback EVTX analysis: {str(e)}")
            return {
                'file_path': str(evtx_path),
                'error': f'Fallback analysis failed: {str(e)}',
                'analysis_method': 'fallback_failed'
            }
