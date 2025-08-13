"""
Report Generator
Generates comprehensive forensic reports from extracted artifacts
"""

import os
import json
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Any, Optional

from ..utils.logger import get_logger


class ReportGenerator:
    """Forensic report generator"""
    
    def __init__(self):
        self.logger = get_logger(__name__)
    
    def generate_report(self, artifacts_dir: Path, output_path: str, 
                       extraction_results: Optional[Dict[str, Any]] = None) -> str:
        """
        Generate comprehensive forensic report
        
        Args:
            artifacts_dir: Directory containing extracted artifacts
            output_path: Path for the output report
            extraction_results: Extraction results metadata
            
        Returns:
            Path to the generated report
        """
        
        self.logger.info(f"Generating forensic report: {output_path}")
        
        try:
            # Determine report format
            if output_path.endswith('.html'):
                return self._generate_html_report(artifacts_dir, output_path, extraction_results)
            elif output_path.endswith('.json'):
                return self._generate_json_report(artifacts_dir, output_path, extraction_results)
            else:
                # Default to HTML
                html_path = output_path.replace('.txt', '.html')
                return self._generate_html_report(artifacts_dir, html_path, extraction_results)
                
        except Exception as e:
            self.logger.error(f"Error generating report: {str(e)}")
            raise
    
    def _generate_html_report(self, artifacts_dir: Path, output_path: str, 
                             extraction_results: Optional[Dict[str, Any]]) -> str:
        """Generate HTML forensic report"""
        
        try:
            # Load artifacts data
            artifacts_data = self._load_artifacts_data(artifacts_dir)
            
            # Perform automatic analysis
            analysis_results = self._perform_automatic_analysis(artifacts_data, artifacts_dir)
            
            # Generate HTML content
            html_content = self._create_html_content(artifacts_data, extraction_results, analysis_results)
            
            # Write HTML file
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(html_content)
            
            self.logger.info(f"HTML report generated: {output_path}")
            return output_path
            
        except Exception as e:
            self.logger.error(f"Error generating HTML report: {str(e)}")
            import traceback
            self.logger.error(f"Traceback: {traceback.format_exc()}")
            raise
    
    def _generate_json_report(self, artifacts_dir: Path, output_path: str, 
                             extraction_results: Optional[Dict[str, Any]]) -> str:
        """Generate JSON forensic report"""
        
        try:
            # Load artifacts data
            artifacts_data = self._load_artifacts_data(artifacts_dir)
            
            # Create comprehensive report
            report_data = {
                'report_metadata': {
                    'generation_time': datetime.now().isoformat(),
                    'report_version': '1.0.0',
                    'artifacts_directory': str(artifacts_dir.absolute())
                },
                'extraction_results': extraction_results or {},
                'artifacts_summary': self._create_artifacts_summary(artifacts_data),
                'detailed_artifacts': artifacts_data
            }
            
            # Write JSON file
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(report_data, f, indent=2, ensure_ascii=False)
            
            self.logger.info(f"JSON report generated: {output_path}")
            return output_path
            
        except Exception as e:
            self.logger.error(f"Error generating JSON report: {str(e)}")
            raise
    
    def _perform_automatic_analysis(self, artifacts_data: Dict[str, Any], artifacts_dir: Path) -> Dict[str, Any]:
        """
        Perform automatic analysis of extracted artifacts for security investigation
        
        Args:
            artifacts_data: Loaded artifacts data
            artifacts_dir: Directory containing artifacts
            
        Returns:
            Analysis results dictionary
        """
        self.logger.info("Performing automatic analysis of artifacts")
        
        analysis_results = {
            'analysis_time': datetime.now().isoformat(),
            'security_findings': [],
            'anomalies': [],
            'timeline_events': [],
            'risk_assessment': {},
            'investigation_recommendations': []
        }
        
        try:
            # Analyze EVTX data if available
            if 'evtx' in artifacts_data:
                evtx_analysis = self._analyze_evtx_data(artifacts_data['evtx'])
                analysis_results['security_findings'].extend(evtx_analysis.get('findings', []))
                analysis_results['anomalies'].extend(evtx_analysis.get('anomalies', []))
                analysis_results['timeline_events'].extend(evtx_analysis.get('timeline', []))
            
            # Analyze registry data
            if 'registry' in artifacts_data:
                registry_analysis = self._analyze_registry_data(artifacts_data['registry'])
                analysis_results['security_findings'].extend(registry_analysis.get('findings', []))
                analysis_results['anomalies'].extend(registry_analysis.get('anomalies', []))
            
            # Analyze network data
            if 'network' in artifacts_data:
                network_analysis = self._analyze_network_data(artifacts_data['network'])
                analysis_results['security_findings'].extend(network_analysis.get('findings', []))
                analysis_results['anomalies'].extend(network_analysis.get('anomalies', []))
            
            # Analyze user activity
            if 'user_activity' in artifacts_data:
                user_analysis = self._analyze_user_activity_data(artifacts_data['user_activity'])
                analysis_results['security_findings'].extend(user_analysis.get('findings', []))
                analysis_results['anomalies'].extend(user_analysis.get('anomalies', []))
            
            # Generate risk assessment
            analysis_results['risk_assessment'] = self._generate_risk_assessment(analysis_results)
            
            # Generate investigation recommendations
            analysis_results['investigation_recommendations'] = self._generate_investigation_recommendations(analysis_results)
            
            # Save analysis results
            analysis_dir = artifacts_dir / "Analysis"
            analysis_dir.mkdir(exist_ok=True)
            
            with open(analysis_dir / "automatic_analysis.json", 'w') as f:
                json.dump(analysis_results, f, indent=2, default=str)
            
            self.logger.info("Automatic analysis completed")
            return analysis_results
            
        except Exception as e:
            self.logger.error(f"Error during automatic analysis: {str(e)}")
            return analysis_results
    
    def _analyze_evtx_data(self, evtx_data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze EVTX data for security findings"""
        findings = []
        anomalies = []
        timeline = []
        
        try:
            if 'analysis_results' in evtx_data:
                analysis = evtx_data['analysis_results']
                
                # Check for security events
                if 'security_events' in analysis:
                    for event in analysis['security_events']:
                        event_id = event.get('event_id')
                        if event_id in [4625, 4720, 4728, 4688, 5152, 5153]:
                            findings.append({
                                'type': 'security_event',
                                'severity': 'high',
                                'description': f"Critical security event detected: {event.get('description', 'Unknown')}",
                                'event_id': event_id,
                                'timestamp': event.get('timestamp'),
                                'details': event
                            })
                
                # Check for anomalies
                if 'anomalies' in analysis:
                    for anomaly in analysis['anomalies']:
                        anomalies.append({
                            'type': 'evtx_anomaly',
                            'severity': 'medium',
                            'description': anomaly.get('description', 'Unknown anomaly'),
                            'details': anomaly
                        })
                
                # Add timeline events
                if 'timeline' in analysis:
                    timeline.extend(analysis['timeline'])
                    
        except Exception as e:
            self.logger.error(f"Error analyzing EVTX data: {str(e)}")
        
        return {'findings': findings, 'anomalies': anomalies, 'timeline': timeline}
    
    def _analyze_registry_data(self, registry_data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze registry data for security findings"""
        findings = []
        anomalies = []
        
        try:
            # Check for suspicious run keys
            if 'run_keys' in registry_data:
                for run_key in registry_data['run_keys']:
                    if any(suspicious in run_key.get('value', '').lower() for suspicious in 
                          ['powershell', 'cmd', 'wscript', 'cscript', 'rundll32']):
                        findings.append({
                            'type': 'suspicious_run_key',
                            'severity': 'medium',
                            'description': f"Suspicious run key found: {run_key.get('value', 'Unknown')}",
                            'details': run_key
                        })
            
            # Check for unusual uninstall entries
            if 'uninstall_info' in registry_data:
                uninstall_count = len(registry_data['uninstall_info'])
                if uninstall_count > 50:
                    anomalies.append({
                        'type': 'high_uninstall_count',
                        'severity': 'low',
                        'description': f"High number of uninstall entries: {uninstall_count}",
                        'details': {'count': uninstall_count}
                    })
                    
        except Exception as e:
            self.logger.error(f"Error analyzing registry data: {str(e)}")
        
        return {'findings': findings, 'anomalies': anomalies}
    
    def _analyze_network_data(self, network_data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze network data for security findings"""
        findings = []
        anomalies = []
        
        try:
            # Check for suspicious network connections
            if 'network_connections' in network_data:
                for conn in network_data['network_connections']:
                    remote_ip = conn.get('remote_address', '')
                    if remote_ip and remote_ip not in ['127.0.0.1', '::1', '0.0.0.0']:
                        # Check for suspicious ports or IPs
                        if any(suspicious in remote_ip for suspicious in ['192.168.', '10.', '172.']):
                            findings.append({
                                'type': 'internal_network_connection',
                                'severity': 'low',
                                'description': f"Internal network connection to: {remote_ip}",
                                'details': conn
                            })
            
            # Check browser history for suspicious sites
            if 'browser_data' in network_data:
                for browser, data in network_data['browser_data'].items():
                    if 'history' in data:
                        for entry in data['history']:
                            url = entry.get('url', '').lower()
                            if any(suspicious in url for suspicious in 
                                  ['malware', 'virus', 'hack', 'crack', 'keygen']):
                                findings.append({
                                    'type': 'suspicious_browser_activity',
                                    'severity': 'medium',
                                    'description': f"Suspicious URL visited: {entry.get('url', 'Unknown')}",
                                    'details': entry
                                })
                    
        except Exception as e:
            self.logger.error(f"Error analyzing network data: {str(e)}")
        
        return {'findings': findings, 'anomalies': anomalies}
    
    def _analyze_user_activity_data(self, user_data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze user activity data for security findings"""
        findings = []
        anomalies = []
        
        try:
            # Check recent files for suspicious extensions
            if 'recent_files' in user_data:
                for location in user_data['recent_files']:
                    for file_info in location.get('files', []):
                        filename = file_info.get('name', '').lower()
                        if any(suspicious in filename for suspicious in 
                              ['.exe', '.bat', '.cmd', '.ps1', '.vbs', '.js']):
                            findings.append({
                                'type': 'suspicious_recent_file',
                                'severity': 'medium',
                                'description': f"Suspicious file accessed: {file_info.get('name', 'Unknown')}",
                                'details': file_info
                            })
            
            # Check run history
            if 'run_history' in user_data:
                for entry in user_data['run_history']:
                    command = entry.get('command', '').lower()
                    if any(suspicious in command for suspicious in 
                          ['powershell', 'cmd', 'wscript', 'cscript']):
                        findings.append({
                            'type': 'suspicious_run_command',
                            'severity': 'medium',
                            'description': f"Suspicious command executed: {entry.get('command', 'Unknown')}",
                            'details': entry
                        })
                    
        except Exception as e:
            self.logger.error(f"Error analyzing user activity data: {str(e)}")
        
        return {'findings': findings, 'anomalies': anomalies}
    
    def _generate_risk_assessment(self, analysis_results: Dict[str, Any]) -> Dict[str, Any]:
        """Generate risk assessment based on findings"""
        risk_level = 'low'
        risk_score = 0
        
        # Calculate risk score
        for finding in analysis_results.get('security_findings', []):
            severity = finding.get('severity', 'low')
            if severity == 'high':
                risk_score += 10
            elif severity == 'medium':
                risk_score += 5
            else:
                risk_score += 1
        
        # Determine risk level
        if risk_score >= 20:
            risk_level = 'high'
        elif risk_score >= 10:
            risk_level = 'medium'
        
        return {
            'risk_level': risk_level,
            'risk_score': risk_score,
            'total_findings': len(analysis_results.get('security_findings', [])),
            'total_anomalies': len(analysis_results.get('anomalies', []))
        }
    
    def _generate_investigation_recommendations(self, analysis_results: Dict[str, Any]) -> List[str]:
        """Generate investigation recommendations"""
        recommendations = []
        
        # Check for specific findings and provide recommendations
        findings = analysis_results.get('security_findings', [])
        
        if any(f.get('type') == 'security_event' for f in findings):
            recommendations.append("Review all security events in detail, especially failed logon attempts and account changes")
        
        if any(f.get('type') == 'suspicious_run_key' for f in findings):
            recommendations.append("Investigate suspicious run keys for potential persistence mechanisms")
        
        if any(f.get('type') == 'suspicious_browser_activity' for f in findings):
            recommendations.append("Review browser history for potential malicious activity or data exfiltration")
        
        if any(f.get('type') == 'suspicious_recent_file' for f in findings):
            recommendations.append("Analyze recent file access for potential malware execution or data theft")
        
        if analysis_results.get('risk_assessment', {}).get('risk_level') == 'high':
            recommendations.append("System shows high risk indicators - conduct comprehensive security review")
        
        if not recommendations:
            recommendations.append("No immediate security concerns detected, but continue monitoring")
        
        return recommendations
    
    def _load_artifacts_data(self, artifacts_dir: Path) -> Dict[str, Any]:
        """Load all artifacts data from directory"""
        
        artifacts_data = {}
        
        try:
            # Look for JSON files in artifacts directory
            for json_file in artifacts_dir.rglob("*.json"):
                try:
                    with open(json_file, 'r', encoding='utf-8') as f:
                        data = json.load(f)
                    
                    # Use relative path as key
                    relative_path = json_file.relative_to(artifacts_dir)
                    artifacts_data[str(relative_path)] = data
                    
                except Exception as e:
                    self.logger.warning(f"Error loading {json_file}: {str(e)}")
        
        except Exception as e:
            self.logger.error(f"Error loading artifacts data: {str(e)}")
        
        return artifacts_data
    
    def _create_artifacts_summary(self, artifacts_data: Dict[str, Any]) -> Dict[str, Any]:
        """Create summary of extracted artifacts"""
        
        summary = {
            'total_artifacts': len(artifacts_data),
            'artifact_types': {},
            'extraction_statistics': {}
        }
        
        try:
            for artifact_path, artifact_data in artifacts_data.items():
                # Count artifact types
                artifact_type = artifact_path.split('/')[0] if '/' in artifact_path else 'unknown'
                summary['artifact_types'][artifact_type] = summary['artifact_types'].get(artifact_type, 0) + 1
                
                # Extract statistics if available
                if isinstance(artifact_data, dict):
                    if 'extraction_time' in artifact_data:
                        summary['extraction_statistics'][artifact_path] = {
                            'extraction_time': artifact_data['extraction_time']
                        }
        
        except Exception as e:
            self.logger.error(f"Error creating artifacts summary: {str(e)}")
        
        return summary
    
    def _create_html_content(self, artifacts_data: Dict[str, Any], 
                           extraction_results: Optional[Dict[str, Any]],
                           analysis_results: Optional[Dict[str, Any]] = None) -> str:
        """Create comprehensive HTML content for the forensic report"""
        
        html_template = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Windows Forensic Analysis Report</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 20px;
        }
        
        .container {
            max-width: 1400px;
            margin: 0 auto;
            background-color: white;
            border-radius: 15px;
            box-shadow: 0 20px 40px rgba(0,0,0,0.1);
            overflow: hidden;
        }
        
        .header {
            background: linear-gradient(135deg, #2c3e50 0%, #34495e 100%);
            color: white;
            padding: 40px;
            text-align: center;
            position: relative;
        }
        
        .header::before {
            content: '🔍';
            font-size: 3em;
            display: block;
            margin-bottom: 20px;
        }
        
        .header h1 {
            font-size: 2.8em;
            margin-bottom: 10px;
            font-weight: 300;
        }
        
        .header p {
            font-size: 1.2em;
            opacity: 0.9;
        }
        
        .content {
            padding: 40px;
        }
        
        .section {
            margin-bottom: 40px;
            background: #f8f9fa;
            border-radius: 10px;
            padding: 30px;
            border-left: 5px solid #3498db;
        }
        
        .section h2 {
            color: #2c3e50;
            font-size: 1.8em;
            margin-bottom: 20px;
            display: flex;
            align-items: center;
        }
        
        .section h2::before {
            margin-right: 10px;
        }
        
        .section.executive h2::before { content: '📊'; }
        .section.metadata h2::before { content: '⚙️'; }
        .section.artifacts h2::before { content: '📁'; }
        .section.analysis h2::before { content: '🔍'; }
        .section.timeline h2::before { content: '⏰'; }
        .section.findings h2::before { content: '⚠️'; }
        .section.recommendations h2::before { content: '💡'; }
        
        .summary-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin: 20px 0;
        }
        
        .stat-card {
            background: white;
            padding: 25px;
            border-radius: 10px;
            text-align: center;
            box-shadow: 0 5px 15px rgba(0,0,0,0.1);
            transition: transform 0.3s ease;
        }
        
        .stat-card:hover {
            transform: translateY(-5px);
        }
        
        .stat-card h3 {
            font-size: 2.5em;
            color: #3498db;
            margin-bottom: 10px;
        }
        
        .stat-card p {
            color: #7f8c8d;
            font-weight: 500;
        }
        
        .artifact-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 20px;
            margin: 20px 0;
        }
        
        .artifact-card {
            background: white;
            border-radius: 10px;
            padding: 20px;
            box-shadow: 0 5px 15px rgba(0,0,0,0.1);
            border-left: 4px solid #3498db;
        }
        
        .artifact-card h4 {
            color: #2c3e50;
            margin-bottom: 15px;
            font-size: 1.2em;
        }
        
        .artifact-card .meta {
            background: #ecf0f1;
            padding: 10px;
            border-radius: 5px;
            margin: 10px 0;
            font-size: 0.9em;
        }
        
        .artifact-card .data-preview {
            background: #2c3e50;
            color: #ecf0f1;
            padding: 15px;
            border-radius: 5px;
            font-family: 'Courier New', monospace;
            font-size: 0.85em;
            overflow-x: auto;
            max-height: 200px;
            overflow-y: auto;
        }
        
        .timeline-item {
            background: white;
            padding: 15px;
            margin: 10px 0;
            border-radius: 8px;
            border-left: 4px solid #e74c3c;
            box-shadow: 0 2px 5px rgba(0,0,0,0.1);
        }
        
        .timeline-item .time {
            color: #7f8c8d;
            font-size: 0.9em;
            margin-bottom: 5px;
        }
        
        .timeline-item .event {
            color: #2c3e50;
            font-weight: 500;
        }
        
        .finding-item {
            background: white;
            padding: 20px;
            margin: 15px 0;
            border-radius: 8px;
            border-left: 4px solid #e74c3c;
        }
        
        .finding-item.high { border-left-color: #e74c3c; }
        .finding-item.medium { border-left-color: #f39c12; }
        .finding-item.low { border-left-color: #27ae60; }
        
        .finding-item h4 {
            color: #2c3e50;
            margin-bottom: 10px;
        }
        
        .finding-item .severity {
            display: inline-block;
            padding: 3px 8px;
            border-radius: 12px;
            font-size: 0.8em;
            font-weight: bold;
            margin-bottom: 10px;
        }
        
        .finding-item.high .severity { background: #e74c3c; color: white; }
        .finding-item.medium .severity { background: #f39c12; color: white; }
        .finding-item.low .severity { background: #27ae60; color: white; }
        
        .recommendation-item {
            background: white;
            padding: 20px;
            margin: 15px 0;
            border-radius: 8px;
            border-left: 4px solid #3498db;
        }
        
        .recommendation-item h4 {
            color: #2c3e50;
            margin-bottom: 10px;
        }
        
        .metadata-table {
            width: 100%;
            border-collapse: collapse;
            background: white;
            border-radius: 8px;
            overflow: hidden;
            box-shadow: 0 5px 15px rgba(0,0,0,0.1);
        }
        
        .metadata-table th,
        .metadata-table td {
            padding: 15px;
            text-align: left;
            border-bottom: 1px solid #ecf0f1;
        }
        
        .metadata-table th {
            background: #34495e;
            color: white;
            font-weight: 500;
        }
        
        .metadata-table tr:hover {
            background: #f8f9fa;
        }
        
        .risk-indicator {
            display: inline-block;
            padding: 10px 20px;
            border-radius: 25px;
            font-weight: bold;
            font-size: 1.1em;
            margin: 10px 0;
        }
        
        .risk-high { background: #e74c3c; color: white; }
        .risk-medium { background: #f39c12; color: white; }
        .risk-low { background: #27ae60; color: white; }
        
        .footer {
            background: #2c3e50;
            color: white;
            text-align: center;
            padding: 30px;
        }
        
        .footer p {
            margin: 5px 0;
            opacity: 0.9;
        }
        
        .tabs {
            display: flex;
            border-bottom: 2px solid #ecf0f1;
            margin-bottom: 20px;
        }
        
        .tab {
            padding: 10px 20px;
            background: #ecf0f1;
            border: none;
            cursor: pointer;
            border-radius: 5px 5px 0 0;
            margin-right: 5px;
        }
        
        .tab.active {
            background: #3498db;
            color: white;
        }
        
        .tab-content {
            display: none;
        }
        
        .tab-content.active {
            display: block;
        }
        
        @media (max-width: 768px) {
            .container {
                margin: 10px;
                border-radius: 10px;
            }
            
            .content {
                padding: 20px;
            }
            
            .header {
                padding: 20px;
            }
            
            .header h1 {
                font-size: 2em;
            }
            
            .summary-grid {
                grid-template-columns: 1fr;
            }
            
            .artifact-grid {
                grid-template-columns: 1fr;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Windows Forensic Analysis Report</h1>
            <p>Comprehensive Digital Forensics Investigation Report</p>
            <p>Generated on {generation_time}</p>
        </div>
        
        <div class="content">
            <!-- Executive Summary -->
            <div class="section executive">
                <h2>Executive Summary</h2>
                <div class="summary-grid">
                    <div class="stat-card">
                        <h3>{total_artifacts}</h3>
                        <p>Total Artifacts Extracted</p>
                    </div>
                    <div class="stat-card">
                        <h3>{artifact_types}</h3>
                        <p>Artifact Categories</p>
                    </div>
                    <div class="stat-card">
                        <h3>{risk_level}</h3>
                        <p>Overall Risk Level</p>
                    </div>
                    <div class="stat-card">
                        <h3>{findings_count}</h3>
                        <p>Security Findings</p>
                    </div>
                </div>
                
                <div class="risk-indicator risk-{risk_level}">
                    Risk Assessment: {risk_level_upper} ({risk_score}/100)
                </div>
            </div>
            
            <!-- Extraction Metadata -->
            <div class="section metadata">
                <h2>Extraction Metadata</h2>
                {extraction_metadata}
            </div>
            
            <!-- Artifacts Summary -->
            <div class="section artifacts">
                <h2>Artifacts Summary</h2>
                {artifacts_summary}
            </div>
            
            <!-- Detailed Artifacts -->
            <div class="section artifacts">
                <h2>Detailed Artifacts Analysis</h2>
                <div class="tabs">
                    <button class="tab active" onclick="showTab('registry')">Registry</button>
                    <button class="tab" onclick="showTab('filesystem')">File System</button>
                    <button class="tab" onclick="showTab('network')">Network</button>
                    <button class="tab" onclick="showTab('memory')">Memory</button>
                    <button class="tab" onclick="showTab('evtx')">Event Logs</button>
                </div>
                
                <div id="registry" class="tab-content active">
                    {registry_artifacts}
                </div>
                <div id="filesystem" class="tab-content">
                    {filesystem_artifacts}
                </div>
                <div id="network" class="tab-content">
                    {network_artifacts}
                </div>
                <div id="memory" class="tab-content">
                    {memory_artifacts}
                </div>
                <div id="evtx" class="tab-content">
                    {evtx_artifacts}
                </div>
            </div>
            
            <!-- Timeline Analysis -->
            <div class="section timeline">
                <h2>Timeline Analysis</h2>
                {timeline_events}
            </div>
            
            <!-- Security Findings -->
            <div class="section findings">
                <h2>Security Findings</h2>
                {security_findings}
            </div>
            
            <!-- Recommendations -->
            <div class="section recommendations">
                <h2>Investigation Recommendations</h2>
                {recommendations}
            </div>
        </div>
        
        <div class="footer">
            <p><strong>Windows Forensic Artifact Extractor v2.0</strong></p>
            <p>This report is for authorized forensic analysis purposes only.</p>
            <p>Generated with comprehensive artifact analysis and security assessment.</p>
        </div>
    </div>
    
    <script>
        function showTab(tabName) {
            // Hide all tab contents
            var tabContents = document.getElementsByClassName('tab-content');
            for (var i = 0; i < tabContents.length; i++) {
                tabContents[i].classList.remove('active');
            }
            
            // Remove active class from all tabs
            var tabs = document.getElementsByClassName('tab');
            for (var i = 0; i < tabs.length; i++) {
                tabs[i].classList.remove('active');
            }
            
            // Show selected tab content
            document.getElementById(tabName).classList.add('active');
            
            // Add active class to clicked tab
            event.target.classList.add('active');
        }
    </script>
</body>
</html>
        """
        
        # Prepare data for template
        generation_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")
        
        # Calculate summary statistics
        total_artifacts = len(artifacts_data) if artifacts_data else 0
        artifact_types = len(set(path.split('/')[0] for path in artifacts_data.keys() if '/' in path)) if artifacts_data else 0
        
        # Risk assessment
        risk_level = 'low'
        risk_score = 0
        findings_count = 0
        
        if analysis_results:
            risk_assessment = analysis_results.get('risk_assessment', {})
            risk_level = risk_assessment.get('risk_level', 'low')
            risk_score = risk_assessment.get('risk_score', 0)
            findings_count = len(analysis_results.get('security_findings', []))
        
        risk_level_upper = risk_level.upper()
        
        # Generate detailed sections
        extraction_metadata = self._generate_detailed_metadata(extraction_results)
        artifacts_summary = self._generate_artifacts_summary(artifacts_data)
        registry_artifacts = self._generate_registry_section(artifacts_data)
        filesystem_artifacts = self._generate_filesystem_section(artifacts_data)
        network_artifacts = self._generate_network_section(artifacts_data)
        memory_artifacts = self._generate_memory_section(artifacts_data)
        evtx_artifacts = self._generate_evtx_section(artifacts_data)
        timeline_events = self._generate_timeline_section(artifacts_data, analysis_results)
        security_findings = self._generate_findings_section(analysis_results)
        recommendations = self._generate_recommendations_section(analysis_results)
        
        # Fill template
        html_content = html_template
        html_content = html_content.replace('{generation_time}', generation_time)
        html_content = html_content.replace('{total_artifacts}', str(total_artifacts))
        html_content = html_content.replace('{artifact_types}', str(artifact_types))
        html_content = html_content.replace('{risk_level}', risk_level)
        html_content = html_content.replace('{risk_level_upper}', risk_level_upper)
        html_content = html_content.replace('{risk_score}', str(risk_score))
        html_content = html_content.replace('{findings_count}', str(findings_count))
        html_content = html_content.replace('{extraction_metadata}', extraction_metadata)
        html_content = html_content.replace('{artifacts_summary}', artifacts_summary)
        html_content = html_content.replace('{registry_artifacts}', registry_artifacts)
        html_content = html_content.replace('{filesystem_artifacts}', filesystem_artifacts)
        html_content = html_content.replace('{network_artifacts}', network_artifacts)
        html_content = html_content.replace('{memory_artifacts}', memory_artifacts)
        html_content = html_content.replace('{evtx_artifacts}', evtx_artifacts)
        html_content = html_content.replace('{timeline_events}', timeline_events)
        html_content = html_content.replace('{security_findings}', security_findings)
        html_content = html_content.replace('{recommendations}', recommendations)
        
        return html_content
    
    def _generate_detailed_metadata(self, extraction_results: Optional[Dict[str, Any]]) -> str:
        """Generate detailed extraction metadata section"""
        
        if not extraction_results:
            return "<p>No extraction metadata available.</p>"
        
        html = "<table class='metadata-table'>"
        html += "<tr><th>Field</th><th>Value</th></tr>"
        
        try:
            metadata = extraction_results.get('metadata', {})
            
            for key, value in metadata.items():
                if isinstance(value, dict):
                    html += f"<tr><td><strong>{key}</strong></td><td><pre>{json.dumps(value, indent=2)}</pre></td></tr>"
                elif isinstance(value, list):
                    html += f"<tr><td><strong>{key}</strong></td><td>{len(value)} items</td></tr>"
                else:
                    html += f"<tr><td><strong>{key}</strong></td><td>{value}</td></tr>"
        
        except Exception as e:
            html += f"<tr><td><strong>Error</strong></td><td>{str(e)}</td></tr>"
        
        html += "</table>"
        return html
    
    def _generate_artifacts_summary(self, artifacts_data: Dict[str, Any]) -> str:
        """Generate artifacts summary section"""
        
        if not artifacts_data:
            return "<p>No artifacts data available.</p>"
        
        html = "<div class='summary-grid'>"
        
        try:
            # Count artifact types
            artifact_types = {}
            for path in artifacts_data.keys():
                artifact_type = path.split('/')[0] if '/' in path else 'unknown'
                artifact_types[artifact_type] = artifact_types.get(artifact_type, 0) + 1
            
            for artifact_type, count in artifact_types.items():
                html += f"""
                <div class="stat-card">
                    <h3>{count}</h3>
                    <p>{artifact_type.replace('_', ' ').title()}</p>
                </div>
                """
        
        except Exception as e:
            html += f"<p>Error creating summary: {str(e)}</p>"
        
        html += "</div>"
        return html
    
    def _generate_registry_section(self, artifacts_data: Dict[str, Any]) -> str:
        """Generate registry artifacts section"""
        
        html = "<div class='artifact-grid'>"
        
        try:
            registry_data = artifacts_data.get('registry_artifacts', {})
            if not registry_data:
                return "<p>No registry artifacts found.</p>"
            
            # Registry run keys
            if 'run_keys' in registry_data.get('artifacts', {}):
                run_keys = registry_data['artifacts']['run_keys']
                html += f"""
                <div class="artifact-card">
                    <h4>Registry Run Keys</h4>
                    <div class="meta">Extraction Time: {run_keys.get('extraction_time', 'N/A')}</div>
                    <div class="data-preview">
                        {json.dumps(run_keys.get('run_keys', {})[:5], indent=2)}
                    </div>
                </div>
                """
            
            # System information
            if 'system_info' in registry_data.get('artifacts', {}):
                sys_info = registry_data['artifacts']['system_info']
                html += f"""
                <div class="artifact-card">
                    <h4>System Information</h4>
                    <div class="meta">Extraction Time: {sys_info.get('extraction_time', 'N/A')}</div>
                    <div class="data-preview">
                        {json.dumps(sys_info.get('system_info', {}), indent=2)}
                    </div>
                </div>
                """
            
            # User activity
            if 'user_activity' in registry_data.get('artifacts', {}):
                user_activity = registry_data['artifacts']['user_activity']
                html += f"""
                <div class="artifact-card">
                    <h4>User Activity</h4>
                    <div class="meta">Extraction Time: {user_activity.get('extraction_time', 'N/A')}</div>
                    <div class="data-preview">
                        {json.dumps(user_activity.get('user_activity', {})[:5], indent=2)}
                    </div>
                </div>
                """
        
        except Exception as e:
            html += f"<p>Error processing registry data: {str(e)}</p>"
        
        html += "</div>"
        return html
    
    def _generate_filesystem_section(self, artifacts_data: Dict[str, Any]) -> str:
        """Generate filesystem artifacts section"""
        
        html = "<div class='artifact-grid'>"
        
        try:
            filesystem_data = artifacts_data.get('filesystem_artifacts', {})
            if not filesystem_data:
                return "<p>No filesystem artifacts found.</p>"
            
            # File timeline
            if 'file_timeline' in filesystem_data.get('artifacts', {}):
                timeline = filesystem_data['artifacts']['file_timeline']
                html += f"""
                <div class="artifact-card">
                    <h4>File Timeline</h4>
                    <div class="meta">Extraction Time: {timeline.get('extraction_time', 'N/A')}</div>
                    <div class="data-preview">
                        {json.dumps(timeline.get('timeline_entries', [])[:5], indent=2)}
                    </div>
                </div>
                """
            
            # Recent files
            if 'recent_files' in filesystem_data.get('artifacts', {}):
                recent_files = filesystem_data['artifacts']['recent_files']
                html += f"""
                <div class="artifact-card">
                    <h4>Recent Files</h4>
                    <div class="meta">Extraction Time: {recent_files.get('extraction_time', 'N/A')}</div>
                    <div class="data-preview">
                        {json.dumps(recent_files.get('recent_files', {})[:5], indent=2)}
                    </div>
                </div>
                """
        
        except Exception as e:
            html += f"<p>Error processing filesystem data: {str(e)}</p>"
        
        html += "</div>"
        return html
    
    def _generate_network_section(self, artifacts_data: Dict[str, Any]) -> str:
        """Generate network artifacts section"""
        
        html = "<div class='artifact-grid'>"
        
        try:
            network_data = artifacts_data.get('network_artifacts', {})
            if not network_data:
                return "<p>No network artifacts found.</p>"
            
            # Network connections
            if 'network_connections' in network_data.get('artifacts', {}):
                connections = network_data['artifacts']['network_connections']
                html += f"""
                <div class="artifact-card">
                    <h4>Network Connections</h4>
                    <div class="meta">Extraction Time: {connections.get('extraction_time', 'N/A')}</div>
                    <div class="data-preview">
                        {json.dumps(connections.get('connections', [])[:5], indent=2)}
                    </div>
                </div>
                """
            
            # Browser data
            if 'browser_data' in network_data.get('artifacts', {}):
                browser_data = network_data['artifacts']['browser_data']
                html += f"""
                <div class="artifact-card">
                    <h4>Browser Data</h4>
                    <div class="meta">Extraction Time: {browser_data.get('extraction_time', 'N/A')}</div>
                    <div class="data-preview">
                        {json.dumps(browser_data.get('browser_data', {})[:5], indent=2)}
                    </div>
                </div>
                """
        
        except Exception as e:
            html += f"<p>Error processing network data: {str(e)}</p>"
        
        html += "</div>"
        return html
    
    def _generate_memory_section(self, artifacts_data: Dict[str, Any]) -> str:
        """Generate memory artifacts section"""
        
        html = "<div class='artifact-grid'>"
        
        try:
            memory_data = artifacts_data.get('memory_artifacts', {})
            if not memory_data:
                return "<p>No memory artifacts found.</p>"
            
            # Process information
            if 'process_information' in memory_data.get('artifacts', {}):
                processes = memory_data['artifacts']['process_information']
                html += f"""
                <div class="artifact-card">
                    <h4>Process Information</h4>
                    <div class="meta">Extraction Time: {processes.get('extraction_time', 'N/A')}</div>
                    <div class="data-preview">
                        {json.dumps(processes.get('processes', [])[:5], indent=2)}
                    </div>
                </div>
                """
            
            # Memory information
            if 'memory_information' in memory_data.get('artifacts', {}):
                mem_info = memory_data['artifacts']['memory_information']
                html += f"""
                <div class="artifact-card">
                    <h4>Memory Information</h4>
                    <div class="meta">Extraction Time: {mem_info.get('extraction_time', 'N/A')}</div>
                    <div class="data-preview">
                        {json.dumps(mem_info.get('memory_info', {}), indent=2)}
                    </div>
                </div>
                """
        
        except Exception as e:
            html += f"<p>Error processing memory data: {str(e)}</p>"
        
        html += "</div>"
        return html
    
    def _generate_evtx_section(self, artifacts_data: Dict[str, Any]) -> str:
        """Generate EVTX artifacts section"""
        
        html = "<div class='artifact-grid'>"
        
        try:
            evtx_data = artifacts_data.get('evtx_artifacts', {})
            if not evtx_data:
                return "<p>No EVTX artifacts found.</p>"
            
            # Event log analysis
            if 'analysis_results' in evtx_data.get('artifacts', {}):
                analysis = evtx_data['artifacts']['analysis_results']
                html += f"""
                <div class="artifact-card">
                    <h4>Event Log Analysis</h4>
                    <div class="meta">Analysis Time: {analysis.get('analysis_time', 'N/A')}</div>
                    <div class="data-preview">
                        {json.dumps(analysis.get('analysis_results', {})[:5], indent=2)}
                    </div>
                </div>
                """
        
        except Exception as e:
            html += f"<p>Error processing EVTX data: {str(e)}</p>"
        
        html += "</div>"
        return html
    
    def _generate_timeline_section(self, artifacts_data: Dict[str, Any], analysis_results: Optional[Dict[str, Any]]) -> str:
        """Generate timeline analysis section"""
        
        html = ""
        
        try:
            timeline_events = []
            
            # Extract timeline from various artifacts
            if artifacts_data:
                # From filesystem timeline
                if 'filesystem_artifacts' in artifacts_data:
                    fs_data = artifacts_data['filesystem_artifacts']
                    if 'file_timeline' in fs_data.get('artifacts', {}):
                        timeline = fs_data['artifacts']['file_timeline']
                        for entry in timeline.get('timeline_entries', [])[:10]:
                            timeline_events.append({
                                'time': entry.get('modified_time_utc', 'N/A'),
                                'event': f"File modified: {entry.get('file_name', 'Unknown')}"
                            })
            
            # From analysis results
            if analysis_results and 'timeline' in analysis_results:
                for event in analysis_results['timeline'][:10]:
                    timeline_events.append({
                        'time': event.get('timestamp', 'N/A'),
                        'event': event.get('description', 'Unknown event')
                    })
            
            # Sort by time
            timeline_events.sort(key=lambda x: x['time'])
            
            if timeline_events:
                for event in timeline_events:
                    html += f"""
                    <div class="timeline-item">
                        <div class="time">{event['time']}</div>
                        <div class="event">{event['event']}</div>
                    </div>
                    """
            else:
                html = "<p>No timeline events found.</p>"
        
        except Exception as e:
            html = f"<p>Error generating timeline: {str(e)}</p>"
        
        return html
    
    def _generate_findings_section(self, analysis_results: Optional[Dict[str, Any]]) -> str:
        """Generate security findings section"""
        
        if not analysis_results:
            return "<p>No security analysis performed.</p>"
        
        html = ""
        
        try:
            findings = analysis_results.get('security_findings', [])
            
            if findings:
                for finding in findings:
                    severity = finding.get('severity', 'low')
                    html += f"""
                    <div class="finding-item {severity}">
                        <span class="severity">{severity.upper()}</span>
                        <h4>{finding.get('type', 'Unknown Finding')}</h4>
                        <p>{finding.get('description', 'No description available')}</p>
                        <div class="data-preview">
                            {json.dumps(finding.get('details', {}), indent=2)}
                        </div>
                    </div>
                    """
            else:
                html = "<p>No security findings detected.</p>"
        
        except Exception as e:
            html = f"<p>Error processing findings: {str(e)}</p>"
        
        return html
    
    def _generate_recommendations_section(self, analysis_results: Optional[Dict[str, Any]]) -> str:
        """Generate investigation recommendations section"""
        
        html = ""
        
        try:
            recommendations = self._generate_investigation_recommendations(analysis_results or {})
            
            if recommendations:
                for i, recommendation in enumerate(recommendations, 1):
                    html += f"""
                    <div class="recommendation-item">
                        <h4>Recommendation {i}</h4>
                        <p>{recommendation}</p>
                    </div>
                    """
            else:
                html = "<p>No specific recommendations available.</p>"
        
        except Exception as e:
            html = f"<p>Error generating recommendations: {str(e)}</p>"
        
        return html
    
    def _format_extraction_metadata(self, extraction_results: Optional[Dict[str, Any]]) -> str:
        """Format extraction metadata for HTML"""
        
        if not extraction_results:
            return "<p>No extraction metadata available.</p>"
        
        html = "<h4>Extraction Information</h4><table>"
        
        try:
            metadata = extraction_results.get('metadata', {})
            
            for key, value in metadata.items():
                if isinstance(value, dict):
                    html += f"<tr><th>{key}</th><td><pre>{json.dumps(value, indent=2)}</pre></td></tr>"
                else:
                    html += f"<tr><th>{key}</th><td>{value}</td></tr>"
        
        except Exception as e:
            html += f"<tr><th>Error</th><td>{str(e)}</td></tr>"
        
        html += "</table>"
        return html
    
    def _format_artifacts_summary(self, artifacts_data: Dict[str, Any]) -> str:
        """Format artifacts summary for HTML"""
        
        html = "<div class='summary-stats'>"
        
        try:
            # Count artifact types
            artifact_types = {}
            for path in artifacts_data.keys():
                artifact_type = path.split('/')[0] if '/' in path else 'unknown'
                artifact_types[artifact_type] = artifact_types.get(artifact_type, 0) + 1
            
            for artifact_type, count in artifact_types.items():
                html += f"""
                <div class="stat-card">
                    <h3>{count}</h3>
                    <p>{artifact_type.replace('_', ' ').title()}</p>
                </div>
                """
        
        except Exception as e:
            html += f"<p>Error creating summary: {str(e)}</p>"
        
        html += "</div>"
        return html
    
    def _format_detailed_artifacts(self, artifacts_data: Dict[str, Any]) -> str:
        """Format detailed artifacts for HTML"""
        
        html = ""
        
        try:
            for artifact_path, artifact_data in artifacts_data.items():
                html += f"""
                <div class="artifact-item">
                    <h4>{artifact_path}</h4>
                """
                
                if isinstance(artifact_data, dict):
                    # Show extraction time if available
                    if 'extraction_time' in artifact_data:
                        html += f"<p><strong>Extraction Time:</strong> {artifact_data['extraction_time']}</p>"
                    
                    # Show artifact count if available
                    if 'artifacts' in artifact_data:
                        artifact_count = len(artifact_data['artifacts'])
                        html += f"<p><strong>Artifacts Found:</strong> {artifact_count}</p>"
                    
                    # Show sample data (first few items)
                    if 'artifacts' in artifact_data and artifact_data['artifacts']:
                        html += "<p><strong>Sample Data:</strong></p>"
                        html += "<div class='code-block'>"
                        sample_data = dict(list(artifact_data['artifacts'].items())[:3])
                        html += json.dumps(sample_data, indent=2)
                        html += "</div>"
                
                html += "</div>"
        
        except Exception as e:
            html += f"<p>Error formatting artifacts: {str(e)}</p>"
        
        return html

    def _format_analysis_results(self, analysis_results: Dict[str, Any]) -> str:
        """Format analysis results for HTML"""
        
        html = """
        <div class="section">
            <h2>Security Analysis Results</h2>
        """
        
        try:
            # Risk Assessment
            risk_assessment = analysis_results.get('risk_assessment', {})
            risk_level = risk_assessment.get('risk_level', 'unknown')
            risk_score = risk_assessment.get('risk_score', 0)
            
            risk_color = {
                'high': '#e74c3c',
                'medium': '#f39c12', 
                'low': '#27ae60',
                'unknown': '#95a5a6'
            }.get(risk_level, '#95a5a6')
            
            html += f"""
            <div class="section" style="border-left: 5px solid {risk_color};">
                <h3>Risk Assessment</h3>
                <div class="summary-stats">
                    <div class="stat-card">
                        <h3 style="color: {risk_color};">{risk_level.upper()}</h3>
                        <p>Risk Level</p>
                    </div>
                    <div class="stat-card">
                        <h3>{risk_score}</h3>
                        <p>Risk Score</p>
                    </div>
                    <div class="stat-card">
                        <h3>{risk_assessment.get('total_findings', 0)}</h3>
                        <p>Security Findings</p>
                    </div>
                    <div class="stat-card">
                        <h3>{risk_assessment.get('total_anomalies', 0)}</h3>
                        <p>Anomalies</p>
                    </div>
                </div>
            </div>
            """
            
            # Security Findings
            findings = analysis_results.get('security_findings', [])
            if findings:
                html += """
                <div class="section">
                    <h3>Security Findings</h3>
                """
                
                for finding in findings[:10]:  # Show top 10 findings
                    severity = finding.get('severity', 'low')
                    severity_color = {
                        'high': '#e74c3c',
                        'medium': '#f39c12',
                        'low': '#27ae60'
                    }.get(severity, '#95a5a6')
                    
                    html += f"""
                    <div class="artifact-item" style="border-left-color: {severity_color};">
                        <h4>{finding.get('type', 'Unknown').replace('_', ' ').title()}</h4>
                        <p><strong>Severity:</strong> <span style="color: {severity_color};">{severity.upper()}</span></p>
                        <p><strong>Description:</strong> {finding.get('description', 'No description')}</p>
                        <p><strong>Timestamp:</strong> {finding.get('timestamp', 'N/A')}</p>
                    </div>
                    """
                
                html += "</div>"
            
            # Anomalies
            anomalies = analysis_results.get('anomalies', [])
            if anomalies:
                html += """
                <div class="section">
                    <h3>Detected Anomalies</h3>
                """
                
                for anomaly in anomalies[:10]:  # Show top 10 anomalies
                    html += f"""
                    <div class="artifact-item" style="border-left-color: #f39c12;">
                        <h4>{anomaly.get('type', 'Unknown').replace('_', ' ').title()}</h4>
                        <p><strong>Description:</strong> {anomaly.get('description', 'No description')}</p>
                        <p><strong>Count:</strong> {anomaly.get('count', 'N/A')}</p>
                    </div>
                    """
                
                html += "</div>"
            
            # Investigation Recommendations
            recommendations = analysis_results.get('investigation_recommendations', [])
            if recommendations:
                html += """
                <div class="section">
                    <h3>Investigation Recommendations</h3>
                    <ul>
                """
                
                for recommendation in recommendations:
                    html += f"<li>{recommendation}</li>"
                
                html += """
                    </ul>
                </div>
                """
            
            # Timeline Events (if available)
            timeline = analysis_results.get('timeline_events', [])
            if timeline:
                html += """
                <div class="section">
                    <h3>Timeline Events</h3>
                    <div class="code-block">
                """
                
                for event in timeline[:20]:  # Show last 20 events
                    html += f"{event.get('timestamp', 'N/A')} - {event.get('description', 'Unknown event')}<br>"
                
                html += """
                    </div>
                </div>
                """
                
        except Exception as e:
            html += f"<p>Error formatting analysis results: {str(e)}</p>"
            import traceback
            self.logger.error(f"Error in _format_analysis_results: {str(e)}")
            self.logger.error(f"Traceback: {traceback.format_exc()}")
        
        html += "</div>"
        return html
