# Windows Forensic Artifacts Reference Guide

## Overview

This document provides a comprehensive reference for Windows forensic artifacts supported by the Windows Forensic Artifact Extractor. The artifacts are categorized based on their forensic significance and extraction complexity.

## Table of Contents

1. [Basic Artifacts](#basic-artifacts)
2. [Advanced Execution Artifacts](#advanced-execution-artifacts)
3. [Windows Event Logs (EVTX)](#windows-event-logs-evtx)
4. [Registry Artifacts](#registry-artifacts)
5. [File System Artifacts](#file-system-artifacts)
6. [Memory Artifacts](#memory-artifacts)
7. [Network Artifacts](#network-artifacts)
8. [User Activity Artifacts](#user-activity-artifacts)
9. [Advanced System Artifacts](#advanced-system-artifacts)
10. [Extraction Methods](#extraction-methods)
11. [Forensic Analysis](#forensic-analysis)

---

## Basic Artifacts

### Registry Artifacts
**Location**: `C:\Windows\System32\config\`
**Forensic Value**: High
**Description**: Windows Registry contains configuration data, user settings, and system information.

#### Key Registry Hives
- **SYSTEM**: System-wide settings and hardware configuration
- **SOFTWARE**: Installed software and application settings
- **SAM**: Security Account Manager (user accounts and passwords)
- **SECURITY**: Security policies and access control
- **DEFAULT**: Default user profile settings
- **NTUSER.DAT**: Current user profile settings
- **UsrClass.dat**: User-specific class registration data

#### Important Registry Keys
```
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce
HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache
```

### File System Artifacts
**Location**: Various system directories
**Forensic Value**: High
**Description**: File system metadata, timestamps, and file access patterns.

#### Key Locations
- **Recent Files**: `%USERPROFILE%\AppData\Roaming\Microsoft\Windows\Recent\`
- **Startup Items**: `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\`
- **Temp Files**: `%TEMP%\` and `C:\Windows\Temp\`
- **User Documents**: `%USERPROFILE%\Documents\`
- **System Files**: `C:\Windows\System32\`

### Memory Artifacts
**Location**: RAM (volatile)
**Forensic Value**: Critical
**Description**: Live system memory containing running processes, network connections, and volatile data.

#### Memory Components
- **Process List**: Currently running processes
- **Network Connections**: Active network connections
- **Loaded Modules**: DLLs and loaded libraries
- **Memory Dumps**: Full memory acquisition
- **Handle Information**: Open file handles and objects

### Network Artifacts
**Location**: Various network-related directories
**Forensic Value**: High
**Description**: Network activity, browser data, and connection history.

#### Browser Data
- **Chrome**: `%LOCALAPPDATA%\Google\Chrome\User Data\Default\`
- **Firefox**: `%APPDATA%\Mozilla\Firefox\Profiles\`
- **Edge**: `%LOCALAPPDATA%\Microsoft\Edge\User Data\Default\`
- **Internet Explorer**: `%LOCALAPPDATA%\Microsoft\Windows\INetCache\`

#### Network Configuration
- **DNS Cache**: System DNS resolution cache
- **ARP Cache**: Network address resolution
- **Network Shares**: Shared folders and access
- **Network Interfaces**: Network adapter configuration

### User Activity Artifacts
**Location**: User profile directories
**Forensic Value**: High
**Description**: User behavior patterns, recent activities, and interaction history.

#### Key Components
- **Recent Files**: Recently accessed files
- **Run History**: Start → Run command history
- **User Profiles**: User account information
- **Shell Bags**: Explorer folder browsing history
- **Typed Paths**: Manually entered paths in Explorer

---

## Advanced Execution Artifacts

### Prefetch Files
**Location**: `C:\Windows\Prefetch\`
**File Extension**: `.pf`
**Forensic Value**: High
**Description**: Windows performance optimization files that track application execution.

#### Forensic Significance
- **Execution History**: Tracks when applications were last executed
- **Run Count**: Number of times an application was executed
- **Dependencies**: Files and directories accessed during execution
- **Timestamps**: Creation, modification, and access times

#### Key Information
- **Max Files**: 1024 (Windows 10), 124 (Windows 8)
- **Hash Calculation**: Based on complete file path
- **Special Cases**: MMC.EXE, SVCHOST.EXE, DLLHOST.EXE, RUNDLL32.EXE include parameters
- **Tools**: PECmd.exe for analysis

#### Analysis Commands
```bash
# Analyze single prefetch file
PECmd.exe -f <pf_file>

# Analyze all prefetch files in directory
PECmd.exe -d <directory> --csv <output_folder>
```

### ShimCache (AppCompatCache)
**Location**: Registry - `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache`
**Forensic Value**: High
**Description**: Application compatibility cache that tracks executable files.

#### Forensic Significance
- **File Existence**: Shows which executables were present on the system
- **Execution Evidence**: Windows 8 and earlier can indicate execution
- **Timestamps**: Last modified dates of executables
- **Max Entries**: 1024 files

#### Important Notes
- **Windows 10+**: Cannot conclusively prove execution (InsertFlag removed)
- **File Visibility**: Only includes files seen through Explorer or execution
- **Hidden Files**: Not included unless executed
- **Tools**: AppCompatCacheParser.exe

#### Analysis Commands
```bash
# Live system analysis
AppCompatCacheParser.exe

# Export to CSV
AppCompatCacheParser.exe --csv c:\temp -csvf results.csv

# Offline analysis
AppCompatCacheParser.exe -f <filepath>
```

### Amcache
**Location**: `C:\Windows\appcompat\Programs\Amcache.hve`
**Forensic Value**: High
**Description**: Application compatibility database that tracks executed applications and drivers.

#### Forensic Significance
- **Application Tracking**: Records executed applications
- **Driver Information**: Tracks loaded drivers
- **File Metadata**: File size, version, compilation time
- **SHA1 Hash**: First 30MB of executable files
- **Product Information**: Vendor and product names

#### Key Components
- **InventoryApplicationFile**: Application execution records
- **InventoryDriverBinary**: Driver loading records
- **Shortcuts/Link Files**: Shortcut file information
- **PnPs**: Removable device information

#### Analysis Tools
- **Registry Explorer**: Live system analysis
- **AmcacheParser.exe**: Offline analysis

### PCA (Program Compatibility Assistant)
**Location**: `C:\Windows\appcompat\pca\`
**Forensic Value**: Medium
**Description**: Windows 11 feature that tracks program compatibility issues and execution.

#### Key Files
- **PcaAppLaunchDic.txt**: File name, folder, and last execution time
- **PcaGeneralDb1.txt**: Time, AmcacheID, filename, foldername, exit code

### MUICache
**Location**: User registry - `HKCU\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache`
**Forensic Value**: Medium
**Description**: Multilingual User Interface cache for GUI applications.

#### Forensic Significance
- **GUI Applications**: Only tracks GUI-based applications
- **No Timestamps**: Execution time not tracked
- **Cross-Drive**: Can see executables from other drives
- **Metadata**: Application company and name from resource data

### UserAssist
**Location**: User registry - `HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\UserAssist`
**Forensic Value**: High
**Description**: Tracks user interaction with GUI applications.

#### Forensic Significance
- **Program Execution**: Which programs were executed
- **Execution Time**: When programs were executed
- **Run Counter**: Number of executions
- **Focus Information**: Focus count and time
- **ROT-13 Encoding**: Data is encoded in ROT-13

#### Analysis Tools
- **Registry Explorer**: NTUser.Dat analysis
- **ReCMD.exe**: Command-line analysis

### SRUM (System Resource Usage Monitor)
**Location**: `C:\Windows\System32\sru\`
**Forensic Value**: High
**Description**: Detailed file interaction timeline and system resource usage.

#### Key Files
- **SRU.chk**: Checkpoint file
- **SRU.log**: Transaction log
- **SRU00FBC.log, SRU00FBD.log**: Data files

#### Forensic Significance
- **Network Data**: Per-program network usage (exfiltration analysis)
- **Application Usage**: Detailed application interaction timeline
- **File Operations**: File access patterns and timestamps
- **Resource Usage**: System resource consumption

#### Analysis Tools
- **FTK Imager**: Export SRUM information
- **SrumECmd.exe**: Command-line analysis

#### Analysis Commands
```bash
# Export SRUM data
SrumECmd.exe -d <directory> --csv <output_folder>
```

### Registry ASEP (Auto-Start Extensibility Points)
**Location**: Various registry locations
**Forensic Value**: Critical
**Description**: Registry keys that allow programs to start automatically.

#### Key ASEP Locations
```
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce
HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run
HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run
```

#### Forensic Significance
- **Persistence**: Common malware persistence mechanism
- **Startup Behavior**: Unauthorized startup behavior detection
- **Security Monitoring**: Critical for threat detection

#### Analysis Tools
- **AutoRuns**: Microsoft tool for ASEP analysis
- **RECmd.exe**: Registry analysis with batch examples
- **KAPE**: Automated ASEP extraction and analysis

#### Analysis Commands
```bash
# RECmd batch analysis
RECmd.exe --bn BatchExamples\RegistryASEPs.reb -f <registry_file> --csv <output>

# KAPE ASEP module
KAPE --target C:\ --module RegistryASEPs
```

### Volume Shadow Copies
**Location**: System snapshots
**Forensic Value**: High
**Description**: System snapshots that preserve file system state.

#### Forensic Significance
- **Deleted Files**: Can recover deleted files
- **Historical State**: Previous system states
- **Anti-Forensics**: Bypass anti-forensic techniques
- **EVTX Recovery**: Recover deleted event logs

#### Analysis Commands
```bash
# List shadow copies
vssadmin list shadows

# Mount shadow copy
vssadmin mount shadow <shadow_id>
```

### Windows Crash Dumps
**Location**: `C:\ProgramData\Microsoft\Windows\WER\`
**Forensic Value**: Medium
**Description**: Windows Error Reporting crash dump files.

#### Key Locations
- **ReportQueue**: `C:\ProgramData\Microsoft\Windows\WER\ReportQueue\`
- **ReportArchive**: `C:\ProgramData\Microsoft\Windows\WER\ReportArchive\`

#### File Naming Convention
```
EventName_FriendlyId_SignatureHash_AppIdentityHash_cab_ReportId
```

#### Forensic Significance
- **Application Crashes**: Track application failures
- **Malware Analysis**: Malicious application crashes
- **System Stability**: System health indicators
- **Timeline Analysis**: Crash timeline correlation

---

## Windows Event Logs (EVTX)

### Event Log Locations
**Primary Location**: `C:\Windows\System32\winevt\Logs\`
**Archive Location**: `C:\Windows\System32\winevt\Logs\Archive\`
**Forensic Value**: Critical

### Important Event Logs
- **Application**: Application events and errors
- **Security**: Authentication and authorization events
- **System**: System events and service status
- **Setup**: System setup and configuration events
- **Forwarded Events**: Events forwarded from other systems

### Critical Security Event IDs

#### Authentication Events
- **4624**: Successful logon
- **4625**: Failed logon
- **4634**: Account logoff
- **4647**: User initiated logoff
- **4648**: Logon with explicit credentials (RunAs)
- **4672**: Special privileges assigned to new logon
- **4776**: Domain controller credential validation
- **4768**: Kerberos TGT requested
- **4769**: Kerberos service ticket requested
- **4771**: Kerberos pre-authentication failed

#### Account Management
- **4720**: User account created
- **4722**: User account enabled
- **4728**: Member added to security-enabled global group
- **4729**: Member removed from security-enabled global group

#### Process and Service Events
- **4688**: New process created
- **4698**: Scheduled task created
- **7045**: New service installed
- **7034**: Service terminated unexpectedly
- **7009**: Service timeout

#### Network Events
- **5140**: Network share object accessed
- **5145**: Network share object access check
- **5152**: Windows Filtering Platform blocked a packet
- **5153**: Windows Filtering Platform blocked a connection

#### System Events
- **104**: Log file cleared
- **1102**: Audit log cleared

### PowerShell Events
- **400**: Engine state changed
- **600**: Provider started
- **4104**: Script block logging (creating scriptblock text)

### Task Scheduler Events
- **106**: Task registered
- **141**: Task deleted
- **100**: Task started
- **102**: Task finished

### Windows Defender Events
- **1116**: Malware detected
- **1117**: Malware action performed

### Remote Desktop Events
- **21**: Session logon succeeded
- **22**: Shell start notification
- **23**: Session logoff succeeded
- **24**: Session disconnected
- **25**: Session reconnection succeeded
- **1149**: User authentication succeeded (network connection only)
- **1029**: Username hash (Base64 SHA256)

### Logon Types
- **2**: Console (hands on keyboard)
- **3**: Network
- **4**: Batch (scheduled task)
- **5**: Windows Services
- **7**: Screen Lock/Unlock
- **8**: Network (Cleartext logon)
- **9**: Alternate credentials (RunAs)
- **10**: Remote Interactive (RDP)
- **11**: Cached credentials
- **12**: Cached Remote Interactive
- **13**: Cached unlock

### Analysis Tools
- **Get-WinEvent**: PowerShell cmdlet for event log analysis
- **EvtECmd**: Eric Zimmerman's event log analysis tool
- **Log Parser**: Microsoft's log analysis tool

#### Analysis Commands
```powershell
# Get all security events
Get-WinEvent -LogName Security

# Get specific event ID
Get-WinEvent -LogName Security | Where-Object {$_.Id -eq 4624}

# Export events to CSV
Get-WinEvent -LogName Security | Export-Csv -Path security_events.csv
```

---

## Registry Artifacts

### Registry Structure
**Location**: `C:\Windows\System32\config\`
**Components**: Default, SAM, Security, Software, System

### Registry Hives
- **HKEY_CLASSES_ROOT**: File association information
- **HKEY_CURRENT_USER**: Current user settings (NTUSER.DAT, USRCLASS.DAT)
- **HKEY_LOCAL_MACHINE**: System-wide settings
- **HKEY_USERS**: All user settings
- **HKEY_CURRENT_CONFIG**: Hardware configuration

### Important Registry Keys

#### Explorer Keys
```
HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer
├── ComDlg32
│   ├── LastVisitedPidlMRU (apps used to open/save files)
│   └── OpenSavePidlMRU (files accessed via open/save dialog)
├── Mountpoints2 (removable devices)
├── RecentDocs (recent file interaction)
├── RunMRU (Start → Run history)
├── TypedPaths (manually entered paths)
├── UserAssist (GUI program execution)
└── WordWheelQuery (Explorer search history)
```

#### Shell Bags
```
HKCU\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\Shell
├── BagMRU
└── Bags
```

#### USB Device Tracking
```
HKLM\SYSTEM\CurrentControlSet\Enum\USB (Vendor ID, Product ID)
HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR (Class ID, Serial Number)
HKLM\SYSTEM\MountedDevices (Serial # to Drive Letter mapping)
HKLM\SOFTWARE\Microsoft\Windows Portable Devices\Devices (FriendlyName)
HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\EMDMgmt (Volume Serial Numbers)
```

#### Network Information
```
HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Shares (Network Shares)
HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces (Network Interfaces)
HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList (Network Profiles)
```

### Analysis Tools
- **Registry Explorer**: GUI-based registry analysis
- **RECmd**: Command-line registry analysis
- **rla.exe**: Transaction log replay
- **RegRipper**: Automated registry analysis

#### Analysis Commands
```bash
# RECmd batch analysis
RECmd.exe --bn BatchExamples\Kroll_Batch.reb -f <registry_file> --csv <output>

# RegRipper analysis
rip -r <registry_file> -f <profile>
rip -r <registry_file> -a (all plugins)
```

---

## File System Artifacts

### Critical Directories
- **`C:\Windows\System32\config\`**: Registry hives
- **`C:\Windows\repair\`**: Registry backups
- **`C:\Windows\System32\winevt\`**: Event logs
- **`C:\Windows\Prefetch\`**: Prefetch files
- **`C:\Windows\AppCompat\Programs\`**: Amcache
- **`C:\Users\*\NTUSER.dat`**: User registry
- **`C:\Users\*\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\`**: User startup
- **`C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\`**: System startup

### File System Timeline
- **Creation Time**: File creation timestamp
- **Modification Time**: Last content modification
- **Access Time**: Last file access
- **Change Time**: Last metadata change

### Analysis Tools
- **Timeline Explorer**: Timeline analysis
- **Log2Timeline**: Automated timeline generation
- **FTK Imager**: File system imaging and analysis

---

## Memory Artifacts

### Memory Components
- **Process List**: Running processes with details
- **Network Connections**: Active network connections
- **Loaded Modules**: DLLs and loaded libraries
- **Memory Dumps**: Full memory acquisition
- **Handle Information**: Open file handles and objects

### Memory Analysis Tools
- **Volatility**: Memory analysis framework
- **Rekall**: Memory analysis framework
- **WinDbg**: Microsoft debugger

---

## Network Artifacts

### Browser Data
- **History**: Browsing history
- **Cookies**: Session and tracking cookies
- **Downloads**: Download history
- **Cache**: Browser cache files
- **Bookmarks**: Saved bookmarks

### Network Configuration
- **DNS Cache**: System DNS resolution cache
- **ARP Cache**: Network address resolution
- **Network Shares**: Shared folders and access
- **Network Interfaces**: Network adapter configuration

### Analysis Tools
- **Browser History Viewer**: Browser data analysis
- **NetworkMiner**: Network traffic analysis
- **Wireshark**: Network packet analysis

---

## User Activity Artifacts

### Recent Activity
- **Recent Files**: Recently accessed files
- **Run History**: Start → Run command history
- **User Profiles**: User account information
- **Shell Bags**: Explorer folder browsing history
- **Typed Paths**: Manually entered paths in Explorer

### Analysis Tools
- **Timeline Explorer**: Activity timeline analysis
- **Registry Explorer**: User activity analysis
- **RECmd**: Automated user activity extraction

---

## Advanced System Artifacts

### NTDS.dit
**Location**: `C:\Windows\NTDS\ntds.dit`
**Forensic Value**: Critical
**Description**: Active Directory database containing user credentials.

#### Important Notes
- Only LSASS can write to NTDS.dit
- Only one LSASS process runs at a time
- Contains encrypted passwords and Active Directory details
- NTDSutil can access this data
- Often targeted by attackers for credential extraction

### System Information
- **Hardware Information**: CPU, RAM, disk configuration
- **Software Information**: Installed applications and versions
- **Configuration**: System settings and policies
- **Network Configuration**: Network adapters and settings

---

## Extraction Methods

### Live System Extraction
- **Registry Access**: Direct registry hive access
- **File System Access**: Direct file system access
- **Memory Access**: Live memory acquisition
- **Event Log Access**: Direct event log access

### Offline System Extraction
- **Disk Imaging**: Full disk image acquisition
- **Registry Hive Extraction**: Offline registry analysis
- **File System Analysis**: Offline file system analysis
- **Memory Analysis**: Memory dump analysis

### Tools Integration
- **Arsenal Image Mounter**: Disk image mounting
- **FTK Imager**: Evidence acquisition and analysis
- **KAPE**: Automated artifact extraction
- **RECmd**: Registry analysis

---

## Forensic Analysis

### Timeline Analysis
- **Event Correlation**: Correlate events across artifacts
- **Activity Patterns**: Identify user activity patterns
- **Anomaly Detection**: Detect unusual activity
- **Incident Reconstruction**: Reconstruct security incidents

### Artifact Correlation
- **Cross-Reference**: Cross-reference multiple artifacts
- **Validation**: Validate findings across sources
- **Completeness**: Ensure comprehensive analysis
- **Accuracy**: Verify artifact accuracy

### Reporting
- **Executive Summary**: High-level findings
- **Technical Details**: Detailed technical analysis
- **Evidence Documentation**: Document all evidence
- **Recommendations**: Provide actionable recommendations

### Best Practices
- **Chain of Custody**: Maintain evidence integrity
- **Documentation**: Document all analysis steps
- **Validation**: Validate all findings
- **Reporting**: Provide clear and actionable reports

---

## Conclusion

This reference guide provides a comprehensive overview of Windows forensic artifacts and their forensic significance. The Windows Forensic Artifact Extractor supports extraction and analysis of all these artifact types, providing investigators with powerful tools for digital forensics and incident response.

For more detailed information about specific artifacts, refer to the individual documentation files and the Native Logs folder for additional technical details and analysis techniques.
