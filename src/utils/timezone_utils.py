"""
Timezone utilities for forensic analysis
Ensures all timestamps are converted to UTC for consistency
"""

import pytz
from datetime import datetime, timezone
from typing import Union, Optional
import logging

logger = logging.getLogger(__name__)

def get_system_timezone() -> str:
    """
    Get the system's current timezone
    
    Returns:
        Timezone string (e.g., 'Asia/Kolkata', 'America/New_York')
    """
    try:
        import winreg
        
        # Read timezone from Windows registry
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, 
                           r"SYSTEM\CurrentControlSet\Control\TimeZoneInformation") as key:
            timezone_name = winreg.QueryValueEx(key, "TimeZoneKeyName")[0]
            
        # Map Windows timezone names to IANA timezone names
        timezone_mapping = {
            "India Standard Time": "Asia/Kolkata",
            "Eastern Standard Time": "America/New_York",
            "Central Standard Time": "America/Chicago",
            "Mountain Standard Time": "America/Denver",
            "Pacific Standard Time": "America/Los_Angeles",
            "UTC": "UTC",
            "GMT Standard Time": "Europe/London",
            "Central Europe Standard Time": "Europe/Berlin",
            "Tokyo Standard Time": "Asia/Tokyo",
            "China Standard Time": "Asia/Shanghai",
            "AUS Eastern Standard Time": "Australia/Sydney",
            "New Zealand Standard Time": "Pacific/Auckland"
        }
        
        return timezone_mapping.get(timezone_name, "UTC")
        
    except Exception as e:
        logger.warning(f"Could not determine system timezone: {e}")
        return "UTC"

def convert_to_utc(timestamp: Union[datetime, str, float], 
                  source_timezone: Optional[str] = None) -> datetime:
    """
    Convert a timestamp to UTC
    
    Args:
        timestamp: Timestamp to convert (datetime, string, or float)
        source_timezone: Source timezone (if None, uses system timezone)
        
    Returns:
        UTC datetime object
    """
    try:
        # Handle different input types
        if isinstance(timestamp, str):
            # Try to parse ISO format
            if 'T' in timestamp and ('+' in timestamp or 'Z' in timestamp):
                # Already has timezone info
                dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
            else:
                # Assume local timezone
                dt = datetime.fromisoformat(timestamp)
                if source_timezone is None:
                    source_timezone = get_system_timezone()
                tz = pytz.timezone(source_timezone)
                dt = tz.localize(dt)
                
        elif isinstance(timestamp, float):
            # Unix timestamp
            dt = datetime.fromtimestamp(timestamp)
            if source_timezone is None:
                source_timezone = get_system_timezone()
            tz = pytz.timezone(source_timezone)
            dt = tz.localize(dt)
            
        elif isinstance(timestamp, datetime):
            dt = timestamp
            if dt.tzinfo is None:
                # Naive datetime, assume system timezone
                if source_timezone is None:
                    source_timezone = get_system_timezone()
                tz = pytz.timezone(source_timezone)
                dt = tz.localize(dt)
        else:
            raise ValueError(f"Unsupported timestamp type: {type(timestamp)}")
        
        # Convert to UTC
        if dt.tzinfo != timezone.utc:
            dt = dt.astimezone(timezone.utc)
            
        return dt
        
    except Exception as e:
        logger.error(f"Error converting timestamp to UTC: {e}")
        # Return current UTC time as fallback
        return datetime.now(timezone.utc)

def format_utc_timestamp(timestamp: Union[datetime, str, float], 
                        format_str: str = "%Y-%m-%d %H:%M:%S UTC") -> str:
    """
    Convert timestamp to UTC and format as string
    
    Args:
        timestamp: Timestamp to convert
        format_str: Format string for output
        
    Returns:
        Formatted UTC timestamp string
    """
    utc_dt = convert_to_utc(timestamp)
    return utc_dt.strftime(format_str)

def get_utc_isoformat(timestamp: Union[datetime, str, float]) -> str:
    """
    Convert timestamp to UTC ISO format
    
    Args:
        timestamp: Timestamp to convert
        
    Returns:
        UTC timestamp in ISO format
    """
    utc_dt = convert_to_utc(timestamp)
    return utc_dt.isoformat()

def convert_file_timestamps_to_utc(stat_result) -> dict:
    """
    Convert file timestamps to UTC
    
    Args:
        stat_result: os.stat_result object
        
    Returns:
        Dictionary with UTC timestamps
    """
    return {
        'created_time_utc': get_utc_isoformat(stat_result.st_ctime),
        'modified_time_utc': get_utc_isoformat(stat_result.st_mtime),
        'accessed_time_utc': get_utc_isoformat(stat_result.st_atime),
        'created_time_local': datetime.fromtimestamp(stat_result.st_ctime).isoformat(),
        'modified_time_local': datetime.fromtimestamp(stat_result.st_mtime).isoformat(),
        'accessed_time_local': datetime.fromtimestamp(stat_result.st_atime).isoformat()
    }

def get_current_utc_time() -> datetime:
    """
    Get current time in UTC
    
    Returns:
        Current UTC datetime
    """
    return datetime.now(timezone.utc)

def get_current_utc_isoformat() -> str:
    """
    Get current time in UTC ISO format
    
    Returns:
        Current UTC time in ISO format
    """
    return get_current_utc_time().isoformat()



