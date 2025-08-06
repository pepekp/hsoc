"""
Helper script for directory paths.
Create project directories if they do not exist.
"""

from pathlib import Path

# Get project home directory
def app_home() -> object:
    app_home_path = Path(__file__).parent
    return app_home_path

# Netflow directory and files path
def netflow_home_dir_path() -> object:
    netflow_home_path = Path(__file__).parent / 'netflow'
    netflow_home_path.mkdir(parents=True, exist_ok=True)
    return netflow_home_path

# Directory path where nfcapd store netflow files.
def netflow_dir_path() -> object:
    netflow_dir = Path(__file__).parent / 'netflow/flows'
    netflow_dir.mkdir(parents=True, exist_ok=True)
    return str(netflow_dir)

# Syslog directory and files path
def syslog_path() -> object:
    syslog_dir = Path(__file__).parent / 'sysloging/syslogs'
    syslog_dir.mkdir(parents=True, exist_ok=True)
    return syslog_dir

# Project log files directory
def app_logs_dir_path() -> object:
    app_logs_dir = Path(__file__).parent / 'app_logs'
    app_logs_dir.mkdir(parents=True, exist_ok=True)
    return app_logs_dir

netflow_home_dir = netflow_home_dir_path()
flows_dir = netflow_dir_path()
app_home_dir = app_home()
# app_logs
app_logs_directory = app_logs_dir_path()
syslog_dir_path = syslog_path()

#print(netflow_home_dir, flows_dir)
