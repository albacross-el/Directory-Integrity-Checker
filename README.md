# Directory Integrity Checker

A command-line File Integrity Monitoring (FIM) tool that detects and tracks changes to files in a specified directory. Monitors for file creation, modification, deletion, and alerts on suspicious file with type checking to identify commonly associated file extensions with ransomware or malicious activity.

## Features

- **Real-Time Monitoring**: Continuously watches a target directory for file system changes
- **SHA-256 Hashing**: Maintains cryptographic hashes of all files to detect modifications
- **Baseline Creation**: Automatically scans and creates a hash baseline of all files on startup
- **Change Detection**: Tracks file creation, modification, and deletion events
- **Suspicious Activity Alerts**: Flags files with dangerous extensions

## Requirements

- Python 3.6+
- `watchdog` library for file system event monitoring

## Installation

1. Clone or download this repository
2. Install the required dependency:
   ```bash
   pip install watchdog
   ```

## Usage

Run the program from your terminal:

```bash
python FILE.py
```

### Menu Options

Upon execution, you'll see an interactive menu with the following options:

1. **Start Monitoring Directory** - Begin monitoring a target directory
   - Enter the full path to the directory you want to monitor
   - The program will scan all files and create a baseline
   - Real-time alerts will display as changes occur

2. **Stop Monitoring** - Halt the current monitoring session
   - Safely stops the file system observer
   - You can start monitoring a different directory afterward

3. **View Monitoring Status** - Check current monitoring status
   - Displays whether monitoring is active or inactive
   - Shows the log file location for your reference

4. **Exit Program** - Close the application
   - Automatically stops monitoring if active before exiting

## How It Works

1. **Baseline Phase**: When you start monitoring, the tool recursively scans your target directory and creates SHA-256 hashes of all existing files
2. **Monitoring Phase**: Once baseline is complete, the tool watches for changes in real-time
3. **Event Detection**: 
   - **File Created**: New file added to directory - hash is recorded
   - **File Modified**: Existing file changed - new hash compared to baseline, alert if different
   - **File Deleted**: File removed from directory - logged and alerted
   - **Suspicious Extensions**: Any file with dangerous extensions triggers an immediate warning

## Output

### Console Alerts
Real-time alerts appear in the terminal showing:
- Type of change (created, modified, deleted)
- Full file path
- Hash values (for modifications, shows both old and new hashes)
- Suspicious activity warnings

### Log File
All events are recorded in `fim_audit.log` with timestamps:
```
[2026-09-03 14:22:15,123] [INFO] FILE CREATED: /path/to/file.txt | Hash: abc123...
[2026-09-03 14:22:30,456] [INFO] FILE MODIFIED: /path/to/document.pdf | New Hash: xyz789... (Old Hash: abc456...)
[2026-09-03 14:22:45,789] [WARNING] SUSPICIOUS ACTIVITY: Executable/Encrypted extension added -> /path/to/file.exe
```

## Example

```
============================================
   FILE INTEGRITY MONITOR [Status: STOPPED]
============================================
1. Start Monitoring Directory
2. Stop Monitoring
3. View Monitoring Status
4. Exit Program
---------------------------------------------
Select an option (1-4): 1
Enter target directory path to monitor: C:\Users\YourName\Documents

[+] Building initial baseline. Scanning files...
[+] Baseline created! Hashed 1542 files.

[+] File Integrity Monitor started for: C:\Users\YourName\Documents

[ALERT - INTEGRITY CHANGED] File modified!
 -> File: C:\Users\YourName\Documents\report.docx
 -> Previous Hash: a1b2c3d4e5f6...
 -> Current Hash:  9z8y7x6w5v4u...
```

## Security Considerations

- This tool is intended for detecting unauthorized changes to files
- Suspicious extension detection provides early warning of potential ransomware activity
- Logs are stored locally and should be reviewed regularly
- For production use, consider backing up logs to a secure location
- Run with appropriate file system permissions to ensure complete directory access

## License

This project is provided as-is for security and monitoring purposes.
