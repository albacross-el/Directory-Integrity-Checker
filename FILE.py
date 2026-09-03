import os
import sys
import hashlib
import logging
from logging.handlers import RotatingFileHandler
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# ----------------------------------------------------------------------
# Configuration & Logging Setup
# ----------------------------------------------------------------------
LOG_FILE = "fim_audit.log"
MAX_LOG_BYTES = 50 * 1024 * 1024  # 50 MB
BACKUP_COUNT = 3                  # Keep up to 3 old log files

logger = logging.getLogger("FIM_Logger")
logger.setLevel(logging.INFO)

# File Handler (Rotating Log File - Max 50 MB)
file_handler = RotatingFileHandler(
    LOG_FILE, maxBytes=MAX_LOG_BYTES, backupCount=BACKUP_COUNT
)
file_formatter = logging.Formatter("[%(asctime)s] [%(levelname)s] %(message)s")
file_handler.setFormatter(file_formatter)
logger.addHandler(file_handler)

# Suspicious file extensions commonly associated with ransomware or script threats
SUSPICIOUS_EXTENSIONS = {".locked", ".crypto", ".enc", ".bat", ".vbs", ".ps1", ".exe", ".sh"}

# ----------------------------------------------------------------------
# Helper Functions
# ----------------------------------------------------------------------
def calculate_sha256(filepath):
    """Computes SHA-256 hash of a file safely."""
    sha256 = hashlib.sha256()
    try:
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                sha256.update(chunk)
        return sha256.hexdigest()
    except (PermissionError, FileNotFoundError, OSError):
        return None

# ----------------------------------------------------------------------
# Event Handler Class
# ----------------------------------------------------------------------
class IntegrityMonitorHandler(FileSystemEventHandler):
    def __init__(self, target_dir):
        super().__init__()
        self.target_dir = target_dir
        self.baseline = {}
        self.build_baseline()

    def build_baseline(self):
        """Scans the directory recursively to build an initial hash baseline."""
        print("\n[+] Building initial baseline. Scanning files...")
        count = 0
        for root, _, files in os.walk(self.target_dir):
            for file in files:
                filepath = os.path.join(root, file)
                # Ignore the log file itself if placed in the same directory
                if os.path.abspath(filepath) == os.path.abspath(LOG_FILE):
                    continue
                file_hash = calculate_sha256(filepath)
                if file_hash:
                    self.baseline[filepath] = file_hash
                    count += 1
        print(f"[+] Baseline created! Hashed {count} files.\n")
        logger.info(f"Baseline initialized for directory: {self.target_dir} ({count} files)")

    def on_created(self, event):
        if event.is_directory or os.path.abspath(event.src_path) == os.path.abspath(LOG_FILE):
            return
        
        filepath = event.src_path
        file_hash = calculate_sha256(filepath)
        self.baseline[filepath] = file_hash
        
        log_msg = f"FILE CREATED: {filepath} | Hash: {file_hash}"
        logger.info(log_msg)

        # Alert if new file has a suspicious extension
        ext = os.path.splitext(filepath)[1].lower()
        if ext in SUSPICIOUS_EXTENSIONS:
            print(f"\n[ALERT - SUSPICIOUS FILE DETECTED] New executable/encrypted extension created!")
            print(f" -> Path: {filepath}\n")
            logger.warning(f"SUSPICIOUS ACTIVITY: Executable/Encrypted extension added -> {filepath}")

    def on_modified(self, event):
        if event.is_directory or os.path.abspath(event.src_path) == os.path.abspath(LOG_FILE):
            return
        
        filepath = event.src_path
        old_hash = self.baseline.get(filepath)
        new_hash = calculate_sha256(filepath)

        if new_hash and old_hash != new_hash:
            self.baseline[filepath] = new_hash
            log_msg = f"FILE MODIFIED: {filepath} | New Hash: {new_hash} (Old Hash: {old_hash})"
            logger.info(log_msg)

            # High-priority alert on console
            print(f"\n[ALERT - INTEGRITY CHANGED] File modified!")
            print(f" -> File: {filepath}")
            print(f" -> Previous Hash: {old_hash}")
            print(f" -> Current Hash:  {new_hash}\n")

    def on_deleted(self, event):
        if event.is_directory or os.path.abspath(event.src_path) == os.path.abspath(LOG_FILE):
            return
        
        filepath = event.src_path
        if filepath in self.baseline:
            del self.baseline[filepath]
        
        log_msg = f"FILE DELETED: {filepath}"
        logger.info(log_msg)
        print(f"\n[ALERT - FILE REMOVED] File deleted: {filepath}\n")

# ----------------------------------------------------------------------
# Application Manager
# ----------------------------------------------------------------------
class FIMService:
    def __init__(self):
        self.observer = None
        self.is_running = False

    def start(self, target_directory):
        if self.is_running:
            print("[!] Monitor is already running.")
            return

        if not os.path.exists(target_directory):
            print("[!] Error: Specified path does not exist.")
            return

        event_handler = IntegrityMonitorHandler(target_directory)
        self.observer = Observer()
        self.observer.schedule(event_handler, target_directory, recursive=True)
        self.observer.start()
        self.is_running = True
        print(f"[+] File Integrity Monitor started for: {os.path.abspath(target_directory)}")

    def stop(self):
        if not self.is_running or not self.observer:
            print("[!] Monitor is not currently running.")
            return

        print("[-] Stopping monitor service...")
        self.observer.stop()
        self.observer.join()
        self.is_running = False
        print("[+] Monitor stopped successfully.")

# ----------------------------------------------------------------------
# Command Line Interface (CMD Menu)
# ----------------------------------------------------------------------
def main():
    service = FIMService()

    while True:
        status_str = "RUNNING" if service.is_running else "STOPPED"
        print("\n" + "=" * 45)
        print(f"   FILE INTEGRITY MONITOR [Status: {status_str}]")
        print("=" * 45)
        print("1. Start Monitoring Directory")
        print("2. Stop Monitoring")
        print("3. View Monitoring Status")
        print("4. Exit Program")
        print("-" * 45)

        choice = input("Select an option (1-4): ").strip()

        if choice == "1":
            if service.is_running:
                print("[!] Monitor is already running. Stop it first to switch directories.")
            else:
                directory = input("Enter target directory path to monitor: ").strip()
                # Remove quotes if user drag-and-dropped a folder into terminal
                directory = directory.strip('"').strip("'")
                service.start(directory)

        elif choice == "2":
            service.stop()

        elif choice == "3":
            print(f"\nCurrent Status: {'ACTIVE' if service.is_running else 'INACTIVE'}")
            print(f"Log File Location: {os.path.abspath(LOG_FILE)}")

        elif choice == "4":
            if service.is_running:
                service.stop()
            print("[+] Exiting FIM program. Goodbye!")
            sys.exit(0)

        else:
            print("[!] Invalid option. Please enter 1, 2, 3, or 4.")

if __name__ == "__main__":
    main()
