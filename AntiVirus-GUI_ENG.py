from threading import *
from tkinter import *
from tkinter.filedialog import askopenfilename
from tkinter.messagebox import showerror
import tkinter, tkinter.scrolledtext
import threading
import os
import sys
import ctypes
import urllib.request
import glob
import time
import hashlib
import socket
import subprocess
import quarantaene 
import SystemFileScanner
import requests
import hashlib
import logging
import json
import win32api
import win32security
import ntsecuritycon as con

os_name = sys.platform
verzeichnisse = []
files = []
partitionen = []
terminations = []

def has_read_permissions(path):
    """
    Check if the current user has read permissions for a path
    """
    try:
        # Attempt to list directory contents
        os.listdir(path)
        return True
    except PermissionError:
        return False
    except Exception:
        return False

def get_user_sid():
    """
    Get the current user's SID
    """
    try:
        # Get current process token
        hToken = win32security.OpenProcessToken(
            win32api.GetCurrentProcess(), 
            win32security.TOKEN_QUERY
        )
        
        # Get user SID from token
        user_sid, _ = win32security.GetTokenInformation(
            hToken, 
            win32security.TokenUser
        )
        return user_sid
    except Exception as e:
        logging.error(f"Could not retrieve user SID: {e}")
        return None

def check_folder_permissions(folder_path):
    """
    Advanced folder permission checking
    """
    try:
        # Get current user's SID
        user_sid = get_user_sid()
        if not user_sid:
            logging.warning("Could not determine user SID")
            return False

        # Get file/folder security descriptor
        sd = win32security.GetFileSecurity(
            folder_path, 
            win32security.OWNER_SECURITY_INFORMATION | 
            win32security.DACL_SECURITY_INFORMATION
        )

        # Get DACL (Discretionary Access Control List)
        dacl = sd.GetSecurityDescriptorDacl()

        # Check explicit permissions
        for i in range(dacl.GetAceCount()):
            ace = dacl.GetAce(i)
            sid = ace[2]
            
            # Check if ACE applies to current user
            if win32security.IsValidSid(sid):
                access_mask = ace[1]
                
                # Check for read and list folder contents permissions
                if (access_mask & (
                    con.FILE_GENERIC_READ | 
                    con.FILE_LIST_DIRECTORY
                )) and sid == user_sid:
                    return True

        return False

    except Exception as e:
        logging.error(f"Permission check error for {folder_path}: {e}")
        return False

def safe_listdir(path):
    """
    Safely list directory contents with multiple permission checks
    """
    try:
        # Multiple permission checking strategies
        if not os.path.exists(path):
            logging.warning(f"Path does not exist: {path}")
            return []

        if not os.path.isdir(path):
            logging.warning(f"Not a directory: {path}")
            return []

        # Strategy 1: Basic permission check
        if not has_read_permissions(path):
            logging.warning(f"No read permissions: {path}")
            return []

        # Strategy 2: Advanced Windows permission check
        if not check_folder_permissions(path):
            logging.warning(f"Detailed permission check failed: {path}")
            return []

        # Attempt to list directory
        entries = os.listdir(path)
        return entries

    except PermissionError:
        logging.warning(f"PermissionError accessing: {path}")
        return []
    except OSError as e:
        logging.error(f"OS Error accessing {path}: {e}")
        return []
    except Exception as e:
        logging.error(f"Unexpected error accessing {path}: {e}")
        return []

def recursive_file_discovery(
    root_path, 
    max_depth=3, 
    current_depth=0, 
    ignored_paths=None
):
    """
    Robust recursive file discovery
    """
    # Default ignored paths
    if ignored_paths is None:
        ignored_paths = {
            # Windows system paths to ignore
            r'C:\Windows',
            r'C:\Program Files',
            r'C:\Program Files (x86)',
            r'C:\ProgramData',
            # User profile paths with potential restrictions
            r'C:\Users\Default',
            r'C:\Users\Public',
        }

    discovered_files = []

    # Depth and path validation
    if (current_depth > max_depth or 
        any(root_path.startswith(ignored) for ignored in ignored_paths)):
        return discovered_files

    try:
        # Safe directory listing
        entries = safe_listdir(root_path)

        for entry_name in entries:
            full_path = os.path.join(root_path, entry_name)

            try:
                # Skip symbolic links and system files
                if os.path.islink(full_path):
                    continue

                # File handling
                if os.path.isfile(full_path):
                    discovered_files.append(full_path)

                # Directory recursion
                elif os.path.isdir(full_path):
                    # Additional path filtering
                    if (not entry_name.startswith('.') and 
                        '$' not in entry_name and 
                        entry_name.lower() not in {'temp', 'temporary'}):
                        
                        sub_files = recursive_file_discovery(
                            full_path, 
                            max_depth, 
                            current_depth + 1,
                            ignored_paths
                        )
                        discovered_files.extend(sub_files)

            except Exception as e:
                logging.error(f"Error processing {full_path}: {e}")

    except Exception as e:
        logging.error(f"Comprehensive scan error for {root_path}: {e}")

    return discovered_files

def scan_system_drives(max_depth=2):
    """
    Comprehensive and safe system drive scanning
    """
    total_files = 0
    scanned_drives = []

    # Get system drives
    drives = [
        f"{letter}:\\" for letter in 'CDEFGH' 
        if os.path.exists(f"{letter}:\\")
    ]

    logging.info(f"Scanning {len(drives)} accessible drives")

    for drive in drives:
        try:
            logging.info(f"Scanning drive: {drive}")

            # Perform recursive file discovery
            drive_files = recursive_file_discovery(
                drive, 
                max_depth=max_depth
            )

            total_files += len(drive_files)
            scanned_drives.append(drive)

            logging.info(f"Found {len(drive_files)} files in {drive}")

        except Exception as e:
            logging.error(f"Error scanning drive {drive}: {e}")

    logging.info(f"Scan Complete. Total Files: {total_files}")
    return total_files, scanned_drives

class TextBoxHandler(logging.Handler):
    def __init__(self, text_widget):
        super().__init__()
        self.text_widget = text_widget
        self.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s: %(message)s'))

    def emit(self, record):
        msg = self.format(record)
        def append():
            self.text_widget.configure(state='normal')
            self.text_widget.insert(tkinter.END, msg + "\n")
            self.text_widget.see(tkinter.END)
            self.text_widget.configure(state='disabled')
        
        self.text_widget.after(0, append)

def setup_logging(text_box):
    # Remove any existing handlers
    for handler in logging.root.handlers[:]:
        logging.root.removeHandler(handler)
    
    # Create and configure text box handler
    text_handler = TextBoxHandler(text_box)
    text_handler.setLevel(logging.INFO)
    
    # Configure root logger
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s: %(message)s',
        handlers=[text_handler]
    )

#Virtot Scanner
class VirusTotalScanner:
    def __init__(self, api_key="maltek"):
        self.api_key = api_key
        self.base_url = "https://www.virustotal.com/api/v3/files"
        self.headers = {
            "accept": "application/json",
            "x-apikey": self.api_key
        }

    def debug_request(self, method, url, **kwargs):
        """
        Debug method to log detailed request and response information
        """
        try:
            logging.info(f"Making {method} request to {url}")
            logging.info(f"Headers: {kwargs.get('headers', {})}")
            
            # Make the request
            response = requests.request(method, url, **kwargs)
            
            # Log response details
            logging.info(f"Response Status Code: {response.status_code}")
            logging.info(f"Response Headers: {response.headers}")
            
            # Log raw response content
            logging.info(f"Raw Response Content: {response.text}")
            
            # Try to parse JSON
            try:
                json_response = response.json()
                logging.info(f"Parsed JSON Response: {json.dumps(json_response, indent=2)}")
                return response
            except json.JSONDecodeError as je:
                logging.error(f"JSON Decode Error: {je}")
                logging.error(f"Response Content: {response.text}")
                return None
        
        except requests.RequestException as e:
            logging.error(f"Request Exception: {e}")
            return None

    def get_file_hash(self, filepath):
        """
        Generate MD5 hash of a file
        """
        try:
            if not os.path.exists(filepath):
                logging.error(f"File not found: {filepath}")
                return None

            MAX_FILE_SIZE = 32 * 1024 * 1024  # 32 MB
            if os.path.getsize(filepath) > MAX_FILE_SIZE:
                logging.warning(f"File too large for scanning: {filepath}")
                return None

            hash_md5 = hashlib.md5()
            with open(filepath, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hash_md5.update(chunk)
            
            file_hash = hash_md5.hexdigest()
            logging.info(f"Generated MD5 hash: {file_hash}")
            return file_hash

        except Exception as e:
            logging.error(f"Hash generation error: {e}")
            return None

    def scan_file(self, filepath):
        """
        Advanced file scanning method with extensive error handling
        """
        try:
            # Validate file and get hash
            file_hash = self.get_file_hash(filepath)
            if not file_hash:
                return {
                    'is_malicious': False,
                    'error': 'Could not generate file hash'
                }

            # Construct URL for file report
            check_url = f"{self.base_url}/{file_hash}"
            
            # Debug request
            response = self.debug_request('GET', check_url, headers=self.headers)
            
            if not response:
                return {
                    'is_malicious': False,
                    'error': 'Failed to get response from VirusTotal'
                }

            # Check response status
            if response.status_code not in [200, 404]:
                logging.error(f"Unexpected VirusTotal response: {response.status_code}")
                return {
                    'is_malicious': False,
                    'error': f'API error: {response.status_code}'
                }

            # Try to parse JSON safely
            try:
                result = response.json()
            except json.JSONDecodeError:
                logging.error("Failed to decode JSON response")
                logging.error(f"Raw response: {response.text}")
                return {
                    'is_malicious': False,
                    'error': 'Invalid JSON response'
                }

            # Handle different response scenarios
            if response.status_code == 404:
                # File not in database, upload for scanning
                return self.upload_file_for_scanning(filepath)

            # Analyze detection results
            try:
                if 'data' in result and 'attributes' in result['data']:
                    stats = result['data']['attributes']['last_analysis_stats']
                    
                    malicious_count = stats.get('malicious', 0)
                    total_engines = sum(stats.values())
                    
                    return {
                        'is_malicious': malicious_count > 0,
                        'positives': malicious_count,
                        'total': total_engines,
                        'details': stats
                    }
                else:
                    logging.warning("Unexpected VirusTotal response structure")
                    return {
                        'is_malicious': False,
                        'error': 'Unexpected response structure'
                    }
            
            except Exception as parse_err:
                logging.error(f"Error parsing VirusTotal response: {parse_err}")
                return {
                    'is_malicious': False,
                    'error': f'Response parsing error: {parse_err}'
                }

        except Exception as e:
            logging.error(f"Comprehensive scanning error: {e}")
            return {
                'is_malicious': False,
                'error': f'Unexpected error: {e}'
            }

    def upload_file_for_scanning(self, filepath):
        """
        Upload file to VirusTotal for scanning
        """
        try:
            with open(filepath, 'rb') as file:
                files = {'file': file}
                
                # Debug the upload request
                response = self.debug_request(
                    'POST', 
                    "https://www.virustotal.com/api/v3/files", 
                    headers=self.headers, 
                    files=files
                )
                
                if not response:
                    return {
                        'is_malicious': False,
                        'error': 'File upload failed'
                    }

                # Parse upload result
                try:
                    upload_result = response.json()
                    return {
                        'is_malicious': False,
                        'analysis_id': upload_result.get('data', {}).get('id'),
                        'message': 'File uploaded for scanning'
                    }
                except json.JSONDecodeError:
                    logging.error("Failed to decode upload response")
                    return {
                        'is_malicious': False,
                        'error': 'Invalid upload response'
                    }
        
        except Exception as e:
            logging.error(f"File upload comprehensive error: {e}")
            return {
                'is_malicious': False,
                'error': f'Upload error: {e}'
            }
        
def scan_virustotal(self, file_hash):
        url = self.virustotal_api_endpoint.format(file_hash)
        headers = {
            "accept": "application/json",
            "x-apikey": self.api_key,
            "content-type": "multipart/form-data"
        }
        response = requests.get(url, headers=headers)
        return response.json()

if "win" in os_name:
    if not os.path.exists("AntiVirus\\Quarantine\\"):
        os.makedirs("AntiVirus\\Quarantine\\")
    if not os.path.exists("AntiVirus\\sf\\"):
        os.makedirs("AntiVirus\\sf\\")
    if not os.path.exists("AntiVirus\\wl\\"):
        os.makedirs("AntiVirus\\wl\\")
    if not os.path.exists("AntiVirus\\Large_Update_File\\"):
        os.makedirs("AntiVirus\\Large_Update_File")
    quarantine_folder = "AntiVirus\\Quarantine\\*"
    file_to_quarantine = "AntiVirus\\Quarantine\\"
    partitionen_folder = "AntiVirus\\sf\\sf.txt"
    whitelist_path = "Antivirus\\wl\\wl.txt"
    detected_drives = SystemFileScanner.add_drives_to_whitelist(whitelist_path)
    links_current = "AntiVirus\\Large_Update_File\\links_current.txt"
    links_downloaded = "AntiVirus\\Large_Update_File\\links_downloaded.txt"
    large_signatures = "AntiVirus\\Large_Update_File\\signatures.txt"
    f = open(partitionen_folder, "a")
    f.close()
    f = open(links_current, "a")
    f.close()
    f = open(links_downloaded, "a")
    f.close()
    f = open(large_signatures, "a")
    f.close()
else:
    if not os.path.exists("AntiVirus//Quarantine//"):
        os.makedirs("AntiVirus//Quarantine//")
    if not os.path.exists("AntiVirus//sf//"):
        os.makedirs("AntiVirus//sf//")
    if not os.path.exists("AntiVirus//wl//"):
        os.makedirs("AntiVirus//wl//")
    if not os.path.exists("AntiVirus//Large_Update_File//"):
        os.makedirs("AntiVirus//Large_Update_File//")
    quarantine_folder = "AntiVirus//Quarantine//*"
    file_to_quarantine = "AntiVirus//Quarantine//"
    partitionen_folder = "AntiVirus//sf//sf.txt"
    links_current = "AntiVirus//Large_Update_File//links_current.txt"
    links_downloaded = "AntiVirus//Large_Update_File//links_downloaded.txt"
    large_signatures = "AntiVirus//arge_Update_File//signatures.txt"
    f = open(partitionen_folder, "a")
    f.close()
    f = open(links_current, "a")
    f.close()
    f = open(links_downloaded, "a")
    f.close()
    f = open(large_signatures, "a")
    f.close()

print("Detected drives:", detected_drives)
    
files_len = counter = 0
main = None
update_button = None
scan_button = None
fullscan_button = None
quit_button = None
b_delete = None
b_delete_all = None
b_restore = None
b_restore_all = None
b_add_file = None
text_box = None
e = None
li = None
rb1 = None
rb2 = None
method = None
bgc = None
fgc = None
special = None
special_text = None
t_time = None

daytime = int(time.strftime("%H", time.localtime()))

#Adjusting the brightness for the current day_time
#It's totally unnecessary but I wanted to play around a little
if daytime >= 18 or daytime <= 4:
    bgc = "black"
    fgc = "white"
    special = "brown"
    special_text = "（°_°）☽ ☆ Good evening " + os.getlogin() + " ☆ ☾（°_°）\n"
elif daytime > 4 and daytime <= 8:
    special_text = "＼(o￣∇￣o)/ Good morning " + os.getlogin() + " ＼(o￣∇￣o)/\n"
    bgc = "#b4d60c"
    fgc = "black"
    special = "orange"
else:
    bgc = "white"
    fgc = "black"
    special = "#1ccaed"
    special_text = "\(≧∇≦)/ Welcome " + os.getlogin() + " \(≧∇≦)/\n"
    
def clock_thread():
    global e
    
    months = ["January", "February", "March", "April", "May", "June", "Juli", "August", "September", "October", "November", "December"]
    while True:
        string_time = "%H:%M:%S o'clock, on %d.{0}.%Y"
        month_name = time.strftime("%B", time.localtime())
        for i in range(len(months)):
            if months[i] == month_name:
                month_name = str(i+1)
                if int(month_name) < 10:
                    month_name = "0" + month_name
                break
        string_time = string_time.format(month_name)
        current_time = time.strftime(string_time, time.localtime())
        e.delete(0, len(e.get()))
        e.update()
        e.insert(0, current_time)
        e.update()
        time.sleep(1)
        
def scan_system_files(scan_depth=3):
    """
    Comprehensive system file scanning method
    
    :param scan_depth: Depth of directory traversal
    """
    # Global logging setup
    logging.info("Starting comprehensive system file scanning")
    
    # Track scan statistics
    total_files_found = 0
    scanned_directories = []
    
    try:
        # Detect system drives
        drives = get_system_drives()
        
        logging.info(f"Detected drives for scanning: {drives}")
        
        # Scan each drive
        for drive in drives:
            logging.info(f"Scanning drive: {drive}")
            
            # Recursive file discovery
            files_in_drive = recursive_file_discovery(drive, max_depth=scan_depth)
            
            total_files_found += len(files_in_drive)
            scanned_directories.append(drive)
            
            # Optional: Log files found in each drive
            logging.info(f"Found {len(files_in_drive)} files in {drive}")
    
    except Exception as e:
        logging.error(f"System file scanning error: {e}")
    
    # Final scan report
    logging.info(f"Scan Complete")
    logging.info(f"Total Files Found: {total_files_found}")
    logging.info(f"Directories Scanned: {scanned_directories}")
    
    return total_files_found

def get_system_drives():
    """
    Detect all available system drives
    """
    drives = []
    
    # Windows drive detection
    if os.name == 'nt':
        import string
        for letter in string.ascii_uppercase:
            drive_path = f"{letter}:\\"
            if os.path.exists(drive_path):
                drives.append(drive_path)
    
    # Unix/Linux drive detection
    else:
        drives = ['/']  # Root directory
        # Optional: Add mount points
        try:
            with open('/proc/mounts', 'r') as mounts:
                for line in mounts:
                    if line.startswith('/dev/'):
                        mount_point = line.split()[1]
                        drives.append(mount_point)
        except:
            pass
    
    return drives

def recursive_file_discovery(root_path, max_depth=3, current_depth=0):
    """
    Recursively discover files with depth limitation
    
    :param root_path: Starting directory
    :param max_depth: Maximum recursion depth
    :param current_depth: Current recursion level
    :return: List of file paths
    """
    discovered_files = []
    
    # Prevent excessive recursion
    if current_depth > max_depth:
        return discovered_files
    
    try:
        # List all entries in the directory
        for entry in os.scandir(root_path):
            try:
                # File handling
                if entry.is_file():
                    discovered_files.append(entry.path)
                
                # Directory recursion
                elif entry.is_dir() and not entry.is_symlink():
                    # Skip system and hidden directories
                    if not entry.name.startswith('.') and 'Windows' not in entry.path:
                        sub_files = recursive_file_discovery(
                            entry.path, 
                            max_depth, 
                            current_depth + 1
                        )
                        discovered_files.extend(sub_files)
            
            except PermissionError:
                # Log permission issues without stopping
                logging.warning(f"Permission denied: {entry.path}")
            except Exception as e:
                logging.error(f"Error scanning {entry.path}: {e}")
    
    except Exception as e:
        logging.error(f"Directory scan error for {root_path}: {e}")
    
    return discovered_files

# Example Usage
def start_system_scan():
    """
    Main system scanning entry point
    """
    try:
        # Start timing
        start_time = time.time()
        
        # Perform system scan
        total_files = scan_system_files(scan_depth=3)
        
        # Calculate scan duration
        scan_duration = time.time() - start_time
        
        logging.info(f"System Scan Completed")
        logging.info(f"Total Files Processed: {total_files}")
        logging.info(f"Scan Duration: {scan_duration:.2f} seconds")
    
    except Exception as e:
        logging.error(f"System scan initialization error: {e}")

# Integrate with your existing code
def ScanSystemFiles():
    global files
    global text_box
    global files_len
    
    # Clear previous files
    files.clear()
    
    # Start system scan
    total_files = start_system_scan()
    
    # Update UI
    text_box.insert(END, f"[ + ] System scan complete. Found {total_files} files\n")
    text_box.see(END)
    text_box.update()
    
def full_scan(part):
    logging.info("Starting full scan...")
    logging.info("Full scan completed.")
    
    global verzeichnisse
    global files
    global text_box
    global e
    global full_scan
    global files_len
    global lock
    global t_time
    global counter
    
    start = time.time()
    
    if part == 1:#Thread-1
        i = int(len(files)*0.125)
        tmp = 0
    if part == 2:#Thread-2
        i = int(len(files)*0.25)
        tmp = int(len(files)*0.125)
    if part == 3:#Thread-3
        i = int(len(files)*0.375)
        tmp = int(len(files)*0.25)
    if part == 4:#Thread-4
        i = int(len(files)*0.5)
        tmp = int(len(files)*0.375)
    if part == 5:#Thread-5
        i = int(len(files)*0.625)
        tmp = int(len(files)*0.5)
    if part == 6:#Thread-6
        i = int(len(files)*0.75)
        tmp = int(len(files)*0.625)
    if part == 7:#Thread-7
        i = int(len(files)*0.875)
        tmp = int(len(files)*0.75)
    if part == 8:#Thread-8
        i = int(len(files))
        tmp = int(len(files)*0.875)
        
    if len(files) == 0:
        return ScanSystemFiles()
    
    text_box.tag_config('positive', foreground="green")
    text_box.see(END)
    text_box.update()
    counter = 0
    st = 0
    while i >= tmp:
        try:
            f = open(files[i], "rb")
            file_content = f.read()
            f.close()
        except:
            continue        
        ret = scan_auto(files[i])
        if ret == True:
            text_box.insert(END, "[ ! ] Program: " + files[i] + " might be dangerous\n", "important")
            text_box.tag_config("important", foreground="red")
            text_box.see(END)
            text_box.update()
            quarantaene.encode_base64(files[i])       
        files_len -= 1
        i -= 1
    runtime = int(time.time() - start)
    text_box.insert(END, "[ + ] Scan ended after\n " + str(runtime/60) + " minutes.\n", "positive")
    text_box.tag_config("positive", foreground="green")
    if files_len == 0:
        full_scan["state"] = "normal"
    if len(terminations) == 0:
        text_box.insert(END, "[ +++ ] Your PC is safe" + "\n", 'important')
    else:
        text_box.insert(END, "[ !!! ] Found {0} Threats on your PC\n".format(len(terminations)))
    text_box.tag_config("important", background="red")
    text_box.see(END)
    text_box.update()

def quarantine():
    global text_box
    global terminations
    global li
    global b_delete
    global b_delete_all
    global b_restore
    global b_restore_all
    global b_add_file
        

    k = 0
    while True:
        tmp = len(li.get(k))
        if tmp == 0:
            break
        else:
            li.delete(0, tmp)
            k += 1
    li.update()
        
        
    terminations = glob.glob(quarantine_folder)
    if terminations == []:
        text_box.insert(END, "[ + ] No files in quarantine\n", "positive")
        text_box.tag_config('positive', foreground="green")
        text_box.see(END)
        text_box.update()
    else:
        text_box.insert(END, "[ + ] Files in quarantine:\n", "positive")
        text_box.tag_config('positive', foreground="green")
        text_box.see(END)
        text_box.update()
        for i in terminations:
            text_box.insert(END, "[ * ] " + i + "\n", "info")
            text_box.tag_config("info", background = "red")
            text_box.see(END)
            text_box.update()
            li.insert(END, i)
            li.update()
        
    b_delete_all["command"] =lambda:button_action_handler("delete_all")
    b_delete["command"] = lambda:button_action_handler("delete")
    b_restore["command"] = lambda:button_action_handler("restore")
    b_restore_all["command"] = lambda:button_action_handler("restore_all")
    b_add_file["command"] = lambda:button_action_handler("add_file")
    

def delete(file, ALL):#ALL = 1 => deletes all objects in quarantine
    global li
    global text_box
    global terminations

    if len(terminations) != 0:
        if ALL == 1:
            for i in range(len(terminations)):
                os.remove(terminations[i])
                text_box.insert(END, "[ + ] Deletion successful: \n" + terminations[i] + "\n", "positive")
                text_box.tag_config("positive", foreground="green")
                text_box.see(END)
                text_box.update()
                li.delete(0, len(terminations[i]))
                li.update()
        elif ALL == 0:
            os.remove(file)
            li.delete(ACTIVE, len(file))
            li.update()
            text_box.insert(END, "[ + ] Deletion successful:\n" + file + "\n", "positive")
            text_box.tag_config("positive", foreground="green")
            text_box.see(END)
            text_box.update()
            
        terminations = glob.glob(quarantine_folder)
        for i in terminations:
            li.insert(END, i)
        li.update()
    else:
        text_box.insert(END, "[ - ] Unable to locate any files\n", "negative")
        text_box.tag_config("negative", foreground="red")
        text_box.see(END)
        text_box.update()
        
def restore(file, ALL):
    global li
    global text_box
    global terminations

    if len(terminations) != 0:
        if ALL == 1:
            for i in range(len(terminations)):
                quarantaene.decode_base64(terminations[i])
                text_box.insert(END, "[ + ] Successfully restored\n" + terminations[i] + "\n", 'positive')
                text_box.tag_config('positive', foreground="green")
                text_box.see(END)
                text_box.update()
                li.delete(0, len(terminations[i]))
                li.update()
        elif ALL == 0:
            quarantaene.decode_base64(file)
            li.delete(ACTIVE, len(file))
            text_box.insert(END, "[ + ] Successfully restored\n" + file + "\n", "positive")
            text_box.tag_config("positive", foreground="green")
            text_box.see(END)
            text_box.update()
            
        terminations = glob.glob(quarantine_folder)
        for i in terminations:
            li.insert(END, i)
        li.update()
        
    else:
        text_box.insert(END, "[ - ] Unable to locate any files\n", "negative")
        text_box.tag_config("negative", foreground="red")
        text_box.see(END)
        text_box.update()
    

def add_file_to_quarantine():
    global li
    global terminations
    
    file = askopenfilename()
    file = file.replace("/", "\\")
    quarantaene.encode_base64(file, file_to_quarantine)
    text_box.insert(END, "[ + ] Moved to quarantine:\n" + file + "\n", "positive")
    text_box.tag_config("positive", foreground="green")
    text_box.see(END)
    text_box.update()
    li.update()

    k = 0
    while True:
        tmp = len(li.get(k))
        if tmp == 0:
            break
        else:
            li.delete(0, tmp)
            k += 1
    li.update()

    terminations = glob.glob(quarantine_folder)
    for i in terminations:
        li.insert(END, i)
        li.update()

def scan_auto(file):
    time.sleep(3)
    try:
        f = open(file, "rb")
        content = f.read()
        f.close()
        content = create_md5(content)
    except MemoryError:
        f.close()
        return False
    except:
        f.close()
        return False
    
    signatures = open(large_signatures, "rb")
    try:
        if content in signatures.read():#fastest solution
            signatures.close()
            return True
        else:
            signatures.close()
            return False
    except MemoryError:
        try:
            signatures.close()
            signatures = open(large_signatures, "rb")
            if content in signatures.readlines():#again fast, but around 4 times slower than the fastest
                signatures.close()
                return True
            else:
                signatures.close()
                return False
        except MemoryError:
            signatures.close()
            signatures = open(large_signatures, "rb")
            while True:#slowest solution, but can read files sized over 2 GB
                tmp = signatures.readline()
                if tmp == b"":
                    signatures.close()
                    break
                
                if tmp == content:
                    signatures.close()
                    return True
            return False
    except:
        return False
    
def scan():
    global text_box  

    match = False
    file = askopenfilename()
    start = time.time()
    text_box.insert(END, "[ * ] Scanning " + file + "\n")
    text_box.see(END)
    text_box.update()
    try:
        f = open(file, "rb")
        content = f.read()
        f.close()
        content = create_md5(content)
        text_box.insert(END, "MD5-Hash: " + content.decode("utf-8") + "\n")
        text_box.see(END)
        text_box.update()
    except MemoryError:
        text_box.insert(END, "[ - ] Unable to create MD5-Hash:\n----->MemoryError!\n", 'negative')
        text_box.insert(END, "[ ! ] Only select files under 1 GB\n", "negative")
        text_box.tag_config('negative', foreground="red")
        text_box.see(END)
        text_box.update()
        return None
    except Exception as e:
        text_box.insert(END, "[ ! ] Unable to handle problem\n[ ! ] Try again/file might be corrupted\n", "negative")
        text_box.tag_config('negative', foreground="red")
        text_box.see(END)
        text_box.update()
        return None

    signatures = open(large_signatures, "rb")
    try:
        if content in signatures.read():  # fastest solution
            signatures.close()
            match = True
        else:
            signatures.close()
    except MemoryError:
        try:
            signatures.close()
            signatures = open(large_signatures, "rb")
            if content in signatures.readlines():  # again fast, but around 4 times slower than the fastest
                signatures.close()
                match = True
            else:
                signatures.close()
        except MemoryError:
            signatures.close()
            signatures = open(large_signatures, "rb")
            while True:  # slowest solution, but can read files sized over 2 GB
                tmp = signatures.readline()
                if tmp == b"":
                    signatures.close()
                    break

                if tmp == content:
                    signatures.close()
                    match = True

    # NEW: VirusTotal Scanning
    try:
        # Create VirusTotal Scanner instance
        vt_scanner = VirusTotalScanner(api_key="maltek")
        
        # Scan the file using VirusTotal
        vt_result = vt_scanner.scan_file(file)
        
        # Combine local and VirusTotal scan results
        if match or (vt_result and vt_result.get('is_malicious', False)):
            text_box.insert(END, "[ ! ] Potential threat detected!\n", "important")
            text_box.tag_config("important", foreground="red")
            
            # Add VirusTotal details if available
            if vt_result and vt_result.get('is_malicious'):
                text_box.insert(END, f"[ ! ] VirusTotal: {vt_result.get('positives', 0)} out of {vt_result.get('total', 0)} scanners detected issues\n")
            
            # Quarantine the file
            quarantaene.encode_base64(file, file_to_quarantine)
            text_box.insert(END, f"[ ! ] Threat found: {file} moved to quarantine\n", "important")
        else:
            text_box.insert(END, "[ + ] No threat was found\n", "positive")
            text_box.tag_config("positive", foreground="green")
    
    except Exception as e:
        text_box.insert(END, f"[ ! ] VirusTotal scanning error: {str(e)}\n", "negative")
        text_box.tag_config("negative", foreground="red")

    text_box.see(END)
    text_box.update()

    # Runtime calculation
    text_box.insert(END, "[ * ] Scan duration: {0}\n".format(round(time.time()-start, 2)))
    text_box.see(END)
    text_box.update()
    if match:
        quarantaene.encode_base64(file, file_to_quarantine)
        text_box.insert(END, "[ ! ] Threat found: {0}\n[ ! ] File was moved into quarantine", "important")
        text_box.tag_config("important", foreground="red")
        text_box.see(END)
        text_box.update()
    if not match:
        text_box.insert(END, "[ + ] No threat was found\n", "positive")
        text_box.tag_config("positive", foreground="green")
        text_box.see(END)
        text_box.update()
        
def create_md5(content):
    md = hashlib.md5()
    md.update(content)
    return bytes(md.hexdigest(), "utf-8")

def link_collector(): #gets Links to refresh update-site;short spider
    global text_box
    u_list = []

    text_box.insert(END, "[ * ] Searching for update...\n")
    text_box.see(END)
    text_box.update()
    u = urllib.request.urlopen("http://virusshare.com/hashes").read().decode("utf-8").splitlines()
    f = open(links_current, "w")
    for i in u:
        if "href='" in i:
            first = i.find("href='") + len("href='")
            i = i[first:]
            last = i.find("'")
            i = i[:last]
        if 'href="' in i:
            first = i.find('href="') + len('href="')
            i = i[first:]
            last = i.find('"')
            i = i[:last]
        if "VirusShare" in i:
            f.write("http://virusshare.com/hashes/" + i + "\n")
    f.close()
    return update()
    
def update():
    global text_box

    zaehler = 0
    f = open(links_current, "r")
    f2 = open(links_downloaded, "r")
    files_downloaded = f2.read()
    f2.close()
    f2 = open(links_downloaded, "r")
    for i in f.read().splitlines():
        f2 = open(links_downloaded, "r")
        con = f2.read()
        f2.close()
        f2 = open(links_downloaded, "a")
        if i not in con:
            zaehler += 1
            f2.write(i + "\n")
            f2.close()
            text_box.insert(END, "[ * ] Download of:\n"+i)
            text_box.see(END)
            text_box.update()
            signatures = open(large_signatures, "a")
            url = i
            tmp = urllib.request.urlopen(url).read().decode("utf-8").splitlines()
            for j in tmp:
                if j[0] != '#':
                    signatures.write(j + "\n")
            signatures.close()
    if zaehler == 0:
        text_box.insert(END, "[ * ] No new updates were found\n")
        text_box.see(END)
        text_box.update()
    else:
        text_box.insert(END, "[ + ] {0} new updates were made\n".formate(zaehler), "positive")
        text_box.tag_config("positive", foreground="green")
        text_box.see(END)
        text_box.update()
    
def closing():
    main.destroy()
    sys.exit()

def button_action_handler(s):
    global files_len
    global text_box
    global t_time
    global fullscan_button
    global b_delete
    global b_delete_all
    global b_restore
    global b_restore_all
    global b_add_file
    global li
    global rb1
    global rb2
    global method

    if s == "rb1":
        method = 1
        rb1.place_forget()
        rb2.place_forget()
    if s == "rb2":
        method = 2
        rb2.place_forget()
        rb1.place_forget()
        
    if s == "delete":
        tb = Thread(target=delete, args=(li.get(ACTIVE),0))
        tb.start()
    if s == "delete_all":
        tb = Thread(target=delete, args=(0,1))
        tb.start()
    if s == "restore":
        tb = Thread(target=restore, args=(li.get(ACTIVE),0))
        tb.start()
    if s == "restore_all":
        tb = Thread(target=restore, args=(0,1))
        tb.start()
        
    if s == "add_file":
        tb = Thread(target=add_file_to_quarantine)
        tb.start()
        
    if s == "update_button":
        tb = Thread(target=link_collector)
        tb.start()

    if s == "scan_button":
        tb = Thread(target=scan)
        tb.start()

    if s == "fullscan_button":
        if files_len == 0:
            text_box.insert(END, "[ ! ] Preparing program\n", "important")
            text_box.see(END)
            text_box.update()
        elif files_len < len(files):
            text_box.insert(END, "[ ! ] One scan is already in action\n", "important")
            text_box.see(END)
            text_box.update()
        else:
            fullscan_button["state"] = "disabled"
            t_time = time.time()
            text_box.insert(END, "[ ! ] Got {0} files to scan\n".format(files_len), 'important')
            text_box.tag_config("important", foreground="red")
            text_box.update()
            text_box.insert(END, "[ * ] Scan might last for hours...\n")
            text_box.see(END)
            text_box.update()
            tb1 = Thread(target=full_scan, args=(1,))
            tb1.start()
            time.sleep(1)
            tb2 = Thread(target=full_scan, args=(2,))
            tb2.start()
            time.sleep(1)
            tb3 = Thread(target=full_scan, args=(3,))
            tb3.start()
            time.sleep(1)
            tb4 = Thread(target=full_scan, args=(4,))
            tb4.start()
            time.sleep(1)
            tb5 = Thread(target=full_scan, args=(5,))
            tb5.start()
            time.sleep(1)
            tb6 = Thread(target=full_scan, args=(6,))
            tb6.start()
            time.sleep(1)
            tb7 = Thread(target=full_scan, args=(7,))
            tb7.start()
            time.sleep(1)
            tb8 = Thread(target=full_scan, args=(8,))
            tb8.start()

    if s == "quarantine_button":
        if li.winfo_viewable()  == 0:
            b_delete.place(x = 570, y = 70)
            b_delete_all.place(x = 570, y = 95)
            b_restore.place(x = 570, y = 120)
            b_restore_all.place(x = 570, y = 145)
            b_add_file.place(x = 570, y = 170)
            li.place(x = 570, y = 18.5)
            tb = Thread(target=quarantine)
            tb.start()
        if li.winfo_viewable() == 1:
            b_delete.place_forget()
            b_delete_all.place_forget()
            b_restore.place_forget()
            b_restore_all.place_forget()
            b_add_file.place_forget()
            li.place_forget()

    if s == "quit_button":
        tb = Thread(target=closing)
        tb.start()
        
def gui_thread():
    global main
    global scan_button
    global fullscan_button
    global quit_button
    global text_box
    global e
    global files_len
    global files
    global li
    global b_delete
    global b_delete_all
    global b_restore
    global b_restore_all
    global b_add_file
    global rb1
    global rb2
    global method
    global bgc
    global fgc
    global special_text
                        
    main = tkinter.Tk()
    main.title("AntiVirus")
    main.wm_iconbitmap("")
    main.configure(bg=bgc)
    main.geometry("750x205")#width x height
    main.resizable(False, False)
    #main.overrideredirect(1)
    hoehe = 2
    breite = 20

    
    #Buttons
    scan_button = tkinter.Button(main, bg=bgc, fg=fgc, text="Scan", 
                                 command=lambda: button_action_handler("scan_button"), 
                                 height=hoehe, width=breite)
    scan_button.grid(row=0, column=0)

    fullscan_button = tkinter.Button(main, bg=bgc, fg=fgc, text="Full scan", 
                                     command=lambda: button_action_handler("fullscan_button"), 
                                     height=hoehe, width=breite)
    fullscan_button.grid(row=1, column=0)

    quarantine_button = tkinter.Button(main, bg=bgc, fg=fgc, text="Quarantine", 
                                       command=lambda: button_action_handler("quarantine_button"), 
                                       height=hoehe, width=breite)
    quarantine_button.grid(row=2, column=0)

    quit_button = tkinter.Button(main, bg=bgc, fg=fgc, text="Close", 
                                 command=lambda: button_action_handler("quit_button"), 
                                 height=hoehe, width=breite)
    quit_button.grid(row=3, column=0, sticky="w")
    b_delete = tkinter.Button(main, bg=bgc, fg=fgc, text = "Remove current", height=0, width = 25, justify=CENTER)
    b_delete_all = tkinter.Button(main, bg=bgc, fg=fgc, text = "Remove all", height = 0, width = 25, justify=CENTER)
    b_restore = tkinter.Button(main, bg=bgc, fg=fgc, text = "Restore current", height=0, width = 25, justify=CENTER)
    b_restore_all = tkinter.Button(main, bg=bgc, fg=fgc, text = "Restore all", height = 0, width = 25, justify=CENTER)
    b_add_file = tkinter.Button(main, bg=bgc, fg=fgc, text = "Add file", height = 0, width = 25, justify=CENTER)
    b_delete.place(x = 570, y = 70)
    b_delete_all.place(x = 570, y = 95)
    b_restore.place(x = 570, y = 120)
    b_restore_all.place(x = 570, y = 145)
    b_add_file.place(x = 570, y = 170)
    b_delete.place_forget()
    b_delete_all.place_forget()
    b_restore.place_forget()
    b_restore_all.place_forget()
    b_add_file.place_forget()
    
    #Text
    text_box = tkinter.scrolledtext.ScrolledText(main)
    text_box.configure(bg=bgc)
    text_box.configure(fg=fgc)
    text_box.place(height = 205, width = 419,x = 150, y = 0)

    #Listbox
    li = tkinter.Listbox(main, height=3, width = 29)
    li.place(x = 570, y = 18.5)
    li.place_forget()
    
    #Entries
    e = tkinter.Entry(main,width = 30)
    e.place(x = 570, y = 0)
    e["justify"] = CENTER
    e.insert(0, "")
    e["bg"] = bgc
    e["fg"] = fgc
    
    #Intro
    text_box.insert(END, special_text, "VIP")
    text_box.tag_config("VIP", background=special)
    text_box.insert(END, "[ + ] Preparing the program\n", 'positive')
    text_box.tag_config('positive', foreground='green')
    text_box.see(END)
    text_box.update()
    text_box.insert(END, "[ ! ] You might have to wait for a bit\n", 'important')
    text_box.tag_config('important', foreground="red")
    text_box.see(END)
    text_box.update()
    #row_counter += 3
    main.mainloop()

#Executing Threads
t_main = Thread(target=gui_thread)# Main Thread
t_files = Thread(target=ScanSystemFiles)
t_clock = Thread(target=clock_thread)
t_main.start()
time.sleep(1)
t_clock.start()
time.sleep(5)
#print(t_main.isAlive())
t_files.start()
