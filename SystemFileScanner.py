import glob
import time
import sys
import os
import string

os_name = sys.platform
partitionen = []
verzeichnisse = []
files = []

def get_drives():
    """Detect all available drives on the system"""
    drives = []
    if sys.platform.startswith('win'):
        # Get all possible drive letters
        for letter in string.ascii_uppercase:
            drive_path = f"{letter}:\\"
            if os.path.exists(drive_path):
                drives.append(drive_path)
    else:
        drives = ['/']
    return drives

def add_drives_to_whitelist(whitelist_path):
    drives = get_drives()
    
    existing_entries = set()
    if os.path.exists(whitelist_path):
        with open(whitelist_path, 'r') as f:
            existing_entries = set(f.read().splitlines())
    
    # Add new drives to whitelist
    with open(whitelist_path, 'w') as f:
        # First, write existing entries
        for entry in existing_entries:
            f.write(f"{entry}\n")
        
        # Then add new drives
        for drive in drives:
            if drive not in existing_entries:
                f.write(f"{drive}\n")
    
    return drives

def partitions(sfsFolder):
    global partitionen
    big = 65

    if "win" in os_name:
        for i in range(26):
            try:
                if glob.glob(str(chr(big + i)) + ":\\"):
                    #print("Successfully found partition: " + str(chr(big + i)))
                    partitionen.append(str(chr(big + i)) + ":\\")
            except:
                continue
        return indeces(sfsFolder)
    if "win" not in os_name:
        return indeces(sfsFolder)
    if "win" in sys.platform:
        partitionen = get_drives()
        return indeces(sfsFolder)
    if "win" not in sys.platform:
        return indeces(sfsFolder)
    
def indeces(sfsFolder):
    global verzeichnisse
    global files
    
    if "win" in os_name:
        verzeichnisse2 = glob.glob("\\*")
    else:
        verzeichnisse2 = glob.glob("//*")
    verzeichnisse_tmp = []
    x = 1

    if "win" in os_name:
        for ind in range(len(partitionen)):
            #print(partitionen[ind])
            while verzeichnisse2 != []:
                verzeichnisse2 = glob.glob(partitionen[ind] + "\\*"*x)
                for i in range(len(verzeichnisse2)):
                    verzeichnisse.append(verzeichnisse2[i])
                x += 1
            x = 1

        for i in range(len(verzeichnisse)):
            if "." in verzeichnisse[i]:
                files.append(verzeichnisse[i])
        for i in range(len(verzeichnisse)):
            if not os.path.isfile(verzeichnisse[i]):
                verzeichnisse_tmp.append(verzeichnisse[i])
        verzeichnisse = verzeichnisse_tmp
        i = 0
        f = open(sfsFolder, "w")
        for i in range(len(files)):
            f.write(files[i] + "\n")
        f.close()
        time.sleep(3)

    if "win" not in os_name:
        while verzeichnisse2 != []:
            verzeichnisse = glob.glob("//*" * x)
            for i in range(len(verzeichnisse2)):
                verzeichnisse.append(verzeichnisse2[i])
            x += 1
        x = 1

        for i in range(len(verzeichnisse)):
            if "." in verzeichnisse[i]:
                files.append(verzeichnisse[i])
        for i in range(len(verzeichnisse)):
            if not os.path.isfile(verzeichnisse[i]):
                verzeichnisse_tmp.append(verzeichnisse[i])
        verzeichnisse = verzeichnisse_tmp
        i = 0
        f = open(sfsFolder, "w")
        for i in range(len(files)):
            f.write(files[i] + "\n")
        f.close()
        time.sleep(3)
