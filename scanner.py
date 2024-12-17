import os
import hashlib
import requests

class MalwareScanner:
    def __init__(self):
        # Set API Key directly
        self.api_key = "a53dbe85ffba78b77e64c88c2f9d00f75b1756fd9a22cbb0b54941531262ceb0"
        self.virustotal_api_endpoint = "https://www.virustotal.com/api/v3/files/{}"

    def hash_file(self, file_path):
        """Generate MD5 hash of the file."""
        hasher = hashlib.md5()
        with open(file_path, 'rb') as f:
            buffer_size = 8192
            for buffer in iter(lambda: f.read(buffer_size), b''):
                hasher.update(buffer)
        return hasher.hexdigest()

    def scan_directory(self, directory_path):
        """Scan and get hashes of all files in the directory."""
        file_hashes = {}
        for root, dirs, files in os.walk(directory_path):
            for file_name in files:
                file_path = os.path.join(root, file_name)
                file_hash = self.hash_file(file_path)
                file_hashes[file_path] = file_hash
        return file_hashes

    def scan_virustotal(self, file_hash):
        """Send hash to VirusTotal for scanning."""
        url = self.virustotal_api_endpoint.format(file_hash)
        headers = {
            "accept": "application/json",
            "x-apikey": self.api_key
        }
        response = requests.get(url, headers=headers)
        return response.json()

    def is_malicious(self, virustotal_result):
        """Check if the file is malicious based on VirusTotal results."""
        if "data" in virustotal_result:
            malicious_count = virustotal_result["data"]["attributes"]["last_analysis_stats"]["malicious"]
            return malicious_count > 0
        return False

    def delete_file(self, file_path):
        """Delete the file."""
        try:
            os.remove(file_path)
            print(f"File deleted: {file_path}")
        except Exception as e:
            print(f"Error deleting file {file_path}: {e}")

    def perform_scan(self, directory_path):
        """Perform a full scan and delete files detected as malware."""
        # Scan directory and get file hashes
        hashes = self.scan_directory(directory_path)

        # Display scan results and VirusTotal analysis
        for file_path, file_hash in hashes.items():
            print(f"File: {file_path}\nHash: {file_hash}")

            # Check hash using VirusTotal
            virustotal_result = self.scan_virustotal(file_hash)

            # Display VirusTotal scan results
            if self.is_malicious(virustotal_result):
                print("Malware Detected")

        # After scanning the entire directory
        user_input = input("Do you want to delete detected malware files? (yes/no): ").lower()
        if user_input == "yes":
            self.delete_detected_malware_files(hashes)

        print("Scanning process completed.")

    def delete_detected_malware_files(self, hashes):
        """Delete only files detected as malware."""
        for file_path, file_hash in hashes.items():
            virustotal_result = self.scan_virustotal(file_hash)
            if self.is_malicious(virustotal_result):
                self.delete_file(file_path)