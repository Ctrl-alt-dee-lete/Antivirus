import tkinter as tk
from tkinter import filedialog, messagebox
import os
from scanner import MalwareScanner  # Import the MalwareScanner class

class MalwareScannerGUI:
    def __init__(self, master):
        self.master = master
        master.title("Malware Scanner")
        master.geometry("500x400")

        # Create scanner instance
        self.scanner = MalwareScanner()

        # File path variable
        self.file_path = tk.StringVar()

        # Create GUI widgets
        self.create_widgets()

    def create_widgets(self):
        # Choose File Button
        choose_file_btn = tk.Button(
            self.master, 
            text="Choose File", 
            command=self.choose_file
        )
        choose_file_btn.pack(pady=20)

        # File Path Display
        file_path_label = tk.Label(
            self.master, 
            textvariable=self.file_path, 
            wraplength=400
        )
        file_path_label.pack(pady=10)

        # Scan Button
        scan_btn = tk.Button(
            self.master, 
            text="Scan File", 
            command=self.scan_file
        )
        scan_btn.pack(pady=10)

        # Result Label
        self.result_label = tk.Label(
            self.master, 
            text="", 
            font=("Arial", 12)
        )
        self.result_label.pack(pady=10)

    def choose_file(self):
        # Open file dialog to choose a file
        file_selected = filedialog.askopenfilename()
        if file_selected:
            self.file_path.set(file_selected)
            # Reset previous scan results
            self.result_label.config(text="")

    def scan_file(self):
        # Check if a file is selected
        if not self.file_path.get():
            messagebox.showwarning("Warning", "Please select a file first")
            return

        # Calculate file hash
        file_hash = self.scanner.hash_file(self.file_path.get())

        # Check if file is malicious using VirusTotal
        virustotal_result = self.scanner.scan_virustotal(file_hash)

        # Check the result from VirusTotal
        if self.scanner.is_malicious(virustotal_result):
            # Malware detected
            result = messagebox.askyesno(
                "Malware Detected", 
                "Malware detected in the file. Do you want to delete this file?"
            )
            
            if result:  # User chose to delete the file
                try:
                    # Delete the file
                    os.remove(self.file_path.get())
                    messagebox.showinfo("Success", "File deleted successfully")
                    
                    # Reset UI
                    self.file_path.set("")
                    self.result_label.config(text="")
                except Exception as e:
                    messagebox.showerror("Error", f"Could not delete file: {str(e)}")
            
            self.result_label.config(text="Malware Detected!", fg="red")
        else:
            # Clean file
            self.result_label.config(text="File is Safe", fg="green")

def main():
    root = tk.Tk()
    gui = MalwareScannerGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()