import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from PIL import Image, ImageTk
import os
import time
from scanner import MalwareScanner  #untuk memanggil logic/file scanner.py

class MalwareScannerGUI:
    def __init__(self, master):
        self.master = master
        master.title("Maltek Antivirus")
        master.geometry("900x400")
        master.configure(bg="#ffffff")  
        master.resizable(False, False)  

        # Create scanner instance
        self.scanner = MalwareScanner()

        # File path variable
        self.file_path = tk.StringVar()

        # Layout GUI
        self.create_layout()

    def create_layout(self):
        # ===== Sidebar Frame =====
        sidebar = tk.Frame(self.master, bg="#3B4BA0", width=150, height=400)
        sidebar.pack(side="left", fill="y")

        # Scanning All Button
        tk.Button(
            sidebar, text="Scannig File", bg="#748FC9", fg="black",
            font=("Arial", 12), relief="flat", cursor="hand2"
        ).pack(pady=20, fill="x")

        # Exit Button
        tk.Button(
            sidebar, text="Exit", bg="#748FC9", fg="black",
            font=("Arial", 12), relief="flat", cursor="hand2",
            command=self.master.quit
        ).pack(side="bottom", pady=20, fill="x")

        # ===== Center Frame (Rata Kiri) =====
        center_frame = tk.Frame(self.master, bg="#ffffff")
        center_frame.place(x=160, y=20)

        # Judul
        title_label = tk.Label(
            center_frame, text="MALTEK ANTIVIRUS", font=("Arial", 18, "bold"),
            bg="#ffffff", anchor="w"
        )
        title_label.grid(row=0, column=0, sticky="w", pady=10)

        # Choose File Button
        choose_file_btn = tk.Button(
            center_frame, text="Choose File", command=self.choose_file,
            bg="#007ACC", fg="white", font=("Arial", 12, "bold"), relief="flat"
        )
        choose_file_btn.grid(row=1, column=0, sticky="w", pady=10)

        # File Path Display
        file_path_label = tk.Label(
            center_frame, textvariable=self.file_path, wraplength=500,
            bg="#ffffff", font=("Arial", 10), anchor="w"
        )
        file_path_label.grid(row=2, column=0, sticky="w", pady=5)

        # Scan Button
        scan_btn = tk.Button(
            center_frame, text="Scan File", command=self.scan_file,
            bg="#28A745", fg="white", font=("Arial", 12, "bold"), relief="flat"
        )
        scan_btn.grid(row=3, column=0, sticky="w", pady=10)

        # Progress Bar
        self.progress = ttk.Progressbar(center_frame, orient="horizontal", length=400, mode="determinate")
        self.progress.grid(row=4, column=0, sticky="w", pady=10)

        # Result Label
        self.result_label = tk.Label(
            center_frame, text="", font=("Arial", 12, "bold"),
            bg="#ffffff", fg="black"
        )
        self.result_label.grid(row=5, column=0, sticky="w", pady=10)

        # ===== Logo  =====
        try:
            logo_image = Image.open("Av_maltek.png")  # Logo harus berada di folder yang sama
            logo_image = logo_image.resize((250, 250), Image.LANCZOS)
            self.logo = ImageTk.PhotoImage(logo_image)

            logo_label = tk.Label(self.master, image=self.logo, bg="#ffffff")
            logo_label.place(relx=0.85, rely=0.5, anchor="center")
        except Exception as e:
            print("Logo not found or could not be loaded:", e)

    def choose_file(self):
        file_selected = filedialog.askopenfilename()
        if file_selected:
            self.file_path.set(file_selected)
            self.result_label.config(text="")

    def scan_file(self):
        # Check if a file is selected
        if not self.file_path.get():
            messagebox.showwarning("Warning", "Please select a file first")
            return

        # Reset progress bar
        self.progress["value"] = 0
        self.update_progress(20)

        # Calculate file hash
        file_hash = self.scanner.hash_file(self.file_path.get())
        self.update_progress(50)

        # Check if file is malicious using VirusTotal
        virustotal_result = self.scanner.scan_virustotal(file_hash)
        self.update_progress(80)

        # Check the result from VirusTotal
        if self.scanner.is_malicious(virustotal_result):
            # Malware detected
            result = messagebox.askyesno(
                "Malware Detected", 
                "Malware detected. Do you want to delete this file?"
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
            
            self.result_label.config(text="Thanks For Scanning", fg="Green")
        else:
            # Clean file
            self.result_label.config(text="File is Safe", fg="green")
        self.update_progress(100)

    def update_progress(self, value):
        """Update the progress bar value"""
        self.progress["value"] = value
        self.master.update_idletasks()
        time.sleep(0.5)

def main():
    root = tk.Tk()
    gui = MalwareScannerGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()
