import time
import os
import subprocess

restricted_file = r"C:\confidential\secret.txt"

# Ensure directory and file exist
os.makedirs(os.path.dirname(restricted_file), exist_ok=True)
with open(restricted_file, "w") as f:
    f.write("This is a restricted file for testing.")

print(f"Launching notepad to open {restricted_file}...")
proc = subprocess.Popen(["notepad.exe", restricted_file])

print("Waiting 5 seconds for the scanner to detect the window...")
time.sleep(5)

print("Closing notepad...")
proc.terminate()
proc.wait()
print("Done.")
