import time
import os

restricted_file = r"C:\confidential\secret.txt"

# Ensure directory exists
os.makedirs(os.path.dirname(restricted_file), exist_ok=True)
if not os.path.exists(restricted_file):
    with open(restricted_file, "w") as f:
        f.write("test")

print(f"Opening {restricted_file} for 5 seconds...")
f = open(restricted_file, "r")
time.sleep(5)
f.close()
print("Closed.")

print("Waiting 16 seconds for cooldown...")
time.sleep(16)

print(f"Opening {restricted_file} again for 5 seconds...")
f = open(restricted_file, "r")
time.sleep(5)
f.close()
print("Closed.")
