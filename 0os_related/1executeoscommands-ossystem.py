import os

# Execute a simple OS command
os.system("echo Hello, World!")

# Create a new directory
exit_status = os.system("netsh interface show interface")
if exit_status == 0:
    print("Directory created successfully!")
else:
    print("Failed to create directory.")
