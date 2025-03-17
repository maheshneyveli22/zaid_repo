import subprocess

# Execute a simple command
#subprocess.run(["echo", "Hello, World!"])

# List files in the current directory
result = subprocess.run(["netsh", "interface", "show", "interface"], capture_output=True, text=True)
#netsh interface show interface
print("Command Output:")
print(result.stdout)
