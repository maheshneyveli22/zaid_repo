import os
import platform

def scan_programs():
    """Scans and lists installed programs based on the operating system."""

    os_name = platform.system()

    if os_name == "Windows":
        return _scan_windows_programs()
    elif os_name == "Linux":
        return _scan_linux_programs()
    elif os_name == "Darwin":  # macOS
        return _scan_macos_programs()
    else:
        return f"Unsupported operating system: {os_name}"

def _scan_windows_programs():
    """Scans installed programs on Windows."""
    try:
        import winreg  # Only available on Windows

        programs = []
        uninstall_key = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"
        wow6432_key = r"SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall"

        for key_path in [uninstall_key, wow6432_key]: # Check both 32 and 64 bit uninstall registry locations.
            try:
                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path) as key:
                    i = 0
                    while True:
                        try:
                            subkey_name = winreg.EnumKey(key, i)
                            with winreg.OpenKey(key, subkey_name) as subkey:
                                try:
                                    display_name = winreg.QueryValueEx(subkey, "DisplayName")[0]
                                    programs.append(display_name)
                                except OSError:
                                    pass  # Ignore entries without a display name
                        except OSError:
                            break  # No more subkeys
                        i += 1
            except FileNotFoundError:
                pass # if one of the registry paths are not found, continue.

        return programs

    except ImportError:
        return "winreg module not available (not on Windows)."
    except Exception as e:
        return f"Error scanning Windows programs: {e}"

def _scan_linux_programs():
    """Scans installed programs on Linux."""
    try:
        # This is a simplified approach. More robust methods may be needed for specific distributions.
        programs = []

        # Check for commonly used package managers
        if os.path.exists("/usr/bin/dpkg"):  # Debian/Ubuntu based
            output = os.popen("dpkg --get-selections | grep -v deinstall").read()
            programs.extend([line.split()[0] for line in output.splitlines()])

        if os.path.exists("/usr/bin/rpm"):  # Red Hat/Fedora based
            output = os.popen("rpm -qa").read()
            programs.extend(output.splitlines())

        if os.path.exists("/usr/bin/pacman"): # Arch based
            output = os.popen("pacman -Qqe").read()
            programs.extend(output.splitlines())

        if os.path.exists("/usr/bin/emerge"): # Gentoo based
            output = os.popen("emerge -pv").read()
            for line in output.splitlines():
                if line.startswith("* "):
                    programs.append(line[3:])

        return programs

    except Exception as e:
        return f"Error scanning Linux programs: {e}"

def _scan_macos_programs():
    """Scans installed applications on macOS."""
    try:
        programs = []
        applications_dir = "/Applications"
        if os.path.exists(applications_dir):
            for filename in os.listdir(applications_dir):
                if filename.endswith(".app"):
                    programs.append(filename[:-4]) # Remove the '.app' extension
        return programs
    except Exception as e:
        return f"Error scanning macOS programs: {e}"

if __name__ == "__main__":
    installed_programs = scan_programs()
    if isinstance(installed_programs, list):
        print("Installed Programs:")
        for program in installed_programs:
            print(program)
    else:
        print(installed_programs) # Print the error message or OS info