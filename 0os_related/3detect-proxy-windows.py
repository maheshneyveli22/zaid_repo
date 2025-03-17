import urllib.request
import os

def detect_proxy():
    """
    Attempts to detect proxy settings and return proxy address if found.
    Relies on environment variables and system settings.
    """

    # Check environment variables (common on Linux/macOS)
    http_proxy = os.environ.get('http_proxy')
    https_proxy = os.environ.get('https_proxy')
    all_proxy = os.environ.get('all_proxy')

    if http_proxy:
        return http_proxy
    if https_proxy:
        return https_proxy
    if all_proxy:
        return all_proxy

    # Attempt to retrieve system proxy settings (Windows specific, requires winreg)
    try:
        import winreg
        try:
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, r'Software\Microsoft\Windows\CurrentVersion\Internet Settings')
            proxy_enable, _ = winreg.QueryValueEx(key, 'ProxyEnable')
            proxy_server, _ = winreg.QueryValueEx(key, 'ProxyServer')
            winreg.CloseKey(key)

            if proxy_enable:
                return proxy_server

        except FileNotFoundError:
            pass  # Key not found, proxy might not be enabled.
        except OSError:
            pass #Handles permission issues.
    except ImportError:
        pass # winreg not available (non-windows)

    # Attempt to use urllib.request to see if a proxy is being used.
    try:
        proxy_support = urllib.request.ProxyHandler()
        opener = urllib.request.build_opener(proxy_support)
        urllib.request.install_opener(opener)
        #Attempt to open a URL, If a proxy is used, it will go through that proxy.
        urllib.request.urlopen('http://www.example.com', timeout=5) #short timeout
        #If it gets here, no proxy was detected by urllib.
        return None

    except urllib.error.URLError as e:
        if isinstance(e.reason, urllib.error.URLError):
            #This is a proxy error.
            if hasattr(e.reason,'proxy'):
                return str(e.reason.proxy) #returns the proxy that failed.
        return None #other URL errors

    except Exception as e:
        #Catch all other exceptions, and return None.
        return None


if __name__ == "__main__":
    proxy_address = detect_proxy()
    if proxy_address:
        print(f"Proxy address detected: {proxy_address}")
    else:
        print("No proxy address detected.")