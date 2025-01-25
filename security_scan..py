import ssl
import socket
import requests
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from requests.exceptions import RequestException

class SecurityTester:
    def __init__(self, url, host, port, headers):
        self.url = url
        self.host = host
        self.port = port
        self.headers = headers
        self.http_methods = [
            "OPTIONS", "GET", "HEAD", "POST", "PUT", "DELETE", "TRACE", "CONNECT", "PATCH", "PROPFIND"
        ]

    def security_headers(self):
        print("\n[+] Testing for missing security headers...")
        try:
            response = requests.get(self.url)
            headers = response.headers

            required_headers = {
                "Strict-Transport-Security": "HSTS (Strict Transport Security)",
                "Content-Security-Policy": "Content Security Policy",
                "X-Frame-Options": "X-Frame-Options (Clickjacking Protection)",
                "X-Content-Type-Options": "X-Content-Type-Options (MIME Sniffing Protection)",
                "Cache-Control": "Cache Control",
            }

            for header, description in required_headers.items():
                if header not in headers:
                    print(f"[-] Missing {description} header: {header}")
                else:
                    print(f"[+] Found {description} header: {header}")
        except RequestException as e:
            print(f"[-] Error while testing security headers: {e}")

    def http_verb_tampering(self):
        print("\n[+] Testing for HTTP verb tampering vulnerability...")
        for method in self.http_methods:
            try:
                response = requests.request(method, self.url, headers=self.headers)
                print(f"[+] {method} request returned status code: {response.status_code}")
            except RequestException as e:
                print(f"[-] Error testing HTTP method {method}: {e}")

    def cookie_flags(self):
        print("\n[+] Testing for missing cookie flags...")
        try:
            response = requests.get(self.url)
            cookies = response.cookies

            for cookie in cookies:
                if not cookie.secure:
                    print(f"[-] Cookie '{cookie.name}' is missing the 'Secure' flag.")
                if not cookie.has_nonstandard_attr("HttpOnly"):
                    print(f"[-] Cookie '{cookie.name}' is missing the 'HttpOnly' flag.")
                if not cookie.has_nonstandard_attr("SameSite"):
                    print(f"[-] Cookie '{cookie.name}' is missing the 'SameSite' flag.")
        except RequestException as e:
            print(f"[-] Error while testing cookies: {e}")

    def ssl_weak_ciphers(self):
        print("\n[+] Testing for weak SSL/TLS cipher suites...")
        weak_ciphers = ["DES", "3DES", "RC4", "MD5", "SHA1"]
        try:
            context = ssl.create_default_context()
            conn = context.wrap_socket(socket.socket(socket.AF_INET), server_hostname=self.host)
            conn.connect((self.host, self.port))
            cipher = conn.cipher()
            conn.close()

            cipher_name, protocol, _ = cipher
            if any(weak_cipher in cipher_name for weak_cipher in weak_ciphers):
                print(f"[-] Weak cipher suite detected: {cipher_name} ({protocol})")
            else:
                print(f"[+] Strong cipher suite detected: {cipher_name} ({protocol})")
        except Exception as e:
            print(f"[-] Error while testing SSL/TLS ciphers: {e}")

    def header_information_disclosure(self):
        print("\n[+] Testing for HTTP header information disclosure...")
        try:
            response = requests.get(self.url)
            headers = response.headers

            disclosure_headers = ["Server", "X-Powered-By"]

            for header in disclosure_headers:
                if header in headers:
                    print(f"[-] Information disclosure detected: {header}: {headers[header]}")
                else:
                    print(f"[+] No information disclosure for: {header}")
        except RequestException as e:
            print(f"[-] Error while testing HTTP header disclosure: {e}")

    def run_all_tests(self):
        print(f"Starting security tests for {self.url}...\n")
        self.security_headers()
        self.http_verb_tampering()
        self.cookie_flags()
        self.ssl_weak_ciphers()
        self.header_information_disclosure()


if __name__ == "__main__":
    TARGET_URL = "https://zentrianalytics.com"
    TARGET_HOST = "zentrianalytics.com"
    TARGET_PORT = 443

    headers = {
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.0.0 Safari/537.36",
        "Accept": "*/*",
        "Accept-Language": "en-US,en;q=0.5",
        "Content-Type": "application/x-www-form-urlencoded",
        "Cookie": "_ptok=662ATIk183w20l%3An%3B; VM_CARE=41b55b59e852b9080dc3460ccc5d1f9a"
    }

    tester = SecurityTester(TARGET_URL, TARGET_HOST, TARGET_PORT, headers)
    tester.run_all_tests()
