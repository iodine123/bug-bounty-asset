import os
import subprocess
import requests
import concurrent.futures
import argparse

# ===== CONFIG DEFAULT =====
THREADS = 20
EXTENSIONS = ["", ".php", ".asp", ".aspx", ".html", ".bak", ".txt", ".zip"]
HEADERS = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}

# ===== SUBFINDER =====
def run_subfinder(target):
    print("\n[+] Running Subfinder...")
    with open("subdomains.txt", "w") as f:
        subprocess.run(["subfinder", "-d", target, "-silent"], stdout=f)
    print("[+] Subdomains saved to subdomains.txt")

# ===== NAABU =====
def run_naabu():
    print("\n[+] Running Naabu...")
    with open("ports.txt", "w") as f:
        subprocess.run(["naabu", "-list", "subdomains.txt", "-silent"], stdout=f)
    print("[+] Ports saved to ports.txt")

# ===== HTTPX =====
def run_httpx():
    print("\n[+] Running Httpx...")
    with open("alive.txt", "w") as f:
        subprocess.run(["httpx", "-l", "subdomains.txt", "-silent"], stdout=f)
    print("[+] Live hosts saved to alive.txt")

# ===== DIR BRUTEFORCE =====
def check_path(path, base_url):
    results = []
    for ext in EXTENSIONS:
        url = f"{base_url.rstrip('/')}/{path.strip()}{ext}"
        try:
            r = requests.get(url, headers=HEADERS, timeout=5, allow_redirects=False)
            if r.status_code in [200, 301, 302, 403]:
                results.append(f"[+] {url} -> {r.status_code}")
        except requests.RequestException:
            pass
    return results

def dir_bruteforce(wordlist):
    print("\n[+] Running Directory Bruteforce on live hosts...")
    with open("alive.txt", "r") as f:
        alive_hosts = f.readlines()

    with open(wordlist, "r") as f:
        paths = f.readlines()

    for host in alive_hosts:
        host = host.strip()
        print(f"\n[*] Scanning {host}")
        with concurrent.futures.ThreadPoolExecutor(max_workers=THREADS) as executor:
            for result in executor.map(lambda p: check_path(p, host), paths):
                if result:
                    for r in result:
                        print(r)
                        with open("dir_results.txt", "a") as out:
                            out.write(r + "\n")

# ===== WAYBACKURLS + GAU =====
def collect_endpoints(target):
    print("\n[+] Collecting Endpoints with waybackurls...")
    with open(f"{target}_wayback.txt", "w") as f:
        subprocess.run(["waybackurls", target], stdout=f)
    print(f"[+] waybackurls results saved to {target}_wayback.txt")

    print("\n[+] Collecting Endpoints with gau...")
    with open(f"{target}_gau.txt", "w") as f:
        subprocess.run(["gau", target], stdout=f)
    print(f"[+] gau results saved to {target}_gau.txt")

# ===== PARAM FILTER =====
def extract_params(target):
    print("\n[+] Extracting parameterized URLs...")
    combined = set()
    for fname in [f"{target}_wayback.txt", f"{target}_gau.txt"]:
        if os.path.exists(fname):
            with open(fname, "r") as f:
                for line in f:
                    if "?" in line:
                        combined.add(line.strip())
    with open("params.txt", "w") as f:
        for url in sorted(combined):
            f.write(url + "\n")
    print("[+] Parameters saved to params.txt")

# ===== MAIN =====
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Recon Automation Script")
    parser.add_argument("--target", required=True, help="Target domain (example.com)")
    parser.add_argument("--wordlist", required=True, help="Path to wordlist (e.g., SecLists/Discovery/Web-Content/common.txt)")
    parser.add_argument("--mode", choices=["quick", "deep"], default="quick", help="Run mode: quick or deep")
    args = parser.parse_args()

    target = args.target
    wordlist = args.wordlist

    run_subfinder(target)
    run_httpx()
    dir_bruteforce(wordlist)

    if args.mode == "deep":
        run_naabu()
        collect_endpoints(target)
        extract_params(target)

    print(f"\n[+] Recon completed in {args.mode} mode for {target}! Check output files.")
