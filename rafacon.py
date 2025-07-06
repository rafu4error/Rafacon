import requests
import argparse
import threading
from queue import Queue
from urllib.parse import urlparse
from waybackpy import WaybackMachineCDXServerAPI
import re
import json

live_urls = []
lock = threading.Lock()

def fetch_wayback_urls(domain, subs):
    urls = set()
    cdx = WaybackMachineCDXServerAPI(domain, user_agent="Mozilla/5.0")
    for url in cdx.snapshots():
        parsed = urlparse(url.archive_url)
        if subs or parsed.netloc == domain:
            urls.add(url.archive_url)
    return list(urls)

def fetch_commoncrawl_urls(domain):
    urls = set()
    index_list = ["CC-MAIN-2024-10", "CC-MAIN-2024-14"]
    for index in index_list:
        cc_url = f"https://index.commoncrawl.org/{index}-index?url=*.{domain}&output=json"
        try:
            resp = requests.get(cc_url, timeout=10)
            if resp.status_code == 200:
                for line in resp.text.splitlines():
                    try:
                        url = eval(line)["url"]
                        urls.add(url)
                    except:
                        continue
        except:
            pass
    return list(urls)

def remove_blacklisted(urls, blacklist):
    if not blacklist:
        return urls
    return [url for url in urls if not any(url.endswith(f".{ext}") for ext in blacklist)]

def is_live(url):
    try:
        r = requests.head(url, allow_redirects=True, timeout=5)
        return r.status_code < 400
    except:
        return False

def worker(q):
    while not q.empty():
        url = q.get()
        if is_live(url):
            with lock:
                live_urls.append(url)
        q.task_done()

def check_live_urls(urls, threads):
    q = Queue()
    for url in urls:
        q.put(url)
    for _ in range(threads):
        t = threading.Thread(target=worker, args=(q,))
        t.daemon = True
        t.start()
    q.join()
    return live_urls

def save_to_file(urls, filename):
    with open(filename, 'w') as f:
        for url in urls:
            f.write(url + '\n')

def check_cve_issues(urls):
    risky_patterns = [
        r"admin", r"login", r"debug", r"config", r"phpinfo", r"setup", r"shell", r"test", r"wp-login\.php",
        r"db_backup", r"backup", r"sql", r"install", r"cgi-bin", r"auth", r"register"
    ]
    flagged = []
    for url in urls:
        for pattern in risky_patterns:
            if re.search(pattern, url, re.IGNORECASE):
                flagged.append(url)
                break
    return flagged

def check_realtime_cve(urls):
    print("[+] Checking real-time CVEs using CIRCL API...")
    vulnerable_keywords = ["phpmyadmin", "wordpress", "drupal", "joomla", "struts", "laravel", "rails", "node", "django"]
    cve_results = []

    for url in urls:
        for keyword in vulnerable_keywords:
            if keyword in url.lower():
                try:
                    api_url = f"https://cve.circl.lu/api/search/{keyword}"
                    r = requests.get(api_url, timeout=10)
                    if r.status_code == 200:
                        data = r.json()
                        if "results" in data and data["results"]:
                            print(f"\n[!] {url} may be vulnerable ({keyword})")
                            for entry in data["results"][:3]:
                                print(f"  - {entry['id']}: {entry['summary']}")
                            cve_results.append((url, keyword))
                except Exception as e:
                    print(f"[!] Error checking {url}: {e}")
                break
    if not cve_results:
        print("[+] No real-time CVE matches found.")

def main():
    print(r"""
 ____        __
|  _ \ __ _ / _| __ _  ___ ___  _ __
| |_) / _` | |_ / _` |/ __/ _ \| '_ \
|  _ < (_| |  _| (_| | (_| (_) | | | |
|_| \_\__,_|_|  \__,_|\___\___/|_| |_|
    """)

    parser = argparse.ArgumentParser(description="rafacon - Advanced URL collector with live check")
    parser.add_argument("domain", help="Domain to scan")
    parser.add_argument("--subs", action="store_true", help="Include subdomains")
    parser.add_argument("--blacklist", help="Blacklist extensions, e.g., png,jpg,css")
    parser.add_argument("--threads", type=int, default=10, help="Threads for live check")
    parser.add_argument("--live", action="store_true", help="Show only live URLs")
    parser.add_argument("--o", help="Save output to file")
    parser.add_argument("--cve", action="store_true", help="Check URLs for possible CVE/vulnerability patterns")
    parser.add_argument("--realtime-cve", action="store_true", help="Check URLs for real-time CVE info via API")

    args = parser.parse_args()
    print(f"[+] Collecting URLs for: {args.domain}")

    urls = set()
    urls.update(fetch_wayback_urls(args.domain, args.subs))
    urls.update(fetch_commoncrawl_urls(args.domain))

    print(f"[+] Found {len(urls)} total URLs")

    if args.blacklist:
        blacklist = args.blacklist.split(",")
        urls = remove_blacklisted(urls, blacklist)
        print(f"[+] After blacklist filter: {len(urls)} URLs")

    if args.live:
        print("[+] Checking which URLs are live...")
        urls = check_live_urls(list(urls), args.threads)
        print(f"[+] Found {len(urls)} live URLs")

    if args.cve:
        print("[+] Checking URLs for possible CVE/risky patterns...")
        flagged_urls = check_cve_issues(urls)
        print(f"[+] Found {len(flagged_urls)} URLs flagged for possible issues:")
        for f_url in flagged_urls:
            print(f_url)

    if args.realtime_cve:
        check_realtime_cve(urls)

    if args.o:
        save_to_file(urls, args.o)
        print(f"[+] Saved output to {args.o}")
    else:
        for url in urls:
            print(url)

if __name__ == "__main__":
    main()
