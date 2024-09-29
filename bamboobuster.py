#!/usr/bin/env python3
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urljoin, urlparse
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from alive_progress import alive_bar
from queue import Queue
import threading
import requests
import argparse
import urllib3
import socket
import signal
import time
import sys


# class used to kill process (couldnt get KeyboardInterrupt to work)
class GracefulKiller:
    kill_now = False

    def __init__(self):
        signal.signal(signal.SIGINT, self.exit_gracefully)
        signal.signal(signal.SIGTERM, self.exit_gracefully)

    def exit_gracefully(self, signum=None, frame=None):
        self.kill_now = True


# Colors using ANSI
class Colors:
    red = "\033[91m"
    green = "\033[92m"
    yellow = "\033[93m"
    blue = "\033[94m"
    magenta = "\033[95m"
    RESET = "\033[0m"


# DNS cache (apparently improves speed)
class DNSCache:
    def __init__(self):
        self.lock = threading.Lock()
        self.cache = {}

    def resolve(self, url):
        hostname = urlparse(url).hostname
        with self.lock:
            if hostname not in self.cache:
                try:
                    self.cache[hostname] = socket.gethostbyname(hostname)
                except socket.gaierror:
                    self.cache[hostname] = None
            return self.cache[hostname]


# formats the "help" message (i was getting 2 metavars for every flag)
class CustomHelpFormatter(argparse.HelpFormatter):
    def _format_action_invocation(self, action):
        if not action.option_strings:
            return super()._format_action_invocation(action)

        parts = []
        if action.nargs == 0:
            parts.extend(action.option_strings)
        else:
            parts.append(", ".join(action.option_strings))
        return " ".join(parts)


dns_cache = DNSCache()
threadLock = threading.Lock()
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# banner (why not)
def banner():
    font = r""" 
 /$$$$$$$                          /$$                                 /$$$$$$$                        /$$                        
| $$__  $$                        | $$                                | $$__  $$                      | $$                        
| $$  \ $$  /$$$$$$  /$$$$$$/$$$$ | $$$$$$$   /$$$$$$   /$$$$$$       | $$  \ $$ /$$   /$$  /$$$$$$$ /$$$$$$    /$$$$$$   /$$$$$$ 
| $$$$$$$  |____  $$| $$_  $$_  $$| $$__  $$ /$$__  $$ /$$__  $$      | $$$$$$$ | $$  | $$ /$$_____/|_  $$_/   /$$__  $$ /$$__  $$
| $$__  $$  /$$$$$$$| $$ \ $$ \ $$| $$  \ $$| $$  \ $$| $$  \ $$      | $$__  $$| $$  | $$|  $$$$$$   | $$    | $$$$$$$$| $$  \__/
| $$  \ $$ /$$__  $$| $$ | $$ | $$| $$  | $$| $$  | $$| $$  | $$      | $$  \ $$| $$  | $$ \____  $$  | $$ /$$| $$_____/| $$      
| $$$$$$$/|  $$$$$$$| $$ | $$ | $$| $$$$$$$/|  $$$$$$/|  $$$$$$/      | $$$$$$$/|  $$$$$$/ /$$$$$$$/  |  $$$$/|  $$$$$$$| $$      
|_______/  \_______/|__/ |__/ |__/|_______/  \______/  \______/       |_______/  \______/ |_______/    \___/   \_______/|__/      """
    
    print(font + "\n")
    print("Use responsibly. >:(")


# make sure there is "https://" in front of url provided
def ensure_scheme(url):
    parsed_url = urlparse(url)
    if not parsed_url.scheme:
        return f"https://{url}"
    return url


# makes a list of codes to look for
def parse_codes(value):
    results = set()
    for code in value.split(","):
        if "-" in code:
            start, end = map(int, code.split("-"))
            results.update(range(start, end + 1))
        else:
            results.add(int(code))
    return results


# gets response size
def get_response_size(response):
    content_length = response.headers.get("Content-Length")
    return int(content_length) if content_length else len(response.content)


# format the size to "1234MB" format
def format_size(size):
    if size < 1024:
        return f"{size}B"
    elif size < 1024**2:
        return f"{size // 1024}KB"
    elif size < 1024**3:
        return f"{size // (1024**2)}MB"
    else:
        return f"{size // (1024**3)}GB"


# no idea what this does (added by chatgpt for optimizing. idk why i asked it)
def create_session():
    session = requests.Session()
    
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
    }

    session.verify = False
    session.headers.update(headers)
    retries = Retry(total=0, backoff_factor=0.1)
    adapter = HTTPAdapter(max_retries=retries, pool_connections=200, pool_maxsize=200)
    session.mount("https://", adapter)
    session.mount("http://", adapter)

    return session


# fetches status codes and redirected urls
def worker(session, full_url, parsed_codes, killer, output_queue, timeout):
    if killer.kill_now:
        return None

    ip_address = dns_cache.resolve(full_url)
    if ip_address is None:
        output_queue.put((Colors.red, "Error", "DNS resolution failed", "", full_url, ""))
        return None

    try:
        response = session.get(full_url, timeout=timeout, allow_redirects=False)
        redirect_url = urljoin(full_url, response.headers.get("Location", ""))
        size = get_response_size(response)
        size = format_size(size)
        path = urlparse(full_url).path
        status = response.status_code

        if status in parsed_codes:
            if 200 <= status < 300:
                output_queue.put((Colors.green, status, size, path, full_url, redirect_url))
            elif 300 <= status < 400:
                output_queue.put((Colors.blue, status, size, path, full_url, redirect_url))
            else:
                output_queue.put((Colors.red, status, size, path, full_url, redirect_url))
                
    except requests.exceptions.Timeout:
        output_queue.put((Colors.red, "Error", "Timeout", "", full_url, ""))
    except requests.RequestException as e:
        output_queue.put((Colors.red, "Error", str(e), "", full_url, ""))


# prints the output
def printer(output_queue):
    while True:
        item = output_queue.get()
        if item is None:
            break
        color, status, size, path, full_url, redirect_url = item
        if status == "Error":
            print(f"{color}[Error]{Colors.RESET} {size} while processing '{full_url}'\n", end="")
        else:
            print(f"{color}[{status}]{Colors.RESET} - [{Colors.yellow}{size}{Colors.RESET}]  {path:<55}\t{full_url} -> {redirect_url:<45}\n", end="")
        output_queue.task_done()


# preps url with threads (also diplays progress bar
def brute(base_url, wordlist, parsed_codes, killer, extensions, number_threads, timeout):
    base_url = ensure_scheme(base_url)
    if not base_url.endswith("/"):
        base_url += "/"

    start_time = time.time()
    completed_reqs = 0
    total_reqs = len(wordlist) * (len(extensions) + 1)

    output_queue = Queue()

    print_thread = threading.Thread(target=printer, args=(output_queue,))
    print_thread.start()

    session = create_session()

    extended_wordlist = []
    for word in wordlist:
        extended_wordlist.append(word.strip())
        for ext in extensions:
            extended_wordlist.append(word.strip() + "." + ext)

    with ThreadPoolExecutor(max_workers=number_threads) as exe, alive_bar(total_reqs, title="Snooping", spinner="dots", enrich_print=False) as bar:
        future_to_url = {exe.submit(worker, session, base_url + word, parsed_codes, killer, output_queue, timeout): word for word in extended_wordlist}
        for future in as_completed(future_to_url):
            with threadLock:
                completed_reqs += 1

            if killer.kill_now:
                exe.shutdown(wait=False, cancel_futures=True)
                break

            bar()

    output_queue.put(None)
    print_thread.join()

    end_time = time.time()
    elapsed_time = end_time - start_time
    minutes, seconds = divmod(elapsed_time, 60)
    pretty_time = "{:02}:{:02}".format(int(minutes), int(seconds))
    
    if not killer.kill_now:
        print("=" * 100)
        print(f"{Colors.yellow}{pretty_time}{Colors.RESET}\tFinished [{completed_reqs}]")
        
    elif killer.kill_now:
        print("=" * 100)
        print(f"{Colors.yellow}{pretty_time}{Colors.RESET} - {Colors.red}Interrupt received. Exiting... [{completed_reqs}]{Colors.RESET}")

# this should be obvious
def main():    
    parser = argparse.ArgumentParser(description="Testing", formatter_class=CustomHelpFormatter)
    parser.add_argument("-u", "--url", type=str, required=True, help="Target url (eg: https://example.com)")
    parser.add_argument("-w", "--wordlist", type=str, required=True, help="Path to wordlist")
    parser.add_argument("-mc", "--match-codes", type=str, required=False, default="200,300-399", help="Response codes to look for (default: 200,300-399)")
    parser.add_argument("-e", "--extensions", type=str, required=False, default="", help="Comma-separated list of file extensions (e.g., .html,.php)")
    parser.add_argument("-t", "--threads", type=int, required=False, default=25, help="Number of threads (default: 25)")
    parser.add_argument("--timeout", type=int, required=False, default=10, help="Timeout in seconds (default: 10)")
    args = parser.parse_args()

    killer = GracefulKiller()
    parsed_codes = parse_codes(args.match_codes)
    extensions = args.extensions.split(",") if args.extensions else []
    number_threads = int(args.threads)
    timeout = int(args.timeout) 

    try:
        with open(args.wordlist, "r") as f:
            wordlist = f.read().splitlines()
            
    except IOError:
        print(f"{Colors.red}[Error]{Colors.RESET} Could not read '{args.wordlist}'")
        sys.exit(1)

    banner()
    print("=" * 100)
    print(f"BB 1.0\tBy DemonPandaz\n")
    print(f"Wordlist size: {len(wordlist)} | Codes: {args.match_codes} | Extensions: {extensions} | Threads: {number_threads} | Timeout: {timeout}")
    print("=" * 100)

    brute(args.url, wordlist, parsed_codes, killer, extensions, number_threads, timeout)

    if killer.kill_now:
        pass


if __name__ == "__main__":
    main()