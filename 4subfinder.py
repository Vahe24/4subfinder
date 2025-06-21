import asyncio
import aiohttp
import socket
from colorama import init, Fore

from pyfiglet import figlet_format
from yaspin import yaspin
from yaspin.spinners import Spinners

init(autoreset=True)

def load_wordlist(path):
    try:
        with open(path, 'r') as file:
            return [line.strip() for line in file]
    except FileNotFoundError:
        print(Fore.RED + f"File not found: {path}")
        return []

def resolve_dns(subdomain):
    try:
        socket.gethostbyname(subdomain)
        return True
    except socket.gaierror:
        return False

async def check_subdomain(session, url):
    try:
        async with session.get(url, timeout=3) as resp:
            if resp.status < 400:
                print(Fore.GREEN + f"[+] Found: {url} ({resp.status})")
                return url
    except:
        pass
    return None

async def run_scanner(domain, wordlist):
    found = []
    tasks = []

    connector = aiohttp.TCPConnector(ssl=False)
    async with aiohttp.ClientSession(connector=connector) as session:
        for sub in wordlist:
            full_sub = f"{sub}.{domain}"

            if resolve_dns(full_sub):
                tasks.append(check_subdomain(session, f"http://{full_sub}"))
                tasks.append(check_subdomain(session, f"https://{full_sub}"))

        results = await asyncio.gather(*tasks)
        found = [r for r in results if r]

    return found

def main():
    ascii_banner = figlet_format("4SubFinder")
    print(Fore.MAGENTA + ascii_banner)

    domain = input("Enter domain (e.g., example.com): ").strip()
    wordlist = load_wordlist("subdomains.txt")

    print(Fore.CYAN + f"\n[~] Starting scan for {len(wordlist)} subdomains...\n")

    with yaspin(Spinners.dots, text="Scanning subdomains...") as spinner:
        found = asyncio.run(run_scanner(domain, wordlist))
        spinner.ok("✔")

    print(Fore.YELLOW + f"\nScan complete! Found {len(found)} subdomains.")
    print(Fore.YELLOW + "Results shown above.")

if __name__ == "__main__":
    main()
