#!/usr/bin/env python3
import asyncio
import ipaddress
import json
import ssl
import sys
from datetime import datetime

# ===== CONFIG =====
TIMEOUT = 2
MAX_CONCURRENT = 150
RETRIES = 2
OUTPUT_FILE = "scan_results.json"

COMMON_PORTS = [
    21,22,23,25,53,80,110,143,443,
    554,8080,8000,8443,3306,3389
]

# ===== SSL CONTEXT =====
SSL_CTX = ssl.create_default_context()
SSL_CTX.check_hostname = False
SSL_CTX.verify_mode = ssl.CERT_NONE

# ===== DETECTION =====
def detect_service(port, banner):
    b = banner.lower()

    if port == 554:
        return "RTSP Camera"
    if "ssh" in b:
        return "SSH"
    if "ftp" in b:
        return "FTP"
    if "smtp" in b:
        return "SMTP"
    if "mysql" in b:
        return "MySQL"
    if "rdp" in b:
        return "RDP"
    if "nginx" in b:
        return "nginx"
    if "apache" in b:
        return "apache"
    if "http" in b:
        return "HTTP"
    if port == 443:
        return "HTTPS"
    return "Unknown"

# ===== PORT SCAN =====
async def scan_port(ip, port):
    for _ in range(RETRIES):
        try:
            if port in [443, 8443]:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(ip, port, ssl=SSL_CTX), timeout=TIMEOUT
                )
            else:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(ip, port), timeout=TIMEOUT
                )

            banner = ""

            if port in [80, 8080, 8000, 8443, 443]:
                writer.write(b"HEAD / HTTP/1.0\r\n\r\n")
                await writer.drain()

            if port == 554:
                writer.write(b"OPTIONS rtsp://test RTSP/1.0\r\n\r\n")
                await writer.drain()

            try:
                data = await asyncio.wait_for(reader.read(1024), timeout=TIMEOUT)
                if data:
                    banner = data.decode(errors="ignore").strip().split("\n")[0][:200]
            except asyncio.TimeoutError:
                pass

            writer.close()
            try:
                await writer.wait_closed()
            except:
                pass

            return (ip, port, banner)

        except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
            continue
    return None

# ===== TARGET EXPANSION =====
def expand_targets(target):
    try:
        if "/" not in target:
            target += "/32"
        net = ipaddress.ip_network(target, strict=False)
        return [str(ip) for ip in net.hosts()]
    except Exception:
        return []

# ===== SCAN =====
async def scan_network(target):
    ips = expand_targets(target)

    if not ips:
        print("[!] Invalid target format")
        return []

    sem = asyncio.Semaphore(MAX_CONCURRENT)
    results = []

    async def worker(ip, port):
        async with sem:
            await asyncio.sleep(0.001)
            return await scan_port(ip, port)

    tasks = [
        asyncio.create_task(worker(ip, port))
        for ip in ips
        for port in COMMON_PORTS
    ]

    for task in asyncio.as_completed(tasks):
        try:
            res = await task
            if res:
                results.append(res)
                print_result(res)
        except Exception:
            pass

    return results

# ===== PRINT =====
def print_result(res):
    ip, port, banner = res
    service = detect_service(port, banner)

    print(f"[+] {ip}:{port} → {service}")

    if banner:
        print(f"    ├─ Banner: {banner}")

# ===== HTTP ANALYSIS =====
async def analyze_http(ip):
    import aiohttp

    timeout = aiohttp.ClientTimeout(total=5)
    connector = aiohttp.TCPConnector(ssl=False, limit=50)

    async with aiohttp.ClientSession(timeout=timeout, connector=connector) as session:
        for path in ["/", "/admin", "/login"]:
            for proto in ["http", "https"]:
                url = f"{proto}://{ip}{path}"
                try:
                    async with session.get(url) as r:
                        print(f"[WEB] {url} → {r.status}")
                except Exception:
                    pass

# ===== SAVE =====
def save_results(results):
    with open(OUTPUT_FILE, "w") as f:
        json.dump([
            {
                "ip": ip,
                "port": port,
                "service": detect_service(port, banner),
                "banner": banner
            }
            for ip, port, banner in results
        ], f, indent=4)

    print(f"\nResults saved to {OUTPUT_FILE}")

# ===== SUMMARY =====
def summary(results):
    print("\n===== SCAN SUMMARY =====")
    stats = {}

    for ip, port, banner in results:
        service = detect_service(port, banner)
        stats[service] = stats.get(service, 0) + 1

    for k, v in stats.items():
        print(f"{k}: {v}")

# ===== MAIN =====
def main():
    print("\n=== NETWORK SCANNER PRO+++ FIXED ===\n")

    # 🔥 SUPPORT ARGUMENT (no input bug anymore)
    if len(sys.argv) > 1:
        target = sys.argv[1]
        print(f"[+] Target from CLI: {target}")
    else:
        try:
            target = input("Target: ").strip()
        except Exception:
            target = ""

    if not target:
        print("[!] No target provided")
        print("👉 Usage: python main.py 192.168.1.0/24")
        return

    start = datetime.now()

    print("\n[+] Scanning...\n")
    results = asyncio.run(scan_network(target))

    if not results:
        print("[-] No open ports found")
        return

    ips = list(set([r[0] for r in results]))

    choice = "n"
    try:
        choice = input("\nRun deep web scan? (y/n): ")
    except:
        pass

    if choice.lower() == "y":
        print("\n[+] Web scanning...\n")

        async def run():
            await asyncio.gather(*(analyze_http(ip) for ip in ips))

        asyncio.run(run())

    save_results(results)
    summary(results)

    end = datetime.now()
    print(f"\nDuration: {end - start}")
    print("\nScan complete\n")

if __name__ == "__main__":
    main()
