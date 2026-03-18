#!/usr/bin/env python3
import asyncio, ipaddress

# ===== CONFIG =====
TIMEOUT = 1
MAX_CONCURRENT = 800

COMMON_PORTS = [
    21,22,23,25,53,80,110,143,443,
    554,8080,8000,8443,3306,3389
]

# ===== DETECTION =====
def detect_service(port, banner):
    banner = banner.lower()

    if port == 554:
        return "📷 IP Camera (RTSP)"
    if "nginx" in banner:
        return "🌐 nginx"
    if "apache" in banner:
        return "🌐 apache"
    if "ssh" in banner:
        return "🔐 ssh"
    if "ftp" in banner:
        return "📁 ftp"
    if "http" in banner:
        return "🌐 http"
    if port == 443:
        return "🔒 https"
    if port == 3389:
        return "🖥️ rdp"

    return "❓ unknown"

# ===== SCAN PORT =====
async def scan_port(ip, port):
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port), timeout=TIMEOUT
        )

        banner = ""

        # HTTP
        if port in [80, 8080, 8000]:
            writer.write(b"GET / HTTP/1.0\r\n\r\n")
            await writer.drain()

        # RTSP (camera)
        if port == 554:
            writer.write(b"OPTIONS rtsp://test RTSP/1.0\r\n\r\n")
            await writer.drain()

        try:
            data = await asyncio.wait_for(reader.read(1024), timeout=TIMEOUT)
            if data:
                banner = data.decode(errors="ignore").strip().split("\n")[0][:120]
        except:
            pass

        writer.close()
        await writer.wait_closed()

        return (ip, port, banner)

    except:
        return None

# ===== EXPAND IP =====
def expand_targets(target):
    try:
        if "/" not in target:
            target += "/32"
        net = ipaddress.ip_network(target, strict=False)
        return [str(ip) for ip in net.hosts()]
    except:
        return [target]

# ===== SCAN NETWORK =====
async def scan_network(target):
    ips = expand_targets(target)
    results = []

    sem = asyncio.Semaphore(MAX_CONCURRENT)

    async def worker(ip, port):
        async with sem:
            return await scan_port(ip, port)

    tasks = [
        asyncio.create_task(worker(ip, port))
        for ip in ips
        for port in COMMON_PORTS
    ]

    for task in asyncio.as_completed(tasks):
        res = await task
        if res:
            results.append(res)
            print_result(res)

    return results

# ===== PRINT =====
def print_result(res):
    ip, port, banner = res
    service = detect_service(port, banner)

    print(f"[+] {ip}:{port} → {service}")

    if banner:
        print(f"    └─ {banner}")

# ===== HTTP TEST =====
async def test_http(ip):
    import aiohttp

    paths = ["/", "/login", "/admin", "/web", "/camera"]

    async with aiohttp.ClientSession() as session:
        for path in paths:
            url = f"http://{ip}{path}"
            try:
                async with session.get(url, timeout=3) as r:
                    if r.status == 200:
                        print(f"[WEB] {url} → OK (200)")
            except:
                pass

# ===== MAIN =====
def main():
    print("\n=== 🔥 Network Scanner PRO MAX ===\n")

    target = input("Target (ex: 192.168.1.0/24): ").strip()

    print("\n[+] Ultra fast scanning...\n")
    results = asyncio.run(scan_network(target))

    if not results:
        print("\n[-] Aucun port ouvert trouvé.")
        return

    # Unique IPs
    ips = list(set([r[0] for r in results]))

    # HTTP test
    choice = input("\nRun web detection? (y/n): ")

    if choice.lower() == "y":
        print("\n[+] Testing web interfaces...\n")

        async def run_tests():
            await asyncio.gather(*(test_http(ip) for ip in ips))

        asyncio.run(run_tests())

    print("\n✅ Scan terminé.\n")

# ===== RUN =====
if __name__ == "__main__":
    main()
