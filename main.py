#!/usr/bin/env python3
import asyncio, ipaddress, socket

TIMEOUT = 1
MAX_CONCURRENT = 500

COMMON_PORTS = [22, 80, 443, 554, 8080, 8000]

# ================= SCAN PORT =================
async def scan_port(ip, port):
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port), timeout=TIMEOUT
        )

        banner = ""

        # HTTP request
        if port in [80, 8080, 8000]:
            writer.write(b"GET / HTTP/1.0\r\n\r\n")
            await writer.drain()

        # RTSP (caméra)
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

# ================= SCAN RESEAU =================
async def scan_network(network):
    ips = [str(ip) for ip in ipaddress.ip_network(network, strict=False).hosts()]
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
            print_live(res)

    return results

# ================= DETECTION =================
def detect_service(port, banner):
    banner = banner.lower()

    if port == 554:
        return "📷 IP Camera (RTSP)"
    if "apache" in banner:
        return "🌐 Apache Web Server"
    if "nginx" in banner:
        return "🌐 Nginx Web Server"
    if "ssh" in banner:
        return "🔐 SSH"
    if "http" in banner:
        return "🌐 HTTP Server"

    return "❓ Unknown"

# ================= AFFICHAGE =================
def print_live(result):
    ip, port, banner = result
    service = detect_service(port, banner)

    print(f"[+] {ip}:{port} → {service}")

    if banner:
        print(f"    └─ Banner: {banner}")

# ================= TEST BASIC =================
async def test_http(ip):
    import aiohttp

    urls = [
        f"http://{ip}/",
        f"http://{ip}/login",
        f"http://{ip}/admin"
    ]

    async with aiohttp.ClientSession() as session:
        for url in urls:
            try:
                async with session.get(url, timeout=3) as resp:
                    if resp.status == 200:
                        print(f"[WEB] {url} accessible (status 200)")
            except:
                pass

# ================= MAIN =================
def main():
    print("\n=== 🔍 Network Audit Tool PRO (LOCAL) ===\n")

    target = input("Enter network (ex: 192.168.1.0/24): ")

    print("\n[+] Scanning network...\n")
    results = asyncio.run(scan_network(target))

    if not results:
        print("\n[-] No devices found.")
        return

    # Extra tests
    test = input("\nRun HTTP tests? (y/n): ")

    if test.lower() == "y":
        print("\n[+] Testing web interfaces...\n")

        ips = list(set([r[0] for r in results]))

        async def run_tests():
            tasks = [test_http(ip) for ip in ips]
            await asyncio.gather(*tasks)

        asyncio.run(run_tests())

    print("\n✅ Scan completed.\n")

if __name__ == "__main__":
    main()
