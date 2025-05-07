import argparse
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed

METHODS   = ["OPTIONS", "GET", "HEAD", "POST", "PUT", "DELETE", "PATCH"]
PROTOCOLS = ["http", "https"]

def probe_method(url, method, timeout):
    """
    Return HTTP status code (int), or None on error/timeout.
    Uses curl's connect/max timeouts plus Python's subprocess timeout.
    """
    cmd = [
        "curl", "-s", "-o", "/dev/null",
        "-w", "%{http_code}",
        "-X", method,
        "--connect-timeout", str(timeout),
        "--max-time",       str(timeout),
        url
    ]
    try:
        proc = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=timeout+0.5
        )
        return int(proc.stdout.strip())
    except Exception:
        return None

def main(ips_file, ports_file, timeout, workers, output_file):
    ips   = [l.strip() for l in open(ips_file)  if l.strip()]
    ports = [l.strip() for l in open(ports_file) if l.strip()]

    if len(ips) != len(ports):
        sys.stderr.write("Error: ips.txt and ports.txt must have the same number of lines.\n")
        sys.exit(1)

    results = { (ip, port, proto): [] 
                for ip, port in zip(ips, ports) 
                for proto in PROTOCOLS }

    with ThreadPoolExecutor(max_workers=workers) as pool:
        future_map = {}
        for ip, port in zip(ips, ports):
            for proto in PROTOCOLS:
                url = f"{proto}://{ip}:{port}"
                for m in METHODS:
                    fut = pool.submit(probe_method, url, m, timeout)
                    future_map[fut] = (ip, port, proto, m)

        for fut in as_completed(future_map):
            ip, port, proto, method = future_map[fut]
            code = fut.result()
            if code and 200 <= code < 400:
                results[(ip, port, proto)].append(method)

    with open(output_file, "w") as out:
        for ip, port in zip(ips, ports):
            segs = []
            for proto in PROTOCOLS:
                allowed = results[(ip, port, proto)]
                segs.append(f"{proto.upper()}: {', '.join(allowed) or 'None'}")
            line = f"{ip}:{port} → " + " ; ".join(segs) + "\n"
            out.write(line)
            print(line, end="")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Check which HTTP methods are allowed on each ip:port over HTTP/HTTPS",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument("ips",       help="Path to ips.txt (one IP per line)")
    parser.add_argument("ports",     help="Path to ports.txt (one port per line, matching ips)")
    parser.add_argument(
        "-t", "--timeout",
        type=float,
        default=2.0,
        help="Seconds to wait per request"
    )
    parser.add_argument(
        "-w", "--workers",
        type=int,
        default=20,
        help="Number of parallel curl probes"
    )
    parser.add_argument(
        "-o", "--output",
        default="results.txt",
        help="File to write the results to"
    )
    args = parser.parse_args()
    main(args.ips, args.ports, args.timeout, args.workers, args.output)
