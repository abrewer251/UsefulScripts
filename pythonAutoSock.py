"""
Port scanner script: single or bulk scanning with CSV output, detailed metadata, and banner grabbing.

Usage:
    Single scan: port_scanner.py --ip 1.2.3.4 --port 80
    Bulk scan:  port_scanner.py --ips-file ips.txt --ports-file ports.txt --output results.csv
"""
import argparse
import socket
import concurrent.futures
import csv
import time
import ssl
from tqdm import tqdm


def scan_port(ip, port, timeout):
    """
    Connects to the IP:port, gathers metadata, grabs banner, TLS info, and returns a dict.
    """
    result = {
        'ip': ip,
        'port': port,
        'status': False,
        'banner': '',
        'local_ip': '',
        'local_port': '',
        'peer_ip': '',
        'peer_port': '',
        'service': '',
        'latency_ms': '',
        'rdns': '',
        'sndbuf': '',
        'rcvbuf': '',
        'ttl': '',
        'tls_version': '',
        'tls_cipher': '',
        'cert_subject': ''
    }
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    start = time.perf_counter()
    try:
        sock.connect((ip, port))
        result['status'] = True
        result['latency_ms'] = round((time.perf_counter() - start) * 1000, 2)
        # endpoints
        local = sock.getsockname()
        peer = sock.getpeername()
        result['local_ip'], result['local_port'] = local[0], local[1]
        result['peer_ip'], result['peer_port'] = peer[0], peer[1]
        # service lookup
        try:
            result['service'] = socket.getservbyport(port, 'tcp')
        except OSError:
            result['service'] = ''
        # reverse DNS
        try:
            result['rdns'] = socket.gethostbyaddr(ip)[0]
        except socket.herror:
            result['rdns'] = ''
        # socket options
        try:
            result['sndbuf'] = sock.getsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF)
            result['rcvbuf'] = sock.getsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF)
            result['ttl'] = sock.getsockopt(socket.IPPROTO_IP, socket.IP_TTL)
        except Exception:
            pass
        # banner grab
        sock.settimeout(1.0)
        try:
            banner = sock.recv(1024).decode(errors='ignore').strip()
            result['banner'] = banner
        except Exception:
            result['banner'] = ''
        # TLS info
        try:
            ssl_sock = ssl.wrap_socket(sock, server_hostname=ip, do_handshake_on_connect=False)
            ssl_sock.settimeout(timeout)
            ssl_sock.do_handshake()
            result['tls_version'] = ssl_sock.version()
            cipher = ssl_sock.cipher()
            result['tls_cipher'] = cipher[0] if cipher else ''
            cert = ssl_sock.getpeercert()
            subj = cert.get('subject', ((('commonName', ''),),))
            result['cert_subject'] = subj[0][0][1]
            ssl_sock.close()
        except Exception:
            # not TLS or handshake failed
            pass
    except socket.timeout:
        result['status'] = False
        result['banner'] = 'Connection timed out'
    except ConnectionRefusedError:
        result['status'] = False
        result['banner'] = 'Connection refused'
    except Exception as e:
        result['status'] = False
        result['banner'] = f"Error: {e}"
    finally:
        sock.close()
    return result


def main():
    parser = argparse.ArgumentParser(
        description="Check TCP connectivity for IP:Port pairs (single or bulk) with CSV output and metadata"
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--ip', help='IP address for a single scan')
    group.add_argument('--ips-file', help='Path to file with list of IPs (one per line)')
    parser.add_argument('--port', type=int, help='Port for single scan')
    parser.add_argument('--ports-file', help='Path to file with list of ports (one per line)')
    parser.add_argument('--output', help='CSV output file path for bulk scan results')
    parser.add_argument('-t', '--timeout', type=float, default=3.0,
                        help='Timeout per connection in seconds (default: 3.0)')
    parser.add_argument('-w', '--workers', type=int, default=30,
                        help='Number of concurrent workers for bulk scan (default: 30)')
    args = parser.parse_args()

    # Single scan mode
    if args.ip:
        if args.port is None:
            parser.error("argument --port is required when using --ip")
        result = scan_port(args.ip, args.port, args.timeout)
        status = 'open' if result['status'] else 'closed'
        print(f"{status.upper()}: {result['ip']}:{result['port']}")
        for key, val in result.items():
            if key in ('ip', 'port', 'status'):
                continue
            print(f"{key}: {val}")
        return

    # Bulk scan mode
    if not args.ips_file or not args.ports_file or not args.output:
        parser.error("arguments --ips-file, --ports-file and --output are required for bulk scan")

    # Load targets
    with open(args.ips_file) as f:
        ips = [line.strip() for line in f if line.strip()]
    with open(args.ports_file) as f:
        ports = [int(line.strip()) for line in f if line.strip().isdigit()]
    targets = [(ip, port) for ip in ips for port in ports]
    total = len(targets)

    # CSV Output
    columns = ['ip','port','status','banner','local_ip','local_port','peer_ip','peer_port',
               'service','latency_ms','rdns','sndbuf','rcvbuf','ttl','tls_version','tls_cipher','cert_subject']
    with open(args.output, 'w', newline='') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=columns)
        writer.writeheader()
        with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as executor:
            futures = {executor.submit(scan_port, ip, port, args.timeout): (ip, port)
                       for ip, port in targets}
            for future in tqdm(concurrent.futures.as_completed(futures), total=total,
                               desc="Scanning", unit="target"):
                result = future.result()
                result['status'] = 'open' if result['status'] else 'closed'
                writer.writerow({k: result.get(k, '') for k in columns})
    print(f"Bulk scan complete. Results saved to {args.output}")


if __name__ == "__main__":
    main()
