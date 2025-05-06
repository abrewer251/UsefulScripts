#!/usr/bin/env python3
import argparse
import subprocess
import sys
import time
import threading
from concurrent.futures import ThreadPoolExecutor
from queue import Queue

RATE_LIMIT = 30  # 30 connections per second
TIMEOUT = 3      # default nc timeout per connection

METHODS = []  # not used, kept for compatibility


def check_connection(ip, port, result_queue, timeout):
    try:
        result = subprocess.run(
            ['nc', '-v', ip, str(port)],
            capture_output=True,
            text=True,
            timeout=timeout
        )
        if result.returncode == 0:
            result_queue.put((ip, port, True, result.stdout.strip()))
        else:
            result_queue.put((ip, port, False, result.stderr.strip()))
    except subprocess.TimeoutExpired:
        result_queue.put((ip, port, False, "Connection timed out"))
    except Exception as e:
        result_queue.put((ip, port, False, f"Error: {e}"))


def display_progress(total, checked):
    while checked['count'] < total:
        print(f"🔄 Checked {checked['count']} out of {total} IP:Port combinations", flush=True)
        time.sleep(60)


def main(ip_file, port_file, output_file, timeout, workers):
    with open(ip_file, 'r') as infile:
        ips = [line.strip() for line in infile if line.strip()]
    with open(port_file, 'r') as pfile:
        ports = [int(line.strip()) for line in pfile if line.strip().isdigit()]

    targets = [(ip, port) for ip in ips for port in ports]
    total = len(targets)
    checked = {'count': 0}
    result_queue = Queue()
    lock = threading.Lock()

    # Start progress thread
    threading.Thread(target=display_progress, args=(total, checked), daemon=True).start()

    with open(output_file, 'w') as outfile:
        def result_handler():
            while checked['count'] < total:
                try:
                    ip, port, success, info = result_queue.get(timeout=1)
                except:
                    continue
                with lock:
                    checked['count'] += 1
                    if success:
                        message = f"✅ {ip}:{port} - SUCCESS\nInfo: {info}"
                    else:
                        message = f"❌ {ip}:{port} - FAILURE\nError: {info}"
                    print(message, flush=True)
                    outfile.write(message + "\n")
                    outfile.flush()

        # Start result consumer thread
        threading.Thread(target=result_handler, daemon=True).start()

        with ThreadPoolExecutor(max_workers=workers) as executor:
            for ip, port in targets:
                executor.submit(check_connection, ip, port, result_queue, timeout)
                time.sleep(1 / RATE_LIMIT)

        # Wait until all are processed
        while checked['count'] < total:
            time.sleep(1)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Check TCP connectivity for IP:Port pairs with rate limiting and progress display"
    )
    parser.add_argument(
        "ips",
        help="Path to ips.txt (one IP per line)"
    )
    parser.add_argument(
        "ports",
        help="Path to ports.txt (one port per line)"
    )
    parser.add_argument(
        "output",
        help="Path to write results to"
    )
    parser.add_argument(
        "-t", "--timeout",
        type=float,
        default=TIMEOUT,
        help="Timeout in seconds for each connection attempt"
    )
    parser.add_argument(
        "-w", "--workers",
        type=int,
        default=RATE_LIMIT,
        help="Number of parallel connection probes per second"
    )
    args = parser.parse_args()

    # Run main with parsed arguments
    main(args.ips, args.ports, args.output, args.timeout, args.workers)
