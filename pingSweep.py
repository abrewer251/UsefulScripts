"""
Ping sweep script.
Reads a list of IPs/hosts from an input file and writes reachability results to an output file.

Examples:
  ping_sweep.py -i hosts.txt -o results.txt
  ping_sweep.py -i hosts.txt -v
"""

import argparse
import subprocess
import platform
import math


def ping_host(host, count=1, timeout_ms=1000, verbose=False):
    """
    Ping a host with a given count and timeout.

    :param host: IP address or hostname to ping
    :param count: number of echo requests to send
    :param timeout_ms: timeout in milliseconds (Windows) or will be converted to seconds (Unix)
    :param verbose: if True, prints detailed ping output
    :return: True if ping succeeds, False otherwise
    """
    system = platform.system().lower()
    if system == 'windows':
        cmd = ['ping', '-n', str(count), '-w', str(timeout_ms), host]
    else:
        timeout_s = math.ceil(timeout_ms / 1000)
        cmd = ['ping', '-c', str(count), '-W', str(timeout_s), host]

    if verbose:
        stdout = None
        stderr = None
    else:
        stdout = subprocess.DEVNULL
        stderr = subprocess.DEVNULL

    try:
        result = subprocess.run(cmd, stdout=stdout, stderr=stderr)
        return result.returncode == 0
    except Exception:
        return False


def main():
    parser = argparse.ArgumentParser(
        description='Ping sweep script: reads hosts from a file and reports reachability.',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  ping_sweep.py -i hosts.txt -o results.txt
  ping_sweep.py --input hosts.txt --verbose
  ping_sweep.py -i hosts.txt -c 3 -t 2000
'''      
    )
    parser.add_argument('-i', '--input', required=True,
                        help='Input file with one host/IP per line')
    parser.add_argument('-o', '--output', default='results.txt',
                        help='Output file to write results')
    parser.add_argument('-t', '--timeout', type=int, default=1000,
                        help='Timeout in milliseconds for each ping')
    parser.add_argument('-c', '--count', type=int, default=1,
                        help='Number of pings to send per host')
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='Print detailed ping output for each host')
    args = parser.parse_args()

    # Read hosts
    with open(args.input, 'r') as f:
        hosts = [line.strip() for line in f if line.strip()]

    # Perform ping sweep
    with open(args.output, 'w') as out_f:
        for host in hosts:
            reachable = ping_host(
                host,
                count=args.count,
                timeout_ms=args.timeout,
                verbose=args.verbose
            )
            status = 'reachable' if reachable else 'unreachable'
            out_f.write(f"{host},{status}\n")
            print(f"{host}: {status}")

if __name__ == '__main__':
    main()
