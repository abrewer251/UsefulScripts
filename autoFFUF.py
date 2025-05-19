import os
import subprocess
from pathlib import Path
from tqdm import tqdm
import sys

def read_file_lines(filepath):
    with open(filepath, 'r') as f:
        return [line.strip() for line in f if line.strip()]

def run_ffuf_scan(ip, port, wordlist, output_file):
    url = f"http://{ip}:{port}/FUZZ"
    try:
        result = subprocess.run(
            ['ffuf', '-t', '20', '-u', url, '-w', wordlist, '-o', '-', '-of', 'csv'],
            check=True,
            capture_output=True,
            text=True
        )
        with open(output_file, 'a') as out:
            out.write(f"\n===== Port {port} =====\n")
            out.write(result.stdout)
    except subprocess.CalledProcessError as e:
        with open(output_file, 'a') as out:
            out.write(f"\n[!] ffuf scan failed for {ip}:{port} -> {e}\n")

def main(ip_file, wordlist_file, hostname_file, port_file, output_dir):
    if not all(os.path.isfile(f) for f in [ip_file, wordlist_file, hostname_file, port_file]):
        print("[!] One or more input files not found.")
        sys.exit(1)

    ips = read_file_lines(ip_file)
    hostnames = read_file_lines(hostname_file)
    ports = read_file_lines(port_file)
    wordlist = wordlist_file  # pass the path to ffuf

    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    total_tasks = len(ips) * len(ports)
    print(f"[*] Starting ffuf scans on {len(ips)} targets across {len(ports)} ports ({total_tasks} total scans)...")

    with tqdm(total=total_tasks, desc="ffuf Scans", unit="scan") as pbar:
        for ip, hostname in zip(ips, hostnames):
            output_file = output_path / f"{hostname}.csv"
            with open(output_file, 'w') as f:
                f.write(f"# ffuf scan results for {ip} ({hostname})\n")

            for port in ports:
                tqdm.write(f"[*] Scanning {ip}:{port} ({hostname})")
                run_ffuf_scan(ip, port, wordlist, output_file)
                pbar.update(1)

    print(f"[+] All scans completed. Grouped output saved to: {output_dir}")

if __name__ == "__main__":
    if len(sys.argv) != 6:
        print("Usage: python ffuf_batch.py <ip_list.txt> <wordlist.txt> <hostname_list.txt> <port_list.txt> <output_directory>")
        sys.exit(1)

    main(sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5])
