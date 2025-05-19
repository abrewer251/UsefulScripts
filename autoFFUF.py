import os
import subprocess
from pathlib import Path
from tqdm import tqdm
import sys

def read_file_lines(filepath):
    with open(filepath, 'r') as f:
        return [line.strip() for line in f if line.strip()]

def run_ffuf_raw(ip, port, protocol, wordlist):
    url = f"{protocol}://{ip}:{port}/FUZZ"
    try:
        result = subprocess.run(
            ['ffuf', '-u', url, '-w', wordlist, '-t', '20', '-maxtime-job', '3'],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=15
        )
        return result.stdout
    except subprocess.TimeoutExpired:
        return f"[!] ffuf scan timed out for {url}\n"
    except subprocess.CalledProcessError as e:
        return f"[!] ffuf scan failed for {url}\n{e.output if e.output else ''}"

def main(ip_file, wordlist_file, hostname_file, port_file, output_dir):
    if not all(os.path.isfile(f) for f in [ip_file, wordlist_file, hostname_file, port_file]):
        print("[!] One or more input files not found.")
        sys.exit(1)

    ips = read_file_lines(ip_file)
    hostnames = read_file_lines(hostname_file)
    ports = read_file_lines(port_file)
    wordlist = wordlist_file

    if len(ips) != len(hostnames):
        print("[!] IP and hostname lists must be the same length.")
        sys.exit(1)

    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    output_file = output_path / "all_results.txt"

    protocols = ['http', 'https']
    total_tasks = len(ips) * len(ports) * len(protocols)

    print(f"[*] Running ffuf scans: {total_tasks} total")
    with open(output_file, 'w') as f:
        f.write("==== FFUF SCAN RESULTS ====\n")

    with tqdm(total=total_tasks, desc="ffuf Scans", unit="scan") as pbar:
        for ip, hostname in zip(ips, hostnames):
            for port in ports:
                for protocol in protocols:
                    scan_label = f"{hostname} {protocol}://{ip}:{port}/FUZZ"
                    tqdm.write(f"[*] Scanning {scan_label}")
                    ffuf_output = run_ffuf_raw(ip, port, protocol, wordlist)
                    with open(output_file, 'a') as f:
                        f.write(f"\n===== {scan_label} =====\n")
                        f.write(ffuf_output)
                        f.write("\n")
                    pbar.update(1)

    print(f"[+] All scans completed. Raw output saved to: {output_file}")

if __name__ == "__main__":
    if len(sys.argv) != 6:
        print("Usage: python ffuf_batch_raw_single_file.py <ip_list.txt> <wordlist.txt> <hostname_list.txt> <port_list.txt> <output_directory>")
        sys.exit(1)

    main(sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5])
