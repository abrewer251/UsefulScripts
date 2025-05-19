import os
import subprocess
import json
from pathlib import Path
from tqdm import tqdm
import sys

def read_file_lines(filepath):
    with open(filepath, 'r') as f:
        return [line.strip() for line in f if line.strip()]

def run_ffuf_json(ip, port, protocol, wordlist):
    url = f"{protocol}://{ip}:{port}/FUZZ"
    try:
        result = subprocess.run(
            ['ffuf', '-u', url, '-w', wordlist, '-t', '20', '-of', 'json', '-o', '-', '-maxtime-job', '3'],
            check=True,
            capture_output=True,
            text=True,
            timeout=15
        )
        try:
            return json.loads(result.stdout)
        except json.JSONDecodeError:
            return {
                "results": [],
                "error": f"Invalid JSON output.\nstdout: {result.stdout.strip()}\nstderr: {result.stderr.strip()}"
            }
    except subprocess.TimeoutExpired:
        return {"results": [], "error": "Timed out"}
    except subprocess.CalledProcessError as e:
        return {
            "results": [],
            "error": f"ffuf failed: {e.stderr.strip() if e.stderr else 'No stderr'}"
        }

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

    output_data = []
    protocols = ['http', 'https']
    total_tasks = len(ips) * len(ports) * len(protocols)

    print(f"[*] Starting ffuf scans on {len(ips)} targets × {len(ports)} ports × {len(protocols)} protocols = {total_tasks} scans")

    with tqdm(total=total_tasks, desc="ffuf Scans", unit="scan") as pbar:
        for ip, hostname in zip(ips, hostnames):
            for port in ports:
                for protocol in protocols:
                    tqdm.write(f"[*] Scanning {protocol}://{ip}:{port}/FUZZ ({hostname})")
                    result = run_ffuf_json(ip, port, protocol, wordlist)

                    if result.get("results"):
                        for entry in result["results"]:
                            output_data.append({
                                "hostname": hostname,
                                "ip": ip,
                                "protocol": protocol,
                                "port": port,
                                "url": entry.get("url"),
                                "status_code": entry.get("status"),
                                "length": entry.get("length"),
                                "words": entry.get("words"),
                                "lines": entry.get("lines")
                            })
                    elif result.get("error"):
                        output_data.append({
                            "hostname": hostname,
                            "ip": ip,
                            "protocol": protocol,
                            "port": port,
                            "error": result["error"]
                        })

                    pbar.update(1)

    output_file = output_path / "all_results.json"
    with open(output_file, 'w') as f:
        json.dump(output_data, f, indent=2)

    print(f"[+] All scans completed. Consolidated JSON saved to: {output_file}")

if __name__ == "__main__":
    if len(sys.argv) != 6:
        print("Usage: python ffuf_batch_all_json.py <ip_list.txt> <wordlist.txt> <hostname_list.txt> <port_list.txt> <output_directory>")
        sys.exit(1)

    main(sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5])
