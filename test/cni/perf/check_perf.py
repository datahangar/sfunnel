import argparse
import json
import os
from pyroute2 import netns
import re
import requests
import subprocess
import sys
import time

def set_ns():
    ns_name = os.getenv('NETNS')
    if not ns_name:
        return
    netns.setns(ns_name)

def get_lb_ip():
    return subprocess.getoutput(
        "minikube kubectl -- get service my-loadbalancer-service -o jsonpath='{.status.loadBalancer.ingress[0].ip}'"
    )

def get_throughput(output):
    for line in output.splitlines():
        line = line.lower()
        if not line.startswith("[") or "bits" not in line:
            continue
        if re.search(r'\d+\s+\S+', line):
            return float(line.split()[6])

def check_perf_iperf(test_name, fqdn, results, target_ports, src_ips=[]):
    N_WORKERS = int(os.getenv('N_WORKERS', 4))
    debug = int(os.getenv('DEBUG', 0)) == 1
    mss = 1500 - 40 - 20 #IP+TCP overhead + funneling TCP overhead
    CMD = f"iperf --mss {mss} -f m"
    total_throughput = 0
    print(f"[{test_name}] Starting {N_WORKERS} workers against '{fqdn}' with target_ports='{target_ports}', src_ips='{src_ips}'")

    # Start iperf workers in parallel
    src_opt = ""
    processes = []
    for i in range(1, N_WORKERS + 1):
        p = target_ports[i%len(target_ports)]
        if len(src_ips):
            src_opt = "-B " + src_ips[i%len(src_ips)]
        cmd = f"{CMD} -c {fqdn} -p {p} {src_opt}"
        if debug:
            print(cmd)
        p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        processes.append({ 'id': i, 'process': p})

    # Wait for all workers to finish
    for p_ in processes:
        p = p_["process"]
        p.wait()
        output = p.communicate()[0].decode('utf-8')
        if debug:
            print(f"Worker output {p_['id']}:\n{output}")
        total_throughput += get_throughput(output)

    avg_throughput = total_throughput / N_WORKERS
    results[test_name] = {
        'number_of_workers': N_WORKERS,
        'total_throughput': total_throughput,
        'average_throughput': avg_throughput
    }

    print(f"[{test_name}] Total throughput: {total_throughput:.2f} Mbit/s, Average throughput: {avg_throughput:.2f} Mbit/s")
    return results

def check_perf_requests(test_name, fqdn, results, port):
    fqdn = "http://"+fqdn+":"+str(port)+"/testfile.bin"

    print(f"{fqdn}")

    start = time.time()
    r = requests.get(fqdn, stream=True)
    total = sum(len(chunk) for chunk in r.iter_content(8192))
    elapsed = time.time() - start

    throughput = (total * 8) / 1e6 / elapsed
    results[test_name] = {
        'number_of_workers': 1,
        'total_throughput': throughput,
        'average_throughput': throughput
    }
    print(f"[{test_name}] Throughput: {throughput:.2f} Mbit/s")

    return results

def main():
    parser = argparse.ArgumentParser(description="Check perf against LB service.")
    parser.add_argument("command", help="Command to execute {iperf, wget}")
    args = parser.parse_args()

    LB_IP = get_lb_ip()
    results = {}

    # Enter the right NS first
    set_ns()

    if args.command == "iperf":
        results = check_perf_iperf("test_port_80 (calibration)", LB_IP, results, [80])
        results = check_perf_iperf("test_port_8080", LB_IP, results, [8080])
        results = check_perf_iperf("test_port_80_8080", LB_IP, results, [80, 8080])
    else:
        results = check_perf_requests("requests_80", LB_IP, results, 80)
        results = check_perf_requests("requests_8080", LB_IP, results, 8080)

    filename=f".{args.command}_report.json"
    if os.environ.get('DISABLE_GSO') == "1":
        filename = f".{args.command}_report_nogso.json"

    with open(filename, 'w') as json_file:
        json.dump(results, json_file, indent=4)

if __name__ == "__main__":
    main()
