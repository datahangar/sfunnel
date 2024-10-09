import os
import subprocess
import sys
import re
import json

def get_lb_ip():
    return sys.argv[1] if len(sys.argv) > 1 else subprocess.getoutput(
        "minikube kubectl -- get service my-loadbalancer-service -o jsonpath='{.status.loadBalancer.ingress[0].ip}'"
    )


def get_throughput(output):
    for line in output.splitlines():
        line = line.lower()
        if not line.startswith("[") or "bits" not in line:
            continue
        if re.search(r'\d+\s+\S+', line):
            return float(line.split()[6])

def check_perf(test_name, fqdn, results, target_ports, src_ips=[]):
    N_WORKERS = int(os.getenv('N_WORKERS', 4))
    debug = int(os.getenv('DEBUG', 0)) == 1
    CMD = f"sudo ip netns exec {os.getenv('NETNS')} iperf -f m" if os.getenv('NETNS') else "iperf -f m"
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

def main():
    LB_IP = get_lb_ip()

    results = {}

    check_perf("test_port_80 (calibration)", LB_IP, results, [80])
    check_perf("test_port_8080", LB_IP, results, [8080])
    check_perf("test_port_80_8080", LB_IP, results, [80, 8080])

    with open('.last_perf_report.json', 'w') as json_file:
        json.dump(results, json_file, indent=4)

if __name__ == "__main__":
    main()
