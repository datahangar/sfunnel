import re
import json
import platform
import os
import sys
import argparse

def print_header():
    md_report = "# Performance report\n"
    md_report += f"\n"

    md_report += f"## General information \n"
    md_report += f"\n"
    md_report += f"Number of K8s nodes: `{os.getenv('NODES', 'unknown')}`\n"
    md_report += f"CNI: `{os.getenv('CNI', 'unknown')}`\n"
    md_report += f"\n"

    md_report += f"<details>\n<summary> <b>Runner info details</b> </summary>\n\n"
    md_report += f"Hostname: `{platform.node()}`\n"
    md_report += f"OS: `{platform.system()}`\n"
    md_report += f"Architecture: `{platform.machine()}`\n"
    md_report += f"Kernel: `{platform.release()} {platform.version()}`\n\n"
    md_report += f"</details>"
    md_report += f"\n\n"

    print(md_report)

def print_results(filename:str, results_desc:str):
    with open(filename, 'r') as file:
        data = json.load(file)

    md_report = f"## Results {results_desc}\n"

    baseline = data['test_port_80 (calibration)']
    baseline_avg = baseline['average_throughput']
    baseline_total = baseline['total_throughput']

    md_report += f"\n"
    md_report += f"Number of workers: {baseline['number_of_workers']}\n\n"
    md_report += f"| Flow/s       | Avg Throughput per Worker (Mbit/s)  | Total Throughput (Mbit/s)  | Degradation (%)  |\n"
    md_report += f"|--------------|-------------------------------------|----------------------------|------------------|\n"

    for key, elem in data.items():
        avg = elem['average_throughput']
        total = elem['total_throughput']
        degradation = ((baseline_total - total) / baseline_total) * 100
        md_report += f"| {key} | {elem['average_throughput']:.2f} | {elem['total_throughput']:.2f} | **{degradation:.2f}%** |\n"

    print(md_report)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate the performance report")
    parser.add_argument("file", help="JSON file with results")
    parser.add_argument("description", help="Results description")
    parser.add_argument("--no-header", action="store_true", help="Skip printing the header")
    args = parser.parse_args()

    if not args.no_header:
        print_header()
    print_results(args.file, args.description)
