import re
import json
import platform
import os

with open('.last_perf_report.json', 'r') as file:
    data = json.load(file)

md_report = "# Performance report\n"
md_report += f"\n"

md_report += f"## General information \n"
md_report += f"\n"
md_report += f"Number of K8s nodes: {os.getenv('NODES', 'unknown')}\n"
md_report += f"CNI: {os.getenv('CNI', 'unknown')}\n"
md_report += f"\n"

md_report += f"## Runner info\n"
md_report += f"\n"
md_report += f"Hostname: {platform.node()}\n"
md_report += f"OS: {platform.system()}\n"
md_report += f"Architecture: {platform.machine()}\n"
md_report += f"Kernel: {platform.release()} {platform.version()}\n"
md_report += f"\n"

md_report += f"## Results\n"
md_report += f"\n"
for key, elem in data.items():
    md_report += f"### Fixture: {key}\n"
    md_report += f"\n"
    md_report += f"Number of workers: {elem['number_of_workers']}\n"
    md_report += f"\n"
    md_report += f"Average throughput per worker: {elem['average_throughput']:.2f} Mbit/s\n"
    md_report += f"Total throughput: {elem['total_throughput']:.2f} Mbit/s\n"
    md_report += f"\n"

print(md_report)
