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

md_report += f"## Results\n"

baseline = data['test_port_80 (calibration)']
baseline_avg = baseline['average_throughput']
baseline_total = baseline['total_throughput']

md_report += f"\n"
md_report += f"Number of workers: {baseline['number_of_workers']}\n\n"
md_report += f"| Fixture      | Avg Throughput per Worker (Mbit/s)  | Total Throughput (Mbit/s)  | Degradation (%)  |\n"
md_report += f"|--------------|-------------------------------------|----------------------------|------------------|\n"

for key, elem in data.items():
    avg = elem['average_throughput']
    total = elem['total_throughput']
    degradation = ((baseline_total - total) / baseline_total) * 100
    md_report += f"| {key} | {elem['average_throughput']:.2f} | {elem['total_throughput']:.2f} | {degradation:.2f}% |\n"

print(md_report)
