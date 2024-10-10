import re
import json
import platform

with open('.last_perf_report.json', 'r') as file:
    data = json.load(file)

md_report = "# Test reports\n"
md_report += f"Architecture: {platform.machine()}\n"
md_report += f"Kernel: {platform.release()}\n"
md_report += f"OS: {platform.system()}\n"
md_report += f"Hostname: {platform.node()}\n"
md_report += f"\n"

for key, elem in data.items():
    md_report += f"## Test: {key}\n"
    md_report += f"\n"
    md_report += f"Number of workers: {elem['number_of_workers']}\n"
    md_report += f"\n"
    md_report += f"Average throughput per worker: {elem['average_throughput']:.2f} Mbit/s\n"
    md_report += f"Total throughput: {elem['total_throughput']:.2f} Mbit/s\n"
    md_report += f"\n"

print(md_report)
