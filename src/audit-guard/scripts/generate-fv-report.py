#!/usr/bin/env python3
import subprocess
import os
import json
import datetime

def run_command(command_args, cwd=None):
    try:
        result = subprocess.run(command_args, check=True, capture_output=True, text=True, cwd=cwd)
        return result.stdout
    except subprocess.CalledProcessError as e:
        print(f"Error running command: {' '.join(command_args)}")
        print(e.stderr)
        return None

def main():
    root_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
    audit_guard_dir = os.path.join(root_dir, "src", "audit-guard")
    reports_dir = os.path.join(root_dir, "reports")
    os.makedirs(reports_dir, exist_ok=True)

    print("[*] Generating Formal Verification Report...")

    # 1. Run Concurrency Visualizer
    print("[*] Running Concurrency Visualizer...")
    visualizer_path = os.path.join(audit_guard_dir, "visualizer.py")
    # Scan subdirectories to avoid timeout on root
    concurrency_output = ""
    for sub in ["src", "scanner-engine", "anomaly-detector", "verifiable-audit-trail"]:
        target = os.path.join(root_dir, sub)
        if os.path.exists(target):
            concurrency_output += run_command(["python3", visualizer_path, target]) or ""

    # 2. Run Scanner Engine (if built)
    print("[*] Checking Scanner Engine...")
    scanner_bin = os.path.join(root_dir, "scanner-engine", "target", "release", "scanner")
    scanner_output = ""
    if os.path.exists(scanner_bin):
        print("[*] Running Scanner Engine...")
        scanner_output = run_command([scanner_bin, root_dir])
    else:
        print("[!] Scanner Engine not built. Skipping live scan.")
        # Try to read latest-scan.json if it exists
        report_path = os.path.join(reports_dir, "latest-scan.json")
        if os.path.exists(report_path):
            with open(report_path, "r") as f:
                scanner_output = f.read()

    # 3. Generate Markdown Report
    report_md = f"""# Formal Verification Export Report
Generated on: {datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")}

## Concurrency Analysis (Deadlock Freedom)
```
{concurrency_output if concurrency_output else "No output from visualizer."}
```

## Static Analysis (Security Scanner)
"""

    if scanner_output:
        try:
            report_json = json.loads(scanner_output)
            report_md += f"**Target:** {report_json.get('target', 'N/A')}\n"
            report_md += f"**Total Files Scanned:** {report_json.get('total_files', 0)}\n"
            report_md += f"**Report Hash:** `{report_json.get('report_hash', 'N/A')}`\n\n"

            findings = report_json.get('findings', [])
            if findings:
                report_md += "### Findings\n"
                report_md += "| File | Line | Rule | Severity | Snippet |\n"
                report_md += "|------|------|------|----------|---------|\n"
                for f in findings:
                    report_md += f"| {f['file']} | {f['line']} | {f['rule']} | {f['severity']} | `{f['snippet']}` |\n"
            else:
                report_md += "✅ No security findings detected.\n"
        except Exception as e:
            report_md += f"Error parsing scanner output: {e}\n"
            report_md += f"```json\n{scanner_output}\n```"
    else:
        report_md += "No scanner output available.\n"

    report_path = os.path.join(reports_dir, "fv-report.md")
    with open(report_path, "w") as f:
        f.write(report_md)

    print(f"[+] FV Report generated: {report_path}")

if __name__ == "__main__":
    main()
