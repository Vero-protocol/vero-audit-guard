import os
import sys
import json
from datetime import datetime, timedelta
from collections import Counter

def synthesize_reports(reports_dir):
    """
    Report Synthesizer: Compiles weekly security metrics from JSON scan reports.
    """
    now = datetime.now()
    one_week_ago = now - timedelta(days=7)
    
    total_files_scanned = 0
    severity_counts = Counter()
    rules_triggered = Counter()
    processed_reports = 0

    if not os.path.exists(reports_dir):
        print(f"[!] Reports directory not found: {reports_dir}")
        return None

    for root, _, files in os.walk(reports_dir):
        for file in files:
            if file.endswith('.json'):
                path = os.path.join(root, file)
                
                # Check file modification time to see if it's within the last week
                mtime = datetime.fromtimestamp(os.path.getmtime(path))
                if mtime >= one_week_ago:
                    try:
                        with open(path, 'r', encoding='utf-8') as f:
                            data = json.load(f)
                            processed_reports += 1
                            total_files_scanned += data.get("total_files", 0)
                            
                            findings = data.get("findings", [])
                            for finding in findings:
                                severity_counts[finding.get("severity", "UNKNOWN")] += 1
                                rules_triggered[finding.get("rule", "UNKNOWN")] += 1
                    except Exception as e:
                        print(f"[-] Could not parse {file}: {e}")

    report_content = [
        "# Weekly Security Metrics Report",
        f"**Generated:** {now.strftime('%Y-%m-%d %H:%M:%S')} (UTC)",
        f"**Reporting Period:** {one_week_ago.strftime('%Y-%m-%d')} to {now.strftime('%Y-%m-%d')}",
        "",
        "## Executive Summary",
        f"- **Reports Processed:** {processed_reports}",
        f"- **Total Files Scanned:** {total_files_scanned}",
        "",
        "## Findings by Severity",
    ]
    
    for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]:
        if severity_counts[severity] > 0 or severity == "CRITICAL":
            report_content.append(f"- **{severity}:** {severity_counts[severity]}")
            
    report_content.extend([
        "",
        "## Top Triggered Rules"
    ])
    
    if rules_triggered:
        for rule, count in rules_triggered.most_common(5):
            report_content.append(f"- `{rule}`: {count} occurrences")
    else:
        report_content.append("- *No rules triggered.*")
        
    report_content.extend([
        "",
        "---",
        "*This report was automatically synthesized by the Vero Audit Guard Report Synthesizer to improve visibility into security posture.*"
    ])
    
    return "\n".join(report_content)

def main():
    reports_dir = sys.argv[1] if len(sys.argv) > 1 else "../reports"
    print(f"[*] Compiling weekly metrics from {reports_dir}...")
    
    markdown_report = synthesize_reports(reports_dir)
    
    if markdown_report:
        output_path = os.path.join(reports_dir, "weekly_metrics.md")
        try:
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(markdown_report)
            print(f"[+] Report published successfully to: {output_path}")
            print("\n" + markdown_report)
        except Exception as e:
            print(f"[!] Failed to write report: {e}")
    else:
        print("[-] Could not synthesize report.")

if __name__ == "__main__":
    main()
