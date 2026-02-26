# scanner_core.py
import os
import argparse
import tempfile
import subprocess
import json
import shutil
from collections import Counter
from datetime import datetime
import sys
import io
import ssl
import certifi

# --- GLOBAL SCAN STATUS ---
scan_status = {
    "running": False,
    "progress": 0,
    "current_file": "",
    "error": None
}

def create_certifi_ssl_context():
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.load_verify_locations(certifi.where())
    return context

ssl._create_default_https_context = create_certifi_ssl_context

# Local import from the new handler file
from git_handler import clone_repository_from_env

from langchain_google_genai import ChatGoogleGenerativeAI
from langchain_core.prompts import PromptTemplate
from langchain_core.output_parsers import StrOutputParser
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()


def ensure_osv_scanner():
    """
    Checks if osv-scanner is installed. If not, attempts to install it via 'go install'.
    Returns True on success, False on failure.
    """
    if shutil.which("osv-scanner"):
        print("✅ OSV-Scanner is already installed.", flush=True)
        return True

    print("⚠️ OSV-Scanner not found. Attempting to install via 'go install'...", flush=True)
    try:
        install_command = ["go", "install", "github.com/google/osv-scanner/v2/cmd/osv-scanner@latest"]
        original_gobin = os.environ.get('GOBIN')
        temp_gobin_created = False

        if not original_gobin:
            temp_gobin_dir = tempfile.mkdtemp()
            os.environ['GOBIN'] = temp_gobin_dir
            os.environ['PATH'] = f"{temp_gobin_dir}:{os.environ.get('PATH', '')}"
            temp_gobin_created = True

        process = subprocess.run(install_command, check=False, capture_output=True, text=True)

        if shutil.which("osv-scanner"):
            print("✅ OSV-Scanner installed successfully.", flush=True)
            return True
        else:
            return False
    except Exception as e:
        print(f"❌ ERROR: Failed to install OSV-Scanner: {e}", flush=True)
        return False
    finally:
        if temp_gobin_created:
            if 'GOBIN' in os.environ:
                os.environ['PATH'] = os.environ['PATH'].replace(f"{os.environ['GOBIN']}:", "")
                del os.environ['GOBIN']
            shutil.rmtree(temp_gobin_dir)
        elif original_gobin is not None:
            os.environ['GOBIN'] = original_gobin


def get_llm():
    google_key = os.getenv("GOOGLE_API_KEY")
    if google_key:
        return ChatGoogleGenerativeAI(model="gemini-2.5-flash", temperature=0.1)
    else:
        raise ValueError("Could not find GOOGLE_API_KEY in .env file.")


def analyze_code(llm, file_content, file_name):
    prompt = PromptTemplate(
        input_variables=["file_name", "code"],
        template="""
        Act as an expert security code reviewer.
        Analyze the following code from the file '{file_name}'.
        Identify potential security vulnerabilities such as SQL injection, XSS, hardcoded secrets,
        insecure deserialization, or command injection.

        For each vulnerability you find, provide a JSON object with the keys:
        "line_number", "vulnerability_type", "risk_explanation", and "suggested_fix".

        If you find no vulnerabilities, return an empty list [].

        CODE:
        ```
        {code}
        ```

        YOUR JSON RESPONSE (must be a valid JSON list inside a json markdown block):
        """
    )
    chain = prompt | llm | StrOutputParser()
    result = chain.invoke({"file_name": file_name, "code": file_content})
    return result


def run_osv_scanner(repo_path):
    try:
        if not shutil.which("osv-scanner"):
            return None
        result = subprocess.run(['osv-scanner', '--recursive', '--json', repo_path], cwd=repo_path, capture_output=True, text=True, check=False)
        if result.returncode not in (0, 1):
            return None
        if not result.stdout.strip():
            return None
        return json.loads(result.stdout)
    except Exception as e:
        return None


def get_severity(vuln_type):
    vuln_type = vuln_type.lower()
    if "injection" in vuln_type or "command execution" in vuln_type or "rce" in vuln_type or "remote code" in vuln_type:
        return "🔴 Critical"
    elif "secret" in vuln_type or "privileged" in vuln_type or "xss" in vuln_type or "deserialization" in vuln_type or "authentication bypass" in vuln_type:
        return "🟠 High"
    elif "insecure" in vuln_type or "exposure" in vuln_type or "misconfiguration" in vuln_type:
        return "🟡 Medium"
    else:
        return "🔵 Low"


def run_scan_logic(repo_url):
    global scan_status
    original_stdout = sys.stdout
    sys.stdout = io.StringIO()

    try:
        llm = get_llm()
        ai_findings = []
        osv_results = None

        with tempfile.TemporaryDirectory() as temp_dir:
            scan_status["current_file"] = "Cloning repository..."
            clone_successful = clone_repository_from_env(repo_url, temp_dir)

            if not clone_successful:
                raise RuntimeError("Repository cloning failed. Check URL, permissions, and .env configuration.")

            scan_status["current_file"] = "Running Dependency Scanner (OSV)..."
            osv_results = run_osv_scanner(temp_dir)

            scan_status["current_file"] = "Gathering files for AI Scan..."
            all_files = []
            for subdir, _, files in os.walk(temp_dir):
                if ".git" in subdir:
                    continue
                for file in files:
                    if file.endswith(('.py', '.js', '.java', '.go', '.rb', '.ts', '.tf', '.sh', '.yml', '.yaml', '.json', '.xml', 'Dockerfile', 'Jenkinsfile', '.env', '.config', '.conf', '.properties')):
                        all_files.append(os.path.join(subdir, file))

            total_files = len(all_files)

            for index, file_path in enumerate(all_files):
                relative_path = os.path.relpath(file_path, temp_dir)
                scan_status["current_file"] = relative_path
                if total_files > 0:
                    scan_status["progress"] = int(((index + 1) / total_files) * 100)

                try:
                    with open(file_path, 'r', errors='ignore') as f:
                        content = f.read()
                        if len(content.strip()) == 0 or len(content) > 50000:
                            continue

                        analysis_result = analyze_code(llm, content, relative_path)

                        cleaned_json_str = analysis_result.strip()
                        if cleaned_json_str.startswith("```json"):
                            cleaned_json_str = cleaned_json_str[7:]
                        if cleaned_json_str.endswith("```"):
                            cleaned_json_str = cleaned_json_str[:-3]
                        cleaned_json_str = cleaned_json_str.strip()

                        try:
                            if cleaned_json_str:
                                vulnerabilities = json.loads(cleaned_json_str)
                                if isinstance(vulnerabilities, list) and vulnerabilities:
                                    for vuln in vulnerabilities:
                                        vuln['file_path'] = relative_path
                                        vuln.setdefault('line_number', 'N/A')
                                        vuln.setdefault('vulnerability_type', 'Unknown')
                                        vuln.setdefault('risk_explanation', 'No details provided.')
                                        vuln.setdefault('suggested_fix', 'No fix suggested.')
                                        ai_findings.append(vuln)
                        except json.JSONDecodeError:
                            pass
                except Exception as e:
                    pass

        # --- Full Report Generation Logic ---
        report_lines = []
        scan_date = datetime.now().strftime("%B %d, %Y %H:%M:%S")

        report_lines.append("# 🛡️ Security Scan Report")
        report_lines.append(f"\n**Repository:** `{repo_url}`")
        report_lines.append(f"**Scan Date:** {scan_date}")
        report_lines.append("\n---")
        report_lines.append("## 📊 Executive Summary")

        total_vulns = len(ai_findings)
        dep_vulns = 0
        if osv_results and osv_results.get('results'):
            for result in osv_results['results']:
                for package in result.get('packages', []):
                    dep_vulns += len(package.get('vulnerabilities', []))
        total_vulns += dep_vulns

        if total_vulns == 0:
            report_lines.append("\n✅ **Excellent!** No security vulnerabilities were found in the source code or dependencies.")
        else:
            report_lines.append(f"\nThe scan identified a total of **{total_vulns} vulnerabilities.**")

        if ai_findings:
            report_lines.append("\n### Source Code Vulnerability Overview")
            report_lines.append("\n| Severity | Vulnerability Type | File Location |")
            report_lines.append("| :--- | :--- | :--- |")
            severity_order = {"🔴 Critical": 4, "🟠 High": 3, "🟡 Medium": 2, "🔵 Low": 1}
            sorted_ai_findings = sorted(ai_findings, key=lambda x: severity_order.get(get_severity(x.get('vulnerability_type', '')), 0), reverse=True)

            for vuln in sorted_ai_findings:
                severity = get_severity(vuln.get('vulnerability_type', ''))
                vuln_type = vuln.get('vulnerability_type', 'Unknown')
                location = f"`{vuln['file_path']}` (Line {vuln.get('line_number', 'N/A')})"
                report_lines.append(f"| {severity} | {vuln_type} | {location} |")
            report_lines.append("\n### Source Code Vulnerability Distribution Chart")
            report_lines.append("\n```mermaid")
            report_lines.append("pie title Source Code Vulnerability Distribution")
            vuln_counts = Counter(v.get('vulnerability_type', 'Unknown') for v in ai_findings)
            for vuln_type, count in vuln_counts.items():
                report_lines.append(f'    "{vuln_type}" : {count}')
            report_lines.append("```")

        report_lines.append("\n---")
        report_lines.append("\n## 📦 Dependency Vulnerabilities (from OSV-Scanner)")
        if osv_results and osv_results.get('results'):
            dependency_vuln_count = 0
            for result in osv_results['results']:
                source = result['source']['path']
                packages_with_vulns = [p for p in result.get('packages', []) if p.get('vulnerabilities')]
                if packages_with_vulns:
                    report_lines.append(f"\n### File: `{source}`")
                    for package in packages_with_vulns:
                        for vuln in package['vulnerabilities']:
                            dependency_vuln_count += 1
                            report_lines.append(f"- **ID:** {vuln['id']}")
                            report_lines.append(f"  - **Package:** {package['package']['name']} (Version: {package['package'].get('version', 'N/A')})")

                            osv_severity = "N/A"
                            if vuln.get('severity'):
                                sev_entry = vuln['severity'][0]
                                sev_type = sev_entry.get('type')
                                sev_score = sev_entry.get('score')
                                if sev_type and sev_score is not None:
                                    osv_severity = f"{sev_type} (Score: {sev_score})"
                                elif sev_type:
                                    osv_severity = sev_type
                            report_lines.append(f"  - **Severity:** {osv_severity}")

                            report_lines.append(f"  - **Summary:** {vuln.get('summary', 'No summary provided.')}")
                            report_lines.append(f"  - **Details:** {vuln.get('details', 'No details provided.')[:500]}...")
                            if vuln.get('database_specific') and vuln['database_specific'].get('url'):
                                report_lines.append(f"  - **More Info:** [{vuln['id']}]({vuln['database_specific']['url']})")
                            report_lines.append("")
            if dependency_vuln_count == 0:
                 report_lines.append("\n✅ **Status:** No dependency vulnerabilities were found by OSV-Scanner.")
        else:
            report_lines.append("\n✅ **Status:** No dependency vulnerabilities were found by OSV-Scanner.")

        report_lines.append("\n\n---\n")
        report_lines.append("## 📝 Source Code Vulnerabilities (from AI Scan)")
        if not ai_findings:
            report_lines.append("\n✅ **Status:** The AI scan found no source code vulnerabilities.")
        else:
            report_lines.append("\nBelow is a detailed breakdown of each vulnerability found in the source code.")
            findings_by_file = {}
            for finding in sorted_ai_findings:
                if finding['file_path'] not in findings_by_file:
                    findings_by_file[finding['file_path']] = []
                findings_by_file[finding['file_path']].append(finding)

            for file_path, vulnerabilities in findings_by_file.items():
                report_lines.append(f"\n### 📄 File: `{file_path}`")
                for vuln in vulnerabilities:
                    severity = get_severity(vuln.get('vulnerability_type', ''))
                    report_lines.append(f"\n#### **Vulnerability: {vuln.get('vulnerability_type', 'Unknown')}**")
                    report_lines.append(f"- **Severity:** {severity}")
                    report_lines.append(f"- **Line:** {vuln.get('line_number', 'N/A')}")
                    report_lines.append("\n**🚨 Risk:**")
                    report_lines.append(vuln.get('risk_explanation', 'No details provided.'))
                    report_lines.append("\n**✅ Recommendation:**")
                    suggested_fix = vuln.get('suggested_fix', 'No fix suggested.')
                    if suggested_fix.count("```") >= 2:
                        report_lines.append(f"{suggested_fix}")
                    else:
                        report_lines.append(f"```\n{suggested_fix}\n```")
                    report_lines.append("<br>")

        timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        report_filename = f"ai_repoguard_{timestamp}.md"

        report_content = "\n".join(report_lines)

        scan_status["progress"] = 100
        scan_status["running"] = False

        return report_content, report_filename
    except Exception as e:
        scan_status["running"] = False
        scan_status["error"] = str(e)
        raise
    finally:
        sys.stdout = original_stdout