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

# Local import from the new handler file
from git_handler import clone_repository_from_env

from langchain_google_genai import ChatGoogleGenerativeAI
from langchain_core.prompts import PromptTemplate

#from langchain.prompts import PromptTemplate
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
    print("(This requires the Go programming language to be installed and configured correctly.)", flush=True)
    try:
        install_command = [
            "go", "install", "github.com/google/osv-scanner/v2/cmd/osv-scanner@latest"
        ]
        
        # Capture current GOBIN to restore later
        original_gobin = os.environ.get('GOBIN')
        temp_gobin_created = False

        # If GOBIN is not set, create a temporary one and add to PATH for this process
        if not original_gobin:
            temp_gobin_dir = tempfile.mkdtemp()
            os.environ['GOBIN'] = temp_gobin_dir
            # Ensure the temporary GOBIN is at the start of PATH to be found first
            os.environ['PATH'] = f"{temp_gobin_dir}:{os.environ.get('PATH', '')}"
            temp_gobin_created = True
        
        # Execute the Go install command
        process = subprocess.run(install_command, check=False, capture_output=True, text=True)
        
        # Check if osv-scanner is now in the PATH after installation
        if shutil.which("osv-scanner"):
            print("✅ OSV-Scanner installed successfully.", flush=True)
            return True
        else:
            print("❌ Installation seemed to succeed, but 'osv-scanner' is still not in the PATH.", flush=True)
            print("   Please ensure your Go bin directory (e.g., $GOPATH/bin or $GOBIN) is in your system's PATH.", flush=True)
            print(f"   Go install stdout:\n{process.stdout}\nGo install stderr:\n{process.stderr}", flush=True)
            return False
    except FileNotFoundError:
        print("❌ ERROR: The 'go' command was not found.", flush=True)
        print("   Please install the Go programming language first: https://go.dev/doc/install", flush=True)
        return False
    except subprocess.CalledProcessError as e:
        print(f"❌ ERROR: Failed to install OSV-Scanner. Return code: {e.returncode}", flush=True)
        print(f"   Stderr: {e.stderr}", flush=True)
        return False
    finally:
        # Clean up temporary GOBIN if it was created
        if temp_gobin_created:
            if 'GOBIN' in os.environ:
                os.environ['PATH'] = os.environ['PATH'].replace(f"{os.environ['GOBIN']}:", "")
                del os.environ['GOBIN']
            shutil.rmtree(temp_gobin_dir)
        elif original_gobin is not None:
            os.environ['GOBIN'] = original_gobin # Restore original GOBIN


def get_llm():
    """
    Checks environment variables and returns the Gemini LLM instance.
    """
    google_key = os.getenv("GOOGLE_API_KEY")
    if google_key:
        print("🔑 Google API key found. Using Google Gemini model (gemini-2.5-flash).", flush=True)
        return ChatGoogleGenerativeAI(model="gemini-2.5-flash", temperature=0.1)
    else:
        raise ValueError("Could not find GOOGLE_API_KEY in .env file.")


def analyze_code(llm, file_content, file_name):
    """Uses the provided LLM and LangChain to analyze a single file's content."""
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
    """Executes the OSV-Scanner tool on the repository path."""
    print("\nRunning OSV-Scanner for dependencies...", flush=True)
    try:
        # Ensure osv-scanner is callable
        if not shutil.which("osv-scanner"):
            print("❌ ERROR: 'osv-scanner' command not found. Please ensure it's installed and in PATH.", flush=True)
            return None

        result = subprocess.run(
            ['osv-scanner', '--recursive', '--json', repo_path],
            cwd=repo_path,
            capture_output=True,
            text=True,
            check=False
        )

        if result.returncode not in (0, 1): # 0 for no vulnerabilities, 1 for vulnerabilities found
            print(f"❌ OSV-Scanner encountered an error (return code {result.returncode}):\n{result.stderr}", flush=True)
            return None

        if result.stderr.strip():
            # OSV-Scanner often prints non-critical warnings/info to stderr, capture and log.
            # Filter out common benign messages if desired, e.g., "no lockfiles found"
            filtered_stderr = [line for line in result.stderr.splitlines() if not "no lockfiles found" in line.lower()]
            if filtered_stderr:
                print(f"OSV-Scanner stderr output:\n{''.join(filtered_stderr)}", flush=True)

        if not result.stdout.strip():
            print("✅ OSV-Scanner ran successfully and found no vulnerabilities.", flush=True)
            return None

        return json.loads(result.stdout)

    except FileNotFoundError:
        print("❌ ERROR: 'osv-scanner' command not found. Please install it or add to PATH.", flush=True)
        return None
    except json.JSONDecodeError:
        print(f"❌ ERROR: Could not parse OSV-Scanner JSON output. Raw output:\n{result.stdout}", flush=True)
        return None
    except Exception as e:
        print(f"❌ An unexpected error occurred while running OSV-Scanner: {e}", flush=True)
        return None


def get_severity(vuln_type):
    """Assigns a severity level to a vulnerability type."""
    vuln_type = vuln_type.lower()
    if "injection" in vuln_type or "command execution" in vuln_type or "rce" in vuln_type or "remote code" in vuln_type:
        return "🔴 Critical"
    elif "secret" in vuln_type or "privileged" in vuln_type or "xss" in vuln_type or "deserialization" in vuln_type or "authentication bypass" in vuln_type:
        return "🟠 High"
    elif "insecure" in vuln_type or "exposure" in vuln_type or "misconfiguration" in vuln_type:
        return "🟡 Medium"
    else:
        return "🔵 Low" # Default for unknown or less critical


def run_scan_logic(repo_url):
    """
    Core scan logic, refactored to be callable by a web app or CLI.
    Returns (report_content_as_string, report_filename_suggestion).
    Raises an exception if setup or cloning fails.
    """
    # Redirect stdout temporarily to capture print statements only for immediate logging,
    # then restore for the main report generation.
    original_stdout = sys.stdout
    sys.stdout = io.StringIO()

    try:
        # ensure_osv_scanner() is called at the app startup, so we trust it's there.
        # However, a secondary check for `shutil.which("osv-scanner")` is still good in `run_osv_scanner`.
        
        llm = get_llm()
    
        ai_findings = []
        osv_results = None

        with tempfile.TemporaryDirectory() as temp_dir:
            print(f"Cloning repository {repo_url} into temporary directory: {temp_dir}", flush=True)
            clone_successful = clone_repository_from_env(repo_url, temp_dir)
            
            if not clone_successful:
                raise RuntimeError("Repository cloning failed. Check URL, permissions, and .env configuration.")

            osv_results = run_osv_scanner(temp_dir)

            print("\nStarting AI source code scan...", flush=True)
            for subdir, _, files in os.walk(temp_dir):
                if ".git" in subdir:
                    continue
                for file in files:
                    # Extended common file types including config and env files for secrets
                    if file.endswith(('.py', '.js', '.java', '.go', '.rb', '.ts', '.tf', '.sh', '.yml', '.yaml', '.json', '.xml', 'Dockerfile', 'Jenkinsfile', '.env', '.config', '.conf', '.properties')):
                        file_path = os.path.join(subdir, file)
                        relative_path = os.path.relpath(file_path, temp_dir)

                        print(f"Scanning file: {relative_path}", flush=True)
                        try:
                            with open(file_path, 'r', errors='ignore') as f:
                                content = f.read()
                                if len(content.strip()) == 0:
                                    print(f"  └─ Skipping empty file: {relative_path}", flush=True)
                                    continue
                                if len(content) > 50000: # Skip very large files to prevent LLM overload
                                    print(f"  └─ Skipping large file ({len(content)} bytes): {relative_path}", flush=True)
                                    continue
                                
                                analysis_result = analyze_code(llm, content, relative_path)
                                
                                cleaned_json_str = analysis_result.strip()
                                # Clean markdown JSON block
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
                                                # Ensure required keys exist, or provide defaults
                                                vuln['file_path'] = relative_path
                                                vuln.setdefault('line_number', 'N/A')
                                                vuln.setdefault('vulnerability_type', 'Unknown')
                                                vuln.setdefault('risk_explanation', 'No details provided.')
                                                vuln.setdefault('suggested_fix', 'No fix suggested.')
                                                ai_findings.append(vuln)
                                except json.JSONDecodeError:
                                    print(f"  └─ ⚠️ WARNING: AI returned non-JSON output for {relative_path}. Raw output (truncated): {cleaned_json_str[:200]}...", flush=True)
                        
                        except Exception as e:
                            print(f"  └─ ❌ ERROR: Could not process file {relative_path}: {e}", flush=True)

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
            # Sort findings by severity (Critical, High, Medium, Low)
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
                            
                            # Extract severity from OSV output
                            osv_severity = "N/A"
                            if vuln.get('severity'):
                                # OSV-Scanner severity can be a list, take the first one or combine
                                sev_entry = vuln['severity'][0]
                                sev_type = sev_entry.get('type')
                                sev_score = sev_entry.get('score')
                                if sev_type and sev_score is not None:
                                    osv_severity = f"{sev_type} (Score: {sev_score})"
                                elif sev_type:
                                    osv_severity = sev_type
                            report_lines.append(f"  - **Severity:** {osv_severity}")

                            report_lines.append(f"  - **Summary:** {vuln.get('summary', 'No summary provided.')}")
                            report_lines.append(f"  - **Details:** {vuln.get('details', 'No details provided.')[:500]}...") # Truncate long details
                            if vuln.get('database_specific') and vuln['database_specific'].get('url'):
                                report_lines.append(f"  - **More Info:** [{vuln['id']}]({vuln['database_specific']['url']})")
                            report_lines.append("") # Empty line for readability
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
            for finding in sorted_ai_findings: # Use sorted findings
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
                    # Render code blocks properly if present, otherwise wrap in one
                    if suggested_fix.count("```") >= 2:
                        report_lines.append(f"{suggested_fix}")
                    else:
                        report_lines.append(f"```\n{suggested_fix}\n```") # Ensure simple fixes are also code blocks
                    report_lines.append("<br>")
        
        timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        report_filename = f"ai_repoguard_{timestamp}.md"
        
        report_content = "\n".join(report_lines)
        print(f"\n✅ Scan complete! Report generated.", flush=True)
        return report_content, report_filename
    except Exception as e:
        print(f"❌ Critical error during scan: {e}", flush=True)
        raise # Re-raise to be caught by the Flask app
    finally:
        # Restore original stdout
        sys.stdout = original_stdout

# This __name__ block allows the script to be run directly for CLI testing
# without running the Flask app.
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Hybrid AI & Dependency Security Scanner (CLI Mode)")
    parser.add_argument("--repo_url", required=True, help="URL of the Git repository to scan")
    args = parser.parse_args()

    # Ensure osv-scanner is installed for CLI mode
    if not ensure_osv_scanner():
        print("\nHalting CLI script because OSV-Scanner is not available.")
        sys.exit(1)

    try:
        report_content, report_filename = run_scan_logic(args.repo_url)
        with open(report_filename, "w") as report_file:
            report_file.write(report_content)
        print(f"\nCLI Scan complete! Report saved to {report_filename}")
    except Exception as e:
        print(f"CLI Scan failed: {e}")
        sys.exit(1)
