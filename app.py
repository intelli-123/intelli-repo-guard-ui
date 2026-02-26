# app.py
import io
import os
import tempfile
import json
import threading
from flask import Flask, render_template, request, send_file, redirect, url_for, flash, jsonify
from datetime import datetime
import shutil
import sys
import ssl
import certifi


def create_certifi_ssl_context():
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.load_verify_locations(certifi.where())
    return context

ssl._create_default_https_context = create_certifi_ssl_context

from scanner_core import run_scan_logic, ensure_osv_scanner, scan_status

app = Flask(__name__)
app.secret_key = os.urandom(24)

current_report_data = {
    "content": None,
    "filename": None,
    "scan_timestamp": None
}

# --- Background Task Runner ---
def run_scan_in_background(repo_url):
    try:
        scan_status["running"] = True
        scan_status["progress"] = 0
        scan_status["error"] = None

        report_content, report_filename = run_scan_logic(repo_url)

        current_report_data["content"] = report_content
        current_report_data["filename"] = report_filename
        current_report_data["scan_timestamp"] = datetime.now()

    except Exception as e:
        scan_status["running"] = False
        scan_status["error"] = str(e)
        app.logger.error(f"Scan failed for {repo_url}", exc_info=True)


@app.route('/')
def index():
    return render_template('index.html', report_available=current_report_data["content"] is not None)

@app.route('/scan', methods=['POST'])
def scan_repository():
    repo_url = request.form['repo_url']
    if not repo_url:
        flash("Repository URL cannot be empty!", "error")
        return redirect(url_for('index'))

    # Start the scan in a separate thread so we can respond to the browser immediately
    thread = threading.Thread(target=run_scan_in_background, args=(repo_url,))
    thread.start()

    # Render the new scanning progress page
    return render_template('scanning.html', repo_url=repo_url)

@app.route('/scan-status')
def get_scan_status():
    # Return the global dictionary as JSON for the frontend to poll
    return jsonify(scan_status)

@app.route('/report')
def view_report():
    if current_report_data["content"]:
        return render_template('report.html',
                               report_content=current_report_data["content"],
                               report_filename=current_report_data["filename"],
                               scan_timestamp=current_report_data["scan_timestamp"])
    else:
        flash("No report available or scan failed. Please perform a scan first.", "warning")
        return redirect(url_for('index'))


@app.route('/download')
def download_report():
    if current_report_data["content"] and current_report_data["filename"]:
        # 1. Create an in-memory byte buffer
        mem_file = io.BytesIO()

        # 2. Write the string content encoded as UTF-8 bytes
        mem_file.write(current_report_data["content"].encode('utf-8'))

        # 3. Reset the buffer's cursor back to the beginning so Flask can read it
        mem_file.seek(0)

        # 4. Send the file directly from memory!
        return send_file(
            mem_file,
            as_attachment=True,
            download_name=current_report_data["filename"],
            mimetype='text/markdown'
        )
    else:
        flash("No report to download.", "warning")
        return redirect(url_for('index'))


if __name__ == '__main__':
    print("Performing initial OSV-Scanner check...", flush=True)
    if not ensure_osv_scanner():
        print("CRITICAL: OSV-Scanner is not available. The application will not be able to perform dependency scans. Exiting.", flush=True)
        sys.exit(1)
    print("OSV-Scanner check passed. Starting Flask application.", flush=True)

    app.run(debug=True, host='0.0.0.0', port=5000)