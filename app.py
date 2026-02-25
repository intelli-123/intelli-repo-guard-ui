# app.py
import os
import tempfile
import json
from flask import Flask, render_template, request, send_file, redirect, url_for, flash
from datetime import datetime
import shutil

# Import the core scanning logic
from scanner_core import run_scan_logic, ensure_osv_scanner

app = Flask(__name__)
app.secret_key = os.urandom(24) # Needed for flash messages

# Simple in-memory storage for the last report.
# For a production app, consider a database or persistent storage.
current_report_data = {
    "content": None,
    "filename": None,
    "scan_timestamp": None
}

@app.route('/')
def index():
    return render_template('index.html', report_available=current_report_data["content"] is not None)

@app.route('/scan', methods=['POST'])
def scan_repository():
    repo_url = request.form['repo_url']
    if not repo_url:
        flash("Repository URL cannot be empty!", "error")
        return redirect(url_for('index'))

    # Display an initial message immediately
    flash(f"Starting scan for {repo_url}... This may take a few minutes.", "info")

    try:
        # Run the core scan logic
        report_content, report_filename = run_scan_logic(repo_url)
        
        # Store the report in our simple global variable
        current_report_data["content"] = report_content
        current_report_data["filename"] = report_filename
        current_report_data["scan_timestamp"] = datetime.now()
        
        flash("Scan complete! View the report below.", "success")
        return redirect(url_for('view_report'))
    except Exception as e:
        flash(f"An error occurred during scanning: {e}", "error")
        app.logger.error(f"Scan failed for {repo_url}", exc_info=True)
        return redirect(url_for('index'))


@app.route('/report')
def view_report():
    if current_report_data["content"]:
        return render_template('report.html', 
                               report_content=current_report_data["content"],
                               report_filename=current_report_data["filename"],
                               scan_timestamp=current_report_data["scan_timestamp"])
    else:
        flash("No report available. Please perform a scan first.", "warning")
        return redirect(url_for('index'))

@app.route('/download')
def download_report():
    if current_report_data["content"] and current_report_data["filename"]:
        # Create a temporary file to save the report content
        # This is necessary because send_file needs a path to an actual file.
        temp_dir = tempfile.mkdtemp()
        report_path = os.path.join(temp_dir, current_report_data["filename"])
        with open(report_path, "w") as f:
            f.write(current_report_data["content"])
        
        try:
            return send_file(report_path, as_attachment=True, download_name=current_report_data["filename"])
        finally:
            # Clean up the temporary directory after sending the file
            shutil.rmtree(temp_dir)
    else:
        flash("No report to download.", "warning")
        return redirect(url_for('index'))

if __name__ == '__main__':
    # Initial check for osv-scanner on app startup.
    # This prevents the app from starting if a crucial dependency is missing.
    print("Performing initial OSV-Scanner check...", flush=True)
    if not ensure_osv_scanner():
        print("CRITICAL: OSV-Scanner is not available. The application will not be able to perform dependency scans. Exiting.", flush=True)
        sys.exit(1) # Exit if OSV-Scanner is not available
    print("OSV-Scanner check passed. Starting Flask application.", flush=True)
    
    # Run Flask in debug mode for development, use Gunicorn for production (in Dockerfile)
    app.run(debug=True, host='0.0.0.0', port=5000)
