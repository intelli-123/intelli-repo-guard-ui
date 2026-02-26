
# 🛡️ AI RepoGuard

**AI RepoGuard** is a hybrid security scanning application that combines traditional dependency vulnerability checking with advanced, AI-powered Static Application Security Testing (SAST).

By leveraging **Google's OSV-Scanner** and **Gemini 2.5 Flash** (via LangChain), this tool thoroughly analyzes Git repositories to identify vulnerable packages, hardcoded secrets, SQL injections, XSS risks, and insecure configurations. It features a modern, responsive web interface built with Flask and Milligram CSS.

---

## ✨ Features

* **Hybrid Analysis:** Combines static dependency scanning with AI-driven source code review.
* **Dependency Scanning:** Automatically installs and utilizes `osv-scanner` to check for known vulnerabilities in open-source packages and lockfiles.
* **AI Source Code Review:** Analyzes source code files (`.py`, `.js`, `.java`, `.tf`, `.env`, etc.) using Google Gemini to detect logical vulnerabilities and hardcoded secrets.
* **Real-time Progress UI:** Asynchronous backend processing allows the web UI to display a live progress bar and current file status during the scan.
* **Comprehensive Reporting:** Generates detailed reports complete with risk explanations, suggested code fixes, and Mermaid.js pie charts.
* **Export Options:** Download reports in raw Markdown (`.md`) or capture perfectly formatted PDFs directly from the browser.

---

## 📋 Prerequisites

Before you begin, ensure you have the following installed on your system:

1. **Python 3.12+**
2. **Go (Golang):** Required to automatically install and run Google's OSV-Scanner. ([Download Go](https://go.dev/doc/install))
3. **Git:** Required to clone the target repositories.
4. **Google Gemini API Key:** You need an API key from Google AI Studio to power the LangChain code analysis.

---

## 🚀 Installation & Setup

**1. Clone the repository:**

```bash
git origin  https://github.com/intelli-123/intelli-repo-guard-ui.git
cd intelli-repo-guard-ui

```

**2. Create and activate a virtual environment:**

```bash
# Windows
python -m venv venv
venv\Scripts\activate

# macOS/Linux
python3 -m venv venv
source venv/bin/activate

```

**3. Install Python dependencies:**

```bash
pip install Flask langchain langchain-core langchain-google-genai python-dotenv certifi

```

**4. Configure Environment Variables:**
Create a `.env` file in the root directory of the project and add your Google API key:

```ini
# .env
GOOGLE_API_KEY="your_google_gemini_api_key_here"
IS_PUBLIC_REPO="true"

# (Optional) Add any GitHub/GitLab tokens if your git_handler.py requires them for private repos

```

---

## 💻 Usage

### Web Interface (Recommended)

Start the Flask web server:

```bash
python app.py

```

1. Open your browser and navigate to `http://localhost:5000`.
2. Paste the URL of a public Git repository (e.g., `https://github.com/owner/repo.git`).
3. Click **Start Scan**. The app will clone the repo, run the OSV-scanner, query the AI, and display real-time progress.
4. Once finished, view the results on the dashboard or download the report as a `.md` or `.pdf` file.


The CLI will output the progress to the console and generate a Markdown file (e.g., `ai_repoguard_YYYY-MM-DD_HH-MM-SS.md`) in the current directory.

---

## 📁 Project Structure

* `app.py`: The main Flask application handling routing, threaded background scanning, and serving the frontend.
* `scanner_core.py`: The core logic engine. Handles OSV-scanner installation/execution, LLM initialization, file parsing, and Markdown report generation.
* `git_handler.py`: Utility functions for cloning repositories securely into temporary directories.
* `templates/`: Contains the HTML frontend.
* `base.html`: The master layout utilizing Milligram CSS.
* `index.html`: The homepage and URL input form.
* `scanning.html`: The live progress bar view.
* `report.html`: Renders the Markdown report into HTML and handles PDF generation via `html2pdf.js`.



---

## ⚠️ Disclaimer

This tool utilizes a Large Language Model (LLM) to identify potential security risks. While it is highly capable, AI can produce false positives or miss complex, multi-file vulnerabilities. This tool is meant to assist developers and security researchers, not to replace professional security audits or dedicated SAST/DAST enterprise software.

