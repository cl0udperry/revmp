# 🛡️ Enterprise Vulnerability Management Platform (Re:VMP)

**Re:VMP** is a lightweight dashboard application designed to **visualize and manage vulnerabilities** across the development lifecycle. It integrates seamlessly with existing **JIRA workflows** to provide real-time visibility into vulnerability data, with built-in support for **deduplication** and **commit-level tracking**.

The platform addresses a common challenge faced in many organizations: duplicated "production vulnerabilities" that persist across multiple releases. Re:VMP helps ensure vulnerabilities are actively tracked and remediated during development, without disrupting current CI/CD processes.

This project began as a **personal proof of concept (POC)** to explore a scalable and minimally disruptive solution to a vulnerability data problem. It was built with the intention of solving a real-world challenge **independently and pragmatically**, without overhauling existing deployment pipelines.

---

## ✅ Use Cases

### For Security Teams:
- View vulnerability counts by severity
- Track vulnerabilities by commit and release
- Manage triage status and add comments
- Filter and search across applications easily

### For Developers & Project Teams:
- Track and resolve vulnerabilities per organizational timelines
- Gain visibility on what needs fixing before production
- Improve development accountability with commit-level tracking

### For Reporting:
- Simplifies vulnerability reporting and summaries
- Enables integration with external dashboards for management visibility

---

## ✨ Features

### 📊 Dashboard Summary
- Table of all applications with severity breakdown
- Toggleable bar chart for Coverity and BlackDuck vulnerabilities
- Summary of total vulnerabilities by severity

### 🔍 Per-Commit Vulnerability Detail
- View vulnerabilities by specific commit and release
- Coverity and BlackDuck details with severity and type
- Add triage status and comments (Fix Required, False Positive, Risk Mitigated)

### 🧱 Data Model
- Commit-level granularity
- App UUIDs mapped to Bitbucket + BlackDuck metadata
- Built-in deduplication of vulnerabilities across development/production

---

## 🛠️ Tech Stack

- **Backend**: Python, FastAPI, SQLAlchemy, SQLite
- **Frontend**: Jinja2 Templates, HTML/CSS, Chart.js
- **Styling**: Responsive layout with clean, minimal UI

---

## ⚙️ Setup & Installation

```bash
# 1. Clone the repository
git clone https://github.com/your-username/revmp.git
cd revmp

# 2. (Optional) Set up virtual environment
python -m venv venv
source venv/bin/activate  # or venv\Scripts\activate on Windows

# 3. Install dependencies
pip install -r requirements.txt

# 4. Initialize the SQLite database (for clean setup)
python init_db.py

# Note: Test data is included in the provided sample DB file if you don’t have access to Coverity/BlackDuck.

# 5. Run the development server
uvicorn main:app --reload

'''
📌 TODO / Future Improvements
- User login and roles
- Full Comments and Triage working workflow
- Enhancements to visualisations and overall design of platform
- Management report export (CSV, PDF)

📄 License
This project is licensed under the MIT License.
Feel free to fork, adapt, or contribute to improve it for your own organization or security team.

🙏 Acknowledgements
- Coverity
- BlackDuck
- FastAPI
- Chart.js
'''
