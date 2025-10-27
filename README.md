# Web App Vulnerability Scanner

**A lightweight Flask-based web crawler and vulnerability scanner (educational use only).**

---

## 🚀 Overview

This project is a simple web scanner built with Flask. It crawls a target website, discovers pages and forms, and performs automated checks for common web vulnerabilities such as XSS, SQL Injection. The tool is designed for educational and authorized security testing only — do **not** use it against systems you do not own or have permission to test.
---

## 📌 Key Features

-   **Web-Based UI:** A clean and responsive user interface built with Flask, accessible from any web browser.
-   **Automated Web Crawler:** Discovers in-scope links and HTML forms (`<form>`) to identify potential attack surfaces.
-   **Multi-Vulnerability Scanning Engine:**
    -   **Cross-Site Scripting (XSS):** Detects reflected XSS vulnerabilities by injecting payloads and checking for their presence in the response.
    -   **SQL Injection (SQLi):** Identifies error-based SQLi by analyzing server responses for common database error messages.
-   **Real-Time Logging:** The UI provides a live log of the crawler and scanner's progress.
-   **Dynamic Results:** Discovered vulnerabilities are populated in a results table in real-time.
-   **JSON Report Export:** Allows users to download a detailed JSON report of all findings for documentation and analysis.

---

## 🛠 Technology Stack

-   **Backend:** Python 3, Flask
-   **HTTP & Parsing:** `requests`, `BeautifulSoup4`
-   **Frontend:** HTML, CSS, JavaScript (using `fetch` API for async communication)

---

## ⚙️Installation & 📜 Source Code

The complete source code for this project can be viewed at the following Google Docs link:

[**View Project Code Here**](https://docs.google.com/document/d/1QzSea_cTprO1uVJj6Jv_lc8H3pR2jwGJqW2UJy01i5Q/edit?usp=sharing)

---

## 🚀 How to Use

1. Run the Flask application from the project root:

```bash
python Vuln Scanner.py
```

2. Open your browser and visit:

```
http://127.0.0.1:5000/
```

3. Start a Scan (workflow):

* The input box will be pre-filled with the target URL `http://testphp.vulnweb.com/` (change it if you wish).
* Click **Start Crawl**. Watch the logs for the crawler discovering pages and forms.
* After the crawl completes, the **Scan Endpoints** button will enable.
* Click **Scan Endpoints** to start vulnerability testing for discovered forms.
* Watch the logs and the results table for any discovered vulnerabilities.
* When the scan finishes, click **Export Report** to download a JSON file of the findings.

---

## 🔬 Vulnerability Detection Logic (Implementation Notes)

* **XSS**: Inject payloads into one parameter at a time and check if the payload is reflected in the raw HTML response.
* **SQL Injection**: Inject error-inducing payloads and analyze the response for common database error strings (for example, `mysql`, `syntax error`, etc.).

---

## ⚠️ Disclaimer

This tool is intended for educational purposes and authorized security testing only. Using it against web applications without explicit permission from the owner is illegal and unethical. The author and maintainers are not responsible for any misuse or damage caused by this software. Always obtain permission and follow legal and ethical guidelines.

---

## 📄 License

This project is licensed under the **MIT License**. See `LICENSE` for full details.
