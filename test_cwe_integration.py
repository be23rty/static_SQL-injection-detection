"""Quick integration test – verifies both analyzers emit cwe_id + cwe_description."""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "v21_firewall_work"))

# ---- broad_security_analyzer (Python AST) ----
from broad_security_analyzer import analyze_source as py_analyze

py_code = """
import os, subprocess, pickle, hashlib
username = input("User: ")
q = "SELECT * FROM users WHERE name = '" + username + "'"
cursor.execute(q)                          # SQL injection
os.system(username)                        # command injection
data = pickle.loads(username.encode())     # unsafe deserialization
hashlib.md5(username.encode())             # weak hash
"""

print("=" * 60)
print("broad_security_analyzer (Python AST) findings")
print("=" * 60)
py_results = py_analyze(py_code, "demo.py")
for r in py_results:
    print(f"  Line {r['line']:3d}  Sev:{r['severity']:8s}  Rule:{r['rule_violated']:25s}  CWE:{r['cwe_id']}  ({r['cwe_description']})")
print(f"\nTotal Python findings: {len(py_results)}\n")

# ---- multilang_security_analyzer (JS/Java/C) ----
from multilang_security_analyzer import analyze_source as ml_analyze

js_code = """
const express = require('express');
const app = express();
app.get('/search', (req, res) => {
    const name = req.query.name;
    db.query("SELECT * FROM users WHERE name = '" + name + "'", cb);
    res.send("<div>" + name + "</div>");   // XSS
    eval(name);                             // code injection
});
"""

print("=" * 60)
print("multilang_security_analyzer (JavaScript) findings")
print("=" * 60)
js_results = ml_analyze(js_code, "demo.js")
for r in js_results:
    print(f"  Line {r['line']:3d}  Sev:{r['severity']:8s}  Rule:{r['rule_violated']:25s}  CWE:{r['cwe_id']}  ({r['cwe_description']})")
print(f"\nTotal JS findings: {len(js_results)}\n")

# ---- summary ----
all_results = py_results + js_results
no_cwe = [r for r in all_results if r.get("cwe_id") == "CWE-0"]
print("=" * 60)
print(f"TOTAL findings: {len(all_results)}")
print(f"Findings WITH a CWE ID : {len(all_results) - len(no_cwe)}")
print(f"Findings WITHOUT CWE   : {len(no_cwe)}")
print("=" * 60)
