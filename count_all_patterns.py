"""
Count every detectable pattern across the full SecureCode AI pipeline.
Prints a per-analyzer breakdown and a grand total.
"""
import sys, re, ast as pyast, json
sys.path.insert(0, "v21_firewall_work")

# ── 1. broad_security_analyzer (Python AST) ─────────────────────────────────
import broad_security_analyzer as bsa

# Count distinct _add() call sites → each is one unique detection rule
bsa_src = open("v21_firewall_work/broad_security_analyzer.py").read()
bsa_rules = set(re.findall(r'"([A-Z][A-Z0-9\-]+)"(?=,\s*"(?:SQL Injection|Command Injection|Code Injection|Cross-Site Scripting|Server-Side Template Injection|Path Traversal|Hard-coded Secret|Unsafe Deserialization|SSRF|Authentication|Transport Security|Security Misconfiguration|Weak Randomness|Insecure File Handling|Secrets|Weak Cryptography|Network Security|XML Security))', bsa_src))
# Also count rule_violated strings directly
bsa_rule_violated = set(re.findall(r'self\._add\(\s*"[^"]+",\s*\w+,\s*"([A-Z][A-Z0-9\-]+)"', bsa_src))
bsa_all = bsa_rules | bsa_rule_violated

# Count SOURCE_CALLS, SANITIZER_CALLS, SQL_METHODS, COMMAND_FUNCS, DESERIALIZERS
def count_set(name):
    m = re.search(name + r'\s*=\s*\{([^}]+)\}', bsa_src, re.S)
    return len(re.findall(r'"[^"]+"', m.group(1))) if m else 0

bsa_sources      = count_set("SOURCE_CALLS")
bsa_sanitizers   = count_set("SANITIZER_CALLS")
bsa_sql          = count_set("SQL_METHODS")
bsa_cmd          = count_set("COMMAND_FUNCS")
bsa_deser        = count_set("DESERIALIZERS")

# ── 2. multilang_security_analyzer ──────────────────────────────────────────
ml_src = open("v21_firewall_work/multilang_security_analyzer.py").read()

# Taint source patterns per language
ml_sources = len(re.findall(r"r'\\b", ml_src))
# Explicit rule tuples  (pat, sev, cat, sink, desc, fix, conf)
ml_rule_tuples = len(re.findall(r'\(r\'[^\']+\',\s*\'(?:CRITICAL|HIGH|MEDIUM|LOW)', ml_src))
# _RULE_TO_CWE entries
ml_cwe_entries = len(re.findall(r'"[A-Z]+-[A-Z0-9-]+"\s*:\s*"CWE-\d+"', ml_src))
# Sink patterns
ml_sinks = len(re.findall(r"r'\\b[^']+(?:_sinks|_sink)", ml_src))
# SQL construction patterns
ml_sql_constructions = len(re.findall(r'sql_words', ml_src))
# Hard-coded credential patterns
ml_cred_pats = len(re.findall(r'cred_pat', ml_src))

# ── 3. secret_scanner ────────────────────────────────────────────────────────
ss_src = open("v21_firewall_work/secret_scanner.py").read()
ss_signatures  = len(re.findall(r'\(r"[^"]+"\s*,', ss_src))
ss_entropy     = 1 if "entropy" in ss_src.lower() else 0

# ── 4. dependency_scanner (CVE patterns) ────────────────────────────────────
ds_src = open("v21_firewall_work/dependency_scanner.py").read()
ds_cve = len(re.findall(r'"CVE-\d+-\d+"', ds_src))
ds_pkg = len(re.findall(r'"[a-z][a-z0-9\-_]+":\s*\{', ds_src))

# ── 5. AI Firewall injection rules ──────────────────────────────────────────
fw_src = open("v21_firewall_work/ai_firewall.py").read()
fw_rules = len(re.findall(r'\("[\w_]+",\s*re\.compile', fw_src))

# ── 6. CWE map coverage ──────────────────────────────────────────────────────
from cwe_mapping import CWE_MAP
cwe_total = len(CWE_MAP)
from broad_security_analyzer import _RULE_TO_CWE as bsa_rule_cwe
from multilang_security_analyzer import _RULE_TO_CWE as ml_rule_cwe
all_rule_cwe = {**bsa_rule_cwe, **ml_rule_cwe}
active_cwes = set(all_rule_cwe.values())

# ── REPORT ───────────────────────────────────────────────────────────────────
sep = "─" * 65
print(sep)
print("  SecureCode AI — Pattern Coverage Report")
print(sep)

print("\n📌  broad_security_analyzer.py  (Python AST taint engine)")
print(f"   Detection rules (_add call sites)   : {len(bsa_rule_violated):>4}")
print(f"   Taint source APIs                   : {bsa_sources:>4}")
print(f"   Sanitizer / safe-sink APIs          : {bsa_sanitizers:>4}")
print(f"   SQL execution methods               : {bsa_sql:>4}")
print(f"   Command execution functions         : {bsa_cmd:>4}")
print(f"   Unsafe deserializers                : {bsa_deser:>4}")
bsa_total = len(bsa_rule_violated) + bsa_sources + bsa_sanitizers + bsa_sql + bsa_cmd + bsa_deser

print(f"   ── subtotal ──────────────────────── {bsa_total:>4}")

print("\n📌  multilang_security_analyzer.py  (JS / Java / C / C++)")
print(f"   Explicit rule tuples (regex+sev)    : {ml_rule_tuples:>4}")
print(f"   Taint source patterns               : {ml_sources:>4}")
print(f"   Sink category patterns              : {ml_sinks:>4}")
print(f"   Rule → CWE mappings                 : {ml_cwe_entries:>4}")
ml_total = ml_rule_tuples + ml_sources + ml_sinks
print(f"   ── subtotal ──────────────────────── {ml_total:>4}")

print("\n📌  secret_scanner.py  (credential / key detection)")
print(f"   Regex signatures                    : {ss_signatures:>4}")
print(f"   Entropy detector                    : {ss_entropy:>4}")
ss_total = ss_signatures + ss_entropy
print(f"   ── subtotal ──────────────────────── {ss_total:>4}")

print("\n📌  dependency_scanner.py  (SCA / CVE)")
print(f"   CVE fingerprints                    : {ds_cve:>4}")
print(f"   Vulnerable package entries          : {ds_pkg:>4}")
ds_total = ds_cve + ds_pkg
print(f"   ── subtotal ──────────────────────── {ds_total:>4}")

print("\n📌  ai_firewall.py  (prompt-injection guardrails)")
print(f"   Injection regex rules               : {fw_rules:>4}")
print(f"   ── subtotal ──────────────────────── {fw_rules:>4}")

grand = bsa_total + ml_total + ss_total + ds_total + fw_rules
print(f"\n{sep}")
print(f"  GRAND TOTAL PATTERNS                  {grand:>4}")
print(f"{sep}")

print(f"\n📂  CWE Coverage")
print(f"   CWE entries in cwe_mapping.py       : {cwe_total:>4}")
print(f"   Active CWEs (linked to rules)       : {len(active_cwes):>4}")
print(f"\n   Active CWE IDs:")
for cwe in sorted(active_cwes, key=lambda x: int(x.split("-")[1])):
    print(f"     {cwe:12s}  {CWE_MAP.get(cwe, 'Unknown')}")
print(sep)
